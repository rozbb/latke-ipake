use hkdf::{
    hmac::{digest::MacError, Hmac, Mac},
    Hkdf,
};
use lioness::{LionessDefault, LionessError, RAW_KEY_SIZE as LIONESS_KEY_SIZE};
use rand_core::RngCore;
use saber::firesaber::{
    decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
    keygen_ind_cpa as kem_keygen, Ciphertext, INDCPAPublicKey, INDCPASecretKey,
};
use sha2::{Digest, Sha256};

const NONCE_BYTELEN: usize = 16;
const INITIATOR_AUTH_STR: &[u8] = b"initiator";
const RESPONDER_AUTH_STR: &[u8] = b"respondder";

type Nonce = [u8; NONCE_BYTELEN];
type Ssid = [u8; 2 * NONCE_BYTELEN];
type SessionKey = [u8; 32];
type AuthKey = [u8; 32];
type AuthTag = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
enum InitiatorState {
    Initialized,
    SentNonce1,
    RecvdNonce2,
    SentStep1,
    RecvdStep2,
    SentStep3,
}

impl Default for InitiatorState {
    fn default() -> Self {
        InitiatorState::Initialized
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ResponderState {
    Initialized,
    RecvdNonce1,
    SentNonce2,
    RecvdStep1,
    SentStep2,
    RecvdStep3,
}

impl Default for ResponderState {
    fn default() -> Self {
        ResponderState::Initialized
    }
}

fn lioness_encrypt(
    domain_sep: u8,
    ssid: &[u8],
    password: &[u8],
    payload: &mut [u8],
) -> Result<(), LionessError> {
    let mut lioness_key = [0u8; LIONESS_KEY_SIZE];

    // KDF the domain separator, ssid, and password into a key of the appropriate length
    let password_hash = Sha256::digest(password);
    let hk = Hkdf::<Sha256>::from_prk(&password_hash).unwrap();
    hk.expand_multi_info(&[&[domain_sep], ssid], &mut lioness_key)
        .unwrap();

    let cipher = LionessDefault::new_raw(&lioness_key);
    cipher.encrypt(payload)
}

fn lioness_decrypt(
    domain_sep: u8,
    ssid: &[u8],
    password: &[u8],
    payload: &mut [u8],
) -> Result<(), LionessError> {
    let mut lioness_key = [0u8; LIONESS_KEY_SIZE];

    // KDF the domain separator, ssid, and password into a key of the appropriate length
    let password_hash = Sha256::digest(password);
    let hk = Hkdf::<Sha256>::from_prk(&password_hash).unwrap();
    hk.expand_multi_info(&[&[domain_sep], ssid], &mut lioness_key)
        .unwrap();

    let cipher = LionessDefault::new_raw(&lioness_key);
    cipher.decrypt(payload)
}

#[derive(Default)]
struct CakeInitiator {
    state: InitiatorState,
    nonce1: Nonce,
    ssid: Ssid,
    eph_pk: Option<INDCPAPublicKey>,
    eph_sk: Option<INDCPASecretKey>,
    sess_key: SessionKey,
    auth_key: AuthKey,
}

#[derive(Default)]
struct CakeResponder {
    state: ResponderState,
    nonce1: Nonce,
    eph_pk: Option<INDCPAPublicKey>,
    ciphertext: Ciphertext,
    ssid: Ssid,
    sess_key: SessionKey,
    auth_key: AuthKey,
}

impl CakeResponder {
    pub fn get_sess_key(&self) -> SessionKey {
        assert_eq!(self.state, ResponderState::RecvdStep3);
        self.sess_key
    }

    fn nonce1_rx(&mut self, nonce1: &Nonce) {
        assert_eq!(self.state, ResponderState::Initialized);
        self.state = ResponderState::RecvdNonce1;

        self.nonce1 = *nonce1;
    }

    fn nonce2_tx(&mut self, mut rng: impl RngCore) -> Nonce {
        assert_eq!(self.state, ResponderState::RecvdNonce1);
        self.state = ResponderState::SentNonce2;

        let mut nonce2 = Nonce::default();
        rng.fill_bytes(&mut nonce2);

        self.ssid[..NONCE_BYTELEN].copy_from_slice(&self.nonce1);
        self.ssid[NONCE_BYTELEN..].copy_from_slice(&nonce2);

        nonce2
    }

    fn step1_rx(&mut self, eph_pk: &INDCPAPublicKey) {
        assert_eq!(self.state, ResponderState::SentNonce2);
        self.state = ResponderState::RecvdStep1;

        self.eph_pk = Some(eph_pk.clone());
    }

    fn step2_tx(&mut self) -> (Ciphertext, AuthTag) {
        assert_eq!(self.state, ResponderState::RecvdStep1);
        self.state = ResponderState::SentStep2;

        let (shared_secret, ct) = kem_encap(self.eph_pk.as_ref().unwrap());

        // Start the HKDF over the shared secret. We're gonna take two hashes
        let hk = Hkdf::<Sha256>::from_prk(shared_secret.as_slice()).unwrap();

        // Domain-separate our hashes
        let eph_pk_bytes = self.eph_pk.as_ref().unwrap().to_bytes();
        let sess_key_ctx = &[
            b"sess_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &ct.as_bytes()[..],
        ];
        let auth_key_ctx = &[
            b"auth_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &ct.as_bytes()[..],
        ];

        // Set the session key
        hk.expand_multi_info(sess_key_ctx, &mut self.sess_key)
            .unwrap();
        // Set the auth key
        hk.expand_multi_info(auth_key_ctx, &mut self.auth_key)
            .unwrap();

        // Compute the auth tag
        let auth_tag = {
            let mut hm = Hmac::<Sha256>::new_from_slice(&self.auth_key).unwrap();
            hm.update(RESPONDER_AUTH_STR);
            hm.finalize()
        };

        (ct, auth_tag.into_bytes().into())
    }

    fn step3_rx(&mut self, auth_tag1: &AuthTag) -> Result<(), MacError> {
        assert_eq!(self.state, ResponderState::SentStep2);

        // Verify the incoming auth tag
        let mut hm = Hmac::<Sha256>::new_from_slice(&self.auth_key).unwrap();
        hm.update(INITIATOR_AUTH_STR);
        hm.verify_slice(auth_tag1)?;

        self.state = ResponderState::RecvdStep3;

        Ok(())
    }
}

impl CakeInitiator {
    pub fn get_sess_key(&self) -> SessionKey {
        assert_eq!(self.state, InitiatorState::SentStep3);
        self.sess_key
    }

    /// Sends the nonce
    fn nonce1_tx(&mut self, mut rng: impl RngCore) -> Nonce {
        assert_eq!(self.state, InitiatorState::Initialized);
        self.state = InitiatorState::SentNonce1;

        rng.fill_bytes(&mut self.nonce1);
        self.nonce1
    }

    /// Receives a nonce, thus establishing the ssid
    fn nonce2_rx(&mut self, nonce2: &Nonce) {
        assert_eq!(self.state, InitiatorState::SentNonce1);
        self.state = InitiatorState::RecvdNonce2;

        // ssid = nonce1 || nonce2
        self.ssid[..NONCE_BYTELEN].copy_from_slice(&self.nonce1);
        self.ssid[NONCE_BYTELEN..].copy_from_slice(nonce2);
    }

    /// Send an ephemeral pubkey
    fn step1_tx(&mut self) -> INDCPAPublicKey {
        assert_eq!(self.state, InitiatorState::RecvdNonce2);
        self.state = InitiatorState::SentStep1;

        // Generate the keypair
        let (pk, sk) = kem_keygen();
        self.eph_pk = Some(pk.clone());
        self.eph_sk = Some(sk);

        pk
    }

    /// Receives a ciphertext and derives the shared secret
    fn step2_rx(&mut self, ct: &Ciphertext, auth_tag2: &AuthTag) -> Result<(), MacError> {
        assert_eq!(self.state, InitiatorState::SentStep1);

        let shared_secret = kem_decap(ct, self.eph_sk.as_ref().unwrap());

        let hk = Hkdf::<Sha256>::from_prk(shared_secret.as_slice()).unwrap();

        // Domain-separate our hashes
        let eph_pk_bytes = self.eph_pk.as_ref().unwrap().to_bytes();
        let sess_key_ctx = &[
            b"sess_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &ct.as_bytes()[..],
        ];
        let auth_key_ctx = &[
            b"auth_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &ct.as_bytes()[..],
        ];

        // Set the session key
        hk.expand_multi_info(sess_key_ctx, &mut self.sess_key)
            .unwrap();
        // Set the auth key
        hk.expand_multi_info(auth_key_ctx, &mut self.auth_key)
            .unwrap();

        // Verify the incoming auth tag
        let mut hm = Hmac::<Sha256>::new_from_slice(&self.auth_key).unwrap();
        hm.update(RESPONDER_AUTH_STR);
        hm.verify_slice(auth_tag2)?;

        self.state = InitiatorState::RecvdStep2;
        Ok(())
    }

    /// Sends an auth tag
    fn step3_tx(&mut self) -> AuthTag {
        assert_eq!(self.state, InitiatorState::RecvdStep2);
        self.state = InitiatorState::SentStep3;

        let mut hm = Hmac::<Sha256>::new_from_slice(&self.auth_key).unwrap();
        hm.update(INITIATOR_AUTH_STR);
        hm.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn cake_correctness() {
        let mut rng = thread_rng();

        let mut initiator = CakeInitiator::default();
        let mut responder = CakeResponder::default();

        let nonce1 = initiator.nonce1_tx(&mut rng);
        responder.nonce1_rx(&nonce1);
        let nonce2 = responder.nonce2_tx(&mut rng);
        initiator.nonce2_rx(&nonce2);
        let eph_pk = initiator.step1_tx();
        responder.step1_rx(&eph_pk);
        let (ct, auth_tag2) = responder.step2_tx();
        initiator.step2_rx(&ct, &auth_tag2).unwrap();
        let auth_tag1 = initiator.step3_tx();
        responder.step3_rx(&auth_tag1).unwrap();

        assert_eq!(initiator.sess_key, responder.sess_key);
    }
}
