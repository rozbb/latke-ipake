use hkdf::{
    hmac::{digest::MacError, Hmac, Mac},
    Hkdf,
};
use lioness::{LionessDefault, LionessError, RAW_KEY_SIZE as LIONESS_KEY_SIZE};
use rand_core::RngCore;
use saber::{
    firesaber::{
        decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
        keygen_ind_cpa as kem_keygen, Ciphertext as EncappedKey, INDCPAPublicKey, INDCPASecretKey,
        BYTES_CCA_DEC, INDCPA_PUBLICKEYBYTES,
    },
    Error as SaberError,
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
type EncryptedPubkey = [u8; INDCPA_PUBLICKEYBYTES];
type EncryptedEncappedKey = [u8; BYTES_CCA_DEC];

#[derive(Debug)]
enum CakeError {
    Mac(MacError),
    Saber(SaberError),
}

impl From<MacError> for CakeError {
    fn from(e: MacError) -> Self {
        CakeError::Mac(e)
    }
}

impl From<SaberError> for CakeError {
    fn from(e: SaberError) -> Self {
        CakeError::Saber(e)
    }
}

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
    password: Vec<u8>,
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
    password: Vec<u8>,
    nonce1: Nonce,
    eph_pk: Option<INDCPAPublicKey>,
    encapped_key: EncappedKey,
    ssid: Ssid,
    sess_key: SessionKey,
    auth_key: AuthKey,
}

impl CakeResponder {
    pub fn new(password: &[u8]) -> CakeResponder {
        CakeResponder {
            password: password.to_vec(),
            ..Default::default()
        }
    }

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

    fn step1_rx(&mut self, enc_eph_pk: &EncryptedPubkey) {
        assert_eq!(self.state, ResponderState::SentNonce2);
        self.state = ResponderState::RecvdStep1;

        // Decrypt the ephemeral pubkey
        let mut eph_pk = [0u8; INDCPA_PUBLICKEYBYTES];
        eph_pk.copy_from_slice(enc_eph_pk);
        let domain_sep = 0u8;
        lioness_decrypt(domain_sep, &self.ssid, &self.password, &mut eph_pk).unwrap();
        let eph_pk = INDCPAPublicKey::from_bytes(&eph_pk);
        self.eph_pk = Some(eph_pk);
    }

    fn step2_tx(&mut self) -> (EncryptedEncappedKey, AuthTag) {
        assert_eq!(self.state, ResponderState::RecvdStep1);
        self.state = ResponderState::SentStep2;

        let (shared_secret, encapped_key) = kem_encap(self.eph_pk.as_ref().unwrap());

        // Encrypt the encapsulated key
        let mut enc_encapped_key = [0u8; BYTES_CCA_DEC];
        enc_encapped_key.copy_from_slice(encapped_key.as_bytes());
        let domain_sep = 1u8;
        lioness_encrypt(
            domain_sep,
            &self.ssid,
            &self.password,
            &mut enc_encapped_key,
        )
        .unwrap();

        // Start the HKDF over the shared secret. We're gonna take two hashes
        let hk = Hkdf::<Sha256>::from_prk(shared_secret.as_slice()).unwrap();

        // Domain-separate our hashes
        let eph_pk_bytes = self.eph_pk.as_ref().unwrap().to_bytes();
        let sess_key_ctx = &[
            b"sess_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &enc_encapped_key,
        ];
        let auth_key_ctx = &[
            b"auth_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &enc_encapped_key,
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

        (enc_encapped_key, auth_tag.into_bytes().into())
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
    pub fn new(password: &[u8]) -> CakeInitiator {
        CakeInitiator {
            password: password.to_vec(),
            ..Default::default()
        }
    }

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
    fn step1_tx(&mut self) -> EncryptedPubkey {
        assert_eq!(self.state, InitiatorState::RecvdNonce2);
        self.state = InitiatorState::SentStep1;

        // Generate the keypair
        let (mut pk, sk) = kem_keygen();
        self.eph_pk = Some(pk.clone());
        self.eph_sk = Some(sk);

        // Now encrypt pk with the password and SSID
        let mut encrypted_pk = [0u8; INDCPA_PUBLICKEYBYTES];
        encrypted_pk.copy_from_slice(pk.to_bytes().as_bytes());
        let domain_sep = 0u8;
        lioness_encrypt(domain_sep, &self.ssid, &self.password, &mut encrypted_pk).unwrap();

        encrypted_pk
    }

    /// Receives an encapsulated key and derives the shared secret
    fn step2_rx(
        &mut self,
        enc_encapped_key: &EncryptedEncappedKey,
        auth_tag2: &AuthTag,
    ) -> Result<(), CakeError> {
        assert_eq!(self.state, InitiatorState::SentStep1);

        // Decrypt the encapsulated key
        let mut encapped_key = [0u8; BYTES_CCA_DEC];
        encapped_key.copy_from_slice(enc_encapped_key);
        let domain_sep = 1u8;
        lioness_decrypt(domain_sep, &self.ssid, &self.password, &mut encapped_key).unwrap();
        let encapped_key = EncappedKey::from_bytes(&encapped_key)?;

        // Decapsulate
        let shared_secret = kem_decap(&encapped_key, self.eph_sk.as_ref().unwrap());

        let hk = Hkdf::<Sha256>::from_prk(shared_secret.as_slice()).unwrap();

        // Domain-separate our hashes
        let eph_pk_bytes = self.eph_pk.as_ref().unwrap().to_bytes();
        let sess_key_ctx = &[
            b"sess_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &enc_encapped_key[..],
        ];
        let auth_key_ctx = &[
            b"auth_key",
            &self.ssid[..],
            &eph_pk_bytes.as_bytes()[..],
            &enc_encapped_key[..],
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
        let password = b"hello world";

        let mut initiator = CakeInitiator::new(password);
        let mut responder = CakeResponder::new(password);

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
