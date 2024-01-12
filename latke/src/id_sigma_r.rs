use crate::{
    auth_enc::{auth_decrypt, auth_encrypt, AuthEncKey},
    Id, MyKdf, MyMac, Nonce, PartyRole, SessKey, Ssid,
};

use blake2::Digest;
use hkdf::hmac::digest::{Mac, MacError};
use pqcrypto_dilithium::dilithium2::{
    detached_sign, public_key_bytes as sig_pubkey_size, signature_bytes as sig_size,
    verify_detached_signature, DetachedSignature, KeygenCoins, PublicKey as SigPubkey,
    SecretKey as SigPrivkey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey, VerificationError,
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use saber::{
    lightsaber::{
        decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
        keygen_ind_cpa as kem_keygen, Ciphertext as EncappedKey, INDCPAPublicKey, INDCPASecretKey,
    },
    Error as SaberError,
};
use sha2::Sha256;

#[derive(Debug)]
enum SigmaError {
    Kem(SaberError),
    InvalidLength(pqcrypto_traits::Error),
    Sig(VerificationError),
    Mac(MacError),
    InvalidSsid,
}

impl From<SaberError> for SigmaError {
    fn from(err: SaberError) -> Self {
        Self::Kem(err)
    }
}

impl From<MacError> for SigmaError {
    fn from(err: MacError) -> Self {
        Self::Mac(err)
    }
}

impl From<pqcrypto_traits::Error> for SigmaError {
    fn from(err: pqcrypto_traits::Error) -> Self {
        Self::InvalidLength(err)
    }
}

impl From<VerificationError> for SigmaError {
    fn from(err: VerificationError) -> Self {
        Self::Sig(err)
    }
}

struct Executor {
    role: PartyRole,
    /// The SSIDs for the two parties
    ssids: (Option<Ssid>, Option<Ssid>),
    /// The nonces for the two parties
    nonces: (Option<Nonce>, Option<Nonce>),
    /// The main public key of this identity-based system. This is used to verify certificates.
    mpk: SigPubkey,
    /// The certificate Extracted for this party by the key generation center
    cert: SigmaCert,
    /// The corresponding secret key for the public key in `cert`
    sig_privkey: SigPrivkey,

    // Ephemeral values
    kem_pubkey: Option<INDCPAPublicKey>,
    kem_privkey: Option<INDCPASecretKey>,
    encapped_key: Option<EncappedKey>,
    mac_key: Option<[u8; 32]>,
    enc_keys: Option<([u8; 32], [u8; 32])>,

    // The output of a post-specified peer IBKE is (ID, session_key)
    output_id: Option<Id>,
    output_key: Option<SessKey>,

    next_step: usize,
}

impl Executor {
    fn extract(msk: SigPrivkey, id: &Id, upk: &SigPubkey) -> SigmaCert {
        let sig = detached_sign(&[id, upk.as_bytes()].concat(), &msk);
        SigmaCert {
            id: id.clone(),
            upk: upk.clone(),
            sig,
        }
    }

    /// Creates a new IBKE executor from a main public key, a certificate, a user signing key for the `upk` in that certificate, and a protocol role
    fn new<R: RngCore + CryptoRng>(
        mut rng: R,
        mpk: SigPubkey,
        cert: SigmaCert,
        usk: SigPrivkey,
        role: PartyRole,
    ) -> Self {
        let mut my_ssid = Ssid::default();
        let mut my_nonce = Nonce::default();
        rng.fill_bytes(&mut my_ssid);
        rng.fill_bytes(&mut my_nonce);

        let ssids = if role == PartyRole::Initiator {
            (Some(my_ssid), None)
        } else {
            (None, Some(my_ssid))
        };
        let nonces = if role == PartyRole::Initiator {
            (Some(my_nonce), None)
        } else {
            (None, Some(my_nonce))
        };

        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Self {
            role,
            ssids,
            nonces,
            mpk,
            cert,
            sig_privkey: usk,
            kem_pubkey: None,
            kem_privkey: None,
            encapped_key: None,
            mac_key: None,
            enc_keys: None,

            output_id: None,
            output_key: None,

            next_step,
        }
    }

    fn finalize(&self) -> (Id, SessKey) {
        (self.output_id.unwrap(), self.output_key.unwrap())
    }

    fn run<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        incoming_msg: &[u8],
    ) -> Result<Option<Vec<u8>>, SigmaError> {
        let out = match self.next_step {
            // Generate an ephemeral keypair and send the pubkey
            0 => {
                assert_eq!(incoming_msg.len(), 0);

                // Generate an ephemeral KEM keypair
                let (kem_pubkey, kem_privkey) = kem_keygen();
                self.kem_pubkey = Some(kem_pubkey);
                self.kem_privkey = Some(kem_privkey);

                // Send (ssid_a, nonce_a, pubkey)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                    ]
                    .concat(),
                )
            }
            1 => {
                // Deserialize everything
                let (ssid_and_nonce, kem_pubkey_bytes) = incoming_msg.split_at(64);
                let (ssid, nonce) = ssid_and_nonce.split_at(32);
                self.ssids.0 = Some(ssid.try_into().unwrap());
                self.nonces.0 = Some(nonce.try_into().unwrap());
                self.kem_pubkey = Some(INDCPAPublicKey::from_bytes(kem_pubkey_bytes));

                // Encapsulate to the pubkey
                let (shared_secret, encapped_key) = kem_encap(&self.kem_pubkey.as_ref().unwrap());
                self.encapped_key = Some(encapped_key);

                // Generate the session key and the MAC key from the shared secret
                let mut output_key = SessKey::default();
                let mut mac_key = [0u8; 32];
                let mut enc_key_a = AuthEncKey::default();
                let mut enc_key_b = AuthEncKey::default();
                let hk = MyKdf::from_prk(shared_secret.as_slice()).unwrap();
                hk.expand(b"output_key", &mut output_key).unwrap();
                hk.expand(b"mac_key", &mut mac_key).unwrap();
                hk.expand(b"enc_key_a", &mut enc_key_a).unwrap();
                hk.expand(b"enc_key_b", &mut enc_key_b).unwrap();
                self.output_key = Some(output_key);
                self.mac_key = Some(mac_key);
                self.enc_keys = Some((enc_key_a, enc_key_b));

                // Output (ssid_a, ssid_b, nonce_b, encapped_key)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        self.encapped_key.as_ref().unwrap().as_bytes().as_slice(),
                    ]
                    .concat(),
                )
            }
            2 => {
                // Deserialize everything
                let (ssids_and_nonce, encapped_key_bytes) = incoming_msg.split_at(96);
                let (ssids, nonce_b) = ssids_and_nonce.split_at(64);
                let (ssid_a, ssid_b) = ssids.split_at(32);

                // Save all the values and check that the ssid_a matches what we gave the peer
                self.encapped_key = Some(EncappedKey::from_bytes(encapped_key_bytes)?);
                self.nonces.1 = Some(nonce_b.try_into().unwrap());
                self.ssids.1 = Some(ssid_b.try_into().unwrap());
                if ssid_a != self.ssids.0.as_ref().unwrap().as_slice() {
                    return Err(SigmaError::InvalidSsid);
                }

                // Compute the shared secret and derive all the keys
                let shared_secret = kem_decap(
                    self.encapped_key.as_ref().unwrap(),
                    self.kem_privkey.as_ref().unwrap(),
                );
                let mut output_key = SessKey::default();
                let mut mac_key = [0u8; 32];
                let mut enc_key_a = AuthEncKey::default();
                let mut enc_key_b = AuthEncKey::default();
                let hk = MyKdf::from_prk(shared_secret.as_slice()).unwrap();
                hk.expand(b"output_key", &mut output_key).unwrap();
                hk.expand(b"mac_key", &mut mac_key).unwrap();
                hk.expand(b"enc_key_a", &mut enc_key_a).unwrap();
                hk.expand(b"enc_key_b", &mut enc_key_b).unwrap();
                self.output_key = Some(output_key);
                self.mac_key = Some(mac_key);
                self.enc_keys = Some((enc_key_a, enc_key_b));

                let cert_bytes = self.cert.to_bytes();

                // Time for some key confirmation. Send the cert, a signature over the transcript, and a MAC over the ID
                // Now compute the signature over what's happened so far
                let sig = detached_sign(
                    &[
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        &cert_bytes,
                    ]
                    .concat(),
                    &self.sig_privkey,
                );

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.cert.id)
                    .finalize()
                    .into_bytes();

                // Encrypt (sig, mac, cert)
                let msg_to_encrypt = [sig.as_bytes(), mac.as_slice(), &cert_bytes].concat();
                let ciphertext = auth_encrypt(&mut rng, enc_key_a, &msg_to_encrypt);

                // Send (ssid_A, ssid_B, ciphertext)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        ciphertext.as_slice(),
                    ]
                    .concat(),
                )
            }
            3 => {
                // Deserialize and decrypt everything
                let (ssids, ciphertext) = incoming_msg.split_at(64);
                let (ssid_a, ssid_b) = ssids.split_at(32);
                let sig_mac_cert = auth_decrypt(self.enc_keys.as_ref().unwrap().0, ciphertext)?;
                let (sig_mac, incoming_cert_bytes) =
                    sig_mac_cert.split_at(sig_mac_cert.len() - SigmaCert::size());
                let (sig, incoming_mac) = sig_mac.split_at(sig_size());

                let incoming_sig = DetachedSignature::from_bytes(sig)?;
                let incoming_cert = SigmaCert::from_bytes(incoming_cert_bytes)?;
                self.output_id = Some(incoming_cert.id);

                // Do the verifications. Check the SSIDs match, that the certificate verifies, and that the signature and MAC verify
                if ssid_a != self.ssids.0.as_ref().unwrap().as_slice()
                    || ssid_b != self.ssids.1.as_ref().unwrap().as_slice()
                {
                    return Err(SigmaError::InvalidSsid);
                }
                // Check the certificate verifies
                verify_detached_signature(
                    &incoming_cert.sig,
                    &[&incoming_cert.id, incoming_cert.upk.as_bytes()].concat(),
                    &self.mpk,
                )?;
                // Check the other signature verifies
                verify_detached_signature(
                    &incoming_sig,
                    &[
                        self.nonces.1.as_ref().unwrap().as_slice(),
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        &incoming_cert_bytes,
                    ]
                    .concat(),
                    &incoming_cert.upk,
                )?;
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.output_id.as_ref().unwrap())
                    .verify_slice(incoming_mac)?;

                // Now compute the final message. Compute the signature and MAC, similar to above
                let my_cert_bytes = self.cert.to_bytes();
                let sig = detached_sign(
                    &[
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        &my_cert_bytes,
                    ]
                    .concat(),
                    &self.sig_privkey,
                );

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.cert.id)
                    .finalize()
                    .into_bytes();

                // Encrypt (sig, mac, cert)
                let ciphertext = auth_encrypt(
                    &mut rng,
                    self.enc_keys.as_ref().unwrap().1,
                    &[sig.as_bytes(), mac.as_slice(), &my_cert_bytes].concat(),
                );

                // Send (ssid_A, ssid_B, ciphertext)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        ciphertext.as_slice(),
                    ]
                    .concat(),
                )
            }
            4 => {
                // Deserialize and decrypt everything
                let (ssids, ciphertext) = incoming_msg.split_at(64);
                let (ssid_a, ssid_b) = ssids.split_at(32);
                let sig_mac_cert = auth_decrypt(self.enc_keys.as_ref().unwrap().1, ciphertext)?;
                let (sig_mac, incoming_cert_bytes) =
                    sig_mac_cert.split_at(sig_mac_cert.len() - SigmaCert::size());
                let (sig, incoming_mac) = sig_mac.split_at(sig_size());

                let incoming_sig = DetachedSignature::from_bytes(sig)?;
                let incoming_cert = SigmaCert::from_bytes(incoming_cert_bytes)?;
                self.output_id = Some(incoming_cert.id);

                // Do the verifications. Check the SSIDs match, that the certificate verifies, and that the signature and MAC verify
                if ssid_a != self.ssids.0.as_ref().unwrap().as_slice()
                    || ssid_b != self.ssids.1.as_ref().unwrap().as_slice()
                {
                    return Err(SigmaError::InvalidSsid);
                }
                // Check the certificate verifies
                verify_detached_signature(
                    &incoming_cert.sig,
                    &[&incoming_cert.id, incoming_cert.upk.as_bytes()].concat(),
                    &self.mpk,
                )?;
                // Check the other signature verifies
                verify_detached_signature(
                    &incoming_sig,
                    &[
                        self.nonces.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        self.encapped_key.as_ref().unwrap().as_bytes(),
                        self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                        &incoming_cert_bytes,
                    ]
                    .concat(),
                    &incoming_cert.upk,
                )?;
                // Compute the MAC over the (ssid, ID)
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.output_id.as_ref().unwrap())
                    .verify_slice(incoming_mac)?;

                None
            }
            _ => {
                panic!("protocol already finished")
            }
        };

        self.next_step += 2;

        Ok(out)
    }
}

/// A certificate is a signed statement that a party with a given ID has a certain public key.
/// For our PQ Sigma protocol, the signature is a Dilithium signature, and the public key is a Dilithium public key.
struct SigmaCert {
    id: Id,
    upk: SigPubkey,
    sig: DetachedSignature,
}

impl SigmaCert {
    fn size() -> usize {
        Id::default().len() + sig_pubkey_size() + sig_size()
    }

    /// Serialize as upk || sig
    fn to_bytes(&self) -> Vec<u8> {
        [&self.id, self.upk.as_bytes(), self.sig.as_bytes()].concat()
    }

    /// Deserialize from upk || sig
    fn from_bytes(bytes: &[u8]) -> Result<Self, SigmaError> {
        if bytes.len() != Self::size() {
            return Err(SigmaError::InvalidLength(
                pqcrypto_traits::Error::BadLength {
                    name: "cert",
                    actual: bytes.len(),
                    expected: Self::size(),
                },
            ));
        }
        let (id_upk_bytes, sig_bytes) = bytes.split_at(Id::default().len() + sig_pubkey_size());
        let (id, upk_bytes) = id_upk_bytes.split_at(Id::default().len());
        Ok(Self {
            id: id.try_into().unwrap(),
            upk: SigPubkey::from_bytes(upk_bytes)?,
            sig: DetachedSignature::from_bytes(sig_bytes)?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pqcrypto_dilithium::dilithium2::keypair as gen_sig_keypair;

    #[test]
    fn sigma_r_correctness() {
        let mut rng = rand::thread_rng();
        let (mpk, msk) = gen_sig_keypair();
        let (upk1, usk1) = gen_sig_keypair();
        let (upk2, usk2) = gen_sig_keypair();

        let id1 = rng.gen();
        let id2 = rng.gen();

        let cert1 = Executor::extract(msk, &id1, &upk1);
        let cert2 = Executor::extract(msk, &id2, &upk2);

        let mut user1 = Executor::new(&mut rng, mpk.clone(), cert1, usk1, PartyRole::Initiator);
        let mut user2 = Executor::new(&mut rng, mpk.clone(), cert2, usk2, PartyRole::Responder);

        let msg1 = user1.run(&mut rng, &[]).unwrap().unwrap();
        let msg2 = user2.run(&mut rng, &msg1).unwrap().unwrap();
        let msg3 = user1.run(&mut rng, &msg2).unwrap().unwrap();
        let msg4 = user2.run(&mut rng, &msg3).unwrap().unwrap();
        let msg5 = user1.run(&mut rng, &msg4).unwrap();

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        assert!(msg5.is_none());
        assert!(user1_interlocutor == id2);
        assert!(user2_interlocutor == id1);
        assert_eq!(user1_key, user2_key);
    }
}
