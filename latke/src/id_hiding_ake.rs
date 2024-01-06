use crate::{MyKdf, MyMac, Nonce, PartyRole, SessKey, Ssid};

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
use saber::{
    lightsaber::{
        decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
        keygen_ind_cpa as kem_keygen, Ciphertext as EncappedKey, INDCPAPublicKey, INDCPASecretKey,
    },
    Error as SaberError,
};

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
    sig_privkey: SigPrivkey,
    sig_pubkey: SigPubkey,
    kem_pubkey: Option<INDCPAPublicKey>,
    kem_privkey: Option<INDCPASecretKey>,
    encapped_key: Option<EncappedKey>,
    mac_key: Option<[u8; 32]>,
    enc_keys: Option<([u8; 32], [u8; 32])>,

    // The output of a post-specified peer IBKE is (ID, session_key)
    output_id: Option<SigPubkey>,
    output_key: Option<SessKey>,

    next_step: usize,
}

impl Executor {
    fn new<R: Rng>(mut rng: R, keypair: (SigPubkey, SigPrivkey), role: PartyRole) -> Self {
        let ssids = if role == PartyRole::Initiator {
            (Some(rng.gen()), None)
        } else {
            (None, Some(rng.gen()))
        };
        let nonces = if role == PartyRole::Initiator {
            (Some(rng.gen()), None)
        } else {
            (None, Some(rng.gen()))
        };

        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Self {
            role,
            ssids,
            nonces,
            sig_privkey: keypair.1,
            sig_pubkey: keypair.0,
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

    fn finalize(&self) -> (SigPubkey, SessKey) {
        (self.output_id.unwrap(), self.output_key.unwrap())
    }

    fn run(&mut self, incoming_msg: &[u8]) -> Result<Option<Vec<u8>>, SigmaError> {
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
                let mut enc_key_a = [0u8; 32];
                let mut enc_key_b = [0u8; 32];
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
                let mut enc_key_a = [0u8; 32];
                let mut enc_key_b = [0u8; 32];
                let hk = MyKdf::from_prk(shared_secret.as_slice()).unwrap();
                hk.expand(b"output_key", &mut output_key).unwrap();
                hk.expand(b"mac_key", &mut mac_key).unwrap();
                hk.expand(b"enc_key_a", &mut enc_key_a).unwrap();
                hk.expand(b"enc_key_b", &mut enc_key_b).unwrap();
                self.output_key = Some(output_key);
                self.mac_key = Some(mac_key);
                self.enc_keys = Some((enc_key_a, enc_key_b));

                // Time for some key confirmation. Send the user ID (i.e., the sig pubkey), a signature over the transcript, and a MAC over the ID
                // Now compute the signature over what's happened so far
                let msg_to_sign = [
                    self.nonces.1.as_ref().unwrap().as_slice(),
                    self.ssids.0.as_ref().unwrap().as_slice(),
                    self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                    self.encapped_key.as_ref().unwrap().as_bytes(),
                ]
                .concat();
                let sig = detached_sign(&msg_to_sign, &self.sig_privkey);

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.sig_pubkey.as_bytes())
                    .finalize()
                    .into_bytes();

                // Send (ssid_A, ssid_B, ID, sig, mac)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        self.sig_pubkey.as_bytes(),
                        sig.as_bytes(),
                        mac.as_slice(),
                    ]
                    .concat(),
                )
            }
            3 => {
                // Deserialize everything
                let (ssids_id_and_sig, incoming_mac) =
                    incoming_msg.split_at(dbg!(64 + sig_pubkey_size() + dbg!(sig_size())));
                let (ssids_and_id, sig) = ssids_id_and_sig.split_at(64 + sig_pubkey_size());
                let (ssids, id) = ssids_and_id.split_at(64);
                let (ssid_a, ssid_b) = ssids.split_at(32);

                self.output_id = Some(SigPubkey::from_bytes(id)?);
                let incoming_sig = DetachedSignature::from_bytes(sig)?;

                // Do the verifications. Check the SSIDs match and that the signature and MAC verify
                if ssid_a != self.ssids.0.as_ref().unwrap().as_slice()
                    || ssid_b != self.ssids.1.as_ref().unwrap().as_slice()
                {
                    return Err(SigmaError::InvalidSsid);
                }
                let msg_to_verify = [
                    self.nonces.1.as_ref().unwrap().as_slice(),
                    self.ssids.0.as_ref().unwrap().as_slice(),
                    self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                    self.encapped_key.as_ref().unwrap().as_bytes(),
                ]
                .concat();
                verify_detached_signature(
                    &incoming_sig,
                    &msg_to_verify,
                    &self.output_id.as_ref().unwrap(),
                )?;
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x00])
                    .chain_update(self.output_id.as_ref().unwrap().as_bytes())
                    .verify_slice(incoming_mac)?;

                // Now comput the final message. Compute the signature and MAC, similar to above
                let msg_to_sign = [
                    self.nonces.0.as_ref().unwrap().as_slice(),
                    self.ssids.1.as_ref().unwrap().as_slice(),
                    self.encapped_key.as_ref().unwrap().as_bytes(),
                    self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                ]
                .concat();
                let sig = detached_sign(&msg_to_sign, &self.sig_privkey);

                // Compute the MAC over the (ssid, ID)
                let mac = MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.sig_pubkey.as_bytes())
                    .finalize()
                    .into_bytes();

                // Send (ssid_A, ssid_B, ID, sig, mac)
                Some(
                    [
                        self.ssids.0.as_ref().unwrap().as_slice(),
                        self.ssids.1.as_ref().unwrap().as_slice(),
                        self.sig_pubkey.as_bytes(),
                        sig.as_bytes(),
                        mac.as_slice(),
                    ]
                    .concat(),
                )
            }
            4 => {
                // Deserialize everything
                let (ssids_id_and_sig, incoming_mac) =
                    incoming_msg.split_at(64 + sig_pubkey_size() + sig_size());
                let (ssids_and_id, sig) = ssids_id_and_sig.split_at(64 + sig_pubkey_size());
                let (ssids, id) = ssids_and_id.split_at(64);
                let (ssid_a, ssid_b) = ssids.split_at(32);

                self.output_id = Some(SigPubkey::from_bytes(id)?);
                let incoming_sig = DetachedSignature::from_bytes(sig)?;

                // Do the verifications. Check the SSIDs match and that the signature and MAC verify
                if ssid_a != self.ssids.0.as_ref().unwrap().as_slice()
                    || ssid_b != self.ssids.1.as_ref().unwrap().as_slice()
                {
                    return Err(SigmaError::InvalidSsid);
                }
                let msg_to_verify = [
                    self.nonces.0.as_ref().unwrap().as_slice(),
                    self.ssids.1.as_ref().unwrap().as_slice(),
                    self.encapped_key.as_ref().unwrap().as_bytes(),
                    self.kem_pubkey.as_ref().unwrap().to_bytes().as_bytes(),
                ]
                .concat();
                verify_detached_signature(
                    &incoming_sig,
                    &msg_to_verify,
                    &self.output_id.as_ref().unwrap(),
                )?;
                // Compute the MAC over the (ssid, ID)
                MyMac::new_from_slice(self.mac_key.as_ref().unwrap())
                    .unwrap()
                    .chain_update(&[0x01])
                    .chain_update(self.output_id.as_ref().unwrap().as_bytes())
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

#[cfg(test)]
mod test {
    use super::*;
    use pqcrypto_dilithium::dilithium2::keypair as gen_sig_keypair;

    #[test]
    fn sigma_r_correctness() {
        let keypair1 = gen_sig_keypair();
        let keypair2 = gen_sig_keypair();

        let mut user1 = Executor::new(rand::thread_rng(), keypair1, PartyRole::Initiator);
        let mut user2 = Executor::new(rand::thread_rng(), keypair2, PartyRole::Responder);

        let msg1 = user1.run(&[]).unwrap().unwrap();
        let msg2 = user2.run(&msg1).unwrap().unwrap();
        let msg3 = user1.run(&msg2).unwrap().unwrap();
        let msg4 = user2.run(&msg3).unwrap().unwrap();
        let msg5 = user1.run(&msg4).unwrap();

        let (user1_interlocutor, user1_key) = user1.finalize();
        let (user2_interlocutor, user2_key) = user2.finalize();

        assert!(msg5.is_none());
        assert!(user1_interlocutor == keypair2.0);
        assert!(user2_interlocutor == keypair1.0);
        assert_eq!(user1_key, user2_key);
    }
}
