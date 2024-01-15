//! Defines the CAKE PAKE protocol, by [Beguinet et al.](https://eprint.iacr.org/2023/470)
use crate::{
    ideal_cipher::{wide_block_decrypt, wide_block_encrypt},
    MyHash256, MyKdf, Pake, PartyRole, SessKey, Ssid,
};

use hkdf::hmac::digest::Digest;
use rand_core::{CryptoRng, RngCore};
use saber::lightsaber::{
    decapsulate_ind_cpa as kem_decap, encapsulate_ind_cpa as kem_encap,
    keygen_ind_cpa as kem_keygen, Ciphertext as EncappedKey, INDCPAPublicKey, INDCPASecretKey,
    INDCPA_PUBLICKEYBYTES,
};

/// Encrypts `payload` with a pseudorandom permutation given by `domain_sep`, `ssid`, and `password`.
fn ideal_cipher_encrypt(domain_sep: u8, ssid: &[u8], password: &[u8], payload: &mut [u8]) {
    // Hash all the input values to a single key
    let mut key = [0u8; 32];
    // Gotta hash the password so it's small enough to use as PRK
    let hk = MyKdf::from_prk(&MyHash256::digest(&password)).unwrap();
    hk.expand_multi_info(&[&[domain_sep], ssid], &mut key)
        .unwrap();

    // Encrypt payload
    wide_block_encrypt(&key, payload)
}

/// Decrypts `payload` with a pseudorandom permutation given by `domain_sep`, `ssid`, and `password`.
fn ideal_cipher_decrypt(domain_sep: u8, ssid: &[u8], password: &[u8], payload: &mut [u8]) {
    // Hash all the input values to a single key
    let mut key = [0u8; 32];
    // Gotta hash the password so it's small enough to use as PRK
    let hk = MyKdf::from_prk(&MyHash256::digest(&password)).unwrap();
    hk.expand_multi_info(&[&[domain_sep], ssid], &mut key)
        .unwrap();

    // Decrypt payload
    wide_block_decrypt(&key, payload)
}

/// The CAKE PAKE protocol, by [Beguinet et al.](https://eprint.iacr.org/2023/470)
#[derive(Default)]
pub struct Cake {
    password: Vec<u8>,
    ssid: Ssid,
    eph_pk: Option<INDCPAPublicKey>,
    eph_sk: Option<INDCPASecretKey>,
    sess_key: Option<SessKey>,
    next_step: usize,
    done: bool,
}

impl Pake for Cake {
    type Error = ();

    fn new<R: RngCore + CryptoRng>(_: R, ssid: Ssid, password: &[u8], role: PartyRole) -> Cake {
        // The initiator does even steps, the responder does odd steps
        let next_step = if role == PartyRole::Initiator { 0 } else { 1 };

        Cake {
            password: password.to_vec(),
            ssid,
            eph_pk: None,
            eph_sk: None,
            sess_key: None,
            next_step,
            done: false,
        }
    }

    fn finalize(&self) -> SessKey {
        self.sess_key.unwrap()
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn run(&mut self, incoming_msg: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let out = match self.next_step {
            // Send an ephemeral pubkey, encrypted with the password and SSID
            0 => {
                assert!(incoming_msg.is_empty());

                // Generate the keypair
                let (pk, sk) = kem_keygen();
                self.eph_pk = Some(pk.clone());
                self.eph_sk = Some(sk);

                // Encrypt eph_pk with the password and SSID
                let mut encrypted_pk = [0u8; INDCPA_PUBLICKEYBYTES];
                encrypted_pk.copy_from_slice(pk.to_bytes().as_bytes());
                ideal_cipher_encrypt(0x00, &self.ssid, &self.password, &mut encrypted_pk);

                Some(encrypted_pk.to_vec())
            }
            // Receive the ephemral pubkey, decrypt it, and encapsulate to it
            1 => {
                let mut eph_pk = [0u8; INDCPA_PUBLICKEYBYTES];
                eph_pk.copy_from_slice(&incoming_msg);
                // Decrypt the ephemeral pubkey
                ideal_cipher_decrypt(0x00, &self.ssid, &self.password, &mut eph_pk);
                let eph_pk = INDCPAPublicKey::from_bytes(&eph_pk);

                // Encapsulate to the ephemeral pubkey. After this message, we're done.
                let (shared_secret, mut encapped_key) = kem_encap(&eph_pk);
                self.sess_key = Some(*shared_secret.as_bytes());
                self.done = true;

                // Encrypt the encapsulated key with the password and SSID
                ideal_cipher_encrypt(0x01, &self.ssid, &self.password, encapped_key.as_mut());
                let enc_encapped_key = encapped_key;

                // Send the encrypted encapped key
                Some(enc_encapped_key.as_bytes().to_vec())
            }
            // Receive the encapsulated key, decrypt it, and decapsulate it
            2 => {
                // Decrypt
                // We can make an EncappedKey from a ciphertext because (1) the encryption adds no extra bytes, and (2) there's no structure to a ciphertext
                let mut encapped_key = EncappedKey::from_bytes(incoming_msg).unwrap();
                ideal_cipher_decrypt(0x01, &self.ssid, &self.password, encapped_key.as_mut());

                // Decapsulate
                let shared_secret = kem_decap(&encapped_key, self.eph_sk.as_ref().unwrap());
                self.sess_key = Some(*shared_secret.as_bytes());
                self.done = true;

                None
            }
            _ => {
                panic!("protocol already finished")
            }
        };

        // Initiator gets the even steps, responder gets the odd steps
        self.next_step += 2;

        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn cake_correctness() {
        let mut rng = thread_rng();
        let password = b"hello world";

        let ssid = rng.gen();
        let mut user1 = Cake::new(&mut rng, ssid, password, PartyRole::Initiator);
        let mut user2 = Cake::new(&mut rng, ssid, password, PartyRole::Responder);

        let msg1 = user1.run(&[]).unwrap().unwrap();
        let msg2 = user2.run(&msg1).unwrap().unwrap();
        let msg3 = user1.run(&msg2).unwrap();

        // Check that the protocol terminated successfully and both parties agree on the keys
        assert!(msg3.is_none());
        assert_eq!(user1.finalize(), user2.finalize());
    }
}
