//! Implementation of the SIM*-AC-CCA-secure Encrypt-then-Mac construction by Jäger and Tyagi.

use crate::MyMac;

use blake2::digest::OutputSizeUser;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hkdf::hmac::digest::{typenum::Unsigned, Mac, MacError};
use rand_core::{CryptoRng, RngCore};

type MyCipher = ChaCha20;

pub(crate) const TAGLEN: usize = <MyMac as OutputSizeUser>::OutputSize::USIZE;

/// A key for authenticated encryption. This is a 256-bit encryption key followed by a 256-bit HMAC key.
pub(crate) type AuthEncKey = [u8; 64];

// Fixed size arrays don't impl Default, so we have to do this manually
pub(crate) const ZERO_AUTH_ENC_KEY: AuthEncKey = [0u8; 64];

/// Performs AES-128-CTR + HMAC authenticated encryption over the given message.
pub(crate) fn auth_encrypt<R: RngCore + CryptoRng>(
    mut rng: R,
    key: AuthEncKey,
    msg: &[u8],
) -> Vec<u8> {
    let (enc_key, mac_key) = key.split_at(32);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    // Encrypt the message with the stream cipher
    let mut ciphertext = msg.to_vec();
    let mut cipher = MyCipher::new(enc_key.try_into().unwrap(), &nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    // Append the IV to the ciphertext
    ciphertext.extend(&nonce);

    // Compute the MAC and append it to the ciphertext
    let mac = MyMac::new_from_slice(&mac_key)
        .unwrap()
        .chain_update(&ciphertext)
        .finalize()
        .into_bytes();
    ciphertext.extend(mac);

    ciphertext
}

/// Performs AES-128-CTR + HMAC authenticated decryption over the given ciphertext.
pub(crate) fn auth_decrypt(key: AuthEncKey, sealed_msg: &[u8]) -> Result<Vec<u8>, MacError> {
    // Deserialize the key and split the MAC and IV from the ciphertext
    let (enc_key, mac_key) = key.split_at(32);
    let mac_size = <MyMac as OutputSizeUser>::output_size();
    let (ciphertext_and_nonce, mac) = sealed_msg.split_at(sealed_msg.len() - mac_size);
    let (ciphertext, nonce) = ciphertext_and_nonce.split_at(ciphertext_and_nonce.len() - 12);

    // Check the MAC
    MyMac::new_from_slice(&mac_key)
        .unwrap()
        .chain_update(&ciphertext_and_nonce)
        .verify(mac.try_into().unwrap())?;

    // Decrypt the message with the stream cipher
    let mut plaintext = ciphertext.to_vec();
    let mut cipher = MyCipher::new(enc_key.try_into().unwrap(), nonce.try_into().unwrap());
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::Rng;

    #[test]
    fn auth_enc_correctness() {
        let mut rng = rand::thread_rng();

        // Make a random encryption key
        let mut key = ZERO_AUTH_ENC_KEY;
        rng.fill_bytes(&mut key);

        // Make a random message of random length up to 2^16
        let msg_len: u16 = rng.gen();
        let mut msg = vec![0u8; msg_len as usize];
        rng.fill_bytes(&mut msg);

        // Encrypt and decrypt the message
        let ciphertext = auth_encrypt(&mut rng, key, &msg);
        let plaintext = auth_decrypt(key, &ciphertext).unwrap();
        assert_eq!(plaintext, msg);
    }

    #[should_panic]
    #[test]
    fn auth_enc_tamper_resistance() {
        let mut rng = rand::thread_rng();

        // Make a random encryption key
        let mut key = ZERO_AUTH_ENC_KEY;
        rng.fill_bytes(&mut key);

        // Make a random message of random length up to 2^16
        let msg_len: u16 = rng.gen();
        let mut msg = vec![0u8; msg_len as usize];
        rng.fill_bytes(&mut msg);

        // Encrypt the message, then flip a random bit and try to decrypt. This should fail
        let mut ciphertext = auth_encrypt(&mut rng, key, &msg);
        let tamper_byte = rng.gen_range(0..ciphertext.len());
        ciphertext[tamper_byte] ^= 1;
        auth_decrypt(key, &ciphertext).unwrap();
    }
}
