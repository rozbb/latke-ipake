//! Implementation of the SIM*-AC-CCA-secure Encrypt-then-Mac construction by Jäger and Tyagi.

use crate::MyMac;

use aes::cipher::{KeyIvInit, StreamCipher};
use blake2::digest::OutputSizeUser;
use hkdf::hmac::digest::{typenum::Unsigned, Mac, MacError};
use rand_core::{CryptoRng, RngCore};

/// Use AES-128 in CTR mode with a 32-bit little-endian counter. Our messages are very small, so 32 bits is more than enough.
type MyCipher = ctr::Ctr32LE<aes::Aes128>;

pub(crate) const TAGLEN: usize = <MyMac as OutputSizeUser>::OutputSize::USIZE;

/// A key for authenticated encryption. This is an AES-128 key followed by a 128-bit HMAC key.
pub(crate) type AuthEncKey = [u8; 32];

/// Performs AES-128-CTR + HMAC authenticated encryption over the given message.
pub(crate) fn auth_encrypt<R: RngCore + CryptoRng>(
    mut rng: R,
    key: AuthEncKey,
    msg: &[u8],
) -> Vec<u8> {
    let (enc_key, mac_key) = key.split_at(16);

    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);

    // Encrypt the message with AES-CTR
    let mut ciphertext = msg.to_vec();
    let mut cipher = MyCipher::new(enc_key.try_into().unwrap(), &iv.into());
    cipher.apply_keystream(&mut ciphertext);

    // Append the IV to the ciphertext
    ciphertext.extend(&iv);

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
    let (enc_key, mac_key) = key.split_at(16);
    let mac_size = <MyMac as OutputSizeUser>::output_size();
    let (ciphertext_and_iv, mac) = sealed_msg.split_at(sealed_msg.len() - mac_size);
    let (ciphertext, iv) = ciphertext_and_iv.split_at(ciphertext_and_iv.len() - 16);

    // Check the MAC
    MyMac::new_from_slice(&mac_key)
        .unwrap()
        .chain_update(&ciphertext_and_iv)
        .verify(mac.try_into().unwrap())?;

    // Decrypt the message with AES-CTR
    let mut plaintext = ciphertext.to_vec();
    let mut cipher = MyCipher::new(enc_key.try_into().unwrap(), iv.try_into().unwrap());
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
        let key = rng.gen();

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
        let key = rng.gen();

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
