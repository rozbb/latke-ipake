//! Implements the Farfalle wide block cipher (WBC) by [Bertoni et al.](https://eprint.iacr.org/2016/1188)

use crypto_permutation::{DeckFunction, Reader, Writer};
use deck_farfalle::{kravatte::KravatteConfig, Farfalle};

// Helper function. Computes left ^= right
fn xor_in_place(left: &mut [u8], right: &[u8]) {
    assert_eq!(left.len(), right.len());
    for (l, r) in left.iter_mut().zip(right.iter()) {
        *l ^= *r;
    }
}

// Helper function. Given domain separators a, b, and input x, evaluates the deck function F_key(a || x || b) with output size outlen
fn eval_deck(
    key: &[u8],
    prefix_domain_sep: u8,
    suffix_domain_sep: u8,
    input: &[u8],
    outlen: usize,
) -> Vec<u8> {
    let mut prf = Farfalle::<KravatteConfig>::init_default(key);
    let mut writer = prf.input_writer();
    writer.write_bytes(&[prefix_domain_sep]).unwrap();
    writer.write_bytes(input).unwrap();
    writer.write_bytes(&[suffix_domain_sep]).unwrap();
    writer.finish();

    let mut out_buf = vec![0u8; outlen];
    let mut output = prf.output_reader();
    output.write_to_slice(&mut out_buf).unwrap();

    out_buf
}

/// The Farfalle-WBC encryption function. See Algorithm 5 in the paper
pub(crate) fn wide_block_encrypt(key: &[u8], inout: &mut [u8]) {
    // R_0 := R_0 ⊕ H_k(L || 0) where R_0 is the first 16 bytes of R
    let (left, right) = inout.split_at_mut(16);
    let (r0, _) = right.split_at_mut(16);
    let hkl = eval_deck(key, b'h', 0x00, &left, r0.len());
    xor_in_place(r0, &hkl);

    // L := L ⊕ G_k(R || 1)
    let (left, right) = inout.split_at_mut(16);
    let gkr = eval_deck(key, b'g', 0x01, &right, left.len());
    xor_in_place(left, &gkr);

    // R := R ⊕ G_k(L || 0)
    let (left, right) = inout.split_at_mut(16);
    let gkl = eval_deck(key, b'g', 0x00, &left, right.len());
    xor_in_place(right, &gkl);

    // L_0 := L_0 ⊕ H_k(R || 1) where L_0 is the first 16 bytes of L
    let (left, right) = inout.split_at_mut(16);
    let (l0, _) = left.split_at_mut(16);
    let hkr = eval_deck(key, b'h', 0x01, &right, l0.len());
    xor_in_place(l0, &hkr);
}

/// The encryption function above, in reverse
pub(crate) fn wide_block_decrypt(key: &[u8], inout: &mut [u8]) {
    // L_0 := L_0 ⊕ H_k(R || 1) where L_0 is the first 16 bytes of L
    let (left, right) = inout.split_at_mut(16);
    let (l0, _) = left.split_at_mut(16);
    let hkr = eval_deck(key, b'h', 0x01, &right, l0.len());
    xor_in_place(l0, &hkr);

    // R := R ⊕ G_k(L || 0)
    let (left, right) = inout.split_at_mut(16);
    let gkl = eval_deck(key, b'g', 0x00, &left, right.len());
    xor_in_place(right, &gkl);

    // L := L ⊕ G_k(R || 1)
    let (left, right) = inout.split_at_mut(16);
    let gkr = eval_deck(key, b'g', 0x01, &right, left.len());
    xor_in_place(left, &gkr);

    // R_0 := R_0 ⊕ H_k(L || 0) where R_0 is the first 16 bytes of R
    let (left, right) = inout.split_at_mut(16);
    let (r0, _) = right.split_at_mut(16);
    let hkl = eval_deck(key, b'h', 0x00, &left, r0.len());
    xor_in_place(r0, &hkl);
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{thread_rng, RngCore};

    #[test]
    fn wide_block_encrypt_correctness() {
        let mut rng = thread_rng();

        // Pick a random key and plaintext
        let mut key = [0u8; 32];
        let mut plaintext = vec![0u8; 700];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut plaintext);

        // Check that encryption and decryption are inverses
        let mut plaintext_copy = plaintext.clone();
        wide_block_encrypt(&key, &mut plaintext_copy);
        wide_block_decrypt(&key, &mut plaintext_copy);
        assert!(plaintext == plaintext_copy);
    }
}
