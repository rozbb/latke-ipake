use criterion::{criterion_group, criterion_main, Criterion};
use saber::firesaber::{
    decapsulate as kem_decap, decapsulate_ind_cpa as kem_decap_ind_cpa, encapsulate as kem_encap,
    encapsulate_ind_cpa as kem_encap_ind_cpa, keygen as kem_keygen,
    keygen_ind_cpa as kem_keygen_ind_cpa,
};

fn bench_kem(c: &mut Criterion) {
    // Consider a server with a key pair
    c.bench_function("FireSaber keygen", |b| b.iter(|| kem_keygen()));
    let server_secret_key = kem_keygen();

    c.bench_function("FireSaber sk -> pk", |b| {
        b.iter(|| server_secret_key.public_key())
    });
    let server_public_key = server_secret_key.public_key();

    // Let a client encapsulate some shared secret for the server
    c.bench_function("FireSaber encap", |b| {
        b.iter(|| kem_encap(&server_public_key))
    });
    let (client_secret, ciphertext) = kem_encap(&server_public_key);

    // Have the server decrypt the ciphertext
    c.bench_function("FireSaber decap", |b| {
        b.iter(|| kem_decap(&ciphertext, &server_secret_key))
    });
    let server_secret = kem_decap(&ciphertext, &server_secret_key);

    assert_eq!(client_secret.as_slice(), server_secret.as_slice());
}

fn bench_ind_cpa_kem(c: &mut Criterion) {
    // Consider a server with a key pair
    c.bench_function("FireSaber IND-CPA keygen", |b| {
        b.iter(|| kem_keygen_ind_cpa())
    });
    let (server_public_key, server_secret_key) = kem_keygen_ind_cpa();

    // Let a client encapsulate some shared secret for the server
    c.bench_function("FireSaber IND-CPA encap", |b| {
        b.iter(|| kem_encap_ind_cpa(&server_public_key))
    });
    let (client_secret, ciphertext) = kem_encap_ind_cpa(&server_public_key);

    // Have the server decrypt the ciphertext
    c.bench_function("FireSaber IND-CPA decap", |b| {
        b.iter(|| kem_decap_ind_cpa(&ciphertext, &server_secret_key))
    });
    let server_secret = kem_decap_ind_cpa(&ciphertext, &server_secret_key);

    assert_eq!(client_secret.as_slice(), server_secret.as_slice());
}

criterion_group!(benches, bench_ind_cpa_kem, bench_kem);
criterion_main!(benches);
