use latke::{
    chip::Chip,
    ibke::{
        fg_ibke::FgIbkeC,
        id_hmqv_c::IdHmqvC,
        id_sig_dh::IdSigDh,
        id_sigma_r::{IdSigmaRDilithium2, IdSigmaREd25519},
    },
    latke::Latke,
    pake::{cake::Cake, kc_spake2::KcSpake2},
    Id, IdentityBasedKeyExchange, Pake, PartyRole,
};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
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

fn bench_pake(c: &mut Criterion) {
    let mut rng = thread_rng();
    let password = b"hello world";
    let ssid = rng.gen();

    c.bench_function("CAKE e2e", |b| {
        b.iter(|| {
            let mut user1 = Cake::new(&mut rng, ssid, password, PartyRole::Initiator);
            let mut user2 = Cake::new(&mut rng, ssid, password, PartyRole::Responder);

            let msg1 = user1.run(&[]).unwrap().unwrap();
            let msg2 = user2.run(&msg1).unwrap().unwrap();
            user1.run(&msg2).unwrap();
        })
    });
}

fn bench_chip(c: &mut Criterion) {
    type C = Chip<KcSpake2>;
    let mut rng = rand::thread_rng();

    // Create random user IDs
    let id1 = rng.gen();
    let id2 = rng.gen();

    // Create a random session ID
    let ssid = rng.gen();

    let password = b"password";

    let pwfile1 = C::gen_pwfile(&mut rng, password.to_vec(), id1);
    let pwfile2 = C::gen_pwfile(&mut rng, password.to_vec(), id2);

    let mut tot_bytes = 0;

    c.bench_function("Chip[KcSpake2]", |b| {
        b.iter(|| {
            tot_bytes = 0;
            let mut user1 =
                C::new_session(&mut rng, ssid, pwfile1.clone(), PartyRole::Initiator, id2);
            let mut user2 =
                C::new_session(&mut rng, ssid, pwfile2.clone(), PartyRole::Responder, id1);

            // Run through the whole protocol
            let mut cur_step = 0;
            let mut cur_msg = Some(Vec::new());
            while cur_msg.is_some() {
                // Record the message size
                tot_bytes += cur_msg.as_ref().map(|s| s.len()).unwrap_or(0);

                cur_msg = if cur_step % 2 == 0 {
                    user1.run(&mut rng, &cur_msg.unwrap()).unwrap()
                } else {
                    user2.run(&mut rng, &cur_msg.unwrap()).unwrap()
                };

                cur_step += 1;
            }
        })
    });

    println!("Chip[KcSpake2] comms: {tot_bytes}B");
}

fn bench_latke_generic<I: IdentityBasedKeyExchange, P: Pake>(name: &str, c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let id1 = rng.gen();
    let id2 = rng.gen();
    let ssid = rng.gen();

    let pwfile1 = Latke::<I, P>::gen_pwfile(&mut rng, b"password", &id1);
    let pwfile2 = Latke::<I, P>::gen_pwfile(&mut rng, b"password", &id2);

    // Run through the whole protocol
    let mut tot_bytes = 0;
    c.bench_function(name, |b| {
        b.iter(|| {
            tot_bytes = 0;
            let mut user1 =
                Latke::<I, P>::new_session(&mut rng, ssid, pwfile1.clone(), PartyRole::Initiator);
            let mut user2 =
                Latke::<I, P>::new_session(&mut rng, ssid, pwfile2.clone(), PartyRole::Responder);

            let mut cur_step = 0;
            let mut cur_msg = Vec::new();
            loop {
                tot_bytes += cur_msg.len();

                let user = if cur_step % 2 == 0 {
                    &mut user1
                } else {
                    &mut user2
                };

                if user.is_done() {
                    // If it's this user's turn to talk, and it's done, then the whole protocol is done
                    break;
                } else {
                    cur_msg = user.run(&mut rng, &cur_msg).unwrap_or(Vec::new());
                }

                cur_step += 1;
            }
        })
    });

    // For consistency, we do not include identity strings in the message size. Every IBKE we use passes 2 identity strings.
    tot_bytes -= 2 * Id::default().len();

    println!("{name} comms: {tot_bytes}B");
}

fn bench_latke(c: &mut Criterion) {
    bench_latke_generic::<FgIbkeC, KcSpake2>("Latke[KcSpake2,FgIbkeC]", c);
    bench_latke_generic::<IdSigDh, KcSpake2>("Latke[KcSpake2,IdSigDh]", c);
    bench_latke_generic::<IdHmqvC, KcSpake2>("Latke[KcSpake2,IdHmqvC]", c);
    bench_latke_generic::<IdSigmaREd25519, Cake>("Latke[Cake,IdSigmaREd25519]", c);
    bench_latke_generic::<IdSigmaRDilithium2, Cake>("Latke[Cake,IdSigmaRDilithium2]", c);
}

criterion_group!(benches, bench_chip, bench_latke);
criterion_main!(benches);
