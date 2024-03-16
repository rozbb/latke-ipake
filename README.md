# LATKE iPAKE

This repo contains an implementation of the LATKE identity-binding password-authenticated key exchange (iPAKE) framework, and a few PAKEs and IBKEs which we instantiate LATKE with. There's also an implementation of the [CHIP iPAKE](https://eprint.iacr.org/2020/529) for baseline comparison in benchmarks.

We also have some vendored support code that was slightly modified from the original:

* [`pqcrypto/`](https://github.com/rustpq/pqcrypto) — Added deterministic key generation to Dilithium, also deleted everything that wasn't Dilithium-related
* [`saber-rust/`](https://github.com/dsprenkels/saber-rust) — Fixed build (I think there might be a subtle bug somewhere though because I get a decapsulation error with probability roughly 3.5e-6, which is way too high)

# How to benchmark

```shell
cd latke
cargo bench
```

# ⚠️ Warning ⚠️

This code is academic-quality code. Absolutely do not use this for anything you want to keep secure.
