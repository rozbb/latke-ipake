# LATKE iPAKE

This repo contains an implementation of the LATKE identity-binding password-authenticated key exchange (iPAKE) framework, and a few PAKEs and IBKEs which we instantiate LATKE with. There's also an implementation of the [CHIP iPAKE](https://eprint.iacr.org/2020/529) for baseline comparison in benchmarks.

We also have some support code: [`pqcrypto/`](https://github.com/rustpq/pqcrypto) and [`saber-rust/`](https://github.com/dsprenkels/saber-rust).

# How to benchmark

```shell
cd latke
cargo bench
```

# ⚠️ Warning ⚠️

This code is academic-quality code. Absolutely do not use this for anything you want to keep secure.
