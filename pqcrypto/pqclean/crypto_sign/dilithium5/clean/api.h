#ifndef PQCLEAN_DILITHIUM5_CLEAN_API_H
#define PQCLEAN_DILITHIUM5_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES 2592
#define PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES 4896
#define PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES 4627
#define PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_ALGNAME "Dilithium5"

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair_with_seed(uint8_t *pk, uint8_t *sk);

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

#endif
