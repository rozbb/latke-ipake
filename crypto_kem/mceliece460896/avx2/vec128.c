#include "vec128.h"

/* input: v, an element in GF(2^m)[y]/(y^96+y^10+y^9+y^6+1) in bitsliced form */
/* input: a, an element in GF(2^m)[y]/(y^96+y^10+y^9+y^6+1) as an array of coefficients */
/* output: out, the product of v and a in bitsliced form */
void vec128_mul_GF(vec128 out[ GFBITS ], vec128 v[ GFBITS ], gf a[ SYS_T ]) {
    int i, j;
    uint64_t buf[GFBITS][3];
    vec128 prod[GFBITS];
    uint64_t p[GFBITS];

    const uint64_t allone = -1;

    // polynomial multiplication

    for (i = 0; i < GFBITS; i++) {
        buf[i][0] = 0;
        buf[i][1] = 0;
        buf[i][2] = 0;
    }

    for (i = SYS_T - 1; i >= 0; i--) {
        for (j = 0; j < GFBITS; j++) {
            buf[j][2] <<= 1;
            buf[j][2] |= buf[j][1] >> 63;
            buf[j][1] <<= 1;
            buf[j][1] |= buf[j][0] >> 63;
            buf[j][0] <<= 1;
        }

        vec128_mul_gf(prod, v, a[i]);

        for (j = 0; j < GFBITS; j++) {
            buf[j][0] ^= vec128_extract(prod[j], 0);
            buf[j][1] ^= vec128_extract(prod[j], 1);
        }
    }

    // reduction modulo y^96+y^10+y^9+y^6+1

    for (i = 0; i < GFBITS; i++) {
        p[i] = buf[i][2];

        buf[i][1] ^= p[i] >> (SYS_T - 10 - 64);
        buf[i][0] ^= p[i] << (64 - (SYS_T - 10 - 64));
        buf[i][1] ^= p[i] >> (SYS_T - 9 - 64);
        buf[i][0] ^= p[i] << (64 - (SYS_T - 9 - 64));
        buf[i][1] ^= p[i] >> (SYS_T - 6 - 64);
        buf[i][0] ^= p[i] << (64 - (SYS_T - 6 - 64));
        buf[i][1] ^= p[i] >> (SYS_T - 64);
        buf[i][0] ^= p[i] << (64 - (SYS_T - 64));
    }

    //

    for (i = 0; i < GFBITS; i++) {
        p[i] = buf[i][1] & (allone << 32);

        buf[i][0] ^= p[i] >> (SYS_T - 10 - 64);
        buf[i][0] ^= p[i] >> (SYS_T - 9 - 64);
        buf[i][0] ^= p[i] >> (SYS_T - 6 - 64);
        buf[i][0] ^= p[i] >> (SYS_T - 64);
    }

    //

    for (i = 0; i < GFBITS; i++) {
        out[i] = vec128_set2x(buf[i][0], buf[i][1] & 0xFFFFFFFF);
    }
}
