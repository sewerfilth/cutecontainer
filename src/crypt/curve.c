/*
 * curve.c — Curve25519 helpers implemented in C.
 *
 * The ASM in asm/<arch>/crypt/cascade/fe25519.S provides fe add / sub /
 * cswap / pack / unpack / reduce; scalarmult.S provides the Montgomery
 * ladder. This file provides cc_fe_mul, cc_fe_sqr, and cc_fe_inv.
 *
 * cc_fe_mul / _sqr need 128-bit product accumulators because 51×51-bit
 * limb products are up to 102 bits — the previous ASM versions used
 * single-width MUL and silently dropped the top 38 bits per product.
 * cc_fe_inv is the standard 254-squaring + 11-multiplication addition
 * chain for a^(p-2).
 */

#include <cutecontainer/crypt/curve.h>

void cc_fe_mul(cc_fe *r, const cc_fe *a, const cc_fe *b)
{
    const __uint128_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2],
                      a3 = a->v[3], a4 = a->v[4];
    const uint64_t b0 = b->v[0], b1 = b->v[1], b2 = b->v[2],
                   b3 = b->v[3], b4 = b->v[4];
    const uint64_t b1_19 = 19 * b1, b2_19 = 19 * b2,
                   b3_19 = 19 * b3, b4_19 = 19 * b4;

    __uint128_t t0 = a0 * (__uint128_t)b0
                   + a1 * (__uint128_t)b4_19
                   + a2 * (__uint128_t)b3_19
                   + a3 * (__uint128_t)b2_19
                   + a4 * (__uint128_t)b1_19;
    __uint128_t t1 = a0 * (__uint128_t)b1
                   + a1 * (__uint128_t)b0
                   + a2 * (__uint128_t)b4_19
                   + a3 * (__uint128_t)b3_19
                   + a4 * (__uint128_t)b2_19;
    __uint128_t t2 = a0 * (__uint128_t)b2
                   + a1 * (__uint128_t)b1
                   + a2 * (__uint128_t)b0
                   + a3 * (__uint128_t)b4_19
                   + a4 * (__uint128_t)b3_19;
    __uint128_t t3 = a0 * (__uint128_t)b3
                   + a1 * (__uint128_t)b2
                   + a2 * (__uint128_t)b1
                   + a3 * (__uint128_t)b0
                   + a4 * (__uint128_t)b4_19;
    __uint128_t t4 = a0 * (__uint128_t)b4
                   + a1 * (__uint128_t)b3
                   + a2 * (__uint128_t)b2
                   + a3 * (__uint128_t)b1
                   + a4 * (__uint128_t)b0;

    const uint64_t mask = ((uint64_t)1 << 51) - 1;
    uint64_t c;
    c = (uint64_t)(t0 >> 51); t0 &= mask; t1 += c;
    c = (uint64_t)(t1 >> 51); t1 &= mask; t2 += c;
    c = (uint64_t)(t2 >> 51); t2 &= mask; t3 += c;
    c = (uint64_t)(t3 >> 51); t3 &= mask; t4 += c;
    c = (uint64_t)(t4 >> 51); t4 &= mask;
    /* Top-limb carry × 19 folded back to t0. */
    t0 += (__uint128_t)(19 * c);
    c = (uint64_t)(t0 >> 51); t0 &= mask; t1 += c;

    r->v[0] = (uint64_t)t0;
    r->v[1] = (uint64_t)t1;
    r->v[2] = (uint64_t)t2;
    r->v[3] = (uint64_t)t3;
    r->v[4] = (uint64_t)t4;
}

void cc_fe_sqr(cc_fe *r, const cc_fe *a)
{
    cc_fe_mul(r, a, a);
}

void cc_fe_reduce(cc_fe *r)
{
    const uint64_t mask = ((uint64_t)1 << 51) - 1;

    /* First carry pass — propagate up. */
    uint64_t v0 = r->v[0], v1 = r->v[1], v2 = r->v[2],
             v3 = r->v[3], v4 = r->v[4];
    uint64_t c;
    c = v0 >> 51; v0 &= mask; v1 += c;
    c = v1 >> 51; v1 &= mask; v2 += c;
    c = v2 >> 51; v2 &= mask; v3 += c;
    c = v3 >> 51; v3 &= mask; v4 += c;
    c = v4 >> 51; v4 &= mask; v0 += 19 * c;
    /* One more carry from v0 in case the +19c overflowed 51 bits. */
    c = v0 >> 51; v0 &= mask; v1 += c;

    /* Conditional subtraction of p = 2^255 - 19. Compute q = 1 iff v >= p
     * by testing whether v + 19 carries past bit 255. */
    uint64_t q = (v0 + 19) >> 51;
    q = (v1 + q) >> 51;
    q = (v2 + q) >> 51;
    q = (v3 + q) >> 51;
    q = (v4 + q) >> 51;

    /* Subtract q*p, which equals subtracting q*(2^255 - 19) = q*2^255 - 19q.
     * Equivalent to adding 19*q to v0 and masking off bit 51 of v4. */
    v0 += 19 * q;
    c = v0 >> 51; v0 &= mask; v1 += c;
    c = v1 >> 51; v1 &= mask; v2 += c;
    c = v2 >> 51; v2 &= mask; v3 += c;
    c = v3 >> 51; v3 &= mask; v4 += c;
    v4 &= mask;

    r->v[0] = v0; r->v[1] = v1; r->v[2] = v2;
    r->v[3] = v3; r->v[4] = v4;
}

/* r = a^(2^252 - 3). Standard inversion chain for p = 2^255 - 19
 * (exponent is p - 2 = 2^255 - 21). Uses 11 multiplications and
 * 254 squarings. Derived from the reference ref10 / tweetnacl chain.
 */
void cc_fe_inv(cc_fe *r, const cc_fe *a)
{
    cc_fe t0, t1, t2, t3;
    int i;

    cc_fe_sqr(&t0, a);                                  /* t0 = a^2 */
    cc_fe_sqr(&t1, &t0); cc_fe_sqr(&t1, &t1);           /* t1 = a^8 */
    cc_fe_mul(&t1, a, &t1);                             /* t1 = a^9 */
    cc_fe_mul(&t0, &t0, &t1);                           /* t0 = a^11 */
    cc_fe_sqr(&t2, &t0);                                /* t2 = a^22 */
    cc_fe_mul(&t1, &t1, &t2);                           /* t1 = a^(2^5 - 1) */

    cc_fe_sqr(&t2, &t1);
    for (i = 1; i < 5; i++) cc_fe_sqr(&t2, &t2);
    cc_fe_mul(&t1, &t2, &t1);                           /* t1 = a^(2^10 - 1) */

    cc_fe_sqr(&t2, &t1);
    for (i = 1; i < 10; i++) cc_fe_sqr(&t2, &t2);
    cc_fe_mul(&t2, &t2, &t1);                           /* t2 = a^(2^20 - 1) */

    cc_fe_sqr(&t3, &t2);
    for (i = 1; i < 20; i++) cc_fe_sqr(&t3, &t3);
    cc_fe_mul(&t2, &t3, &t2);                           /* t2 = a^(2^40 - 1) */

    cc_fe_sqr(&t2, &t2);
    for (i = 1; i < 10; i++) cc_fe_sqr(&t2, &t2);
    cc_fe_mul(&t1, &t2, &t1);                           /* t1 = a^(2^50 - 1) */

    cc_fe_sqr(&t2, &t1);
    for (i = 1; i < 50; i++) cc_fe_sqr(&t2, &t2);
    cc_fe_mul(&t2, &t2, &t1);                           /* t2 = a^(2^100 - 1) */

    cc_fe_sqr(&t3, &t2);
    for (i = 1; i < 100; i++) cc_fe_sqr(&t3, &t3);
    cc_fe_mul(&t2, &t3, &t2);                           /* t2 = a^(2^200 - 1) */

    cc_fe_sqr(&t2, &t2);
    for (i = 1; i < 50; i++) cc_fe_sqr(&t2, &t2);
    cc_fe_mul(&t1, &t2, &t1);                           /* t1 = a^(2^250 - 1) */

    cc_fe_sqr(&t1, &t1);
    for (i = 1; i < 5; i++) cc_fe_sqr(&t1, &t1);
    cc_fe_mul(r, &t1, &t0);                             /* r = a^(2^255 - 21) */
}
