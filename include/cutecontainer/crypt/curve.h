#ifndef CUTECONTAINER_CRYPT_CURVE_H
#define CUTECONTAINER_CRYPT_CURVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Curve25519 field and group operations — all implemented in ASM.
 *
 * Field: GF(2^255 - 19)
 * A field element is 5 × 64-bit limbs in radix-2^51 representation.
 * This is the standard unsaturated limb layout for Curve25519.
 *
 * Group: Edwards form (Ed25519) for add/double,
 *        Montgomery form (X25519) for scalar mul.
 *
 * All operations are constant-time.
 */

/* ---- Field element (5 limbs, radix 2^51) ---- */

typedef struct {
    uint64_t v[5];
} cc_fe;

/* fe = 0 */
void cc_fe_zero(cc_fe *r);

/* fe = 1 */
void cc_fe_one(cc_fe *r);

/* r = a + b mod p */
void cc_fe_add(cc_fe *r, const cc_fe *a, const cc_fe *b);

/* r = a - b mod p */
void cc_fe_sub(cc_fe *r, const cc_fe *a, const cc_fe *b);

/* r = a * b mod p */
void cc_fe_mul(cc_fe *r, const cc_fe *a, const cc_fe *b);

/* r = a^2 mod p */
void cc_fe_sqr(cc_fe *r, const cc_fe *a);

/* r = 1/a mod p  (a^(p-2) via addition chain) */
void cc_fe_inv(cc_fe *r, const cc_fe *a);

/* Reduce limbs to canonical form (all limbs < 2^51, value < p) */
void cc_fe_reduce(cc_fe *r);

/* Constant-time conditional swap: if swap=1, swap a and b */
void cc_fe_cswap(cc_fe *a, cc_fe *b, uint64_t swap);

/* Pack fe to 32 bytes (little-endian canonical) */
void cc_fe_pack(uint8_t out[32], const cc_fe *a);

/* Unpack 32 bytes to fe */
void cc_fe_unpack(cc_fe *r, const uint8_t in[32]);

/* ---- Compressed point (32 bytes) ---- */

typedef struct {
    uint8_t v[32];
} cc_point;

/* ---- Scalar (32 bytes, little-endian) ---- */

typedef struct {
    uint8_t v[32];
} cc_scalar;

/*
 * Scalar multiplication: r = s · G  (basepoint multiply)
 * Uses the Montgomery ladder — constant-time.
 * Input: 32-byte scalar (clamped internally)
 * Output: 32-byte compressed point (x-coordinate)
 */
void cc_scalarmult_base(cc_point *r, const cc_scalar *s);

/*
 * Variable-base scalar multiplication: r = s · P
 * Uses the Montgomery ladder — constant-time.
 */
void cc_scalarmult(cc_point *r, const cc_scalar *s, const cc_point *p);

/*
 * Clamp a scalar for X25519:
 *   s[0]  &= 248
 *   s[31] &= 127
 *   s[31] |= 64
 */
void cc_scalar_clamp(cc_scalar *s);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_CURVE_H */
