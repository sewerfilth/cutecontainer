#include "cutecontainer/crypt/kyber.h"
#include "cutecontainer/crypt/sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#include <bcrypt.h>
#elif defined(__linux__)
#include <sys/random.h>
#endif

/*
 * ML-KEM-768 (Kyber-768) — C reference skeleton
 *
 * This implements the NTT, polynomial arithmetic, and KEM structure.
 * The NTT is a weak symbol that ASM can override for performance.
 *
 * Reference: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)
 */

/* ---- NTT constants ---- */

/* Primitive 256th root of unity mod q=3329: ζ = 17 */
static const int16_t ZETAS[128] = {
      1, 1729, 2580, 3289, 2642,  630, 1897,  848,
   1062, 1919,  193,  797, 2786, 3260,  569, 1746,
    296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
   1426, 2094,  535, 2882, 2864,  585, 1969, 1250,
   2211,  977, 2513, 3309, 2237, 1908, 3246,  818,
   1888, 2041, 2502, 2190, 3060, 1063, 1062, 2180,
   2606, 1496, 3250, 1214, 1689, 1024, 2487, 1190,
   2485,  477, 3076, 1089, 1643, 1828,  479, 3078,
    430, 2309,  441, 1353, 1847,  636, 1757, 2654,
   2027, 2614, 2290, 2308, 1345,  538, 2996, 1655,
   2999, 1834, 1344, 3277, 1023,  766, 2998, 1482,
   2428, 2167,  181, 2994, 2623, 2466,  652, 1731,
    268,  608, 1588,  854,  264, 2098, 1240,  938,
   1322, 2463, 2597, 1717, 2795,  980, 2857, 1715,
    975, 2868, 2781, 2791, 1991, 2977,  278, 2997,
    222, 1100, 1744,  535, 2364, 2222, 1016, 3081,
};

/* Montgomery constant: R = 2^16 mod q */
#define MONT 2285   /* 2^16 mod 3329 */
#define QINV 62209  /* q^(-1) mod 2^16 */

static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * (int16_t)QINV);
    return (int16_t)((a - (int32_t)t * CC_KYBER_Q) >> 16);
}

static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + CC_KYBER_Q / 2) / CC_KYBER_Q;
    t = (int16_t)((int32_t)v * a >> 26);
    t *= CC_KYBER_Q;
    return a - t;
}

/* ---- NTT (weak symbols — ASM overrides) ---- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void cc_kyber_ntt(int16_t poly[CC_KYBER_N]) {
    int k = 1;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < CC_KYBER_N; start += 2 * len) {
            int16_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void cc_kyber_invntt(int16_t poly[CC_KYBER_N]) {
    int k = 127;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < CC_KYBER_N; start += 2 * len) {
            int16_t zeta = ZETAS[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = montgomery_reduce((int32_t)zeta * (poly[j + len] - t));
            }
        }
    }
    /* Multiply by n^{-1} mod q */
    const int16_t f = 3303; /* 128^{-1} * 2^16 mod q */
    for (int i = 0; i < CC_KYBER_N; i++)
        poly[i] = montgomery_reduce((int32_t)f * poly[i]);
}

/* ---- Random bytes (OS-level) ---- */

static void randombytes(uint8_t *out, size_t len) {
#if defined(__APPLE__)
    arc4random_buf(out, len);
#elif defined(_WIN32)
    BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#elif defined(__linux__)
    getrandom(out, len, 0);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(out, 1, len, f); fclose(f); }
#endif
}

/* ---- Polynomial helpers ---- */

typedef struct { int16_t coeffs[CC_KYBER_N]; } poly;
typedef struct { poly vec[CC_KYBER_K]; } polyvec;

static void poly_reduce(poly *p) {
    for (int i = 0; i < CC_KYBER_N; i++)
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
}

static void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < CC_KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

static void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < CC_KYBER_N; i++)
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

static void poly_basemul(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < CC_KYBER_N / 2; i++) {
        int16_t z = ZETAS[64 + i];
        /* basemul on pairs */
        r->coeffs[2*i] = montgomery_reduce(
            (int32_t)a->coeffs[2*i] * b->coeffs[2*i] +
            (int32_t)montgomery_reduce((int32_t)a->coeffs[2*i+1] * b->coeffs[2*i+1]) * z
        );
        r->coeffs[2*i+1] = montgomery_reduce(
            (int32_t)a->coeffs[2*i] * b->coeffs[2*i+1] +
            (int32_t)a->coeffs[2*i+1] * b->coeffs[2*i]
        );
    }
}

static void poly_ntt(poly *p) { cc_kyber_ntt(p->coeffs); }
static void poly_invntt(poly *p) { cc_kyber_invntt(p->coeffs); }

/* CBD sampling (η=2 for Kyber-768) */
static void poly_cbd2(poly *r, const uint8_t buf[128]) {
    for (int i = 0; i < CC_KYBER_N / 8; i++) {
        uint32_t t = (uint32_t)buf[4*i]
                   | ((uint32_t)buf[4*i+1] << 8)
                   | ((uint32_t)buf[4*i+2] << 16)
                   | ((uint32_t)buf[4*i+3] << 24);
        for (int j = 0; j < 8; j++) {
            int16_t a = (t >> (4*j)) & 0x3;
            int16_t b_val = (t >> (4*j+2)) & 0x3;
            /* Count bits */
            a = (a & 1) + ((a >> 1) & 1);
            b_val = (b_val & 1) + ((b_val >> 1) & 1);
            r->coeffs[8*i+j] = a - b_val;
        }
    }
}

/* ---- Encode / decode helpers for byte packing ---- */

static void poly_tobytes(uint8_t r[384], const poly *a) {
    poly t;
    memcpy(&t, a, sizeof(poly));
    poly_reduce(&t);
    for (int i = 0; i < CC_KYBER_N / 2; i++) {
        uint16_t t0 = (uint16_t)t.coeffs[2*i];
        uint16_t t1 = (uint16_t)t.coeffs[2*i+1];
        r[3*i+0] = (uint8_t)(t0);
        r[3*i+1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i+2] = (uint8_t)(t1 >> 4);
    }
}

static void poly_frombytes(poly *r, const uint8_t a[384]) {
    for (int i = 0; i < CC_KYBER_N / 2; i++) {
        r->coeffs[2*i]   = (int16_t)(((uint16_t)a[3*i+0]       | ((uint16_t)a[3*i+1] << 8)) & 0xfff);
        r->coeffs[2*i+1] = (int16_t)(((uint16_t)(a[3*i+1] >> 4) | ((uint16_t)a[3*i+2] << 4)) & 0xfff);
    }
}

static void polyvec_tobytes(uint8_t *r, const polyvec *a) {
    for (int i = 0; i < CC_KYBER_K; i++)
        poly_tobytes(r + i * 384, &a->vec[i]);
}

static void polyvec_frombytes(polyvec *r, const uint8_t *a) {
    for (int i = 0; i < CC_KYBER_K; i++)
        poly_frombytes(&r->vec[i], a + i * 384);
}

/* Inner product in NTT domain */
static void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b) {
    poly t;
    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < CC_KYBER_K; i++) {
        poly_basemul(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

/* ---- KEM API ---- */

int cc_kyber_keygen(uint8_t pk[CC_KYBER_PK_LEN], uint8_t sk[CC_KYBER_SK_LEN]) {
    uint8_t seed[32];
    randombytes(seed, 32);

    /* Hash seed for deterministic generation */
    uint8_t buf[64];
    cc_sha3_ctx sha;
    cc_sha3_256_init(&sha);
    cc_sha3_256_update(&sha, seed, 32);
    cc_sha3_256_final(&sha, buf);
    /* Use SHAKE for expanding into matrix and noise — simplified here */
    randombytes(buf + 32, 32); /* ρ for matrix, σ for noise */

    polyvec s, e, pkv;
    /* Sample secret and error vectors (simplified: use random CBD) */
    for (int i = 0; i < CC_KYBER_K; i++) {
        uint8_t noise[128];
        randombytes(noise, 128);
        poly_cbd2(&s.vec[i], noise);
        poly_ntt(&s.vec[i]);
        randombytes(noise, 128);
        poly_cbd2(&e.vec[i], noise);
        poly_ntt(&e.vec[i]);
    }

    /* Generate matrix A (simplified: random NTT-domain polynomials) */
    polyvec a_rows[CC_KYBER_K];
    for (int i = 0; i < CC_KYBER_K; i++) {
        for (int j = 0; j < CC_KYBER_K; j++) {
            for (int c = 0; c < CC_KYBER_N; c++) {
                uint8_t rb[2];
                randombytes(rb, 2);
                a_rows[i].vec[j].coeffs[c] = (int16_t)((rb[0] | (rb[1] << 8)) % CC_KYBER_Q);
            }
        }
    }

    /* pk = A*s + e */
    for (int i = 0; i < CC_KYBER_K; i++) {
        polyvec_pointwise_acc(&pkv.vec[i], &a_rows[i], &s);
        poly_add(&pkv.vec[i], &pkv.vec[i], &e.vec[i]);
        poly_reduce(&pkv.vec[i]);
    }

    /* Serialize */
    polyvec_tobytes(pk, &pkv);
    memcpy(pk + CC_KYBER_K * 384, buf + 32, 32); /* ρ */

    /* sk = (s || pk || H(pk) || z) */
    polyvec_tobytes(sk, &s);
    memcpy(sk + CC_KYBER_K * 384, pk, CC_KYBER_PK_LEN);
    cc_sha3_256(pk, CC_KYBER_PK_LEN, sk + CC_KYBER_K * 384 + CC_KYBER_PK_LEN);
    randombytes(sk + CC_KYBER_K * 384 + CC_KYBER_PK_LEN + 32, 32); /* z */

    return 0;
}

int cc_kyber_encaps(
    const uint8_t pk[CC_KYBER_PK_LEN],
    uint8_t ct[CC_KYBER_CT_LEN],
    uint8_t ss[CC_KYBER_SS_LEN]
) {
    /* Generate random message m, hash with H(pk) for shared secret */
    uint8_t m[32];
    randombytes(m, 32);

    uint8_t h_pk[32];
    cc_sha3_256(pk, CC_KYBER_PK_LEN, h_pk);

    /* KDF: ss = SHA3-256(m || H(pk)) */
    cc_sha3_ctx sha;
    cc_sha3_256_init(&sha);
    cc_sha3_256_update(&sha, m, 32);
    cc_sha3_256_update(&sha, h_pk, 32);
    cc_sha3_256_final(&sha, ss);

    /* Simplified ciphertext: encrypt m under pk (placeholder) */
    /* In full impl, this does CPA encryption with re-derived randomness */
    memset(ct, 0, CC_KYBER_CT_LEN);
    memcpy(ct, m, 32); /* Placeholder — real impl uses NTT encryption */

    return 0;
}

int cc_kyber_decaps(
    const uint8_t sk[CC_KYBER_SK_LEN],
    const uint8_t ct[CC_KYBER_CT_LEN],
    uint8_t ss[CC_KYBER_SS_LEN]
) {
    /* Recover m from ciphertext using secret key (placeholder) */
    uint8_t m[32];
    memcpy(m, ct, 32); /* Placeholder — real impl uses NTT decryption */

    /* Recover H(pk) from sk */
    const uint8_t *h_pk = sk + CC_KYBER_K * 384 + CC_KYBER_PK_LEN;

    /* ss = SHA3-256(m || H(pk)) */
    cc_sha3_ctx sha;
    cc_sha3_256_init(&sha);
    cc_sha3_256_update(&sha, m, 32);
    cc_sha3_256_update(&sha, h_pk, 32);
    cc_sha3_256_final(&sha, ss);

    return 0;
}
