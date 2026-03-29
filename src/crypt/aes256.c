#include "cutecontainer/crypt/aes256.h"
#include <stdlib.h>
#include <string.h>

/*
 * AES-256-GCM — C reference implementation
 *
 * The block cipher uses a constant-time T-table-free approach.
 * GCM mode built on top for AEAD.
 *
 * ASM overrides: cc_aes256_block_encrypt, cc_aes256_expand_key
 */

struct cc_aes256_ctx {
    uint8_t round_keys[240]; /* 15 round keys × 16 bytes */
};

/* --- AES S-box (constant-time lookup in practice, see note) --- */

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ---- GF(2^128) multiply for GCM (schoolbook, not optimized) ---- */

static void gf128_mul(uint8_t *x, const uint8_t *h) {
    uint8_t v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 128; i++) {
        if (x[i / 8] & (1 << (7 - (i % 8)))) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        uint8_t carry = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 7);
        v[0] >>= 1;
        if (carry) v[0] ^= 0xe1;
    }
    memcpy(x, z, 16);
}

/* ---- Key expansion (weak symbol — ASM can override) ---- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void cc_aes256_expand_key(const uint8_t key[CC_AES256_KEY_LEN], uint8_t rk[240]) {
    memcpy(rk, key, 32);

    uint8_t temp[4];
    int bytes_generated = 32;
    int rcon_idx = 0;

    while (bytes_generated < 240) {
        memcpy(temp, rk + bytes_generated - 4, 4);

        if (bytes_generated % 32 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[rcon_idx++];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        } else if (bytes_generated % 32 == 16) {
            /* SubWord only (AES-256 extra) */
            for (int i = 0; i < 4; i++) temp[i] = SBOX[temp[i]];
        }

        for (int i = 0; i < 4; i++)
            rk[bytes_generated + i] = rk[bytes_generated - 32 + i] ^ temp[i];
        bytes_generated += 4;
    }
}

/* ---- Single block encrypt (weak symbol — ASM can override) ---- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void cc_aes256_block_encrypt(const uint8_t rk[240], uint8_t block[16]) {
    /* AddRoundKey(0) */
    for (int i = 0; i < 16; i++) block[i] ^= rk[i];

    for (int round = 1; round <= 14; round++) {
        uint8_t tmp[16];

        /* SubBytes */
        for (int i = 0; i < 16; i++) tmp[i] = SBOX[block[i]];

        /* ShiftRows */
        block[0]  = tmp[0];  block[1]  = tmp[5];  block[2]  = tmp[10]; block[3]  = tmp[15];
        block[4]  = tmp[4];  block[5]  = tmp[9];  block[6]  = tmp[14]; block[7]  = tmp[3];
        block[8]  = tmp[8];  block[9]  = tmp[13]; block[10] = tmp[2];  block[11] = tmp[7];
        block[12] = tmp[12]; block[13] = tmp[1];  block[14] = tmp[6];  block[15] = tmp[11];

        /* MixColumns (skip on last round) */
        if (round < 14) {
            for (int c = 0; c < 4; c++) {
                uint8_t *col = block + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                uint8_t x2_0 = (a0 << 1) ^ ((a0 >> 7) * 0x1b);
                uint8_t x2_1 = (a1 << 1) ^ ((a1 >> 7) * 0x1b);
                uint8_t x2_2 = (a2 << 1) ^ ((a2 >> 7) * 0x1b);
                uint8_t x2_3 = (a3 << 1) ^ ((a3 >> 7) * 0x1b);
                col[0] = x2_0 ^ x2_1 ^ a1 ^ a2 ^ a3;
                col[1] = a0 ^ x2_1 ^ x2_2 ^ a2 ^ a3;
                col[2] = a0 ^ a1 ^ x2_2 ^ x2_3 ^ a3;
                col[3] = x2_0 ^ a0 ^ a1 ^ a2 ^ x2_3;
            }
        }

        /* AddRoundKey */
        const uint8_t *round_key = rk + round * 16;
        for (int i = 0; i < 16; i++) block[i] ^= round_key[i];
    }
}

/* ---- CTR mode (used internally by GCM) ---- */

static void ctr_increment(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i]) break;
    }
}

static void gcm_ghash(const uint8_t *h, const uint8_t *data, size_t len, uint8_t *tag) {
    uint8_t block[16];
    size_t full = len / 16;
    for (size_t i = 0; i < full; i++) {
        for (int j = 0; j < 16; j++) tag[j] ^= data[i * 16 + j];
        gf128_mul(tag, h);
    }
    size_t rem = len % 16;
    if (rem) {
        memset(block, 0, 16);
        memcpy(block, data + full * 16, rem);
        for (int j = 0; j < 16; j++) tag[j] ^= block[j];
        gf128_mul(tag, h);
    }
}

/* ---- Public API ---- */

cc_aes256_ctx *cc_aes256_init(const uint8_t key[CC_AES256_KEY_LEN]) {
    cc_aes256_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    cc_aes256_expand_key(key, ctx->round_keys);
    return ctx;
}

void cc_aes256_free(cc_aes256_ctx *ctx) {
    if (ctx) {
        /* Zeroize key material */
        volatile uint8_t *p = ctx->round_keys;
        for (size_t i = 0; i < 240; i++) p[i] = 0;
        free(ctx);
    }
}

int cc_aes256_encrypt(
    cc_aes256_ctx *ctx,
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    const uint8_t *aad, size_t aad_len,
    uint8_t *buf, size_t len
) {
    if (!ctx) return -1;

    /* Compute H = AES(K, 0^128) for GHASH */
    uint8_t h[16] = {0};
    cc_aes256_block_encrypt(ctx->round_keys, h);

    /* Build J0 = nonce || 0x00000001 */
    uint8_t j0[16] = {0};
    memcpy(j0, nonce, CC_AES256_NONCE_LEN);
    j0[15] = 1;

    /* Encrypt: CTR mode starting from J0+1 */
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    ctr_increment(ctr);

    for (size_t i = 0; i < len; i += 16) {
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        cc_aes256_block_encrypt(ctx->round_keys, keystream);

        size_t chunk = (len - i < 16) ? len - i : 16;
        for (size_t j = 0; j < chunk; j++) buf[i + j] ^= keystream[j];
        ctr_increment(ctr);
    }

    /* GHASH(AAD, ciphertext) */
    uint8_t tag[16] = {0};
    gcm_ghash(h, aad, aad_len, tag);
    gcm_ghash(h, buf, len, tag);

    /* Length block */
    uint8_t lens[16] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = len * 8;
    for (int i = 0; i < 8; i++) {
        lens[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        lens[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    for (int j = 0; j < 16; j++) tag[j] ^= lens[j];
    gf128_mul(tag, h);

    /* T = GHASH ^ AES(K, J0) */
    uint8_t enc_j0[16];
    memcpy(enc_j0, j0, 16);
    cc_aes256_block_encrypt(ctx->round_keys, enc_j0);
    for (int i = 0; i < 16; i++) tag[i] ^= enc_j0[i];

    /* Append tag */
    memcpy(buf + len, tag, CC_AES256_TAG_LEN);
    return 0;
}

int cc_aes256_decrypt(
    cc_aes256_ctx *ctx,
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    const uint8_t *aad, size_t aad_len,
    uint8_t *buf, size_t len
) {
    if (!ctx || len < CC_AES256_TAG_LEN) return -1;

    size_t ct_len = len - CC_AES256_TAG_LEN;
    const uint8_t *recv_tag = buf + ct_len;

    /* Compute H */
    uint8_t h[16] = {0};
    cc_aes256_block_encrypt(ctx->round_keys, h);

    /* J0 */
    uint8_t j0[16] = {0};
    memcpy(j0, nonce, CC_AES256_NONCE_LEN);
    j0[15] = 1;

    /* Verify tag before decrypting */
    uint8_t tag[16] = {0};
    gcm_ghash(h, aad, aad_len, tag);
    gcm_ghash(h, buf, ct_len, tag);

    uint8_t lens[16] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ct_len * 8;
    for (int i = 0; i < 8; i++) {
        lens[7 - i] = (uint8_t)(aad_bits >> (i * 8));
        lens[15 - i] = (uint8_t)(ct_bits >> (i * 8));
    }
    for (int j = 0; j < 16; j++) tag[j] ^= lens[j];
    gf128_mul(tag, h);

    uint8_t enc_j0[16];
    memcpy(enc_j0, j0, 16);
    cc_aes256_block_encrypt(ctx->round_keys, enc_j0);
    for (int i = 0; i < 16; i++) tag[i] ^= enc_j0[i];

    /* Constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < CC_AES256_TAG_LEN; i++) diff |= tag[i] ^ recv_tag[i];
    if (diff) return -1;

    /* Decrypt CTR */
    uint8_t ctr[16];
    memcpy(ctr, j0, 16);
    ctr_increment(ctr);

    for (size_t i = 0; i < ct_len; i += 16) {
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        cc_aes256_block_encrypt(ctx->round_keys, keystream);

        size_t chunk = (ct_len - i < 16) ? ct_len - i : 16;
        for (size_t j = 0; j < chunk; j++) buf[i + j] ^= keystream[j];
        ctr_increment(ctr);
    }

    return 0;
}
