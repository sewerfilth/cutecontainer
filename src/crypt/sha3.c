#include "cutecontainer/crypt/sha3.h"
#include <string.h>

/*
 * Keccak-f[1600] + SHA3-256 + SHAKE-256 — C reference
 *
 * The permutation function cc_keccak_f1600 is a weak symbol
 * that ASM implementations can override.
 */

/* Round constants */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void cc_keccak_f1600(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        /* θ (theta) */
        uint64_t c[5], d[5];
        for (int x = 0; x < 5; x++)
            c[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20];
        for (int x = 0; x < 5; x++) {
            d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1);
            for (int y = 0; y < 25; y += 5)
                st[y+x] ^= d[x];
        }

        /* ρ (rho) + π (pi) */
        uint64_t t = st[1], tmp;
        static const int PI[24] = {
            10, 7,11,17,18, 3, 5,16, 8,21,24, 4,
            15,23,19,13,12, 2,20,14,22, 9, 6, 1
        };
        static const int RHO[24] = {
             1, 3, 6,10,15,21,28,36,45,55, 2,14,
            27,41,56, 8,25,43,62,18,39,61,20,44
        };
        for (int i = 0; i < 24; i++) {
            tmp = st[PI[i]];
            st[PI[i]] = rotl64(t, RHO[i]);
            t = tmp;
        }

        /* χ (chi) */
        for (int y = 0; y < 25; y += 5) {
            uint64_t row[5];
            for (int x = 0; x < 5; x++) row[x] = st[y+x];
            for (int x = 0; x < 5; x++)
                st[y+x] = row[x] ^ ((~row[(x+1)%5]) & row[(x+2)%5]);
        }

        /* ι (iota) */
        st[0] ^= RC[round];
    }
}

/* ---- Absorb/squeeze helpers ---- */

static void absorb_block(cc_sha3_ctx *ctx, const uint8_t *block) {
    /* XOR block into state (rate bytes) */
    uint8_t *state_bytes = (uint8_t *)ctx->state;
    for (size_t i = 0; i < ctx->rate; i++)
        state_bytes[i] ^= block[i];
    cc_keccak_f1600(ctx->state);
}

/* ---- SHA3-256 ---- */

void cc_sha3_256_init(cc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136; /* 1088 bits = 136 bytes for SHA3-256 */
}

void cc_sha3_256_update(cc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;
    for (size_t i = 0; i < len; i++) {
        state_bytes[ctx->absorbed] ^= data[i];
        ctx->absorbed++;
        if (ctx->absorbed == ctx->rate) {
            cc_keccak_f1600(ctx->state);
            ctx->absorbed = 0;
        }
    }
}

void cc_sha3_256_final(cc_sha3_ctx *ctx, uint8_t out[CC_SHA3_256_HASH_LEN]) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;
    /* SHA3 padding: 0x06 ... 0x80 */
    state_bytes[ctx->absorbed] ^= 0x06;
    state_bytes[ctx->rate - 1] ^= 0x80;
    cc_keccak_f1600(ctx->state);
    memcpy(out, state_bytes, CC_SHA3_256_HASH_LEN);
}

void cc_sha3_256(const uint8_t *data, size_t len, uint8_t out[CC_SHA3_256_HASH_LEN]) {
    cc_sha3_ctx ctx;
    cc_sha3_256_init(&ctx);
    cc_sha3_256_update(&ctx, data, len);
    cc_sha3_256_final(&ctx, out);
}

/* ---- SHAKE-256 (XOF) ---- */

void cc_shake256_init(cc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136; /* 1088 bits = 136 bytes for SHAKE-256 */
}

void cc_shake256_absorb(cc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    /* Same as SHA3 update */
    uint8_t *state_bytes = (uint8_t *)ctx->state;
    for (size_t i = 0; i < len; i++) {
        state_bytes[ctx->absorbed] ^= data[i];
        ctx->absorbed++;
        if (ctx->absorbed == ctx->rate) {
            cc_keccak_f1600(ctx->state);
            ctx->absorbed = 0;
        }
    }
}

void cc_shake256_squeeze(cc_sha3_ctx *ctx, uint8_t *out, size_t len) {
    uint8_t *state_bytes = (uint8_t *)ctx->state;

    if (!ctx->squeezed) {
        /* SHAKE padding: 0x1f ... 0x80 */
        state_bytes[ctx->absorbed] ^= 0x1f;
        state_bytes[ctx->rate - 1] ^= 0x80;
        cc_keccak_f1600(ctx->state);
        ctx->absorbed = 0;
        ctx->squeezed = 1;
    }

    for (size_t i = 0; i < len; i++) {
        if (ctx->absorbed == ctx->rate) {
            cc_keccak_f1600(ctx->state);
            ctx->absorbed = 0;
        }
        out[i] = state_bytes[ctx->absorbed];
        ctx->absorbed++;
    }
}
