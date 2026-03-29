#ifndef CUTECONTAINER_CRYPT_SHA3_H
#define CUTECONTAINER_CRYPT_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SHA3-256 and SHAKE-256
 *
 * Based on Keccak-f[1600]. C reference with optional ASM permutation.
 */

#define CC_SHA3_256_HASH_LEN 32
#define CC_KECCAK_STATE_LEN  200  /* 1600 bits = 200 bytes */

typedef struct {
    uint64_t state[25];   /* Keccak state (5×5 lanes) */
    size_t   absorbed;    /* Bytes absorbed into current block */
    size_t   rate;        /* Rate in bytes (136 for SHA3-256, 136 for SHAKE-256) */
    uint8_t  squeezed;    /* 1 after first squeeze call */
} cc_sha3_ctx;

/* --- SHA3-256 one-shot --- */

void cc_sha3_256(
    const uint8_t *data, size_t len,
    uint8_t out[CC_SHA3_256_HASH_LEN]
);

/* --- SHA3-256 incremental --- */

void cc_sha3_256_init(cc_sha3_ctx *ctx);
void cc_sha3_256_update(cc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void cc_sha3_256_final(cc_sha3_ctx *ctx, uint8_t out[CC_SHA3_256_HASH_LEN]);

/* --- SHAKE-256 (XOF) --- */

void cc_shake256_init(cc_sha3_ctx *ctx);
void cc_shake256_absorb(cc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void cc_shake256_squeeze(cc_sha3_ctx *ctx, uint8_t *out, size_t len);

/* --- Low-level: Keccak-f[1600] permutation --- */
/* ASM implementations override this symbol. */

void cc_keccak_f1600(uint64_t state[25]);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_SHA3_H */
