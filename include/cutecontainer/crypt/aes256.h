#ifndef CUTECONTAINER_CRYPT_AES256_H
#define CUTECONTAINER_CRYPT_AES256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES-256-GCM
 *
 * Hardware-accelerated where available (AES-NI on x86, AESE/AESMC on ARM).
 * Falls back to constant-time C implementation.
 */

#define CC_AES256_KEY_LEN   32
#define CC_AES256_NONCE_LEN 12
#define CC_AES256_TAG_LEN   16

typedef struct cc_aes256_ctx cc_aes256_ctx;

/* Allocate and initialize a context with the given key. */
cc_aes256_ctx *cc_aes256_init(const uint8_t key[CC_AES256_KEY_LEN]);

/* Free context and zeroize key material. */
void cc_aes256_free(cc_aes256_ctx *ctx);

/*
 * Encrypt in-place. `buf` must have room for `len + CC_AES256_TAG_LEN`.
 * Tag is appended after ciphertext.
 * Returns 0 on success, -1 on error.
 */
int cc_aes256_encrypt(
    cc_aes256_ctx *ctx,
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    const uint8_t *aad, size_t aad_len,
    uint8_t *buf, size_t len
);

/*
 * Decrypt in-place. `buf` contains ciphertext + tag (total `len` bytes).
 * Plaintext length = len - CC_AES256_TAG_LEN.
 * Returns 0 on success, -1 on authentication failure.
 */
int cc_aes256_decrypt(
    cc_aes256_ctx *ctx,
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    const uint8_t *aad, size_t aad_len,
    uint8_t *buf, size_t len
);

/*
 * Low-level: expand key into round keys (14 rounds for AES-256).
 * Called internally by cc_aes256_init. Exposed for ASM interop.
 */
void cc_aes256_expand_key(
    const uint8_t key[CC_AES256_KEY_LEN],
    uint8_t round_keys[240]  /* 15 × 16 bytes */
);

/*
 * Low-level: single-block encrypt. 16 bytes in-place.
 * Uses round_keys from cc_aes256_expand_key.
 * ASM implementations override this symbol.
 */
void cc_aes256_block_encrypt(
    const uint8_t round_keys[240],
    uint8_t block[16]
);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_AES256_H */
