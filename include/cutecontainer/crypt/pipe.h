#ifndef CUTECONTAINER_CRYPT_PIPE_H
#define CUTECONTAINER_CRYPT_PIPE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * cutecrypt pipe — the high-level encryption pipeline
 *
 * Encrypt:  Kyber encaps → SHAKE-256 KDF → AES-256-GCM
 * Decrypt:  Kyber decaps → SHAKE-256 KDF → AES-256-GCM
 *
 * Output format (.cute):
 *   [4]   magic "CUTE"
 *   [1]   version (0x01)
 *   [1]   flags
 *   [32]  SHA3-256 content hash (pre-encryption integrity)
 *   [1088] Kyber ciphertext (encapsulated shared secret)
 *   [12]  AES-GCM nonce
 *   [N]   AES-256-GCM ciphertext (includes 16-byte tag)
 */

#define CC_PIPE_MAGIC       "CUTE"
#define CC_PIPE_VERSION     1
#define CC_PIPE_HEADER_LEN  (4 + 1 + 1 + 32 + 1088 + 12)  /* 1138 bytes */
#define CC_PIPE_EXT         ".cute"

/* Opaque pipe context */
typedef struct cc_pipe cc_pipe;

/*
 * Create a pipe for encryption.
 * Takes a Kyber public key. Returns NULL on failure.
 */
cc_pipe *cc_pipe_encrypt_new(const uint8_t pk[1184]);

/*
 * Create a pipe for decryption.
 * Takes a Kyber secret key. Returns NULL on failure.
 */
cc_pipe *cc_pipe_decrypt_new(const uint8_t sk[2400]);

/*
 * Encrypt a buffer. Allocates output.
 * Caller must free `*out` with cc_pipe_free_buf.
 * Returns 0 on success, -1 on error.
 */
int cc_pipe_encrypt(
    cc_pipe *p,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **out, size_t *out_len
);

/*
 * Decrypt a .cute buffer. Allocates output.
 * Caller must free `*out` with cc_pipe_free_buf.
 * Returns 0 on success, -1 on error (bad format, wrong key, tampered).
 */
int cc_pipe_decrypt(
    cc_pipe *p,
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len
);

/*
 * File convenience wrappers.
 * Returns 0 on success, -1 on error.
 */
int cc_pipe_encrypt_file(cc_pipe *p, const char *in_path, const char *out_path);
int cc_pipe_decrypt_file(cc_pipe *p, const char *in_path, const char *out_path);

/* Free a buffer returned by cc_pipe_encrypt / cc_pipe_decrypt. */
void cc_pipe_free_buf(uint8_t *buf);

/* Free the pipe context and zeroize secrets. */
void cc_pipe_free(cc_pipe *p);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_PIPE_H */
