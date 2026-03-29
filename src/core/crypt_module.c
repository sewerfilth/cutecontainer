/*
 * crypt_module.c — built-in crypt module (encryption pipe)
 */

#include "cutecontainer/sdk.h"
#include "cutecontainer/crypt/pipe.h"
#include "cutecontainer/crypt/aes256.h"
#include "cutecontainer/crypt/kyber.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int crypt_probe(const uint8_t *header, size_t len)
{
    if (len < 6) return 0;
    return memcmp(header, CC_PIPE_MAGIC, 4) == 0 && header[4] == CC_PIPE_VERSION;
}

static int crypt_encode(const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len,
                        const cc_opt *opts)
{
    /* find public key from options */
    const uint8_t *pk = NULL;
    if (opts) {
        for (const cc_opt *o = opts; o->key; o++) {
            if (strcmp(o->key, "pk") == 0)
                pk = (const uint8_t *)o->value;
        }
    }
    if (!pk) return CC_ERR_IO;

    cc_pipe *pipe = cc_pipe_encrypt_new(pk);
    if (!pipe) return CC_ERR_NOMEM;

    int rc = cc_pipe_encrypt(pipe, in, in_len, out, out_len);
    cc_pipe_free(pipe);
    return rc == 0 ? CC_OK : CC_ERR_IO;
}

static int crypt_decode(const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len)
{
    /* can't decode without a secret key — return error.
     * callers should use cc_pipe_decrypt_new() directly. */
    (void)in; (void)in_len; (void)out; (void)out_len;
    return CC_ERR_IO;
}

static int crypt_info(const uint8_t *data, size_t len, char *buf, size_t cap)
{
    if (len < CC_PIPE_HEADER_LEN) return CC_ERR_FORMAT;
    size_t payload = len - CC_PIPE_HEADER_LEN - CC_AES256_TAG_LEN;
    snprintf(buf, cap,
        "format:    cutecrypt pipe (v%d)\n"
        "cipher:    AES-256-GCM\n"
        "kem:       ML-KEM-768 (Kyber)\n"
        "payload:   ~%zu bytes\n",
        data[4], payload);
    return CC_OK;
}

static void crypt_free(void *buf) { cc_pipe_free_buf((uint8_t *)buf); }

const cc_module cc_builtin_crypt = {
    .name        = "crypt",
    .description = "Post-quantum encryption (Kyber + AES-256-GCM)",
    .type        = CC_TYPE_CRYPT,
    .sdk_version = CC_SDK_VERSION,
    .caps        = CC_CAP_ENCODE | CC_CAP_DECODE | CC_CAP_ASM,
    .probe       = crypt_probe,
    .encode      = crypt_encode,
    .decode      = crypt_decode,
    .info        = crypt_info,
    .free_buf    = crypt_free,
};
