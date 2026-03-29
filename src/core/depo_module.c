/*
 * depo_module.c — built-in depo module for the SDK
 */

#include "cutecontainer/sdk.h"
#include "cutecontainer/depo.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int depo_probe(const uint8_t *header, size_t len)
{
    if (len < 6) return 0;
    return memcmp(header, DEPO_MAGIC, 4) == 0 &&
           header[4] >= 0x02 && header[4] <= 0x04;
}

static int depo_encode(const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len,
                       const cc_opt *opts)
{
    depo_opts dopts = depo_opts_default();

    if (opts) {
        for (const cc_opt *o = opts; o->key; o++) {
            if (strcmp(o->key, "password") == 0) dopts.password = o->value;
        }
    }

    if (!dopts.password) return CC_ERR_IO;
    return depo_encrypt_buf(in, in_len, out, out_len, &dopts);
}

static int depo_decode(const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len)
{
    /* can't decrypt without password from options */
    (void)in; (void)in_len; (void)out; (void)out_len;
    return CC_ERR_IO;
}

static int depo_info_fn(const uint8_t *data, size_t len, char *buf, size_t cap)
{
    return depo_info(data, len, buf, cap);
}

static void depo_free(void *buf) { free(buf); }

const cc_module cc_builtin_depo = {
    .name        = "depo",
    .description = "Encrypted containers (lock modes, archives, ledger)",
    .type        = CC_TYPE_DEPO,
    .sdk_version = CC_SDK_VERSION,
    .caps        = CC_CAP_ENCODE | CC_CAP_DECODE | CC_CAP_ASM,
    .probe       = depo_probe,
    .encode      = depo_encode,
    .decode      = depo_decode,
    .info        = depo_info_fn,
    .free_buf    = depo_free,
};
