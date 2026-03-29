/*
 * press_module.c — built-in press module (compression)
 */

#include "cutecontainer/sdk.h"
#include "cutecontainer/press.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int press_probe(const uint8_t *header, size_t len)
{
    if (len < 4) return 0;
    return memcmp(header, CP_MAGIC, 4) == 0;
}

static int press_encode(const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len,
                        const cc_opt *opts)
{
    int level = CP_LEVEL_DEFAULT;

    /* parse options */
    if (opts) {
        for (const cc_opt *o = opts; o->key; o++) {
            if (strcmp(o->key, "level") == 0)
                level = atoi(o->value);
        }
    }

    size_t bound = cp_compress_bound(in_len);
    uint8_t *buf = malloc(bound);
    if (!buf) return CC_ERR_NOMEM;

    int64_t cs = cp_compress(in, in_len, buf, bound, level);
    if (cs < 0) { free(buf); return CC_ERR_IO; }

    *out = buf;
    *out_len = (size_t)cs;
    return CC_OK;
}

static int press_decode(const uint8_t *in, size_t in_len,
                        uint8_t **out, size_t *out_len)
{
    uint64_t orig = cp_original_size(in);
    if (orig == 0) return CC_ERR_FORMAT;

    uint8_t *buf = malloc((size_t)orig);
    if (!buf) return CC_ERR_NOMEM;

    int64_t ds = cp_decompress(in, in_len, buf, (size_t)orig);
    if (ds < 0) { free(buf); return CC_ERR_IO; }

    *out = buf;
    *out_len = (size_t)ds;
    return CC_OK;
}

static int press_info(const uint8_t *data, size_t len, char *buf, size_t cap)
{
    if (len < CP_HDR_SIZE) return CC_ERR_FORMAT;
    uint64_t orig = cp_original_size(data);
    snprintf(buf, cap,
        "format:     cutepress (PRSS v%d)\n"
        "original:   %llu bytes\n"
        "compressed: %zu bytes\n"
        "ratio:      %.1f%%\n",
        data[4], (unsigned long long)orig, len,
        len > 0 ? (double)len / (double)orig * 100.0 : 0.0);
    return CC_OK;
}

static void press_free(void *buf) { free(buf); }

const cc_module cc_builtin_press = {
    .name        = "press",
    .description = "rANS entropy coding + LZ match finding compression",
    .type        = CC_TYPE_PRESS,
    .sdk_version = CC_SDK_VERSION,
    .caps        = CC_CAP_ENCODE | CC_CAP_DECODE | CC_CAP_ASM,
    .probe       = press_probe,
    .encode      = press_encode,
    .decode      = press_decode,
    .info        = press_info,
    .free_buf    = press_free,
};
