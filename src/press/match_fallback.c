/*
 * LZ match finder — C fallback
 *
 * Hash-chain match finder with 4-byte minimum match,
 * 64KB sliding window. Used when no ASM available.
 */

#include "cutecontainer/press.h"
#include <string.h>

/* ---- hash function ---- */

static inline uint32_t hash4(const uint8_t *p)
{
    uint32_t v = ((uint32_t)p[0])       |
                 ((uint32_t)p[1] << 8)  |
                 ((uint32_t)p[2] << 16) |
                 ((uint32_t)p[3] << 24);
    return (v * 2654435761u) >> (32 - CP_HASH_BITS);
}

#ifndef CP_ARCH_AARCH64
#ifndef CP_ARCH_X86_64

cp_match cp_find_match(
    const uint8_t *data, size_t data_len, size_t pos,
    cp_match_ctx *ctx)
{
    cp_match best = { 0, 0 };

    if (pos + CP_MIN_MATCH > data_len)
        return best;

    uint32_t h = hash4(data + pos);
    int16_t chain_pos = ctx->head[h];
    int steps = 0;

    while (chain_pos >= 0 && steps < ctx->chain_len) {
        size_t candidate = (size_t)(uint16_t)chain_pos;

        if (candidate < pos) {
            size_t dist = pos - candidate;
            if (dist > 0 && dist <= CP_WINDOW_SIZE) {
                /* compare */
                size_t max_len = data_len - pos;
                if (max_len > CP_MAX_MATCH) max_len = CP_MAX_MATCH;

                const uint8_t *a = data + pos;
                const uint8_t *b = data + candidate;
                size_t len = 0;

                while (len < max_len && a[len] == b[len])
                    len++;

                if (len >= CP_MIN_MATCH && len > best.length) {
                    best.offset = (uint16_t)dist;
                    best.length = (uint16_t)len;
                    if (len == CP_MAX_MATCH) break;
                }
            }
        }

        chain_pos = ctx->chain[candidate % CP_WINDOW_SIZE];
        steps++;
    }

    /* insert current position */
    ctx->chain[pos % CP_WINDOW_SIZE] = ctx->head[h];
    ctx->head[h] = (int16_t)(pos % CP_WINDOW_SIZE);

    return best;
}

void cp_match_insert(
    const uint8_t *data, size_t pos,
    cp_match_ctx *ctx)
{
    uint32_t h = hash4(data + pos);
    ctx->chain[pos % CP_WINDOW_SIZE] = ctx->head[h];
    ctx->head[h] = (int16_t)(pos % CP_WINDOW_SIZE);
}

void cp_memcopy(uint8_t *dst, const uint8_t *src, size_t len)
{
    /* safe overlapping copy (for match expansion where dst > src) */
    for (size_t i = 0; i < len; i++)
        dst[i] = src[i];
}

#endif
#endif
