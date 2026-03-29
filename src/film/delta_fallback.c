/*
 * delta_fallback.c — C fallback for XOR-delta encode/decode
 *
 * Weak symbols: overridden by per-arch ASM on aarch64 / x86_64.
 */

#include "cutecontainer/film.h"

#if defined(__GNUC__) || defined(__clang__)
#define CF_WEAK __attribute__((weak))
#else
#define CF_WEAK
#endif

CF_WEAK
void cf_delta_encode_row(uint32_t *row, size_t width)
{
    if (width <= 1) return;
    for (size_t x = width - 1; x >= 1; x--)
        row[x] ^= row[x - 1];
}

CF_WEAK
void cf_delta_decode_row(uint32_t *row, size_t width)
{
    for (size_t x = 1; x < width; x++)
        row[x] ^= row[x - 1];
}
