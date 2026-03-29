/*
 * xxHash32 — block checksum
 *
 * Portable C implementation. Fast enough that ASM isn't needed here
 * (the bottleneck is rANS and match finding, not checksumming).
 */

#include "cutecontainer/press.h"

#define XXH_PRIME1  0x9E3779B1u
#define XXH_PRIME2  0x85EBCA77u
#define XXH_PRIME3  0xC2B2AE3Du
#define XXH_PRIME4  0x27D4EB2Fu
#define XXH_PRIME5  0x165667B1u

static inline uint32_t xxh_read32(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint32_t xxh_rotl(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

static inline uint32_t xxh_round(uint32_t acc, uint32_t input)
{
    acc += input * XXH_PRIME2;
    acc = xxh_rotl(acc, 13);
    acc *= XXH_PRIME1;
    return acc;
}

uint32_t cp_xxhash32(const uint8_t *data, size_t len, uint32_t seed)
{
    const uint8_t *p = data;
    const uint8_t *end = data + len;
    uint32_t h;

    if (len >= 16) {
        const uint8_t *limit = end - 16;
        uint32_t v1 = seed + XXH_PRIME1 + XXH_PRIME2;
        uint32_t v2 = seed + XXH_PRIME2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH_PRIME1;

        do {
            v1 = xxh_round(v1, xxh_read32(p));      p += 4;
            v2 = xxh_round(v2, xxh_read32(p));      p += 4;
            v3 = xxh_round(v3, xxh_read32(p));      p += 4;
            v4 = xxh_round(v4, xxh_read32(p));      p += 4;
        } while (p <= limit);

        h = xxh_rotl(v1, 1) + xxh_rotl(v2, 7) +
            xxh_rotl(v3, 12) + xxh_rotl(v4, 18);
    } else {
        h = seed + XXH_PRIME5;
    }

    h += (uint32_t)len;

    while (p + 4 <= end) {
        h += xxh_read32(p) * XXH_PRIME3;
        h = xxh_rotl(h, 17) * XXH_PRIME4;
        p += 4;
    }

    while (p < end) {
        h += (*p) * XXH_PRIME5;
        h = xxh_rotl(h, 11) * XXH_PRIME1;
        p++;
    }

    /* avalanche */
    h ^= h >> 15;  h *= XXH_PRIME2;
    h ^= h >> 13;  h *= XXH_PRIME3;
    h ^= h >> 16;

    return h;
}
