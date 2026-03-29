/*
 * cutepress — high-level decompression
 *
 * Reads .press blocks, rANS decodes, then expands LZ literal/match stream.
 */

#include "cutecontainer/press.h"
#include <stdlib.h>
#include <string.h>

#define MATCH_MARKER    0xFE
#define ESCAPE_MARKER   0xFF

static inline uint16_t le16_get(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t le32_get(const uint8_t *p)
{
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t le64_get(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (i * 8);
    return v;
}

uint64_t cp_original_size(const uint8_t *header)
{
    if (memcmp(header, CP_MAGIC, 4) != 0) return 0;
    if (header[4] != CP_VERSION) return 0;
    return le64_get(header + 8);
}

/* Decode LZ stream back to original data.
 * Returns bytes written to out, or 0 on error. */
static size_t lz_decode(const uint8_t *stream, size_t stream_len,
                        uint8_t *out, size_t out_cap)
{
    size_t spos = 0;
    size_t opos = 0;

    while (spos < stream_len && opos < out_cap) {
        uint8_t b = stream[spos++];

        if (b == MATCH_MARKER) {
            if (spos + 3 > stream_len) return 0;
            uint16_t offset = le16_get(stream + spos); spos += 2;
            uint16_t length = (uint16_t)stream[spos++] + CP_MIN_MATCH;

            if (offset == 0 || offset > opos) return 0;
            if (opos + length > out_cap) return 0;

            cp_memcopy(out + opos, out + opos - offset, length);
            opos += length;
        } else if (b == ESCAPE_MARKER) {
            if (spos >= stream_len) return 0;
            if (opos >= out_cap) return 0;
            out[opos++] = stream[spos++];
        } else {
            out[opos++] = b;
        }
    }

    return opos;
}

int64_t cp_decompress(
    const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_cap)
{
    if (src_len < CP_HDR_SIZE)
        return CP_ERR_FORMAT;

    /* validate header */
    if (memcmp(src, CP_MAGIC, 4) != 0)
        return CP_ERR_FORMAT;
    if (src[4] != CP_VERSION)
        return CP_ERR_FORMAT;

    uint64_t orig_size = le64_get(src + 8);
    if (dst_cap < orig_size)
        return CP_ERR_NOMEM;

    size_t in_pos = CP_HDR_SIZE;
    size_t out_pos = 0;

    /* temp buffer for decoded rANS stream */
    size_t stream_cap = CP_BLOCK_SIZE * 2;
    uint8_t *stream_buf = malloc(stream_cap);
    if (!stream_buf) return CP_ERR_NOMEM;

    while (in_pos + CP_BLOCK_HDR_SIZE <= src_len) {
        uint32_t compressed_size = le32_get(src + in_pos);
        uint32_t checksum = le32_get(src + in_pos + 4);
        in_pos += CP_BLOCK_HDR_SIZE;

        if (compressed_size == 0) break; /* end marker */

        if (in_pos + compressed_size > src_len) {
            free(stream_buf);
            return CP_ERR_CORRUPT;
        }

        const uint8_t *block_data = src + in_pos;
        size_t stream_len;

        if (compressed_size >= CP_FREQ_TABLE_SIZE + 4) {
            /* try rANS decode: read frequency table */
            cp_freq_table ft;
            memset(&ft, 0, sizeof(ft));
            uint16_t cum = 0;
            int has_freqs = 1;
            uint32_t freq_sum = 0;

            for (int i = 0; i < 256; i++) {
                ft.syms[i].freq = le16_get(block_data + i * 2);
                ft.syms[i].cumfreq = cum;
                cum += ft.syms[i].freq;
                freq_sum += ft.syms[i].freq;
            }

            if (freq_sum == CP_RANS_SCALE) {
                /* read stream length (number of LZ symbols to decode) */
                uint32_t stream_sym_count = le32_get(block_data + CP_FREQ_TABLE_SIZE);

                const uint8_t *rans_data = block_data + CP_FREQ_TABLE_SIZE + 4;
                size_t rans_len = compressed_size - CP_FREQ_TABLE_SIZE - 4;

                if (stream_sym_count > stream_cap) {
                    free(stream_buf);
                    return CP_ERR_CORRUPT;
                }

                cp_rans_state state;
                stream_len = cp_rans_decode(&state, rans_data, rans_len,
                                           ft.syms, stream_buf, stream_sym_count);

                /* LZ decode */
                size_t decoded = lz_decode(stream_buf, stream_len,
                                          dst + out_pos, dst_cap - out_pos);

                /* verify checksum */
                if (decoded > 0) {
                    uint32_t check = cp_xxhash32(dst + out_pos, decoded, 0);
                    if (check != checksum) {
                        free(stream_buf);
                        return CP_ERR_CORRUPT;
                    }
                    out_pos += decoded;
                } else {
                    free(stream_buf);
                    return CP_ERR_CORRUPT;
                }
            } else {
                has_freqs = 0;
            }

            if (!has_freqs) {
                /* raw LZ stream (no rANS) */
                size_t decoded = lz_decode(block_data, compressed_size,
                                          dst + out_pos, dst_cap - out_pos);
                if (decoded == 0) {
                    free(stream_buf);
                    return CP_ERR_CORRUPT;
                }
                uint32_t check = cp_xxhash32(dst + out_pos, decoded, 0);
                if (check != checksum) {
                    free(stream_buf);
                    return CP_ERR_CORRUPT;
                }
                out_pos += decoded;
            }
        } else {
            /* too small for freq table — raw LZ stream */
            size_t decoded = lz_decode(block_data, compressed_size,
                                      dst + out_pos, dst_cap - out_pos);
            if (decoded == 0) {
                free(stream_buf);
                return CP_ERR_CORRUPT;
            }
            uint32_t check = cp_xxhash32(dst + out_pos, decoded, 0);
            if (check != checksum) {
                free(stream_buf);
                return CP_ERR_CORRUPT;
            }
            out_pos += decoded;
        }

        in_pos += compressed_size;
    }

    free(stream_buf);

    if (out_pos != orig_size)
        return CP_ERR_CORRUPT;

    return (int64_t)out_pos;
}
