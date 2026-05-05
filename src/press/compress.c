/*
 * cutepress — high-level compression
 *
 * Pipeline: input → LZ match finder → literal/match stream → rANS encode → .press blocks
 *
 * The literal/match stream uses a simple scheme:
 *   - Byte 0x00..0xFD: literal byte
 *   - Byte 0xFE: match marker, followed by:
 *       [2] offset (LE uint16, 1-based)
 *       [1] length - CP_MIN_MATCH (0..254)
 *   - Byte 0xFF: escape for literal 0xFE or 0xFF:
 *       [1] the actual byte (0xFE or 0xFF)
 */

#include "cutecontainer/press.h"
#include <stdlib.h>
#include <string.h>

#define MATCH_MARKER    0xFE
#define ESCAPE_MARKER   0xFF

/* chain lengths per compression level (1..9) */
static const int chain_lengths[10] = {
    0, 4, 8, 16, 32, 64, 128, 256, 512, 1024
};

static inline void le16_put(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

static inline void le32_put(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void le64_put(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (i * 8));
}

/* Encode a block of raw data into a literal/match stream.
 * Returns stream length, or 0 on error. */
static size_t lz_encode(const uint8_t *data, size_t len, int level,
                        uint8_t *stream, size_t stream_cap)
{
    cp_match_ctx ctx;
    memset(ctx.head, -1, sizeof(ctx.head));
    memset(ctx.chain, -1, sizeof(ctx.chain));
    ctx.chain_len = chain_lengths[level];

    size_t spos = 0;
    size_t dpos = 0;

    while (dpos < len) {
        cp_match m = cp_find_match(data, len, dpos, &ctx);

        if (m.length >= CP_MIN_MATCH) {
            /* emit match */
            if (spos + 4 > stream_cap) return 0;
            stream[spos++] = MATCH_MARKER;
            le16_put(stream + spos, m.offset); spos += 2;
            stream[spos++] = (uint8_t)(m.length - CP_MIN_MATCH);

            /* insert skipped positions into hash chain */
            for (size_t i = 1; i < m.length; i++) {
                if (dpos + i + CP_MIN_MATCH <= len)
                    cp_match_insert(data, dpos + i, &ctx);
            }
            dpos += m.length;
        } else {
            /* emit literal */
            uint8_t b = data[dpos];
            if (b >= MATCH_MARKER) {
                if (spos + 2 > stream_cap) return 0;
                stream[spos++] = ESCAPE_MARKER;
                stream[spos++] = b;
            } else {
                if (spos + 1 > stream_cap) return 0;
                stream[spos++] = b;
            }
            dpos++;
        }
    }

    return spos;
}

size_t cp_compress_bound(size_t src_len)
{
    /* header + original_size + worst case: each block overhead + data expansion */
    size_t n_blocks = (src_len + CP_BLOCK_SIZE - 1) / CP_BLOCK_SIZE;
    if (n_blocks == 0) n_blocks = 1;
    return CP_HDR_SIZE
         + n_blocks * (CP_BLOCK_HDR_SIZE + CP_FREQ_TABLE_SIZE + CP_BLOCK_SIZE + CP_BLOCK_SIZE / 2)
         + CP_BLOCK_HDR_SIZE; /* end marker */
}

int64_t cp_compress(
    const uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_cap,
    int level)
{
    if (level < CP_LEVEL_FAST) level = CP_LEVEL_FAST;
    if (level > CP_LEVEL_MAX) level = CP_LEVEL_MAX;

    if (dst_cap < CP_HDR_SIZE + CP_BLOCK_HDR_SIZE)
        return CP_ERR_NOMEM;

    /* write header */
    memcpy(dst, CP_MAGIC, 4);
    dst[4] = CP_VERSION;
    dst[5] = 0; /* flags */
    dst[6] = 0; /* reserved */
    dst[7] = 0;
    le64_put(dst + 8, (uint64_t)src_len);

    size_t out_pos = CP_HDR_SIZE;
    size_t in_pos = 0;

    /* temp buffers for LZ stream and rANS output.
     * stream_cap: each input byte expands to at most 2 bytes in the LZ
     * literal stream (escape for 0xFE/0xFF), so 2x is the tight worst
     * case — but matches +1B header are always ≤ 4 bytes for ≥ 4 input
     * bytes, so the literal-only worst case dominates.
     * rans_cap: 4-stream rANS with 8-bit renorm flushes ≤ 1 byte per
     * symbol on average + 16 bytes for state flush; stream_cap + 64
     * is comfortably above the worst case for high-entropy inputs. */
    size_t stream_cap = CP_BLOCK_SIZE * 2;
    size_t rans_cap = stream_cap + 64;
    uint8_t *stream_buf = malloc(stream_cap);
    uint8_t *rans_buf = malloc(rans_cap);
    if (!stream_buf || !rans_buf) {
        free(stream_buf);
        free(rans_buf);
        return CP_ERR_NOMEM;
    }

    while (in_pos < src_len) {
        size_t block_len = src_len - in_pos;
        if (block_len > CP_BLOCK_SIZE) block_len = CP_BLOCK_SIZE;

        const uint8_t *block = src + in_pos;

        /* checksum of uncompressed block */
        uint32_t checksum = cp_xxhash32(block, block_len, 0);

        /* LZ encode. With stream_cap == 2 * block_size this should never
         * overflow; if it ever does the buffer is undersized — abort
         * rather than fall through with a garbled stream that the
         * decoder would misread as a valid LZ encoding. */
        size_t stream_len = lz_encode(block, block_len, level,
                                      stream_buf, stream_cap);
        if (stream_len == 0 && block_len > 0) {
            free(stream_buf);
            free(rans_buf);
            return CP_ERR_NOMEM;
        }

        /* frequency count on the LZ stream */
        cp_freq_table ft;
        cp_freq_count(stream_buf, stream_len, &ft);
        cp_freq_normalize(&ft);

        /* rANS encode. Returns 0 on bound failure (C fallback) — fall back
         * to a raw block in that case. */
        cp_rans_state state;
        size_t rans_len = cp_rans_encode(&state, stream_buf, stream_len,
                                         ft.syms, rans_buf, rans_cap);

        /* Decide block type: rANS+LZ if the encoder produced output and
         * the result is smaller than storing the raw LZ stream;
         * otherwise raw. The block payload is prefixed with a 1-byte
         * type tag (v02 format). */
        size_t rans_payload = CP_FREQ_TABLE_SIZE + 4 + rans_len;
        int use_rans = (rans_len > 0) && (rans_payload < stream_len);

        size_t body_size = use_rans ? rans_payload : stream_len;
        size_t compressed_size = 1 + body_size; /* +1 for type byte */

        /* check output space (block header + payload + end marker) */
        if (out_pos + CP_BLOCK_HDR_SIZE + compressed_size + CP_BLOCK_HDR_SIZE > dst_cap) {
            free(stream_buf);
            free(rans_buf);
            return CP_ERR_NOMEM;
        }

        /* block header */
        le32_put(dst + out_pos, (uint32_t)compressed_size);
        le32_put(dst + out_pos + 4, checksum);
        out_pos += CP_BLOCK_HDR_SIZE;

        /* type byte */
        dst[out_pos++] = use_rans ? CP_BLOCK_TYPE_RANS : CP_BLOCK_TYPE_RAW;

        if (use_rans) {
            /* freq table (256 x uint16 LE) */
            for (int i = 0; i < 256; i++) {
                le16_put(dst + out_pos, ft.syms[i].freq);
                out_pos += 2;
            }
            /* number of LZ symbols to decode */
            le32_put(dst + out_pos, (uint32_t)stream_len);
            out_pos += 4;
            /* rANS data */
            memcpy(dst + out_pos, rans_buf, rans_len);
            out_pos += rans_len;
        } else {
            /* raw LZ stream */
            memcpy(dst + out_pos, stream_buf, stream_len);
            out_pos += stream_len;
        }

        in_pos += block_len;
    }

    /* end marker: compressed_size = 0 */
    if (out_pos + CP_BLOCK_HDR_SIZE > dst_cap) {
        free(stream_buf);
        free(rans_buf);
        return CP_ERR_NOMEM;
    }
    le32_put(dst + out_pos, 0);
    le32_put(dst + out_pos + 4, 0);
    out_pos += CP_BLOCK_HDR_SIZE;

    free(stream_buf);
    free(rans_buf);
    return (int64_t)out_pos;
}
