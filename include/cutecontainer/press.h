/*
 * press.h — extreme compression engine
 *
 * rANS entropy coding + LZ match finding with per-arch ASM.
 * Same API as standalone cutepress, nested under cutecontainer.
 */

#ifndef CUTECONTAINER_PRESS_H
#define CUTECONTAINER_PRESS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Format constants
 *
 * v01 layout (legacy, still readable):
 *   block_payload = freq_table[512] + stream_sym_count[4] + rans_data
 *                 OR raw LZ stream — distinguished by heuristic
 *                 (freq_sum == CP_RANS_SCALE).
 *
 * v02 layout: same block header, but block_payload starts with a 1-byte
 * type tag — removes the heuristic and lets the encoder cleanly fall
 * back to raw when rANS would overflow.
 *
 *   block_payload = type_byte + (raw_lz_stream | rans_payload)
 *     type 0x00 = raw LZ stream
 *     type 0x01 = freq_table[512] + stream_sym_count[4] + rans_data
 */
#define CP_MAGIC            "PRSS"
#define CP_VERSION          0x02
#define CP_VERSION_LEGACY   0x01
#define CP_BLOCK_TYPE_RAW   0x00
#define CP_BLOCK_TYPE_RANS  0x01
#define CP_BLOCK_SIZE       (256 * 1024)
#define CP_WINDOW_SIZE      (64 * 1024)
#define CP_MIN_MATCH        4
#define CP_MAX_MATCH        258
#define CP_HASH_BITS        15
#define CP_HASH_SIZE        (1 << CP_HASH_BITS)

/* rANS constants */
#define CP_RANS_L           (1u << 23)
#define CP_RANS_SCALE_BITS  12
#define CP_RANS_SCALE       (1u << CP_RANS_SCALE_BITS)
#define CP_RANS_STREAMS     4

/* Compression levels */
#define CP_LEVEL_FAST       1
#define CP_LEVEL_DEFAULT    5
#define CP_LEVEL_MAX        9

/* Error codes */
#define CP_OK               0
#define CP_ERR_IO           (-1)
#define CP_ERR_FORMAT       (-2)
#define CP_ERR_CORRUPT      (-3)
#define CP_ERR_NOMEM        (-4)

/* Types */
typedef struct { uint16_t offset; uint16_t length; } cp_match;
typedef struct { uint16_t freq; uint16_t cumfreq; } cp_rans_sym;
typedef struct { uint32_t state[CP_RANS_STREAMS]; } cp_rans_state;

typedef struct {
    cp_rans_sym syms[256];
    uint32_t    freqs[256];
    uint32_t    total;
} cp_freq_table;

typedef struct {
    int16_t head[CP_HASH_SIZE];
    int16_t chain[CP_WINDOW_SIZE];
    int     chain_len;
} cp_match_ctx;

#define CP_HDR_SIZE         16
#define CP_BLOCK_HDR_SIZE   8
#define CP_FREQ_TABLE_SIZE  512

/* ASM entry points */
size_t   cp_rans_encode(cp_rans_state *state, const uint8_t *symbols, size_t n,
                        const cp_rans_sym *table, uint8_t *out, size_t cap);
size_t   cp_rans_decode(cp_rans_state *state, const uint8_t *in, size_t in_len,
                        const cp_rans_sym *table, uint8_t *symbols, size_t max);
cp_match cp_find_match(const uint8_t *data, size_t len, size_t pos, cp_match_ctx *ctx);
void     cp_match_insert(const uint8_t *data, size_t pos, cp_match_ctx *ctx);
void     cp_memcopy(uint8_t *dst, const uint8_t *src, size_t len);
uint32_t cp_xxhash32(const uint8_t *data, size_t len, uint32_t seed);

/* High-level API */
int64_t  cp_compress(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, int level);
int64_t  cp_decompress(const uint8_t *src, size_t src_len,
                       uint8_t *dst, size_t dst_cap);
size_t   cp_compress_bound(size_t src_len);
uint64_t cp_original_size(const uint8_t *header);

/* Frequency table utilities */
void cp_freq_count(const uint8_t *data, size_t len, cp_freq_table *ft);
void cp_freq_normalize(cp_freq_table *ft);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_PRESS_H */
