/*
 * rANS encoder/decoder — C fallback
 *
 * 4-way interleaved rANS with 12-bit frequency scale.
 * Used on architectures without hand-written ASM.
 */

#include "cutecontainer/press.h"
#include <string.h>

/* ---- helpers ---- */

/* Returns 1 on success, 0 if writing would underflow `base`. */
static inline int rans_enc_put(uint32_t *state, uint8_t **pptr, uint8_t *base,
                               uint16_t freq, uint16_t cumfreq)
{
    uint32_t s = *state;
    /* renormalize: flush 8 bits at a time.
     * RANS_L = 1<<23, state ∈ [RANS_L, RANS_L<<8) = [2^23, 2^31).
     * upper = ((RANS_L >> SCALE_BITS) << 8) * freq = freq << 19 */
    uint32_t upper = ((CP_RANS_L >> CP_RANS_SCALE_BITS) << 8) * freq;
    while (s >= upper) {
        if (*pptr <= base) return 0;
        *--(*pptr) = (uint8_t)(s & 0xFF);
        s >>= 8;
    }
    /* encode step */
    *state = ((s / freq) << CP_RANS_SCALE_BITS) + (s % freq) + cumfreq;
    return 1;
}

static inline uint32_t rans_dec_get(uint32_t state)
{
    return state & (CP_RANS_SCALE - 1);
}

static inline void rans_dec_advance(uint32_t *state, const uint8_t **pptr,
                                    const uint8_t *end,
                                    uint16_t freq, uint16_t cumfreq)
{
    uint32_t s = *state;
    s = freq * (s >> CP_RANS_SCALE_BITS) + (s & (CP_RANS_SCALE - 1)) - cumfreq;
    /* renormalize: read 8 bits at a time (matches encoder's 8-bit flush) */
    while (s < CP_RANS_L && *pptr < end) {
        s = (s << 8) | **pptr;
        (*pptr)++;
    }
    *state = s;
}

/* ---- cumulative frequency lookup table (built once per block) ---- */

static void build_cum2sym(const cp_rans_sym *sym_table, uint8_t *cum2sym)
{
    for (int sym = 0; sym < 256; sym++) {
        uint16_t base = sym_table[sym].cumfreq;
        uint16_t freq = sym_table[sym].freq;
        for (uint16_t j = 0; j < freq; j++) {
            cum2sym[base + j] = (uint8_t)sym;
        }
    }
}

/* ---- public API ---- */

#ifndef CP_ARCH_AARCH64
#ifndef CP_ARCH_X86_64

size_t cp_rans_encode(
    cp_rans_state *state,
    const uint8_t *symbols, size_t n_symbols,
    const cp_rans_sym *sym_table,
    uint8_t *out, size_t out_cap)
{
    if (n_symbols == 0) return 0;

    /* initialize states */
    for (int i = 0; i < CP_RANS_STREAMS; i++)
        state->state[i] = CP_RANS_L;

    /* rANS encodes in reverse; output pointer starts at end */
    uint8_t *ptr = out + out_cap;

    /* encode symbols in reverse, interleaving across streams */
    for (size_t i = n_symbols; i > 0; ) {
        i--;
        int stream = i % CP_RANS_STREAMS;
        uint8_t sym = symbols[i];
        if (!rans_enc_put(&state->state[stream], &ptr, out,
                          sym_table[sym].freq, sym_table[sym].cumfreq)) {
            return 0; /* output would underflow — caller falls back to raw */
        }
    }

    /* flush final states (each state = 4 bytes, big-endian) */
    if ((size_t)(ptr - out) < (size_t)(CP_RANS_STREAMS * 4)) return 0;
    for (int i = CP_RANS_STREAMS - 1; i >= 0; i--) {
        ptr -= 4;
        ptr[0] = (uint8_t)(state->state[i] >> 24);
        ptr[1] = (uint8_t)(state->state[i] >> 16);
        ptr[2] = (uint8_t)(state->state[i] >>  8);
        ptr[3] = (uint8_t)(state->state[i]);
    }

    /* move encoded data to front of buffer */
    size_t encoded_len = (size_t)(out + out_cap - ptr);
    memmove(out, ptr, encoded_len);
    return encoded_len;
}

size_t cp_rans_decode(
    cp_rans_state *state,
    const uint8_t *in, size_t in_len,
    const cp_rans_sym *sym_table,
    uint8_t *symbols, size_t max_symbols)
{
    if (in_len < CP_RANS_STREAMS * 4) return 0;

    /* build reverse lookup */
    uint8_t cum2sym[CP_RANS_SCALE];
    build_cum2sym(sym_table, cum2sym);

    const uint8_t *ptr = in;
    const uint8_t *end = in + in_len;

    /* read initial states */
    for (int i = 0; i < CP_RANS_STREAMS; i++) {
        state->state[i] = ((uint32_t)ptr[0] << 24) |
                          ((uint32_t)ptr[1] << 16) |
                          ((uint32_t)ptr[2] <<  8) |
                          ((uint32_t)ptr[3]);
        ptr += 4;
    }

    /* decode */
    for (size_t i = 0; i < max_symbols; i++) {
        int stream = i % CP_RANS_STREAMS;
        uint32_t cum = rans_dec_get(state->state[stream]);
        uint8_t sym = cum2sym[cum];
        symbols[i] = sym;
        rans_dec_advance(&state->state[stream], &ptr, end,
                         sym_table[sym].freq, sym_table[sym].cumfreq);
    }

    return max_symbols;
}

#endif
#endif
