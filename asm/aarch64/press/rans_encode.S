/*
 * cp_rans_encode — aarch64 rANS encoder
 *
 * 4-way interleaved rANS with 12-bit frequency scale.
 * Encodes symbols in reverse, interleaving across 4 streams.
 *
 * size_t cp_rans_encode(
 *     cp_rans_state *state,       // x0
 *     const uint8_t *symbols,     // x1
 *     size_t n_symbols,           // x2
 *     const cp_rans_sym *sym_table, // x3 (256 entries, each {uint16 freq, uint16 cumfreq})
 *     uint8_t *out,               // x4
 *     size_t out_cap              // x5
 * )
 * Returns: number of bytes written to out.
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

    .text
    .globl SYM(cp_rans_encode)
    .p2align 4

SYM(cp_rans_encode):
    /* save callee-saved registers */
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    mov     x29, sp

    /* save args */
    mov     x19, x0             /* state */
    mov     x20, x1             /* symbols */
    mov     x21, x2             /* n_symbols */
    mov     x22, x3             /* sym_table */
    mov     x23, x4             /* out */
    mov     x24, x5             /* out_cap */

    /* if n_symbols == 0, return 0 */
    cbz     x21, .Lenc_zero

    /* initialize 4 rANS states to CP_RANS_L (1 << 23) */
    mov     w25, #(1 << 23)
    str     w25, [x19]
    str     w25, [x19, #4]
    str     w25, [x19, #8]
    str     w25, [x19, #12]

    /* output pointer starts at end of buffer */
    add     x26, x23, x24      /* ptr = out + out_cap */

    /* encode in reverse */
    mov     x27, x21            /* i = n_symbols */

.Lenc_loop:
    cbz     x27, .Lenc_flush

    sub     x27, x27, #1        /* i-- */

    /* stream = i % 4 */
    and     w28, w27, #3
    /* load state[stream] */
    ldr     w9, [x19, x28, lsl #2]  /* w9 = state[stream] */

    /* load symbol */
    ldrb    w10, [x20, x27]     /* w10 = symbols[i] */

    /* load sym_table[sym]: freq at +0 (uint16), cumfreq at +2 (uint16) */
    add     x11, x22, x10, lsl #2
    ldrh    w12, [x11]          /* w12 = freq */
    ldrh    w13, [x11, #2]      /* w13 = cumfreq */

    /* renormalize: upper = ((RANS_L >> SCALE_BITS) << 8) * freq = freq << 19 */
    /* while (state >= upper) { flush 8 bits; state >>= 8 } */
    lsl     w14, w12, #19       /* upper = freq << 19 (32-bit, max freq=4096 → 2^31, fits) */

.Lenc_renorm:
    cmp     w9, w14
    b.lo    .Lenc_put

    /* flush 8 bits: *--ptr = state & 0xFF */
    sub     x26, x26, #1
    strb    w9, [x26]

    lsr     w9, w9, #8
    b       .Lenc_renorm

.Lenc_put:
    /* encode: state = (state / freq) << 12 + (state % freq) + cumfreq */
    udiv    w15, w9, w12        /* w15 = state / freq */
    msub    w16, w15, w12, w9   /* w16 = state - (state/freq)*freq = state % freq */
    lsl     w15, w15, #12       /* (state / freq) << SCALE_BITS */
    add     w9, w15, w16        /* + remainder */
    add     w9, w9, w13         /* + cumfreq */

    /* store state back */
    str     w9, [x19, x28, lsl #2]

    b       .Lenc_loop

.Lenc_flush:
    /* flush final states: 4 bytes each, big-endian */
    mov     w28, #3
.Lenc_flush_loop:
    ldr     w9, [x19, x28, lsl #2]
    sub     x26, x26, #4
    /* big-endian store */
    lsr     w10, w9, #24
    strb    w10, [x26]
    lsr     w10, w9, #16
    strb    w10, [x26, #1]
    lsr     w10, w9, #8
    strb    w10, [x26, #2]
    strb    w9, [x26, #3]

    cbz     w28, .Lenc_move
    sub     w28, w28, #1
    b       .Lenc_flush_loop

.Lenc_move:
    /* encoded data is at [ptr, out+out_cap). Move to front. */
    add     x10, x23, x24      /* end = out + out_cap */
    sub     x0, x10, x26        /* encoded_len = end - ptr */

    /* memmove(out, ptr, encoded_len) */
    mov     x11, x23            /* dst = out */
    mov     x12, x26            /* src = ptr */
    mov     x13, x0             /* len */

    cmp     x11, x12
    b.eq    .Lenc_done

.Lenc_copy:
    cbz     x13, .Lenc_done
    ldrb    w14, [x12], #1
    strb    w14, [x11], #1
    sub     x13, x13, #1
    b       .Lenc_copy

.Lenc_done:
    /* x0 already has encoded_len */
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96
    ret

.Lenc_zero:
    mov     x0, #0
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96
    ret
