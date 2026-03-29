/*
 * cp_rans_decode — aarch64 rANS decoder
 *
 * 4-way interleaved rANS with 12-bit frequency scale.
 *
 * size_t cp_rans_decode(
 *     cp_rans_state *state,       // x0
 *     const uint8_t *in,          // x1
 *     size_t in_len,              // x2
 *     const cp_rans_sym *sym_table, // x3
 *     uint8_t *symbols,           // x4
 *     size_t max_symbols          // x5
 * )
 * Returns: number of symbols decoded.
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

    .text
    .globl SYM(cp_rans_decode)
    .p2align 4

SYM(cp_rans_decode):
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    mov     x29, sp

    mov     x19, x0             /* state */
    mov     x20, x1             /* in */
    mov     x21, x2             /* in_len */
    mov     x22, x3             /* sym_table */
    mov     x23, x4             /* symbols */
    mov     x24, x5             /* max_symbols */

    /* need at least 16 bytes for initial states */
    cmp     x21, #16
    b.lo    .Ldec_zero

    /* build cum2sym table on stack (4096 bytes) */
    sub     sp, sp, #4096
    mov     x25, sp             /* cum2sym base */

    /* fill cum2sym: for each sym 0..255, fill cum2sym[cumfreq..cumfreq+freq-1] = sym */
    mov     w9, #0              /* sym = 0 */
.Ldec_build:
    cmp     w9, #256
    b.ge    .Ldec_build_done

    add     x10, x22, x9, lsl #2
    ldrh    w11, [x10]          /* freq */
    ldrh    w12, [x10, #2]      /* cumfreq */

    cbz     w11, .Ldec_build_next

    mov     w13, #0             /* j = 0 */
.Ldec_fill:
    cmp     w13, w11
    b.ge    .Ldec_build_next
    add     w14, w12, w13       /* cumfreq + j */
    strb    w9, [x25, x14]
    add     w13, w13, #1
    b       .Ldec_fill

.Ldec_build_next:
    add     w9, w9, #1
    b       .Ldec_build

.Ldec_build_done:
    /* read initial states (big-endian, 4 bytes each) */
    mov     x26, x20            /* ptr = in */
    add     x27, x20, x21      /* end = in + in_len */

    mov     w9, #0
.Ldec_read_states:
    cmp     w9, #4
    b.ge    .Ldec_main

    ldrb    w10, [x26]
    ldrb    w11, [x26, #1]
    ldrb    w12, [x26, #2]
    ldrb    w13, [x26, #3]
    add     x26, x26, #4

    lsl     w10, w10, #24
    orr     w10, w10, w11, lsl #16
    orr     w10, w10, w12, lsl #8
    orr     w10, w10, w13

    str     w10, [x19, x9, lsl #2]
    add     w9, w9, #1
    b       .Ldec_read_states

.Ldec_main:
    mov     x28, #0             /* i = 0 */

.Ldec_loop:
    cmp     x28, x24
    b.ge    .Ldec_done

    /* stream = i % 4 */
    and     w9, w28, #3
    ldr     w10, [x19, x9, lsl #2]  /* state */

    /* cum = state & (RANS_SCALE - 1) = state & 0xFFF */
    and     w11, w10, #0xFFF

    /* sym = cum2sym[cum] */
    ldrb    w12, [x25, x11]

    /* store decoded symbol */
    strb    w12, [x23, x28]

    /* look up freq, cumfreq for this symbol */
    add     x13, x22, x12, lsl #2
    ldrh    w14, [x13]          /* freq */
    ldrh    w15, [x13, #2]      /* cumfreq */

    /* advance: state = freq * (state >> 12) + (state & 0xFFF) - cumfreq */
    lsr     w16, w10, #12
    mul     w16, w14, w16       /* freq * (state >> 12) */
    add     w16, w16, w11       /* + (state & 0xFFF) */
    sub     w16, w16, w15       /* - cumfreq */

    /* renormalize: while (state < RANS_L && ptr < end) { state = (state<<8)|*ptr++ } */
    mov     w17, #(1 << 23)     /* RANS_L */
.Ldec_renorm:
    cmp     w16, w17
    b.hs    .Ldec_store_state
    cmp     x26, x27
    b.hs    .Ldec_store_state
    ldrb    w10, [x26], #1
    lsl     w16, w16, #8
    orr     w16, w16, w10
    b       .Ldec_renorm

.Ldec_store_state:
    str     w16, [x19, x9, lsl #2]

    add     x28, x28, #1
    b       .Ldec_loop

.Ldec_done:
    mov     x0, x24             /* return max_symbols */

    add     sp, sp, #4096       /* free cum2sym */
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96
    ret

.Ldec_zero:
    mov     x0, #0
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96
    ret
