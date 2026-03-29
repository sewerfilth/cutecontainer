/*
 * CuteHash compression — aarch64
 *
 * Custom ARX compression for the cascade/fuse system.
 * 7 rounds of column + diagonal G mixing.
 * G function uses BLAKE rotation constants (16, 12, 8, 7).
 *
 * void cc_cute_compress(
 *     const uint8_t ns[32],     x0   namespace
 *     const uint8_t a[32],      x1   input A
 *     const uint8_t b[32],      x2   input B
 *     uint64_t counter,         x3   counter
 *     uint32_t mode,            w4   mode byte
 *     uint8_t out[32]           x5   output
 * )
 *
 * State matrix (4×4 uint32):
 *
 *   v0  v1  v2  v3     ← ns[0..3]
 *   v4  v5  v6  v7     ← ns[4..7]
 *   v8  v9  v10 v11    ← counter_lo, counter_hi, mode, 0xCC00CC00
 *   v12 v13 v14 v15    ← a[0..3] ^ b[0..3]
 *
 * Message (16 × uint32):
 *   m[0..7]  = a[0..31] as LE uint32s
 *   m[8..15] = b[0..31] as LE uint32s
 *
 * Message permutation (same schedule each round, BLAKE3-style):
 *   { 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 }
 */

#ifdef __aarch64__

.text
.align 4

/* Message permutation — applied each round */
.section __DATA,__const
.align 2
Lcute_perm:
    .byte 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8

.text

/*
 * Macro: G function (quarter-round)
 *
 * G(a, b, c, d, mx, my):
 *   a = a + b + mx;  d = ror32(d ^ a, 16);
 *   c = c + d;       b = ror32(b ^ c, 12);
 *   a = a + b + my;  d = ror32(d ^ a, 8);
 *   c = c + d;       b = ror32(b ^ c, 7);
 *
 * Uses wa..wd as state registers, wmx/wmy as message words.
 * Clobbers: wa, wb, wc, wd (in-place).
 */
.macro CUTE_G wa, wb, wc, wd, wmx, wmy
    add     \wa, \wa, \wb
    add     \wa, \wa, \wmx
    eor     \wd, \wd, \wa
    ror     \wd, \wd, #16
    add     \wc, \wc, \wd
    eor     \wb, \wb, \wc
    ror     \wb, \wb, #12
    add     \wa, \wa, \wb
    add     \wa, \wa, \wmy
    eor     \wd, \wd, \wa
    ror     \wd, \wd, #8
    add     \wc, \wc, \wd
    eor     \wb, \wb, \wc
    ror     \wb, \wb, #7
.endm

/* ============================================================
 * cc_cute_compress
 * ============================================================ */
.globl _cc_cute_compress
_cc_cute_compress:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!

    mov     x19, x5                 /* save out pointer */

    /* ---- Build state matrix ---- */

    /* Row 0-1: namespace (8 × uint32 LE) */
    ldp     w6, w7, [x0]           /* ns[0], ns[1] */
    ldp     w8, w9, [x0, #8]      /* ns[2], ns[3] */
    ldp     w10, w11, [x0, #16]   /* ns[4], ns[5] */
    ldp     w12, w13, [x0, #24]   /* ns[6], ns[7] */

    /* Row 2: counter_lo, counter_hi, mode, sentinel */
    mov     w14, w3                 /* counter_lo = (uint32_t)counter */
    lsr     x20, x3, #32
    mov     w15, w20                /* counter_hi */
    mov     w16, w4                 /* mode */
    mov     w17, #0xCC00            /* sentinel = 0xCC00CC00 */
    movk    w17, #0xCC00, lsl #16

    /* Row 3: a[0..3] ^ b[0..3] (first 16 bytes of each, XORed) */
    ldp     w20, w21, [x1]         /* a[0], a[1] as uint32 */
    ldp     w22, w23, [x1, #8]     /* a[2], a[3] */
    ldp     w24, w25, [x2]         /* b[0], b[1] */
    ldp     w26, w27, [x2, #8]     /* b[2], b[3] */
    eor     w20, w20, w24           /* v12 = a[0] ^ b[0] */
    eor     w21, w21, w25           /* v13 = a[1] ^ b[1] */
    eor     w22, w22, w26           /* v14 = a[2] ^ b[2] */
    eor     w23, w23, w27           /* v15 = a[3] ^ b[3] */

    /* Save initial state row 0-1 for feed-forward */
    /* We'll XOR state[0..7] ^ state[8..15] at the end */
    /* Save ns words to stack for feed-forward */
    sub     sp, sp, #96             /* 32 (feed-fwd) + 64 (message) */
    stp     w6, w7, [sp]
    stp     w8, w9, [sp, #8]
    stp     w10, w11, [sp, #16]
    stp     w12, w13, [sp, #24]

    /* ---- Load message (a ‖ b as 16 × uint32 LE) ---- */
    /* m[0..7] = a[0..31], m[8..15] = b[0..31] */
    ldp     w24, w25, [x1]
    stp     w24, w25, [sp, #32]
    ldp     w24, w25, [x1, #8]
    stp     w24, w25, [sp, #40]
    ldp     w24, w25, [x1, #16]
    stp     w24, w25, [sp, #48]
    ldp     w24, w25, [x1, #24]
    stp     w24, w25, [sp, #56]
    ldp     w24, w25, [x2]
    stp     w24, w25, [sp, #64]
    ldp     w24, w25, [x2, #8]
    stp     w24, w25, [sp, #72]
    ldp     w24, w25, [x2, #16]
    stp     w24, w25, [sp, #80]
    ldp     w24, w25, [x2, #24]
    stp     w24, w25, [sp, #88]

    /* ---- 7 rounds ---- */
    /*
     * State in registers:
     *   row 0: w6  w7  w8  w9    (v0..v3)
     *   row 1: w10 w11 w12 w13   (v4..v7)
     *   row 2: w14 w15 w16 w17   (v8..v11)
     *   row 3: w20 w21 w22 w23   (v12..v15)
     *
     * Message on stack at [sp+32].
     * Permutation pointer in x28.
     * w24, w25 used as mx, my temporaries.
     */

    mov     x28, #7                /* round counter */

    /* Load permutation table address */
    adrp    x26, Lcute_perm@PAGE
    add     x26, x26, Lcute_perm@PAGEOFF

    /* For simplicity: keep a permuted index array on the stack
     * and apply the permutation in-place each round.
     * Start with identity: indices[i] = i */
    sub     sp, sp, #16            /* 16 bytes for index array */
    /* Store identity: 0x00,0x01,...,0x0F */
    movz    x24, #0x0302
    movk    x24, #0x0100, lsl #16
    movk    x24, #0x0706, lsl #32  /* 0x0706050403020100 is wrong order, use: */
    /* Actually we want bytes: [0]=0, [1]=1, ..., [7]=7 in LE order */
    movz    x24, #0x0100
    movk    x24, #0x0302, lsl #16
    movk    x24, #0x0504, lsl #32
    movk    x24, #0x0706, lsl #48
    str     x24, [sp]
    movz    x24, #0x0908
    movk    x24, #0x0B0A, lsl #16
    movk    x24, #0x0D0C, lsl #32
    movk    x24, #0x0F0E, lsl #48
    str     x24, [sp, #8]

    add     x27, sp, #48           /* message base (16 idx + 32 feed-fwd) */

Lcute_round:
    /* Load message words via permuted indices.
     * indices are at [sp], message at [sp+48].
     */

    /* Column G0: v0,v4,v8,v12 with m[s[0]], m[s[1]] */
    ldrb    w24, [sp, #0]
    ldr     w24, [x27, w24, uxtw #2]   /* mx = m[s[0]] */
    ldrb    w25, [sp, #1]
    ldr     w25, [x27, w25, uxtw #2]   /* my = m[s[1]] */
    CUTE_G  w6, w10, w14, w20, w24, w25

    /* Column G1: v1,v5,v9,v13 with m[s[2]], m[s[3]] */
    ldrb    w24, [sp, #2]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #3]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w7, w11, w15, w21, w24, w25

    /* Column G2: v2,v6,v10,v14 with m[s[4]], m[s[5]] */
    ldrb    w24, [sp, #4]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #5]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w8, w12, w16, w22, w24, w25

    /* Column G3: v3,v7,v11,v15 with m[s[6]], m[s[7]] */
    ldrb    w24, [sp, #6]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #7]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w9, w13, w17, w23, w24, w25

    /* Diagonal G0: v0,v5,v10,v15 with m[s[8]], m[s[9]] */
    ldrb    w24, [sp, #8]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #9]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w6, w11, w16, w23, w24, w25

    /* Diagonal G1: v1,v6,v11,v12 with m[s[10]], m[s[11]] */
    ldrb    w24, [sp, #10]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #11]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w7, w12, w17, w20, w24, w25

    /* Diagonal G2: v2,v7,v8,v13 with m[s[12]], m[s[13]] */
    ldrb    w24, [sp, #12]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #13]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w8, w13, w14, w21, w24, w25

    /* Diagonal G3: v3,v4,v9,v14 with m[s[14]], m[s[15]] */
    ldrb    w24, [sp, #14]
    ldr     w24, [x27, w24, uxtw #2]
    ldrb    w25, [sp, #15]
    ldr     w25, [x27, w25, uxtw #2]
    CUTE_G  w9, w10, w15, w22, w24, w25

    /* ---- Apply message permutation to indices for next round ---- */
    /* new_s[i] = PERM[old_s[i]]
     * PERM = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8}
     */
    ldrb    w0, [sp, #0]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #0]
    ldrb    w0, [sp, #1]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #1]
    ldrb    w0, [sp, #2]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #2]
    ldrb    w0, [sp, #3]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #3]
    ldrb    w0, [sp, #4]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #4]
    ldrb    w0, [sp, #5]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #5]
    ldrb    w0, [sp, #6]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #6]
    ldrb    w0, [sp, #7]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #7]
    ldrb    w0, [sp, #8]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #8]
    ldrb    w0, [sp, #9]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #9]
    ldrb    w0, [sp, #10]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #10]
    ldrb    w0, [sp, #11]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #11]
    ldrb    w0, [sp, #12]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #12]
    ldrb    w0, [sp, #13]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #13]
    ldrb    w0, [sp, #14]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #14]
    ldrb    w0, [sp, #15]
    ldrb    w0, [x26, w0, uxtw]
    strb    w0, [sp, #15]

    subs    x28, x28, #1
    b.ne    Lcute_round

    /* ---- Feed-forward XOR ---- */
    /* output[0..7] = state[0..7] ⊕ state[8..15] */
    /* state[0..7] = w6..w13 (rows 0-1) */
    /* state[8..15] = w14..w17, w20..w23 (rows 2-3) */
    /* feed-forward: also XOR with saved initial ns[0..7] at [sp+16] */
    /* Full feed-forward: out = final_state[0..7] ^ final_state[8..15] ^ init_state[0..7] */

    /* Load saved initial namespace from [sp+16] (16 idx + 0 offset in feed-fwd area) */
    ldp     w0, w1, [sp, #16]      /* init ns[0], ns[1] */
    ldp     w2, w3, [sp, #24]      /* init ns[2], ns[3] */
    ldp     w4, w5, [sp, #32]      /* init ns[4], ns[5] */

    /* Wait — stack layout:
     *   [sp+0]   16 bytes: index array
     *   [sp+16]  32 bytes: saved feed-forward (init ns[0..7])
     *   [sp+48]  64 bytes: message
     *   Total: 112 bytes allocated
     */
    ldp     w0, w1, [sp, #16]
    ldp     w2, w3, [sp, #24]
    ldp     w4, w5, [sp, #32]
    ldp     w24, w25, [sp, #40]     /* init ns[6], ns[7] */

    /* out[0] = v0 ^ v8 ^ init_ns[0] */
    eor     w6, w6, w14
    eor     w6, w6, w0
    /* out[1] = v1 ^ v9 ^ init_ns[1] */
    eor     w7, w7, w15
    eor     w7, w7, w1
    /* out[2] = v2 ^ v10 ^ init_ns[2] */
    eor     w8, w8, w16
    eor     w8, w8, w2
    /* out[3] = v3 ^ v11 ^ init_ns[3] */
    eor     w9, w9, w17
    eor     w9, w9, w3
    /* out[4] = v4 ^ v12 ^ init_ns[4] */
    eor     w10, w10, w20
    eor     w10, w10, w4
    /* out[5] = v5 ^ v13 ^ init_ns[5] */
    eor     w11, w11, w21
    eor     w11, w11, w5
    /* out[6] = v6 ^ v14 ^ init_ns[6] */
    eor     w12, w12, w22
    eor     w12, w12, w24
    /* out[7] = v7 ^ v15 ^ init_ns[7] */
    eor     w13, w13, w23
    eor     w13, w13, w25

    /* Store output (8 × uint32 = 32 bytes) */
    stp     w6, w7, [x19]
    stp     w8, w9, [x19, #8]
    stp     w10, w11, [x19, #16]
    stp     w12, w13, [x19, #24]

    /* Pop stack frames: 16 (indices) + 32 (feed-fwd) + 64 (message) = 112 */
    add     sp, sp, #112

    ldp     x27, x28, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* ============================================================
 * cc_cute_namespace: derive namespace from context string
 *
 * void cc_cute_namespace(uint8_t ns[32], const char *ctx, size_t len)
 *   x0 = ns output
 *   x1 = context string
 *   x2 = context length
 *
 * Bootstrap: compress with zero namespace, zero counter, mode=0x00.
 * Input A = first 32 bytes of context (zero-padded).
 * Input B = last 32 bytes of context (zero-padded, or zeros if len ≤ 32).
 * ============================================================ */
.globl _cc_cute_namespace
_cc_cute_namespace:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    /* Allocate temp buffers: 32 (zero ns) + 32 (padded A) + 32 (padded B) = 96 */
    sub     sp, sp, #96

    /* Zero namespace */
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]

    /* Zero-pad A and B */
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]

    /* Copy context into A (up to 32 bytes) */
    mov     x3, x2                  /* len */
    cmp     x3, #32
    b.le    Lns_copy_a
    mov     x3, #32
Lns_copy_a:
    cbz     x3, Lns_copy_b_setup
    mov     x4, #0
Lns_copy_a_loop:
    ldrb    w5, [x1, x4]
    strb    w5, [sp, #32]           /* ... need sp+32+x4 */
    add     x6, sp, #32
    strb    w5, [x6, x4]
    add     x4, x4, #1
    cmp     x4, x3
    b.lt    Lns_copy_a_loop

Lns_copy_b_setup:
    /* If len > 32, copy remainder into B */
    cmp     x2, #32
    b.le    Lns_do_compress

    sub     x3, x2, #32            /* remaining = len - 32 */
    cmp     x3, #32
    b.le    Lns_copy_b
    mov     x3, #32
Lns_copy_b:
    mov     x4, #0
    add     x6, x1, #32            /* source = ctx + 32 */
Lns_copy_b_loop:
    ldrb    w5, [x6, x4]
    add     x7, sp, #64
    strb    w5, [x7, x4]
    add     x4, x4, #1
    cmp     x4, x3
    b.lt    Lns_copy_b_loop

Lns_do_compress:
    /* Call cc_cute_compress(zero_ns, padded_a, padded_b, 0, 0x00, out) */
    mov     x5, x0                  /* out = ns output (saved from entry) */
    add     x0, sp, #0             /* ns = zeros */
    add     x1, sp, #32            /* a = padded context part 1 */
    add     x2, sp, #64            /* b = padded context part 2 */
    mov     x3, #0                  /* counter = 0 */
    mov     w4, #0                  /* mode = 0 (namespace derivation) */
    bl      _cc_cute_compress

    add     sp, sp, #96
    ldp     x29, x30, [sp], #16
    ret

#endif /* __aarch64__ */
