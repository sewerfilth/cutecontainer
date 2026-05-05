/*
 * Curve25519 field arithmetic — aarch64
 *
 * Field: GF(2^255 - 19)
 * Representation: 5 × 64-bit limbs in radix 2^51
 *   fe = v[0] + v[1]·2^51 + v[2]·2^102 + v[3]·2^153 + v[4]·2^204
 *
 * Each limb fits in 51 bits after reduction, but may temporarily
 * overflow to ~63 bits between operations.
 *
 * Calling convention (AAPCS64):
 *   x0 = output pointer (cc_fe *)
 *   x1 = input a pointer (const cc_fe *)
 *   x2 = input b pointer (const cc_fe *) or scalar
 *
 * cc_fe is { uint64_t v[5]; } — 40 bytes, 5 consecutive uint64s.
 */

#ifdef __aarch64__

.text
.align 4

/* ============================================================
 * cc_fe_zero: r = 0
 * x0 = r
 * ============================================================ */
.globl _cc_fe_zero
_cc_fe_zero:
    stp     xzr, xzr, [x0]
    stp     xzr, xzr, [x0, #16]
    str     xzr, [x0, #32]
    ret

/* ============================================================
 * cc_fe_one: r = 1
 * x0 = r
 * ============================================================ */
.globl _cc_fe_one
_cc_fe_one:
    mov     x8, #1
    str     x8, [x0]
    stp     xzr, xzr, [x0, #8]
    stp     xzr, xzr, [x0, #24]
    ret

/* ============================================================
 * cc_fe_add: r = a + b
 * x0 = r, x1 = a, x2 = b
 *
 * No reduction — limbs may grow by 1 bit.
 * Caller must reduce before multiply if needed.
 * ============================================================ */
.globl _cc_fe_add
_cc_fe_add:
    ldp     x3, x4, [x1]           /* a[0], a[1] */
    ldp     x5, x6, [x1, #16]      /* a[2], a[3] */
    ldr     x7, [x1, #32]          /* a[4] */

    ldp     x8, x9, [x2]           /* b[0], b[1] */
    ldp     x10, x11, [x2, #16]    /* b[2], b[3] */
    ldr     x12, [x2, #32]         /* b[4] */

    add     x3, x3, x8
    add     x4, x4, x9
    add     x5, x5, x10
    add     x6, x6, x11
    add     x7, x7, x12

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ret

/* ============================================================
 * cc_fe_sub: r = a - b
 * x0 = r, x1 = a, x2 = b
 *
 * Adds 2p before subtracting to keep limbs positive.
 * 2p = 2·(2^255 - 19) represented in radix 2^51:
 *   [0xFFFFFFFFFFFDA, 0x7FFFFFFFFFFFF, 0x7FFFFFFFFFFFF,
 *    0x7FFFFFFFFFFFF, 0x7FFFFFFFFFFFF]
 * ============================================================ */
.globl _cc_fe_sub
_cc_fe_sub:
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]

    ldp     x8, x9, [x2]
    ldp     x10, x11, [x2, #16]
    ldr     x12, [x2, #32]

    /* Add 2p to a before subtracting b. 2p in radix 2^51:
     *   2p[0] = 2*(2^51 - 19) = 2^52 - 38 = 0xFFFFFFFFFFFDA
     *   2p[1..4] = 2*(2^51 - 1) = 2^52 -  2 = 0xFFFFFFFFFFFFE
     * The previous version used p[1..4] for limbs 1..4, so the added
     * constant was not a multiple of p — fe_sub returned a value not
     * congruent to (a - b) mod p. */
    movz    x13, #0xFFFE                /* low 16 bits of 2p[1..4] */
    movk    x13, #0xFFFF, lsl #16
    movk    x13, #0xFFFF, lsl #32
    movk    x13, #0x000F, lsl #48       /* 0xFFFFFFFFFFFFE = 2^52 - 2 */
    movz    x14, #0xFFDA                /* low 16 bits of 2p[0] */
    movk    x14, #0xFFFF, lsl #16
    movk    x14, #0xFFFF, lsl #32
    movk    x14, #0x000F, lsl #48       /* 0xFFFFFFFFFFFDA = 2^52 - 38 */

    add     x3, x3, x14                /* a[0] + 2p[0] */
    add     x4, x4, x13                /* a[1] + 2p[1] */
    add     x5, x5, x13                /* a[2] + 2p[2] */
    add     x6, x6, x13                /* a[3] + 2p[3] */
    add     x7, x7, x13                /* a[4] + 2p[4] */

    sub     x3, x3, x8
    sub     x4, x4, x9
    sub     x5, x5, x10
    sub     x6, x6, x11
    sub     x7, x7, x12

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ret

/* ============================================================
 * cc_fe_cswap: constant-time conditional swap
 * x0 = a, x1 = b, x2 = swap (0 or 1)
 *
 * if swap: a,b = b,a
 * No branches — uses bitwise masking.
 * ============================================================ */
.globl _cc_fe_cswap
_cc_fe_cswap:
    neg     x2, x2                  /* 0 → 0, 1 → 0xFFFFFFFFFFFFFFFF */

    ldp     x3, x4, [x0]           /* a[0], a[1] */
    ldp     x5, x6, [x0, #16]      /* a[2], a[3] */
    ldr     x7, [x0, #32]          /* a[4] */

    ldp     x8, x9, [x1]           /* b[0], b[1] */
    ldp     x10, x11, [x1, #16]    /* b[2], b[3] */
    ldr     x12, [x1, #32]         /* b[4] */

    /* diff = (a ^ b) & mask */
    eor     x13, x3, x8
    and     x13, x13, x2
    eor     x3, x3, x13
    eor     x8, x8, x13

    eor     x13, x4, x9
    and     x13, x13, x2
    eor     x4, x4, x13
    eor     x9, x9, x13

    eor     x13, x5, x10
    and     x13, x13, x2
    eor     x5, x5, x13
    eor     x10, x10, x13

    eor     x13, x6, x11
    and     x13, x13, x2
    eor     x6, x6, x13
    eor     x11, x11, x13

    eor     x13, x7, x12
    and     x13, x13, x2
    eor     x7, x7, x13
    eor     x12, x12, x13

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]

    stp     x8, x9, [x1]
    stp     x10, x11, [x1, #16]
    str     x12, [x1, #32]
    ret

/* cc_fe_reduce is implemented in C (src/crypt/curve.c). The ASM
 * version below only carry-propagated; the value could remain in
 * [p, 2^256), so pack would output a non-canonical representation.
 * The C version adds the final conditional subtraction. */
#if 0
_cc_fe_reduce_unused:
    ldp     x1, x2, [x0]           /* v[0], v[1] */
    ldp     x3, x4, [x0, #16]      /* v[2], v[3] */
    ldr     x5, [x0, #32]          /* v[4] */

    movz    x8, #0xFFFF
    movk    x8, #0xFFFF, lsl #16
    movk    x8, #0xFFFF, lsl #32
    movk    x8, #0x0007, lsl #48    /* mask = 2^51 - 1 */

    /* Carry propagation */
    add     x2, x2, x1, lsr #51
    and     x1, x1, x8
    add     x3, x3, x2, lsr #51
    and     x2, x2, x8
    add     x4, x4, x3, lsr #51
    and     x3, x3, x8
    add     x5, x5, x4, lsr #51
    and     x4, x4, x8

    /* Top limb carry wraps: overflow * 19 added to v[0] */
    mov     x9, #19
    lsr     x10, x5, #51
    and     x5, x5, x8
    madd    x1, x10, x9, x1        /* v[0] += carry * 19 */

    /* Second carry pass (v[0] might have grown) */
    add     x2, x2, x1, lsr #51
    and     x1, x1, x8

    stp     x1, x2, [x0]
    stp     x3, x4, [x0, #16]
    str     x5, [x0, #32]
    ret
#endif

/* cc_fe_mul and cc_fe_sqr are implemented in C (src/crypt/curve.c).
 * The previous ASM implementation here used single-width MUL on 51-bit
 * limbs whose products are up to 102 bits — high bits were silently
 * dropped. The C implementation uses __uint128_t accumulators. */
#if 0
_cc_fe_mul_unused:
    /* Save frame */
    stp     x19, x20, [sp, #-64]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]

    /* Load a[0..4] */
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]

    /* Load b[0..4] */
    ldp     x8, x9, [x2]
    ldp     x10, x11, [x2, #16]
    ldr     x12, [x2, #32]

    /* Precompute b[i] * 19 for reduction */
    mov     x13, #19
    mul     x19, x9, x13           /* 19·b[1] */
    mul     x20, x10, x13          /* 19·b[2] */
    mul     x21, x11, x13          /* 19·b[3] */
    mul     x22, x12, x13          /* 19·b[4] */

    /*
     * r[0] = a[0]·b[0] + a[1]·19b[4] + a[2]·19b[3] + a[3]·19b[2] + a[4]·19b[1]
     * r[1] = a[0]·b[1] + a[1]·b[0]   + a[2]·19b[4] + a[3]·19b[3] + a[4]·19b[2]
     * r[2] = a[0]·b[2] + a[1]·b[1]   + a[2]·b[0]   + a[3]·19b[4] + a[4]·19b[3]
     * r[3] = a[0]·b[3] + a[1]·b[2]   + a[2]·b[1]   + a[3]·b[0]   + a[4]·19b[4]
     * r[4] = a[0]·b[4] + a[1]·b[3]   + a[2]·b[2]   + a[3]·b[1]   + a[4]·b[0]
     *
     * Each product is at most 51+51 = 102 bits.
     * Sum of 5 products: at most 105 bits — fits in 128-bit mul result.
     * We use mul (low 64) only since limbs are ≤51 bits and we have 5 terms.
     */

    /* r[0] */
    mul     x14, x3, x8            /* a[0]·b[0] */
    mul     x15, x4, x22           /* a[1]·19b[4] */
    add     x14, x14, x15
    mul     x15, x5, x21           /* a[2]·19b[3] */
    add     x14, x14, x15
    mul     x15, x6, x20           /* a[3]·19b[2] */
    add     x14, x14, x15
    mul     x15, x7, x19           /* a[4]·19b[1] */
    add     x23, x14, x15          /* r[0] in x23 */

    /* r[1] */
    mul     x14, x3, x9            /* a[0]·b[1] */
    mul     x15, x4, x8            /* a[1]·b[0] */
    add     x14, x14, x15
    mul     x15, x5, x22           /* a[2]·19b[4] */
    add     x14, x14, x15
    mul     x15, x6, x21           /* a[3]·19b[3] */
    add     x14, x14, x15
    mul     x15, x7, x20           /* a[4]·19b[2] */
    add     x24, x14, x15          /* r[1] in x24 */

    /* r[2] */
    mul     x14, x3, x10           /* a[0]·b[2] */
    mul     x15, x4, x9            /* a[1]·b[1] */
    add     x14, x14, x15
    mul     x15, x5, x8            /* a[2]·b[0] */
    add     x14, x14, x15
    mul     x15, x6, x22           /* a[3]·19b[4] */
    add     x14, x14, x15
    mul     x15, x7, x21           /* a[4]·19b[3] */
    add     x25, x14, x15          /* r[2] in x25 */

    /* r[3] */
    mul     x14, x3, x11           /* a[0]·b[3] */
    mul     x15, x4, x10           /* a[1]·b[2] */
    add     x14, x14, x15
    mul     x15, x5, x9            /* a[2]·b[1] */
    add     x14, x14, x15
    mul     x15, x6, x8            /* a[3]·b[0] */
    add     x14, x14, x15
    mul     x15, x7, x22           /* a[4]·19b[4] */
    add     x26, x14, x15          /* r[3] in x26 */

    /* r[4] */
    mul     x14, x3, x12           /* a[0]·b[4] */
    mul     x15, x4, x11           /* a[1]·b[3] */
    add     x14, x14, x15
    mul     x15, x5, x10           /* a[2]·b[2] */
    add     x14, x14, x15
    mul     x15, x6, x9            /* a[3]·b[1] */
    add     x14, x14, x15
    mul     x15, x7, x8            /* a[4]·b[0] */
    add     x14, x14, x15          /* r[4] in x14 */

    /* Carry propagation */
    mov     x8, #0x7FFFFFFFFFFFF    /* 2^51 - 1 */

    add     x24, x24, x23, lsr #51
    and     x23, x23, x8
    add     x25, x25, x24, lsr #51
    and     x24, x24, x8
    add     x26, x26, x25, lsr #51
    and     x25, x25, x8
    add     x14, x14, x26, lsr #51
    and     x26, x26, x8

    /* Top carry * 19 back to r[0] */
    mov     x13, #19
    lsr     x15, x14, #51
    and     x14, x14, x8
    madd    x23, x15, x13, x23

    /* One more carry from r[0] */
    add     x24, x24, x23, lsr #51
    and     x23, x23, x8

    /* Store result */
    stp     x23, x24, [x0]
    stp     x25, x26, [x0, #16]
    str     x14, [x0, #32]

    /* Restore frame */
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret

_cc_fe_sqr_unused:
    mov     x2, x1
    b       _cc_fe_mul
#endif

/* ============================================================
 * cc_fe_pack: serialize fe to 32 bytes (little-endian)
 * x0 = out (uint8_t[32]), x1 = fe (cc_fe *)
 *
 * Reduces, then packs 5×51-bit limbs into 256 bits.
 * ============================================================ */
.globl _cc_fe_pack
_cc_fe_pack:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!

    /* Reduce first (in-place on the input). cc_fe_reduce clobbers x1, so
     * stash the input pointer in a callee-saved register. */
    mov     x19, x0                 /* save out ptr */
    mov     x20, x1                 /* save in ptr */
    mov     x0, x1
    bl      _cc_fe_reduce
    mov     x0, x19
    mov     x1, x20

    /* Reload reduced limbs */
    ldp     x2, x3, [x1]           /* v[0], v[1] */
    ldp     x4, x5, [x1, #16]     /* v[2], v[3] */
    ldr     x6, [x1, #32]         /* v[4] */

    /*
     * Pack: value = v[0] + v[1]<<51 + v[2]<<102 + v[3]<<153 + v[4]<<204
     * Into 4 × 64-bit words (little-endian):
     *   w0 = v[0] | (v[1] << 51)
     *   w1 = (v[1] >> 13) | (v[2] << 38)
     *   w2 = (v[2] >> 26) | (v[3] << 25)
     *   w3 = (v[3] >> 39) | (v[4] << 12)
     */
    orr     x7, x2, x3, lsl #51    /* w0 */
    lsr     x8, x3, #13
    orr     x8, x8, x4, lsl #38    /* w1 */
    lsr     x9, x4, #26
    orr     x9, x9, x5, lsl #25    /* w2 */
    lsr     x10, x5, #39
    orr     x10, x10, x6, lsl #12  /* w3 */

    stp     x7, x8, [x0]
    stp     x9, x10, [x0, #16]

    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* ============================================================
 * cc_fe_unpack: deserialize 32 bytes to fe
 * x0 = fe (cc_fe *), x1 = in (uint8_t[32])
 * ============================================================ */
.globl _cc_fe_unpack
_cc_fe_unpack:
    ldp     x2, x3, [x1]           /* w0, w1 */
    ldp     x4, x5, [x1, #16]     /* w2, w3 */

    movz    x6, #0xFFFF
    movk    x6, #0xFFFF, lsl #16
    movk    x6, #0xFFFF, lsl #32
    movk    x6, #0x0007, lsl #48    /* 51-bit mask */

    and     x7, x2, x6              /* v[0] = w0 & mask */
    lsr     x8, x2, #51
    orr     x8, x8, x3, lsl #13
    and     x8, x8, x6              /* v[1] */
    lsr     x9, x3, #38
    orr     x9, x9, x4, lsl #26
    and     x9, x9, x6              /* v[2] */
    lsr     x10, x4, #25
    orr     x10, x10, x5, lsl #39
    and     x10, x10, x6            /* v[3] */
    lsr     x11, x5, #12
    and     x11, x11, x6            /* v[4] */

    stp     x7, x8, [x0]
    stp     x9, x10, [x0, #16]
    str     x11, [x0, #32]
    ret

#endif /* __aarch64__ */
