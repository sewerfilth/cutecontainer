/*
 * X25519 Montgomery ladder — aarch64
 *
 * Implements cc_scalarmult and cc_scalarmult_base.
 * Constant-time via cc_fe_cswap (no branches on secret bits).
 *
 * The Montgomery ladder operates on the x-coordinate only,
 * using the differential addition formula:
 *
 *   Given (x₂, x₃) with x₃ - x₂ = x₁ (the base point):
 *     x₂', x₃' = ladder_step(x₂, x₃, bit)
 *
 * 255 iterations, one per scalar bit, MSB first.
 *
 * x0 = output cc_point *
 * x1 = scalar cc_scalar *
 * x2 = base point cc_point * (for scalarmult; G for scalarmult_base)
 */

#ifdef __aarch64__

.text
.align 4

/*
 * Basepoint for Curve25519: u = 9
 */
.section __DATA,__const
.align 3
Lbasepoint:
    .byte 9
    .fill 31, 1, 0

.text

/* ============================================================
 * cc_scalar_clamp: clamp scalar for X25519
 * x0 = scalar (in-place)
 * ============================================================ */
.globl _cc_scalar_clamp
_cc_scalar_clamp:
    ldrb    w1, [x0]
    and     w1, w1, #248           /* clear bottom 3 bits */
    strb    w1, [x0]
    ldrb    w1, [x0, #31]
    and     w1, w1, #127           /* clear top bit */
    orr     w1, w1, #64            /* set second-to-top bit */
    strb    w1, [x0, #31]
    ret

/* ============================================================
 * cc_scalarmult_base: r = s · G (basepoint = 9)
 * x0 = r (cc_point *), x1 = s (cc_scalar *)
 * ============================================================ */
.globl _cc_scalarmult_base
_cc_scalarmult_base:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp

    adrp    x2, Lbasepoint@PAGE
    add     x2, x2, Lbasepoint@PAGEOFF

    bl      _cc_scalarmult

    ldp     x29, x30, [sp], #16
    ret

/* ============================================================
 * cc_scalarmult: r = s · P (Montgomery ladder)
 * x0 = r (cc_point *), x1 = s (cc_scalar *), x2 = P (cc_point *)
 *
 * Stack frame layout (all cc_fe = 40 bytes):
 *   [sp+0]    x2 (fe)      — Montgomery x₂
 *   [sp+40]   x3 (fe)      — Montgomery x₃
 *   [sp+80]   z2 (fe)      — Montgomery z₂
 *   [sp+120]  z3 (fe)      — Montgomery z₃
 *   [sp+160]  x1_base (fe) — base point x-coord (constant)
 *   [sp+200]  tmp0 (fe)    — scratch
 *   [sp+240]  tmp1 (fe)    — scratch
 *   [sp+280]  tmp2 (fe)    — scratch
 *   [sp+320]  tmp3 (fe)    — scratch
 *   [sp+360]  tmp4 (fe)    — scratch
 *   [sp+400]  scalar copy  — 32 bytes
 *   [sp+432]  saved r ptr  — 8 bytes
 *   [sp+440]  saved prev_bit — 8 bytes
 *   Total: 448 bytes (round to 448, 16-byte aligned)
 * ============================================================ */

#define FE_SIZE   40
#define FE_X2     0
#define FE_X3     40
#define FE_Z2     80
#define FE_Z3     120
#define FE_XBASE  160
#define FE_TMP0   200
#define FE_TMP1   240
#define FE_TMP2   280
#define FE_TMP3   320
#define FE_TMP4   360
#define SCALAR    400
#define SAVED_R   432
#define SAVED_BIT 440
#define FRAME     448

.globl _cc_scalarmult
_cc_scalarmult:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    sub     sp, sp, #FRAME

    /* Save output pointer */
    str     x0, [sp, #SAVED_R]

    /* Copy and clamp scalar */
    mov     x19, x1                 /* scalar source */
    add     x0, sp, #SCALAR
    ldp     x3, x4, [x19]
    stp     x3, x4, [x0]
    ldp     x3, x4, [x19, #16]
    stp     x3, x4, [x0, #16]
    bl      _cc_scalar_clamp

    /* Unpack base point x-coord into x1_base */
    add     x0, sp, #FE_XBASE
    mov     x1, x2
    bl      _cc_fe_unpack

    /* Initialize ladder:
     *   x2 = 1, z2 = 0   (point at infinity)
     *   x3 = xbase, z3 = 1
     */
    add     x0, sp, #FE_X2
    bl      _cc_fe_one

    add     x0, sp, #FE_Z2
    bl      _cc_fe_zero

    /* x3 = xbase */
    add     x0, sp, #FE_X3
    add     x1, sp, #FE_XBASE
    ldp     x3, x4, [x1]
    stp     x3, x4, [x0]
    ldp     x3, x4, [x1, #16]
    stp     x3, x4, [x0, #16]
    ldr     x3, [x1, #32]
    str     x3, [x0, #32]

    add     x0, sp, #FE_Z3
    bl      _cc_fe_one

    /* prev_bit = 0 */
    str     xzr, [sp, #SAVED_BIT]

    /* Main loop: 254 iterations, bit 254 down to bit 0 */
    mov     x19, #254               /* bit counter */

Lladder_loop:
    /* Extract bit from scalar */
    add     x20, sp, #SCALAR
    lsr     x1, x19, #3            /* byte index */
    ldrb    w1, [x20, x1]
    and     x2, x19, #7            /* bit index */
    lsr     x1, x1, x2
    and     x1, x1, #1             /* current bit */

    /* swap = bit ^ prev_bit; save swap in x20 (callee-saved) */
    ldr     x2, [sp, #SAVED_BIT]
    eor     x20, x1, x2            /* swap in x20 */
    str     x1, [sp, #SAVED_BIT]   /* prev_bit = bit */

    /* Conditional swap x2<->x3 */
    add     x0, sp, #FE_X2
    add     x1, sp, #FE_X3
    mov     x2, x20
    bl      _cc_fe_cswap

    /* Conditional swap z2<->z3 (same swap value) */
    add     x0, sp, #FE_Z2
    add     x1, sp, #FE_Z3
    mov     x2, x20
    bl      _cc_fe_cswap

    /*
     * Montgomery ladder step (differential addition + doubling):
     *
     * A  = x2 + z2
     * AA = A^2
     * B  = x2 - z2
     * BB = B^2
     * E  = AA - BB
     * C  = x3 + z3
     * D  = x3 - z3
     * DA = D * A
     * CB = C * B
     * x3 = (DA + CB)^2
     * z3 = x1 * (DA - CB)^2
     * x2 = AA * BB
     * z2 = E * (AA + a24 * E)   where a24 = 121666
     */

    /* A = x2 + z2 → tmp0 */
    add     x0, sp, #FE_TMP0
    add     x1, sp, #FE_X2
    add     x2, sp, #FE_Z2
    bl      _cc_fe_add

    /* B = x2 - z2 → tmp1 */
    add     x0, sp, #FE_TMP1
    add     x1, sp, #FE_X2
    add     x2, sp, #FE_Z2
    bl      _cc_fe_sub

    /* C = x3 + z3 → tmp2 */
    add     x0, sp, #FE_TMP2
    add     x1, sp, #FE_X3
    add     x2, sp, #FE_Z3
    bl      _cc_fe_add

    /* D = x3 - z3 → tmp3 */
    add     x0, sp, #FE_TMP3
    add     x1, sp, #FE_X3
    add     x2, sp, #FE_Z3
    bl      _cc_fe_sub

    /* DA = D * A → tmp4 */
    add     x0, sp, #FE_TMP4
    add     x1, sp, #FE_TMP3
    add     x2, sp, #FE_TMP0
    bl      _cc_fe_mul

    /* CB = C * B → tmp3 (reuse) */
    add     x0, sp, #FE_TMP3
    add     x1, sp, #FE_TMP2
    add     x2, sp, #FE_TMP1
    bl      _cc_fe_mul

    /* AA = A^2 → tmp0 (reuse A) */
    add     x0, sp, #FE_TMP0
    add     x1, sp, #FE_TMP0
    bl      _cc_fe_sqr

    /* BB = B^2 → tmp1 (reuse B) */
    add     x0, sp, #FE_TMP1
    add     x1, sp, #FE_TMP1
    bl      _cc_fe_sqr

    /* x2 = AA * BB */
    add     x0, sp, #FE_X2
    add     x1, sp, #FE_TMP0
    add     x2, sp, #FE_TMP1
    bl      _cc_fe_mul

    /* E = AA - BB → tmp2 */
    add     x0, sp, #FE_TMP2
    add     x1, sp, #FE_TMP0
    add     x2, sp, #FE_TMP1
    bl      _cc_fe_sub

    /* x3 = (DA + CB)^2 */
    add     x0, sp, #FE_X3
    add     x1, sp, #FE_TMP4       /* DA */
    add     x2, sp, #FE_TMP3       /* CB */
    bl      _cc_fe_add
    add     x0, sp, #FE_X3
    add     x1, sp, #FE_X3
    bl      _cc_fe_sqr

    /* z3 = xbase * (DA - CB)^2 */
    add     x0, sp, #FE_Z3
    add     x1, sp, #FE_TMP4
    add     x2, sp, #FE_TMP3
    bl      _cc_fe_sub
    add     x0, sp, #FE_Z3
    add     x1, sp, #FE_Z3
    bl      _cc_fe_sqr
    add     x0, sp, #FE_Z3
    add     x1, sp, #FE_Z3
    add     x2, sp, #FE_XBASE
    bl      _cc_fe_mul

    /* z2 = E * (AA + a24 * E)
     * a24 = 121666 = (486662 + 2) / 4
     *
     * At this point the other temp slots hold:
     *   tmp0 = AA   (from step 7 / 9 — fe_mul x2 = AA*BB does not clobber tmp0)
     *   tmp1 = BB   (will be overwritten below)
     *   tmp2 = E    (AA - BB)
     *   tmp3 = CB
     *   tmp4 = DA
     */
    /* tmp1 = a24 as fe (121665 in limb v[0], others 0).
     * RFC 7748 §5 defines a24 = (A - 2) / 4 = 121665 for Curve25519. */
    add     x0, sp, #FE_TMP1
    bl      _cc_fe_zero
    movz    x1, #0xDB41             /* 121665 = 0x1DB41 */
    movk    x1, #0x1, lsl #16
    str     x1, [sp, #FE_TMP1]     /* v[0] = 121665, rest = 0 */

    /* tmp1 = a24 * E */
    add     x0, sp, #FE_TMP1
    add     x1, sp, #FE_TMP1
    add     x2, sp, #FE_TMP2       /* E */
    bl      _cc_fe_mul

    /* tmp1 = a24*E + AA */
    add     x0, sp, #FE_TMP1
    add     x1, sp, #FE_TMP1
    add     x2, sp, #FE_TMP0       /* AA */
    bl      _cc_fe_add

    /* z2 = E * (AA + a24*E) */
    add     x0, sp, #FE_Z2
    add     x1, sp, #FE_TMP2       /* E */
    add     x2, sp, #FE_TMP1       /* AA + a24*E */
    bl      _cc_fe_mul

    /* Loop */
    subs    x19, x19, #1
    b.ge    Lladder_loop

    /* Final cswap based on last bit */
    ldr     x2, [sp, #SAVED_BIT]
    add     x0, sp, #FE_X2
    add     x1, sp, #FE_X3
    bl      _cc_fe_cswap
    ldr     x2, [sp, #SAVED_BIT]
    add     x0, sp, #FE_Z2
    add     x1, sp, #FE_Z3
    bl      _cc_fe_cswap

    /* Result = x2 / z2 = x2 * z2^(-1) */
    add     x0, sp, #FE_TMP0
    add     x1, sp, #FE_Z2
    bl      _cc_fe_inv

    add     x0, sp, #FE_TMP1
    add     x1, sp, #FE_X2
    add     x2, sp, #FE_TMP0
    bl      _cc_fe_mul

    /* Pack result to output */
    ldr     x0, [sp, #SAVED_R]
    add     x1, sp, #FE_TMP1
    bl      _cc_fe_pack

    /* Cleanup */
    add     sp, sp, #FRAME
    ldp     x21, x22, [sp], #16
    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/* cc_fe_inv is implemented in C (src/crypt/curve.c) using the standard
 * Curve25519 inversion addition chain over cc_fe_mul / cc_fe_sqr. */

#endif /* __aarch64__ */
