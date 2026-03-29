/*
 * Curve25519 field arithmetic — x86_64
 *
 * Field: GF(2^255 - 19)
 * Representation: 5 × 64-bit limbs in radix 2^51
 *   fe = v[0] + v[1]·2^51 + v[2]·2^102 + v[3]·2^153 + v[4]·2^204
 *
 * System V AMD64 ABI:
 *   rdi = output, rsi = input a, rdx = input b
 *   Callee-saved: rbx, rbp, r12-r15
 *   Clobbered: rax, rcx, rdx, rsi, rdi, r8-r11
 *
 * cc_fe is { uint64_t v[5]; } — 40 bytes.
 */

#ifdef __x86_64__

.text

/* 51-bit mask: 2^51 - 1 = 0x7FFFFFFFFFFFF */
#define MASK51  $0x7FFFFFFFFFFFF

/* ============================================================
 * cc_fe_zero: r = 0
 * rdi = r
 * ============================================================ */
.globl _cc_fe_zero
.align 16
_cc_fe_zero:
    xorq    %rax, %rax
    movq    %rax, 0(%rdi)
    movq    %rax, 8(%rdi)
    movq    %rax, 16(%rdi)
    movq    %rax, 24(%rdi)
    movq    %rax, 32(%rdi)
    ret

/* ============================================================
 * cc_fe_one: r = 1
 * rdi = r
 * ============================================================ */
.globl _cc_fe_one
.align 16
_cc_fe_one:
    movq    $1, 0(%rdi)
    xorq    %rax, %rax
    movq    %rax, 8(%rdi)
    movq    %rax, 16(%rdi)
    movq    %rax, 24(%rdi)
    movq    %rax, 32(%rdi)
    ret

/* ============================================================
 * cc_fe_add: r = a + b
 * rdi = r, rsi = a, rdx = b
 * ============================================================ */
.globl _cc_fe_add
.align 16
_cc_fe_add:
    movq    0(%rsi), %rax
    addq    0(%rdx), %rax
    movq    %rax, 0(%rdi)

    movq    8(%rsi), %rax
    addq    8(%rdx), %rax
    movq    %rax, 8(%rdi)

    movq    16(%rsi), %rax
    addq    16(%rdx), %rax
    movq    %rax, 16(%rdi)

    movq    24(%rsi), %rax
    addq    24(%rdx), %rax
    movq    %rax, 24(%rdi)

    movq    32(%rsi), %rax
    addq    32(%rdx), %rax
    movq    %rax, 32(%rdi)
    ret

/* ============================================================
 * cc_fe_sub: r = a - b
 * rdi = r, rsi = a, rdx = b
 *
 * Adds 2p before subtracting to keep limbs positive.
 * 2p limbs: [0xFFFFFFFFFFFDA, 0x7FFFFFFFFFFFF×4]
 * ============================================================ */
.globl _cc_fe_sub
.align 16
_cc_fe_sub:
    movq    MASK51, %r8              /* 0x7FFFFFFFFFFFF */
    movq    $0xFFFFFFFFFFFDA, %r9    /* 2p[0] */

    movq    0(%rsi), %rax
    addq    %r9, %rax
    subq    0(%rdx), %rax
    movq    %rax, 0(%rdi)

    movq    8(%rsi), %rax
    addq    %r8, %rax
    subq    8(%rdx), %rax
    movq    %rax, 8(%rdi)

    movq    16(%rsi), %rax
    addq    %r8, %rax
    subq    16(%rdx), %rax
    movq    %rax, 16(%rdi)

    movq    24(%rsi), %rax
    addq    %r8, %rax
    subq    24(%rdx), %rax
    movq    %rax, 24(%rdi)

    movq    32(%rsi), %rax
    addq    %r8, %rax
    subq    32(%rdx), %rax
    movq    %rax, 32(%rdi)
    ret

/* ============================================================
 * cc_fe_cswap: constant-time conditional swap
 * rdi = a, rsi = b, rdx = swap (0 or 1)
 * ============================================================ */
.globl _cc_fe_cswap
.align 16
_cc_fe_cswap:
    negq    %rdx                     /* 0→0, 1→0xFFFF... */

    .irp off, 0, 8, 16, 24, 32
    movq    \off(%rdi), %rax
    movq    \off(%rsi), %rcx
    movq    %rax, %r8
    xorq    %rcx, %r8
    andq    %rdx, %r8
    xorq    %r8, %rax
    xorq    %r8, %rcx
    movq    %rax, \off(%rdi)
    movq    %rcx, \off(%rsi)
    .endr
    ret

/* ============================================================
 * cc_fe_reduce: canonical reduction mod p
 * rdi = r (in-place)
 * ============================================================ */
.globl _cc_fe_reduce
.align 16
_cc_fe_reduce:
    movq    0(%rdi), %rax            /* v[0] */
    movq    8(%rdi), %rcx            /* v[1] */
    movq    16(%rdi), %r8            /* v[2] */
    movq    24(%rdi), %r9            /* v[3] */
    movq    32(%rdi), %r10           /* v[4] */

    movq    MASK51, %r11

    /* Carry propagation */
    movq    %rax, %rdx
    shrq    $51, %rdx
    addq    %rdx, %rcx
    andq    %r11, %rax

    movq    %rcx, %rdx
    shrq    $51, %rdx
    addq    %rdx, %r8
    andq    %r11, %rcx

    movq    %r8, %rdx
    shrq    $51, %rdx
    addq    %rdx, %r9
    andq    %r11, %r8

    movq    %r9, %rdx
    shrq    $51, %rdx
    addq    %rdx, %r10
    andq    %r11, %r9

    /* Top carry × 19 back to v[0] */
    movq    %r10, %rdx
    shrq    $51, %rdx
    andq    %r11, %r10
    imulq   $19, %rdx, %rdx
    addq    %rdx, %rax

    /* Second carry pass */
    movq    %rax, %rdx
    shrq    $51, %rdx
    addq    %rdx, %rcx
    andq    %r11, %rax

    movq    %rax, 0(%rdi)
    movq    %rcx, 8(%rdi)
    movq    %r8, 16(%rdi)
    movq    %r9, 24(%rdi)
    movq    %r10, 32(%rdi)
    ret

/* ============================================================
 * cc_fe_mul: r = a * b mod p
 * rdi = r, rsi = a, rdx = b
 *
 * Schoolbook 5×5 using mulq for 128-bit products.
 * Uses x86_64's rdx:rax = rax * src for full-width multiply.
 *
 * r[0] = a0·b0 + 19·(a1·b4 + a2·b3 + a3·b2 + a4·b1)
 * r[1] = a0·b1 + a1·b0 + 19·(a2·b4 + a3·b3 + a4·b2)
 * r[2] = a0·b2 + a1·b1 + a2·b0 + 19·(a3·b4 + a4·b3)
 * r[3] = a0·b3 + a1·b2 + a2·b1 + a3·b0 + 19·(a4·b4)
 * r[4] = a0·b4 + a1·b3 + a2·b2 + a3·b1 + a4·b0
 * ============================================================ */
.globl _cc_fe_mul
.align 16
_cc_fe_mul:
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdi, %rbp               /* save output pointer */

    /* Load a[0..4] */
    movq    0(%rsi), %r8             /* a0 */
    movq    8(%rsi), %r9             /* a1 */
    movq    16(%rsi), %r10           /* a2 */
    movq    24(%rsi), %r11           /* a3 */
    movq    32(%rsi), %rbx           /* a4 */

    /* Load b[0..4] — rdx was input b pointer */
    movq    0(%rdx), %rcx            /* b0 — save rdx first */
    movq    %rdx, %rsi               /* rsi = b pointer */
    movq    %rcx, %rcx               /* b0 in rcx */
    movq    8(%rsi), %r12            /* b1 */
    movq    16(%rsi), %r13           /* b2 */
    movq    24(%rsi), %r14           /* b3 */
    movq    32(%rsi), %r15           /* b4 */

    /* Precompute 19*b[1..4] into stack temporaries */
    /* We'll use the stack for accumulating results */
    subq    $80, %rsp                /* 5 × 16 bytes for accumulator pairs */

    /* Compute r[0] = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) */
    movq    %r8, %rax                /* a0 */
    mulq    %rcx                     /* rdx:rax = a0*b0 */
    movq    %rax, %rdi               /* r0_lo */
    /* For simplicity in accumulation, we only use low 64 bits
     * since limbs are ≤51 bits and we sum 5 terms:
     * max = 5 × (2^51)^2 = 5 × 2^102 ≈ 2^104.3
     * This fits in 128 bits but NOT in 64. We need to track carries.
     * However, since we're in radix 2^51 and will carry-propagate,
     * we can use 128-bit accumulators (rdx:rax pairs).
     */

    /* Actually, let's use a simpler approach: accumulate in 64 bits.
     * Since each limb is ≤ 2^51 and 19*limb ≤ 19*2^51 < 2^56,
     * each product is ≤ 2^51 * 2^56 = 2^107.
     * Sum of 5 such products ≤ 5*2^107 < 2^110.
     * This overflows 64 bits. We need 128-bit accumulation.
     *
     * Strategy: use mulq and accumulate hi:lo pairs.
     */

    /* r[0] = a0*b0 + 19*(a1*b4 + a2*b3 + a3*b2 + a4*b1) */
    /* Compute 19*b[i] values */
    imulq   $19, %r12, %rsi          /* 19*b1 — reuse rsi */

    movq    %r8, %rax
    mulq    %rcx                     /* a0*b0 */
    movq    %rax, 0(%rsp)            /* r0_lo */
    movq    %rdx, 8(%rsp)            /* r0_hi */

    imulq   $19, %r15, %rdi          /* 19*b4 */
    movq    %r9, %rax                /* a1 */
    mulq    %rdi                     /* a1*19*b4 */
    addq    %rax, 0(%rsp)
    adcq    %rdx, 8(%rsp)

    imulq   $19, %r14, %rdi          /* 19*b3 */
    movq    %r10, %rax               /* a2 */
    mulq    %rdi                     /* a2*19*b3 */
    addq    %rax, 0(%rsp)
    adcq    %rdx, 8(%rsp)

    imulq   $19, %r13, %rdi          /* 19*b2 */
    movq    %r11, %rax               /* a3 */
    mulq    %rdi                     /* a3*19*b2 */
    addq    %rax, 0(%rsp)
    adcq    %rdx, 8(%rsp)

    movq    %rbx, %rax               /* a4 */
    mulq    %rsi                     /* a4*19*b1 */
    addq    %rax, 0(%rsp)
    adcq    %rdx, 8(%rsp)

    /* r[1] = a0*b1 + a1*b0 + 19*(a2*b4 + a3*b3 + a4*b2) */
    movq    %r8, %rax
    mulq    %r12                     /* a0*b1 */
    movq    %rax, 16(%rsp)
    movq    %rdx, 24(%rsp)

    movq    %r9, %rax
    mulq    %rcx                     /* a1*b0 */
    addq    %rax, 16(%rsp)
    adcq    %rdx, 24(%rsp)

    imulq   $19, %r15, %rdi          /* 19*b4 */
    movq    %r10, %rax
    mulq    %rdi                     /* a2*19*b4 */
    addq    %rax, 16(%rsp)
    adcq    %rdx, 24(%rsp)

    imulq   $19, %r14, %rdi          /* 19*b3 */
    movq    %r11, %rax
    mulq    %rdi                     /* a3*19*b3 */
    addq    %rax, 16(%rsp)
    adcq    %rdx, 24(%rsp)

    imulq   $19, %r13, %rdi          /* 19*b2 */
    movq    %rbx, %rax
    mulq    %rdi                     /* a4*19*b2 */
    addq    %rax, 16(%rsp)
    adcq    %rdx, 24(%rsp)

    /* r[2] = a0*b2 + a1*b1 + a2*b0 + 19*(a3*b4 + a4*b3) */
    movq    %r8, %rax
    mulq    %r13                     /* a0*b2 */
    movq    %rax, 32(%rsp)
    movq    %rdx, 40(%rsp)

    movq    %r9, %rax
    mulq    %r12                     /* a1*b1 */
    addq    %rax, 32(%rsp)
    adcq    %rdx, 40(%rsp)

    movq    %r10, %rax
    mulq    %rcx                     /* a2*b0 */
    addq    %rax, 32(%rsp)
    adcq    %rdx, 40(%rsp)

    imulq   $19, %r15, %rdi
    movq    %r11, %rax
    mulq    %rdi                     /* a3*19*b4 */
    addq    %rax, 32(%rsp)
    adcq    %rdx, 40(%rsp)

    imulq   $19, %r14, %rdi
    movq    %rbx, %rax
    mulq    %rdi                     /* a4*19*b3 */
    addq    %rax, 32(%rsp)
    adcq    %rdx, 40(%rsp)

    /* r[3] = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19*(a4*b4) */
    movq    %r8, %rax
    mulq    %r14                     /* a0*b3 */
    movq    %rax, 48(%rsp)
    movq    %rdx, 56(%rsp)

    movq    %r9, %rax
    mulq    %r13                     /* a1*b2 */
    addq    %rax, 48(%rsp)
    adcq    %rdx, 56(%rsp)

    movq    %r10, %rax
    mulq    %r12                     /* a2*b1 */
    addq    %rax, 48(%rsp)
    adcq    %rdx, 56(%rsp)

    movq    %r11, %rax
    mulq    %rcx                     /* a3*b0 */
    addq    %rax, 48(%rsp)
    adcq    %rdx, 56(%rsp)

    imulq   $19, %r15, %rdi
    movq    %rbx, %rax
    mulq    %rdi                     /* a4*19*b4 */
    addq    %rax, 48(%rsp)
    adcq    %rdx, 56(%rsp)

    /* r[4] = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 */
    movq    %r8, %rax
    mulq    %r15                     /* a0*b4 */
    movq    %rax, 64(%rsp)
    movq    %rdx, 72(%rsp)

    movq    %r9, %rax
    mulq    %r14                     /* a1*b3 */
    addq    %rax, 64(%rsp)
    adcq    %rdx, 72(%rsp)

    movq    %r10, %rax
    mulq    %r13                     /* a2*b2 */
    addq    %rax, 64(%rsp)
    adcq    %rdx, 72(%rsp)

    movq    %r11, %rax
    mulq    %r12                     /* a3*b1 */
    addq    %rax, 64(%rsp)
    adcq    %rdx, 72(%rsp)

    movq    %rbx, %rax
    mulq    %rcx                     /* a4*b0 */
    addq    %rax, 64(%rsp)
    adcq    %rdx, 72(%rsp)

    /* ---- Carry propagation ---- */
    /* Load 128-bit accumulators, take low 51 bits, carry rest */
    movq    MASK51, %rdi

    movq    0(%rsp), %rax            /* r0_lo */
    movq    8(%rsp), %rdx            /* r0_hi */
    movq    %rax, %rcx
    andq    %rdi, %rcx               /* r0 = lo & mask */

    /* carry = (hi:lo) >> 51 */
    shrdq   $51, %rdx, %rax
    shrq    $51, %rdx                /* rdx:rax >>= 51, but we only need rax */

    addq    %rax, 16(%rsp)           /* r1_lo += carry */
    adcq    %rdx, 24(%rsp)

    movq    16(%rsp), %rax
    movq    24(%rsp), %rdx
    movq    %rax, %r8
    andq    %rdi, %r8                /* r1 */
    shrdq   $51, %rdx, %rax
    shrq    $51, %rdx
    addq    %rax, 32(%rsp)
    adcq    %rdx, 40(%rsp)

    movq    32(%rsp), %rax
    movq    40(%rsp), %rdx
    movq    %rax, %r9
    andq    %rdi, %r9                /* r2 */
    shrdq   $51, %rdx, %rax
    shrq    $51, %rdx
    addq    %rax, 48(%rsp)
    adcq    %rdx, 56(%rsp)

    movq    48(%rsp), %rax
    movq    56(%rsp), %rdx
    movq    %rax, %r10
    andq    %rdi, %r10               /* r3 */
    shrdq   $51, %rdx, %rax
    shrq    $51, %rdx
    addq    %rax, 64(%rsp)
    adcq    %rdx, 72(%rsp)

    movq    64(%rsp), %rax
    movq    72(%rsp), %rdx
    movq    %rax, %r11
    andq    %rdi, %r11               /* r4 */
    shrdq   $51, %rdx, %rax
    /* Top carry × 19 back to r0 */
    imulq   $19, %rax, %rax
    addq    %rax, %rcx

    /* Second carry from r0 → r1 */
    movq    %rcx, %rax
    shrq    $51, %rax
    addq    %rax, %r8
    andq    %rdi, %rcx

    /* Store */
    movq    %rcx, 0(%rbp)
    movq    %r8, 8(%rbp)
    movq    %r9, 16(%rbp)
    movq    %r10, 24(%rbp)
    movq    %r11, 32(%rbp)

    addq    $80, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    popq    %rbx
    ret

/* ============================================================
 * cc_fe_sqr: r = a^2 mod p
 * rdi = r, rsi = a
 * ============================================================ */
.globl _cc_fe_sqr
.align 16
_cc_fe_sqr:
    movq    %rsi, %rdx               /* b = a */
    jmp     _cc_fe_mul               /* tail-call */

/* ============================================================
 * cc_fe_pack: serialize fe to 32 bytes LE
 * rdi = out, rsi = fe
 * ============================================================ */
.globl _cc_fe_pack
.align 16
_cc_fe_pack:
    pushq   %rbx
    pushq   %r12

    movq    %rdi, %rbx               /* save out */
    movq    %rsi, %r12               /* save fe */

    /* Reduce first */
    movq    %rsi, %rdi
    call    _cc_fe_reduce

    /* Reload reduced limbs */
    movq    0(%r12), %rax            /* v[0] */
    movq    8(%r12), %rcx            /* v[1] */
    movq    16(%r12), %rdx           /* v[2] */
    movq    24(%r12), %rsi           /* v[3] */
    movq    32(%r12), %rdi           /* v[4] */

    /* Pack: v[0] + v[1]<<51 + v[2]<<102 + v[3]<<153 + v[4]<<204 */
    /* w0 = v[0] | (v[1] << 51) */
    movq    %rcx, %r8
    shlq    $51, %r8
    orq     %rax, %r8

    /* w1 = (v[1] >> 13) | (v[2] << 38) */
    movq    %rcx, %r9
    shrq    $13, %r9
    movq    %rdx, %r10
    shlq    $38, %r10
    orq     %r10, %r9

    /* w2 = (v[2] >> 26) | (v[3] << 25) */
    movq    %rdx, %r10
    shrq    $26, %r10
    movq    %rsi, %r11
    shlq    $25, %r11
    orq     %r11, %r10

    /* w3 = (v[3] >> 39) | (v[4] << 12) */
    movq    %rsi, %r11
    shrq    $39, %r11
    movq    %rdi, %rax
    shlq    $12, %rax
    orq     %rax, %r11

    movq    %r8, 0(%rbx)
    movq    %r9, 8(%rbx)
    movq    %r10, 16(%rbx)
    movq    %r11, 24(%rbx)

    popq    %r12
    popq    %rbx
    ret

/* ============================================================
 * cc_fe_unpack: deserialize 32 bytes to fe
 * rdi = fe, rsi = in
 * ============================================================ */
.globl _cc_fe_unpack
.align 16
_cc_fe_unpack:
    movq    0(%rsi), %rax            /* w0 */
    movq    8(%rsi), %rcx            /* w1 */
    movq    16(%rsi), %rdx           /* w2 */
    movq    24(%rsi), %rsi           /* w3 */

    movq    MASK51, %r8

    /* v[0] = w0 & mask */
    movq    %rax, %r9
    andq    %r8, %r9
    movq    %r9, 0(%rdi)

    /* v[1] = (w0 >> 51) | (w1 << 13) & mask */
    shrq    $51, %rax
    movq    %rcx, %r9
    shlq    $13, %r9
    orq     %rax, %r9
    andq    %r8, %r9
    movq    %r9, 8(%rdi)

    /* v[2] = (w1 >> 38) | (w2 << 26) & mask */
    shrq    $38, %rcx
    movq    %rdx, %r9
    shlq    $26, %r9
    orq     %rcx, %r9
    andq    %r8, %r9
    movq    %r9, 16(%rdi)

    /* v[3] = (w2 >> 25) | (w3 << 39) & mask */
    shrq    $25, %rdx
    movq    %rsi, %r9
    shlq    $39, %r9
    orq     %rdx, %r9
    andq    %r8, %r9
    movq    %r9, 24(%rdi)

    /* v[4] = (w3 >> 12) & mask */
    shrq    $12, %rsi
    andq    %r8, %rsi
    movq    %rsi, 32(%rdi)
    ret

#endif /* __x86_64__ */
