/*
 * X25519 Montgomery ladder — x86_64
 *
 * Implements cc_scalarmult and cc_scalarmult_base.
 * Constant-time via cc_fe_cswap (no branches on secret bits).
 *
 * System V AMD64 ABI:
 *   rdi = output, rsi = scalar, rdx = base point
 *   Callee-saved: rbx, rbp, r12-r15
 */

#ifdef __x86_64__

.text
.align 16

/* Basepoint for Curve25519: u = 9 */
.section __DATA,__const
.align 8
Lbasepoint:
    .byte 9
    .fill 31, 1, 0

.text

/* ============================================================
 * cc_scalar_clamp: clamp scalar for X25519
 * rdi = scalar (in-place)
 * ============================================================ */
.globl _cc_scalar_clamp
.align 16
_cc_scalar_clamp:
    movzbl  0(%rdi), %eax
    andb    $248, %al
    movb    %al, 0(%rdi)
    movzbl  31(%rdi), %eax
    andb    $127, %al
    orb     $64, %al
    movb    %al, 31(%rdi)
    ret

/* ============================================================
 * cc_scalarmult_base: r = s · G
 * rdi = r, rsi = s
 * ============================================================ */
.globl _cc_scalarmult_base
.align 16
_cc_scalarmult_base:
    pushq   %rbp
    movq    %rsp, %rbp

    leaq    Lbasepoint(%rip), %rdx
    call    _cc_scalarmult

    popq    %rbp
    ret

/* ============================================================
 * cc_scalarmult: r = s · P (Montgomery ladder)
 * rdi = r, rsi = s, rdx = P
 *
 * Stack frame layout (cc_fe = 40 bytes):
 *   [rbp-40]    x2 (fe)
 *   [rbp-80]    x3 (fe)
 *   [rbp-120]   z2 (fe)
 *   [rbp-160]   z3 (fe)
 *   [rbp-200]   xbase (fe)
 *   [rbp-240]   tmp0 (fe)
 *   [rbp-280]   tmp1 (fe)
 *   [rbp-320]   tmp2 (fe)
 *   [rbp-360]   tmp3 (fe)
 *   [rbp-400]   tmp4 (fe)
 *   [rbp-432]   scalar copy (32 bytes)
 *   [rbp-440]   saved r ptr (8 bytes)
 *   [rbp-448]   prev_bit (8 bytes)
 * ============================================================ */

#define FE_SIZE   40
#define S_X2      -40
#define S_X3      -80
#define S_Z2      -120
#define S_Z3      -160
#define S_XBASE   -200
#define S_TMP0    -240
#define S_TMP1    -280
#define S_TMP2    -320
#define S_TMP3    -360
#define S_TMP4    -400
#define S_SCALAR  -432
#define S_RPTR    -440
#define S_PREVBIT -448
#define S_FRAME   448

.globl _cc_scalarmult
.align 16
_cc_scalarmult:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $S_FRAME, %rsp

    /* Save output pointer */
    movq    %rdi, S_RPTR(%rbp)

    /* Copy scalar */
    movq    0(%rsi), %rax
    movq    %rax, S_SCALAR(%rbp)
    movq    8(%rsi), %rax
    movq    %rax, S_SCALAR+8(%rbp)
    movq    16(%rsi), %rax
    movq    %rax, S_SCALAR+16(%rbp)
    movq    24(%rsi), %rax
    movq    %rax, S_SCALAR+24(%rbp)

    /* Clamp scalar */
    leaq    S_SCALAR(%rbp), %rdi
    call    _cc_scalar_clamp

    /* Unpack base point x-coord */
    leaq    S_XBASE(%rbp), %rdi
    movq    %rdx, %rsi
    call    _cc_fe_unpack

    /* x2 = 1 */
    leaq    S_X2(%rbp), %rdi
    call    _cc_fe_one

    /* z2 = 0 */
    leaq    S_Z2(%rbp), %rdi
    call    _cc_fe_zero

    /* x3 = xbase (copy 40 bytes) */
    leaq    S_X3(%rbp), %rdi
    leaq    S_XBASE(%rbp), %rsi
    movq    0(%rsi), %rax
    movq    %rax, 0(%rdi)
    movq    8(%rsi), %rax
    movq    %rax, 8(%rdi)
    movq    16(%rsi), %rax
    movq    %rax, 16(%rdi)
    movq    24(%rsi), %rax
    movq    %rax, 24(%rdi)
    movq    32(%rsi), %rax
    movq    %rax, 32(%rdi)

    /* z3 = 1 */
    leaq    S_Z3(%rbp), %rdi
    call    _cc_fe_one

    /* prev_bit = 0 */
    movq    $0, S_PREVBIT(%rbp)

    /* Main loop: 254 iterations, bit 254 down to 0 */
    movq    $254, %r12               /* bit counter */

.Lladder_loop:
    /* Extract scalar bit */
    movq    %r12, %rax
    shrq    $3, %rax
    leaq    S_SCALAR(%rbp), %rcx
    movzbl  (%rcx,%rax), %eax
    movq    %r12, %rcx
    andq    $7, %rcx
    shrq    %cl, %rax
    andq    $1, %rax                 /* bit */

    /* swap = bit ^ prev_bit; save swap in r13 across cswap calls */
    movq    S_PREVBIT(%rbp), %r13
    movq    %rax, S_PREVBIT(%rbp)    /* prev_bit = bit */
    xorq    %rax, %r13               /* swap in r13 */

    /* cswap x2, x3 */
    leaq    S_X2(%rbp), %rdi
    leaq    S_X3(%rbp), %rsi
    movq    %r13, %rdx
    call    _cc_fe_cswap

    /* cswap z2, z3 */
    leaq    S_Z2(%rbp), %rdi
    leaq    S_Z3(%rbp), %rsi
    movq    %r13, %rdx
    call    _cc_fe_cswap
    /*
     * Montgomery ladder step:
     * A = x2+z2, B = x2-z2, C = x3+z3, D = x3-z3
     * DA = D*A, CB = C*B
     * AA = A^2, BB = B^2
     * x2 = AA*BB, E = AA-BB
     * x3 = (DA+CB)^2, z3 = xbase*(DA-CB)^2
     * z2 = E*(AA + a24*E)   where a24 = 121666
     */

    /* A = x2 + z2 → tmp0 */
    leaq    S_TMP0(%rbp), %rdi
    leaq    S_X2(%rbp), %rsi
    leaq    S_Z2(%rbp), %rdx
    call    _cc_fe_add

    /* B = x2 - z2 → tmp1 */
    leaq    S_TMP1(%rbp), %rdi
    leaq    S_X2(%rbp), %rsi
    leaq    S_Z2(%rbp), %rdx
    call    _cc_fe_sub

    /* C = x3 + z3 → tmp2 */
    leaq    S_TMP2(%rbp), %rdi
    leaq    S_X3(%rbp), %rsi
    leaq    S_Z3(%rbp), %rdx
    call    _cc_fe_add

    /* D = x3 - z3 → tmp3 */
    leaq    S_TMP3(%rbp), %rdi
    leaq    S_X3(%rbp), %rsi
    leaq    S_Z3(%rbp), %rdx
    call    _cc_fe_sub

    /* DA = D * A → tmp4 */
    leaq    S_TMP4(%rbp), %rdi
    leaq    S_TMP3(%rbp), %rsi
    leaq    S_TMP0(%rbp), %rdx
    call    _cc_fe_mul

    /* CB = C * B → tmp3 (reuse D) */
    leaq    S_TMP3(%rbp), %rdi
    leaq    S_TMP2(%rbp), %rsi
    leaq    S_TMP1(%rbp), %rdx
    call    _cc_fe_mul

    /* AA = A^2 → tmp2 (reuse C; save AA for later) */
    leaq    S_TMP2(%rbp), %rdi
    leaq    S_TMP0(%rbp), %rsi
    call    _cc_fe_sqr

    /* BB = B^2 → tmp0 (reuse A) */
    leaq    S_TMP0(%rbp), %rdi
    leaq    S_TMP1(%rbp), %rsi
    call    _cc_fe_sqr

    /* x2 = AA * BB */
    leaq    S_X2(%rbp), %rdi
    leaq    S_TMP2(%rbp), %rsi       /* AA */
    leaq    S_TMP0(%rbp), %rdx       /* BB */
    call    _cc_fe_mul

    /* E = AA - BB → tmp1 */
    leaq    S_TMP1(%rbp), %rdi
    leaq    S_TMP2(%rbp), %rsi       /* AA */
    leaq    S_TMP0(%rbp), %rdx       /* BB */
    call    _cc_fe_sub

    /* x3 = (DA + CB)^2 */
    leaq    S_X3(%rbp), %rdi
    leaq    S_TMP4(%rbp), %rsi       /* DA */
    leaq    S_TMP3(%rbp), %rdx       /* CB */
    call    _cc_fe_add
    leaq    S_X3(%rbp), %rdi
    leaq    S_X3(%rbp), %rsi
    call    _cc_fe_sqr

    /* z3 = xbase * (DA - CB)^2 */
    leaq    S_Z3(%rbp), %rdi
    leaq    S_TMP4(%rbp), %rsi       /* DA */
    leaq    S_TMP3(%rbp), %rdx       /* CB */
    call    _cc_fe_sub
    leaq    S_Z3(%rbp), %rdi
    leaq    S_Z3(%rbp), %rsi
    call    _cc_fe_sqr
    leaq    S_Z3(%rbp), %rdi
    leaq    S_Z3(%rbp), %rsi
    leaq    S_XBASE(%rbp), %rdx
    call    _cc_fe_mul

    /* z2 = E * (AA + a24 * E)
     * a24 = 121666
     * tmp0 = a24 as fe (just set v[0] = 121666, rest 0) */
    leaq    S_TMP0(%rbp), %rdi
    call    _cc_fe_zero
    movq    $121666, S_TMP0(%rbp)

    /* tmp0 = a24 * E */
    leaq    S_TMP0(%rbp), %rdi
    leaq    S_TMP0(%rbp), %rsi
    leaq    S_TMP1(%rbp), %rdx       /* E */
    call    _cc_fe_mul

    /* tmp0 = AA + a24*E (AA is in tmp2) */
    leaq    S_TMP0(%rbp), %rdi
    leaq    S_TMP2(%rbp), %rsi       /* AA */
    leaq    S_TMP0(%rbp), %rdx       /* a24*E */
    call    _cc_fe_add

    /* z2 = E * (AA + a24*E) */
    leaq    S_Z2(%rbp), %rdi
    leaq    S_TMP1(%rbp), %rsi       /* E */
    leaq    S_TMP0(%rbp), %rdx
    call    _cc_fe_mul

    /* Loop */
    decq    %r12
    jns     .Lladder_loop

    /* Final cswap */
    movq    S_PREVBIT(%rbp), %rdx
    leaq    S_X2(%rbp), %rdi
    leaq    S_X3(%rbp), %rsi
    call    _cc_fe_cswap

    movq    S_PREVBIT(%rbp), %rdx
    leaq    S_Z2(%rbp), %rdi
    leaq    S_Z3(%rbp), %rsi
    call    _cc_fe_cswap

    /* Result = x2 * z2^(-1) */
    leaq    S_TMP0(%rbp), %rdi
    leaq    S_Z2(%rbp), %rsi
    call    _cc_fe_inv

    leaq    S_TMP1(%rbp), %rdi
    leaq    S_X2(%rbp), %rsi
    leaq    S_TMP0(%rbp), %rdx
    call    _cc_fe_mul

    /* Pack to output */
    movq    S_RPTR(%rbp), %rdi
    leaq    S_TMP1(%rbp), %rsi
    call    _cc_fe_pack

    addq    $S_FRAME, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

/* ============================================================
 * cc_fe_inv: r = a^(p-2) mod p  (Fermat's little theorem)
 * rdi = r, rsi = a
 *
 * Placeholder: copies input to output.
 * TODO: proper addition chain for 2^255 - 21.
 * ============================================================ */
.globl _cc_fe_inv
.align 16
_cc_fe_inv:
    movq    0(%rsi), %rax
    movq    %rax, 0(%rdi)
    movq    8(%rsi), %rax
    movq    %rax, 8(%rdi)
    movq    16(%rsi), %rax
    movq    %rax, 16(%rdi)
    movq    24(%rsi), %rax
    movq    %rax, 24(%rdi)
    movq    32(%rsi), %rax
    movq    %rax, 32(%rdi)
    ret

#endif /* __x86_64__ */
