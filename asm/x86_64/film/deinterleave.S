/*
 * deinterleave.S — x86_64 SSE2 BIP ↔ BSQ conversion
 *
 * Overrides weak C fallbacks in deinterleave_fallback.c.
 * Uses unrolled scalar with SSE2 stores for the output plane.
 */

#ifdef __x86_64__

    .text

/* ──────────────────────────────────────────────────────────────
 * cf_deinterleave_band(const float *bip, float *plane,
 *                      size_t npixels, int num_bands, int band)
 *
 * rdi = bip, rsi = plane, rdx = npixels, ecx = num_bands, r8d = band
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_deinterleave_band
    .p2align 4
_cf_deinterleave_band:
    testq   %rdx, %rdx
    jz      .Ldeint_done_x86

    /* offset to first sample of this band */
    movslq  %r8d, %r8
    leaq    (%rdi,%r8,4), %rdi         /* bip += band */
    movslq  %ecx, %r9
    shlq    $2, %r9                    /* r9 = stride = num_bands * 4 */

    /* 4-pixel unroll with stride gather */
    cmpq    $4, %rdx
    jb      .Ldeint_tail_x86

    movq    %r9, %r10
    leaq    (%r9,%r9), %r11            /* 2 * stride */
    leaq    (%r11,%r9), %rax           /* 3 * stride */

.Ldeint_loop4_x86:
    movss   (%rdi), %xmm0
    movss   (%rdi,%r10), %xmm1
    movss   (%rdi,%r11), %xmm2
    movss   (%rdi,%rax), %xmm3

    /* combine into xmm0 */
    unpcklps %xmm1, %xmm0             /* [s0, s1, ?, ?] */
    unpcklps %xmm3, %xmm2             /* [s2, s3, ?, ?] */
    movlhps  %xmm2, %xmm0             /* [s0, s1, s2, s3] */

    movups  %xmm0, (%rsi)

    leaq    (%rdi,%r9,4), %rdi         /* advance by 4 * stride */
    addq    $16, %rsi
    subq    $4, %rdx
    cmpq    $4, %rdx
    jae     .Ldeint_loop4_x86

.Ldeint_tail_x86:
    testq   %rdx, %rdx
    jz      .Ldeint_done_x86
.Ldeint_tail_loop_x86:
    movl    (%rdi), %eax
    movl    %eax, (%rsi)
    addq    %r9, %rdi
    addq    $4, %rsi
    decq    %rdx
    jnz     .Ldeint_tail_loop_x86

.Ldeint_done_x86:
    retq


/* ──────────────────────────────────────────────────────────────
 * cf_interleave_band(float *bip, const float *plane,
 *                    size_t npixels, int num_bands, int band)
 *
 * rdi = bip, rsi = plane, rdx = npixels, ecx = num_bands, r8d = band
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_interleave_band
    .p2align 4
_cf_interleave_band:
    testq   %rdx, %rdx
    jz      .Lint_done_x86

    /* offset to first sample of this band */
    movslq  %r8d, %r8
    leaq    (%rdi,%r8,4), %rdi
    movslq  %ecx, %r9
    shlq    $2, %r9                    /* stride */

    /* 4-pixel unroll: load 4 contiguous, scatter-store */
    cmpq    $4, %rdx
    jb      .Lint_tail_x86

    movq    %r9, %r10
    leaq    (%r9,%r9), %r11
    leaq    (%r11,%r9), %rax

.Lint_loop4_x86:
    movups  (%rsi), %xmm0             /* [s0, s1, s2, s3] */

    movss   %xmm0, (%rdi)
    shufps  $0x55, %xmm0, %xmm0       /* broadcast s1 — actually we need to extract */

    /* reload for individual stores */
    movl    (%rsi), %ecx
    movl    %ecx, (%rdi)
    movl    4(%rsi), %ecx
    movl    %ecx, (%rdi,%r10)
    movl    8(%rsi), %ecx
    movl    %ecx, (%rdi,%r11)
    movl    12(%rsi), %ecx
    movl    %ecx, (%rdi,%rax)

    leaq    (%rdi,%r9,4), %rdi
    addq    $16, %rsi
    subq    $4, %rdx
    cmpq    $4, %rdx
    jae     .Lint_loop4_x86

.Lint_tail_x86:
    testq   %rdx, %rdx
    jz      .Lint_done_x86
.Lint_tail_loop_x86:
    movl    (%rsi), %eax
    movl    %eax, (%rdi)
    addq    %r9, %rdi
    addq    $4, %rsi
    decq    %rdx
    jnz     .Lint_tail_loop_x86

.Lint_done_x86:
    retq

#endif /* __x86_64__ */
