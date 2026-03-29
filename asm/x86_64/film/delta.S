/*
 * delta.S — x86_64 XOR-delta encode/decode
 *
 * Overrides weak C fallbacks in delta_fallback.c.
 * Unrolled scalar with good instruction scheduling.
 */

#ifdef __x86_64__

    .text

/* ──────────────────────────────────────────────────────────────
 * cf_delta_encode_row(uint32_t *row, size_t width)
 *
 * rdi = row, rsi = width
 * XOR-delta encode right-to-left: row[x] ^= row[x-1]
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_delta_encode_row
    .p2align 4
_cf_delta_encode_row:
    cmpq    $2, %rsi
    jb      .Lenc_done_x86

    leaq    -1(%rsi), %rcx             /* rcx = count = width - 1 */
    leaq    (%rdi,%rcx,4), %rdx        /* rdx = &row[width - 1] */

    /* unroll by 4 */
    cmpq    $4, %rcx
    jb      .Lenc_tail_x86

.Lenc_loop4_x86:
    movl    (%rdx), %eax               /* row[i] */
    movl    -4(%rdx), %r8d             /* row[i-1] */
    movl    -8(%rdx), %r9d             /* row[i-2] */
    movl    -12(%rdx), %r10d           /* row[i-3] */
    movl    -16(%rdx), %r11d           /* row[i-4] */

    xorl    %r8d, %eax                 /* row[i]   ^= row[i-1] */
    xorl    %r9d, %r8d                 /* row[i-1] ^= row[i-2] */
    xorl    %r10d, %r9d                /* row[i-2] ^= row[i-3] */
    xorl    %r11d, %r10d               /* row[i-3] ^= row[i-4] */

    movl    %eax, (%rdx)
    movl    %r8d, -4(%rdx)
    movl    %r9d, -8(%rdx)
    movl    %r10d, -12(%rdx)

    subq    $16, %rdx
    subq    $4, %rcx
    cmpq    $4, %rcx
    jae     .Lenc_loop4_x86

.Lenc_tail_x86:
    testq   %rcx, %rcx
    jz      .Lenc_done_x86
.Lenc_tail_loop_x86:
    movl    (%rdx), %eax
    xorl    -4(%rdx), %eax
    movl    %eax, (%rdx)
    subq    $4, %rdx
    decq    %rcx
    jnz     .Lenc_tail_loop_x86

.Lenc_done_x86:
    retq


/* ──────────────────────────────────────────────────────────────
 * cf_delta_decode_row(uint32_t *row, size_t width)
 *
 * rdi = row, rsi = width
 * XOR-delta decode left-to-right: row[x] ^= row[x-1]
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_delta_decode_row
    .p2align 4
_cf_delta_decode_row:
    cmpq    $2, %rsi
    jb      .Ldec_done_x86

    leaq    -1(%rsi), %rcx             /* rcx = count */
    leaq    4(%rdi), %rdx              /* rdx = &row[1] */
    movl    (%rdi), %eax               /* eax = running value */

    /* unroll by 4 */
    cmpq    $4, %rcx
    jb      .Ldec_tail_x86

.Ldec_loop4_x86:
    xorl    (%rdx), %eax
    movl    %eax, (%rdx)
    xorl    4(%rdx), %eax
    movl    %eax, 4(%rdx)
    xorl    8(%rdx), %eax
    movl    %eax, 8(%rdx)
    xorl    12(%rdx), %eax
    movl    %eax, 12(%rdx)

    addq    $16, %rdx
    subq    $4, %rcx
    cmpq    $4, %rcx
    jae     .Ldec_loop4_x86

.Ldec_tail_x86:
    testq   %rcx, %rcx
    jz      .Ldec_done_x86
.Ldec_tail_loop_x86:
    xorl    (%rdx), %eax
    movl    %eax, (%rdx)
    addq    $4, %rdx
    decq    %rcx
    jnz     .Ldec_tail_loop_x86

.Ldec_done_x86:
    retq

#endif /* __x86_64__ */
