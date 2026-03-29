/*
 * CuteHash compression — x86_64
 *
 * Custom ARX compression for the cascade/fuse system.
 * 7 rounds of column + diagonal G mixing.
 * G function uses BLAKE3-inspired rotation constants (16, 12, 8, 7).
 *
 * void cc_cute_compress(
 *     const uint8_t ns[32],     rdi   namespace
 *     const uint8_t a[32],      rsi   input A
 *     const uint8_t b[32],      rdx   input B
 *     uint64_t counter,         rcx   counter
 *     uint32_t mode,            r8d   mode byte
 *     uint8_t out[32]           r9    output
 * )
 *
 * State matrix (4×4 uint32):
 *   v0  v1  v2  v3     ← ns[0..3]
 *   v4  v5  v6  v7     ← ns[4..7]
 *   v8  v9  v10 v11    ← ctr_lo, ctr_hi, mode, 0xCC00CC00
 *   v12 v13 v14 v15    ← a[0..3] ^ b[0..3]
 *
 * Message = a ‖ b as 16 × uint32 LE.
 */

#ifdef __x86_64__

.text

/* Message permutation table */
.section __DATA,__const
.align 4
Lcute_perm_x86:
    .byte 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8

.text

/*
 * Macro: G function (quarter-round) using stack-based state
 *
 * G(off_a, off_b, off_c, off_d, mx, my):
 *   state[a] += state[b] + mx;  state[d] = ror32(state[d]^state[a], 16)
 *   state[c] += state[d];       state[b] = ror32(state[b]^state[c], 12)
 *   state[a] += state[b] + my;  state[d] = ror32(state[d]^state[a], 8)
 *   state[c] += state[d];       state[b] = ror32(state[b]^state[c], 7)
 *
 * State is at STATE_BASE(%rsp), each uint32 at offset i*4.
 * mx in %r10d, my in %r11d. Clobbers %eax, %ecx, %edx, %r10d, %r11d.
 */
#define STATE_BASE 0

/* ============================================================
 * cc_cute_compress
 * ============================================================ */
.globl _cc_cute_compress
.align 16
_cc_cute_compress:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %r9, %r15                /* save out pointer */
    movq    %rcx, %r14               /* save counter */
    movl    %r8d, %r13d              /* save mode */

    /*
     * Stack layout:
     *   [rsp+0]    state: 16 × uint32 = 64 bytes
     *   [rsp+64]   message: 16 × uint32 = 64 bytes
     *   [rsp+128]  feed-forward: 8 × uint32 = 32 bytes
     *   [rsp+160]  perm indices: 16 bytes
     *   Total: 176 bytes (round to 176, 16-byte aligned → 176)
     */
    subq    $176, %rsp

    /* ---- Build state matrix ---- */

    /* Row 0-1: namespace (8 × uint32 LE) */
    movl    0(%rdi), %eax
    movl    %eax, 0(%rsp)            /* v0 = ns[0] */
    movl    4(%rdi), %eax
    movl    %eax, 4(%rsp)            /* v1 */
    movl    8(%rdi), %eax
    movl    %eax, 8(%rsp)            /* v2 */
    movl    12(%rdi), %eax
    movl    %eax, 12(%rsp)           /* v3 */
    movl    16(%rdi), %eax
    movl    %eax, 16(%rsp)           /* v4 */
    movl    20(%rdi), %eax
    movl    %eax, 20(%rsp)           /* v5 */
    movl    24(%rdi), %eax
    movl    %eax, 24(%rsp)           /* v6 */
    movl    28(%rdi), %eax
    movl    %eax, 28(%rsp)           /* v7 */

    /* Row 2: counter_lo, counter_hi, mode, sentinel */
    movl    %r14d, 32(%rsp)          /* v8 = counter_lo */
    shrq    $32, %r14
    movl    %r14d, 36(%rsp)          /* v9 = counter_hi */
    movl    %r13d, 40(%rsp)          /* v10 = mode */
    movl    $0xCC00CC00, 44(%rsp)    /* v11 = sentinel */

    /* Row 3: a[0..3] ^ b[0..3] */
    movl    0(%rsi), %eax
    xorl    0(%rdx), %eax
    movl    %eax, 48(%rsp)           /* v12 */
    movl    4(%rsi), %eax
    xorl    4(%rdx), %eax
    movl    %eax, 52(%rsp)           /* v13 */
    movl    8(%rsi), %eax
    xorl    8(%rdx), %eax
    movl    %eax, 56(%rsp)           /* v14 */
    movl    12(%rsi), %eax
    xorl    12(%rdx), %eax
    movl    %eax, 60(%rsp)           /* v15 */

    /* Save initial state[0..7] for feed-forward */
    .irp i, 0, 4, 8, 12, 16, 20, 24, 28
    movl    \i(%rsp), %eax
    movl    %eax, 128+\i(%rsp)
    .endr

    /* ---- Load message (a ‖ b as 16 × uint32) ---- */
    .irp i, 0, 4, 8, 12, 16, 20, 24, 28
    movl    \i(%rsi), %eax
    movl    %eax, 64+\i(%rsp)        /* m[0..7] = a */
    .endr
    .irp i, 0, 4, 8, 12, 16, 20, 24, 28
    movl    \i(%rdx), %eax
    movl    %eax, 96+\i(%rsp)        /* m[8..15] = b */
    .endr

    /* Initialize permutation index array (identity) */
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    movb    $\i, 160+\i(%rsp)
    .endr

    /* Load permutation table address */
    leaq    Lcute_perm_x86(%rip), %r12

    /* ---- 7 rounds ---- */
    movl    $7, %ebx

.Lcute_round:
    /*
     * Inline G function: operates on state at (%rsp).
     * For each G call, load the two message words via the permuted
     * index array at 160(%rsp), using the message at 64(%rsp).
     */

    /* Helper macro: load message word by permuted index */
    /* idx_offset = offset in perm array, result in target reg */

/* G(va, vb, vc, vd, s_idx0, s_idx1)
 * va..vd are byte offsets into state, s_idx0/s_idx1 are byte offsets in perm array */
.macro DO_G va, vb, vc, vd, si0, si1
    /* Load mx = message[perm[si0]] */
    movzbl  160+\si0(%rsp), %eax
    movl    64(%rsp,%rax,4), %r10d   /* mx */
    /* Load my = message[perm[si1]] */
    movzbl  160+\si1(%rsp), %eax
    movl    64(%rsp,%rax,4), %r11d   /* my */

    /* a += b + mx */
    movl    \va(%rsp), %eax          /* a */
    addl    \vb(%rsp), %eax          /* a + b */
    addl    %r10d, %eax              /* a + b + mx */
    movl    %eax, \va(%rsp)
    /* d = ror32(d ^ a, 16) */
    movl    \vd(%rsp), %ecx
    xorl    %eax, %ecx
    rorl    $16, %ecx
    movl    %ecx, \vd(%rsp)
    /* c += d */
    movl    \vc(%rsp), %edx
    addl    %ecx, %edx
    movl    %edx, \vc(%rsp)
    /* b = ror32(b ^ c, 12) */
    movl    \vb(%rsp), %ecx
    xorl    %edx, %ecx
    rorl    $12, %ecx
    movl    %ecx, \vb(%rsp)

    /* a += b + my */
    addl    %ecx, %eax
    addl    %r11d, %eax
    movl    %eax, \va(%rsp)
    /* d = ror32(d ^ a, 8) */
    movl    \vd(%rsp), %ecx
    xorl    %eax, %ecx
    rorl    $8, %ecx
    movl    %ecx, \vd(%rsp)
    /* c += d */
    movl    \vc(%rsp), %edx
    addl    %ecx, %edx
    movl    %edx, \vc(%rsp)
    /* b = ror32(b ^ c, 7) */
    movl    \vb(%rsp), %ecx
    xorl    %edx, %ecx
    rorl    $7, %ecx
    movl    %ecx, \vb(%rsp)
.endm

    /* Column rounds: G(v0,v4,v8,v12), G(v1,v5,v9,v13), G(v2,v6,v10,v14), G(v3,v7,v11,v15) */
    /* state offsets: v0=0, v1=4, ..., v15=60 */
    DO_G 0, 16, 32, 48,  0, 1        /* G0: v0,v4,v8,v12, s[0],s[1] */
    DO_G 4, 20, 36, 52,  2, 3        /* G1: v1,v5,v9,v13, s[2],s[3] */
    DO_G 8, 24, 40, 56,  4, 5        /* G2: v2,v6,v10,v14, s[4],s[5] */
    DO_G 12, 28, 44, 60, 6, 7        /* G3: v3,v7,v11,v15, s[6],s[7] */

    /* Diagonal rounds: G(v0,v5,v10,v15), G(v1,v6,v11,v12), G(v2,v7,v8,v13), G(v3,v4,v9,v14) */
    DO_G 0, 20, 40, 60,  8, 9        /* G4: v0,v5,v10,v15, s[8],s[9] */
    DO_G 4, 24, 44, 48,  10, 11      /* G5: v1,v6,v11,v12, s[10],s[11] */
    DO_G 8, 28, 32, 52,  12, 13      /* G6: v2,v7,v8,v13, s[12],s[13] */
    DO_G 12, 16, 36, 56, 14, 15      /* G7: v3,v4,v9,v14, s[14],s[15] */

.purgem DO_G

    /* ---- Apply message permutation to indices ---- */
    .irp i, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    movzbl  160+\i(%rsp), %eax
    movzbl  (%r12,%rax), %eax
    movb    %al, 160+\i(%rsp)
    .endr

    decl    %ebx
    jnz     .Lcute_round

    /* ---- Feed-forward XOR ---- */
    /* out[i] = state[i] ^ state[i+8] ^ init_state[i]  for i=0..7 */
    .irp i, 0, 4, 8, 12, 16, 20, 24, 28
    movl    \i(%rsp), %eax           /* final state[i] */
    xorl    32+\i(%rsp), %eax        /* ^ state[i+8] */
    xorl    128+\i(%rsp), %eax       /* ^ init_state[i] */
    movl    %eax, \i(%r15)           /* store to output */
    .endr

    addq    $176, %rsp

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

/* ============================================================
 * cc_cute_namespace: derive namespace from context string
 *
 * void cc_cute_namespace(uint8_t ns[32], const char *ctx, size_t len)
 *   rdi = ns output
 *   rsi = context string
 *   rdx = context length
 * ============================================================ */
.globl _cc_cute_namespace
.align 16
_cc_cute_namespace:
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12

    movq    %rdi, %rbx               /* save ns output */
    movq    %rsi, %r12               /* save ctx */
    movq    %rdx, %r14               /* save len */

    /* Allocate: 32 (zero ns) + 32 (padded A) + 32 (padded B) = 96 */
    subq    $96, %rsp

    /* Zero all temp buffers */
    xorq    %rax, %rax
    .irp off, 0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88
    movq    %rax, \off(%rsp)
    .endr

    /* Copy context into A (at rsp+32, up to 32 bytes) */
    movq    %r14, %rcx
    cmpq    $32, %rcx
    jbe     1f
    movq    $32, %rcx
1:
    testq   %rcx, %rcx
    jz      2f
    leaq    32(%rsp), %rdi
    movq    %r12, %rsi
    movq    %rcx, %rdx
    /* Byte copy loop */
    xorq    %rax, %rax
.Lns_copy_a:
    movzbl  (%rsi,%rax), %ecx
    movb    %cl, (%rdi,%rax)
    incq    %rax
    cmpq    %rdx, %rax
    jb      .Lns_copy_a

2:
    /* Copy remainder into B (at rsp+64, if len > 32) */
    cmpq    $32, %r14
    jbe     3f
    movq    %r14, %rcx
    subq    $32, %rcx
    cmpq    $32, %rcx
    jbe     2f
    movq    $32, %rcx
2:
    leaq    64(%rsp), %rdi
    leaq    32(%r12), %rsi
    movq    %rcx, %rdx
    xorq    %rax, %rax
.Lns_copy_b:
    movzbl  (%rsi,%rax), %ecx
    movb    %cl, (%rdi,%rax)
    incq    %rax
    cmpq    %rdx, %rax
    jb      .Lns_copy_b

3:
    /* Call cc_cute_compress(zero_ns, padded_a, padded_b, 0, 0x00, ns_out) */
    leaq    0(%rsp), %rdi            /* ns = zeros */
    leaq    32(%rsp), %rsi           /* a */
    leaq    64(%rsp), %rdx           /* b */
    xorq    %rcx, %rcx               /* counter = 0 */
    xorl    %r8d, %r8d               /* mode = 0 */
    movq    %rbx, %r9                /* out = ns output */
    call    _cc_cute_compress

    addq    $96, %rsp
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

#endif /* __x86_64__ */
