/*
 * cp_find_match + cp_match_insert + cp_memcopy — x86_64
 *
 * Hash-chain match finder, 4-byte minimum, 64KB window.
 *
 * cp_match cp_find_match(
 *     const uint8_t *data,    // rdi
 *     size_t data_len,        // rsi
 *     size_t pos,             // rdx
 *     cp_match_ctx *ctx       // rcx
 * )
 * Returns cp_match in eax (packed: low 16 = offset, high 16 = length)
 *
 * void cp_match_insert(const uint8_t *data, size_t pos, cp_match_ctx *ctx)
 *   rdi = data, rsi = pos, rdx = ctx
 *
 * void cp_memcopy(uint8_t *dst, const uint8_t *src, size_t len)
 *   rdi = dst, rsi = src, rdx = len
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

/* cp_match_ctx layout (same as aarch64): */
#define CTX_HEAD        0
#define CTX_CHAIN       65536
#define CTX_CHAIN_LEN   196608

#define HASH_BITS       15
#define WINDOW_SIZE     65536
#define MIN_MATCH       4
#define MAX_MATCH       258

    .text

/* ---- cp_find_match ---- */
    .globl SYM(cp_find_match)
    .p2align 4

SYM(cp_find_match):
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdi, %r12          /* data */
    movq    %rsi, %r13          /* data_len */
    movq    %rdx, %r14          /* pos */
    movq    %rcx, %r15          /* ctx */

    /* best = {0, 0} */
    xorl    %ebx, %ebx          /* best_offset (low 16 of result) */
    xorl    %r11d, %r11d        /* best_length */

    /* if pos + MIN_MATCH > data_len, return {0,0} */
    leaq    MIN_MATCH(%r14), %rax
    cmpq    %r13, %rax
    ja      .Lxf_insert_ret

    /* hash = hash4(data + pos) */
    leaq    (%r12, %r14), %rdi
    movl    (%rdi), %eax
    imull   $0x9E3779B1, %eax
    shrl    $(32 - HASH_BITS), %eax     /* hash in eax */

    /* chain_pos = ctx->head[hash] */
    movswl  (%r15, %rax, 2), %ecx      /* signed int16 */

    /* chain_len = ctx->chain_len */
    movl    CTX_CHAIN_LEN(%r15), %r8d
    xorl    %r9d, %r9d          /* steps = 0 */

.Lxf_chain:
    testl   %ecx, %ecx
    js      .Lxf_insert_ret     /* chain_pos < 0 → done */
    cmpl    %r8d, %r9d
    jge     .Lxf_insert_ret

    /* candidate = (uint16_t)chain_pos */
    movzwl  %cx, %edx           /* candidate */

    /* dist = pos - candidate */
    cmpq    %rdx, %r14
    jbe     .Lxf_next

    movq    %r14, %rdi
    subq    %rdx, %rdi          /* dist */
    testq   %rdi, %rdi
    jz      .Lxf_next
    cmpq    $WINDOW_SIZE, %rdi
    ja      .Lxf_next

    /* compare bytes */
    leaq    (%r12, %r14), %rsi  /* a = data + pos */
    leaq    (%r12, %rdx), %r10  /* b = data + candidate */

    movq    %r13, %rax
    subq    %r14, %rax          /* max_len = data_len - pos */
    cmpq    $MAX_MATCH, %rax
    jbe     1f
    movq    $MAX_MATCH, %rax
1:
    xorq    %rcx, %rcx          /* len = 0 (clobbers chain_pos, save it) */
    /* we need chain_pos later — save candidate for chain traversal */
    pushq   %rdx                /* save candidate */

.Lxf_cmp:
    cmpq    %rax, %rcx
    jge     .Lxf_check
    movzbl  (%rsi, %rcx), %edx
    cmpb    %dl, (%r10, %rcx)
    jne     .Lxf_check
    incq    %rcx
    jmp     .Lxf_cmp

.Lxf_check:
    popq    %rdx                /* restore candidate */

    cmpq    $MIN_MATCH, %rcx
    jb      .Lxf_next2
    cmpl    %r11d, %ecx
    jle     .Lxf_next2

    movl    %edi, %ebx          /* best_offset = dist (edi still has dist) */
    movl    %ecx, %r11d         /* best_length = len */
    cmpl    $MAX_MATCH, %r11d
    jge     .Lxf_insert_ret

.Lxf_next2:
    /* chain_pos = ctx->chain[candidate % WINDOW_SIZE] */
    andl    $(WINDOW_SIZE - 1), %edx
    leaq    CTX_CHAIN(%r15), %rax
    movswl  (%rax, %rdx, 2), %ecx
    incl    %r9d
    jmp     .Lxf_chain

.Lxf_next:
    /* chain_pos = ctx->chain[candidate % WINDOW_SIZE] */
    movzwl  %cx, %edx
    andl    $(WINDOW_SIZE - 1), %edx
    leaq    CTX_CHAIN(%r15), %rax
    movswl  (%rax, %rdx, 2), %ecx
    incl    %r9d
    jmp     .Lxf_chain

.Lxf_insert_ret:
    /* insert pos into hash chain */
    leaq    MIN_MATCH(%r14), %rax
    cmpq    %r13, %rax
    ja      .Lxf_ret

    leaq    (%r12, %r14), %rdi
    movl    (%rdi), %eax
    imull   $0x9E3779B1, %eax
    shrl    $(32 - HASH_BITS), %eax

    /* ctx->chain[pos % WINDOW] = ctx->head[hash] */
    movl    %r14d, %edx
    andl    $(WINDOW_SIZE - 1), %edx
    movswl  (%r15, %rax, 2), %ecx      /* old head */
    leaq    CTX_CHAIN(%r15), %rdi
    movw    %cx, (%rdi, %rdx, 2)

    /* ctx->head[hash] = pos % WINDOW */
    movw    %dx, (%r15, %rax, 2)

.Lxf_ret:
    /* pack result: offset in low 16, length in high 16 */
    andl    $0xFFFF, %ebx
    shll    $16, %r11d
    orl     %r11d, %ebx
    movl    %ebx, %eax

    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

/* ---- cp_match_insert ---- */
    .globl SYM(cp_match_insert)
    .p2align 4

SYM(cp_match_insert):
    /* rdi = data, rsi = pos, rdx = ctx */
    leaq    (%rdi, %rsi), %rax
    movl    (%rax), %eax
    imull   $0x9E3779B1, %eax
    shrl    $(32 - HASH_BITS), %eax

    movl    %esi, %ecx
    andl    $(WINDOW_SIZE - 1), %ecx

    /* ctx->chain[pos%WIN] = ctx->head[hash] */
    movswl  (%rdx, %rax, 2), %r8d
    leaq    CTX_CHAIN(%rdx), %r9
    movw    %r8w, (%r9, %rcx, 2)

    /* ctx->head[hash] = pos % WIN */
    movw    %cx, (%rdx, %rax, 2)
    ret

/* ---- cp_memcopy ---- */
    .globl SYM(cp_memcopy)
    .p2align 4

SYM(cp_memcopy):
    /* rdi = dst, rsi = src, rdx = len */
    testq   %rdx, %rdx
    jz      .Lmc_ret
.Lmc_loop:
    movb    (%rsi), %al
    movb    %al, (%rdi)
    incq    %rsi
    incq    %rdi
    decq    %rdx
    jnz     .Lmc_loop
.Lmc_ret:
    ret
