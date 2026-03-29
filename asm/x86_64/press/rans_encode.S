/*
 * cp_rans_encode — x86_64 rANS encoder
 *
 * 4-way interleaved rANS with 12-bit frequency scale.
 *
 * System V AMD64 ABI:
 *   rdi = cp_rans_state *state
 *   rsi = const uint8_t *symbols
 *   rdx = size_t n_symbols
 *   rcx = const cp_rans_sym *sym_table
 *   r8  = uint8_t *out
 *   r9  = size_t out_cap
 * Returns: rax = bytes written
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

    .text
    .globl SYM(cp_rans_encode)
    .p2align 4

SYM(cp_rans_encode):
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $8, %rsp            /* align + local: -48(%rbp) = end ptr */

    /* save args to callee-saved regs */
    movq    %rdi, %r12          /* state */
    movq    %rsi, %r13          /* symbols */
    movq    %rdx, %r14          /* n_symbols */
    movq    %rcx, %r15          /* sym_table */
    movq    %r8,  %rbx          /* out */

    /* compute and save end = out + out_cap */
    leaq    (%rbx, %r9), %rax
    movq    %rax, -48(%rbp)     /* save end pointer */

    testq   %r14, %r14
    jz      .Lxe_zero

    /* initialize 4 states to RANS_L = 1 << 23 */
    movl    $(1 << 23), %eax
    movl    %eax, (%r12)
    movl    %eax, 4(%r12)
    movl    %eax, 8(%r12)
    movl    %eax, 12(%r12)

    /* r11 = ptr = end of buffer (write backwards) */
    movq    -48(%rbp), %r11

    /* r10 = i = n_symbols */
    movq    %r14, %r10

.Lxe_loop:
    testq   %r10, %r10
    jz      .Lxe_flush

    decq    %r10

    /* stream = i & 3 */
    movl    %r10d, %ecx
    andl    $3, %ecx

    /* load state[stream] */
    movl    (%r12, %rcx, 4), %eax

    /* load symbol */
    movzbl  (%r13, %r10), %edx

    /* sym_table[sym]: freq at +0, cumfreq at +2 (each uint16) */
    movzwl  (%r15, %rdx, 4), %edi      /* freq */
    movzwl  2(%r15, %rdx, 4), %esi     /* cumfreq */

    /* renormalize: upper = freq << 19 (8-bit renorm) */
    movl    %edi, %r8d
    shll    $19, %r8d

.Lxe_renorm:
    cmpl    %r8d, %eax
    jb      .Lxe_put

    /* flush 8 bits: *--ptr = state & 0xFF; state >>= 8 */
    decq    %r11
    movb    %al, (%r11)
    shrl    $8, %eax
    jmp     .Lxe_renorm

.Lxe_put:
    /* encode: state = (state / freq) << 12 + (state % freq) + cumfreq */
    xorl    %edx, %edx
    divl    %edi                /* eax = quot, edx = rem */
    shll    $12, %eax
    addl    %edx, %eax
    addl    %esi, %eax

    movl    %eax, (%r12, %rcx, 4)
    jmp     .Lxe_loop

.Lxe_flush:
    /* flush 4 states big-endian */
    movl    $3, %ecx
.Lxe_flush_loop:
    movl    (%r12, %rcx, 4), %eax
    subq    $4, %r11

    movl    %eax, %edx
    shrl    $24, %edx
    movb    %dl, (%r11)

    movl    %eax, %edx
    shrl    $16, %edx
    movb    %dl, 1(%r11)

    movl    %eax, %edx
    shrl    $8, %edx
    movb    %dl, 2(%r11)

    movb    %al, 3(%r11)

    testl   %ecx, %ecx
    jz      .Lxe_move
    decl    %ecx
    jmp     .Lxe_flush_loop

.Lxe_move:
    /* encoded_len = end - ptr = -48(%rbp) - r11 */
    movq    -48(%rbp), %rax
    subq    %r11, %rax          /* rax = encoded_len */
    movq    %rax, %rcx          /* save len */

    /* memmove(out, ptr, len) — src > dst, so forward copy is safe */
    movq    %rbx, %rdi          /* dst = out */
    movq    %r11, %rsi          /* src = ptr */
    testq   %rcx, %rcx
    jz      .Lxe_done

.Lxe_copy:
    movb    (%rsi), %al
    movb    %al, (%rdi)
    incq    %rsi
    incq    %rdi
    decq    %rcx
    jnz     .Lxe_copy

.Lxe_done:
    /* restore encoded_len to rax */
    movq    -48(%rbp), %rax
    subq    %r11, %rax

    addq    $8, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

.Lxe_zero:
    xorl    %eax, %eax
    addq    $8, %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
