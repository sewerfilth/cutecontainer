/*
 * cp_rans_decode — x86_64 rANS decoder
 *
 * System V AMD64 ABI:
 *   rdi = cp_rans_state *state
 *   rsi = const uint8_t *in
 *   rdx = size_t in_len
 *   rcx = const cp_rans_sym *sym_table
 *   r8  = uint8_t *symbols
 *   r9  = size_t max_symbols
 * Returns: rax = number of symbols decoded
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

    .text
    .globl SYM(cp_rans_decode)
    .p2align 4

SYM(cp_rans_decode):
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdi, %r12          /* state */
    movq    %rsi, %r13          /* in */
    movq    %rdx, %r14          /* in_len */
    movq    %rcx, %r15          /* sym_table */
    movq    %r8,  %rbx          /* symbols (output) */
    movq    %r9, -8(%rbp)       /* save max_symbols (use rbp-relative) */

    /* need >= 16 bytes for initial states */
    cmpq    $16, %r14
    jb      .Lxd_zero

    /* allocate cum2sym[4096] on stack */
    subq    $4096, %rsp

    /* build cum2sym */
    xorl    %ecx, %ecx          /* sym = 0 */
.Lxd_build:
    cmpl    $256, %ecx
    jge     .Lxd_build_done

    movzwl  (%r15, %rcx, 4), %edi      /* freq */
    movzwl  2(%r15, %rcx, 4), %esi     /* cumfreq */

    testl   %edi, %edi
    jz      .Lxd_build_next

    xorl    %edx, %edx          /* j = 0 */
.Lxd_fill:
    cmpl    %edi, %edx
    jge     .Lxd_build_next
    leal    (%esi, %edx), %eax  /* cumfreq + j */
    movb    %cl, (%rsp, %rax)   /* cum2sym[cumfreq+j] = sym */
    incl    %edx
    jmp     .Lxd_fill

.Lxd_build_next:
    incl    %ecx
    jmp     .Lxd_build

.Lxd_build_done:
    /* read 4 initial states (big-endian) */
    movq    %r13, %rsi          /* ptr = in */
    leaq    (%r13, %r14), %r14  /* end = in + in_len (reuse r14) */

    xorl    %ecx, %ecx
.Lxd_read_states:
    cmpl    $4, %ecx
    jge     .Lxd_main

    movzbl  (%rsi), %eax
    shll    $24, %eax
    movzbl  1(%rsi), %edx
    shll    $16, %edx
    orl     %edx, %eax
    movzbl  2(%rsi), %edx
    shll    $8, %edx
    orl     %edx, %eax
    movzbl  3(%rsi), %edx
    orl     %edx, %eax
    addq    $4, %rsi

    movl    %eax, (%r12, %rcx, 4)
    incl    %ecx
    jmp     .Lxd_read_states

.Lxd_main:
    /* rsi = ptr (input cursor) */
    /* r14 = end */
    /* r12 = state */
    /* r15 = sym_table */
    /* rbx = symbols (output) */
    /* rsp = cum2sym */

    xorq    %r13, %r13          /* i = 0 */
    movq    -8(%rbp), %r11      /* max_symbols */

.Lxd_loop:
    cmpq    %r11, %r13
    jge     .Lxd_done

    /* stream = i & 3 */
    movl    %r13d, %ecx
    andl    $3, %ecx

    /* load state */
    movl    (%r12, %rcx, 4), %eax

    /* cum = state & 0xFFF */
    movl    %eax, %edi
    andl    $0xFFF, %edi

    /* sym = cum2sym[cum] */
    movzbl  (%rsp, %rdi), %r8d

    /* store symbol */
    movb    %r8b, (%rbx, %r13)

    /* lookup freq, cumfreq */
    movzwl  (%r15, %r8, 4), %r9d       /* freq */
    movzwl  2(%r15, %r8, 4), %r10d     /* cumfreq */

    /* advance: state = freq * (state >> 12) + (state & 0xFFF) - cumfreq */
    movl    %eax, %edx
    shrl    $12, %edx
    imull   %r9d, %edx          /* freq * (state >> 12) */
    addl    %edi, %edx          /* + (state & 0xFFF) */
    subl    %r10d, %edx         /* - cumfreq */

    /* renormalize */
    movl    $(1 << 23), %eax    /* RANS_L */
.Lxd_renorm:
    cmpl    %eax, %edx
    jae     .Lxd_store
    cmpq    %r14, %rsi
    jae     .Lxd_store
    movzbl  (%rsi), %r8d
    incq    %rsi
    shll    $8, %edx
    orl     %r8d, %edx
    jmp     .Lxd_renorm

.Lxd_store:
    movl    %edx, (%r12, %rcx, 4)
    incq    %r13
    jmp     .Lxd_loop

.Lxd_done:
    movq    -8(%rbp), %rax      /* return max_symbols */
    addq    $4096, %rsp         /* free cum2sym */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

.Lxd_zero:
    xorl    %eax, %eax
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
