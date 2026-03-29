/*
 * AES-256 block encrypt — x86-64 with AES-NI
 *
 * void cc_aes256_block_encrypt(const uint8_t round_keys[240], uint8_t block[16])
 *   rdi = round_keys
 *   rsi = block
 */

#ifdef __x86_64__

.text
.align 16
.globl _cc_aes256_block_encrypt
_cc_aes256_block_encrypt:
    movdqu  (%rsi), %xmm0              /* Load block */

    movdqu    0(%rdi), %xmm1           /* rk[0] — initial AddRoundKey */
    pxor    %xmm1, %xmm0

    movdqu   16(%rdi), %xmm1           /* rk[1] */
    aesenc  %xmm1, %xmm0
    movdqu   32(%rdi), %xmm1           /* rk[2] */
    aesenc  %xmm1, %xmm0
    movdqu   48(%rdi), %xmm1           /* rk[3] */
    aesenc  %xmm1, %xmm0
    movdqu   64(%rdi), %xmm1           /* rk[4] */
    aesenc  %xmm1, %xmm0
    movdqu   80(%rdi), %xmm1           /* rk[5] */
    aesenc  %xmm1, %xmm0
    movdqu   96(%rdi), %xmm1           /* rk[6] */
    aesenc  %xmm1, %xmm0
    movdqu  112(%rdi), %xmm1           /* rk[7] */
    aesenc  %xmm1, %xmm0
    movdqu  128(%rdi), %xmm1           /* rk[8] */
    aesenc  %xmm1, %xmm0
    movdqu  144(%rdi), %xmm1           /* rk[9] */
    aesenc  %xmm1, %xmm0
    movdqu  160(%rdi), %xmm1           /* rk[10] */
    aesenc  %xmm1, %xmm0
    movdqu  176(%rdi), %xmm1           /* rk[11] */
    aesenc  %xmm1, %xmm0
    movdqu  192(%rdi), %xmm1           /* rk[12] */
    aesenc  %xmm1, %xmm0
    movdqu  208(%rdi), %xmm1           /* rk[13] */
    aesenc  %xmm1, %xmm0
    movdqu  224(%rdi), %xmm1           /* rk[14] — last round */
    aesenclast %xmm1, %xmm0

    movdqu  %xmm0, (%rsi)              /* Store result */
    ret

#endif /* __x86_64__ */
