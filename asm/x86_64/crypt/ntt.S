/*
 * NTT — x86-64 AVX2 stub
 *
 * void cc_kyber_ntt(int16_t poly[256])
 *   rdi = poly
 *
 * Placeholder — returns immediately, letting the C weak symbol handle it.
 * Full implementation would use vpmullw/vpmulhw for Montgomery mul
 * and vpaddw/vpsubw for butterfly additions on 16×int16 YMM lanes.
 */

#ifdef __x86_64__

.text
.align 16
.globl _cc_kyber_ntt
_cc_kyber_ntt:
    ret

.globl _cc_kyber_invntt
_cc_kyber_invntt:
    ret

#endif /* __x86_64__ */
