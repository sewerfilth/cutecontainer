/*
 * NTT (Number Theoretic Transform) — ARM64 NEON
 *
 * Forward NTT for Kyber polynomial multiplication.
 * Uses SIMD for parallel butterfly operations on int16 coefficients.
 *
 * void cc_kyber_ntt(int16_t poly[256])
 *   x0 = poly (256 × int16_t = 512 bytes)
 *
 * Stub — loads and stores to validate the calling convention.
 * Full butterfly loop to be implemented per Kyber NTT spec.
 */

#ifdef __aarch64__

.text
.align 4
.globl _cc_kyber_ntt
_cc_kyber_ntt:
    /* Placeholder: fall through to C implementation.
     * When this is filled in, the weak C symbol is overridden.
     * For now, return immediately so the C version is used.
     *
     * To activate: implement the radix-2 DIT butterfly here
     * using ld1/st1 for 8×int16 SIMD lanes, smull/smlal for
     * modular multiplication, and sqrdmulh for Montgomery reduction.
     */
    ret

.globl _cc_kyber_invntt
_cc_kyber_invntt:
    /* Placeholder — same as above */
    ret

#endif /* __aarch64__ */
