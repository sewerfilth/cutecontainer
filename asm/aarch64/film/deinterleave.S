/*
 * deinterleave.S — aarch64 NEON BIP ↔ BSQ conversion
 *
 * Overrides weak C fallbacks in deinterleave_fallback.c.
 *
 * For 4-band mode (CF_SPECTRAL_128): uses LD4/ST4 for perfect
 * 4-way deinterleave — NEON handles the shuffle in hardware.
 * For 8/16-band modes: uses stride-gather with NEON stores.
 */

#ifdef __aarch64__

    .text
    .align 4

/* ──────────────────────────────────────────────────────────────
 * cf_deinterleave_band(const float *bip, float *plane,
 *                      size_t npixels, int num_bands, int band)
 *
 * x0 = bip, x1 = plane, x2 = npixels, w3 = num_bands, w4 = band
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_deinterleave_band
    .p2align 4
_cf_deinterleave_band:
    cbz     x2, .Ldeint_done

    /* zero-extend 32-bit args to 64-bit */
    uxtw    x4, w4                      /* band */
    uxtw    x3, w3                      /* num_bands (keep w3 for cmp below) */

    /* offset to first sample of this band */
    add     x0, x0, x4, lsl #2         /* bip += band * sizeof(float) */
    lsl     x5, x3, #2                 /* x5 = stride = num_bands * 4 bytes */

    /* fast path: 4 bands — use LD4 */
    cmp     w3, #4
    b.ne    .Ldeint_generic

    /* LD4 path: process 4 pixels at a time
     * LD4 {v0.4s-v3.4s}, [x6] loads 16 floats and deinterleaves into
     * 4 vectors of 4 consecutive same-band values.
     * We rewind x0 to the base (undo the band offset). */
    sub     x6, x0, x4, lsl #2         /* x6 = original bip base */

    /* which vector register holds our band? */
    cmp     w4, #0
    b.eq    .Lld4_b0
    cmp     w4, #1
    b.eq    .Lld4_b1
    cmp     w4, #2
    b.eq    .Lld4_b2
    b       .Lld4_b3

    /* band 0: result in v0 */
.Lld4_b0:
    cmp     x2, #4
    b.lo    .Lld4_b0_tail
.Lld4_b0_loop:
    ld4     {v0.4s, v1.4s, v2.4s, v3.4s}, [x6], #64
    st1     {v0.4s}, [x1], #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lld4_b0_loop
.Lld4_b0_tail:
    /* x0 was offset to band 0, which is base — recalc for scalar tail */
    mov     x0, x6
    b       .Ldeint_scalar_tail

    /* band 1: result in v1 */
.Lld4_b1:
    cmp     x2, #4
    b.lo    .Lld4_b1_tail
.Lld4_b1_loop:
    ld4     {v0.4s, v1.4s, v2.4s, v3.4s}, [x6], #64
    st1     {v1.4s}, [x1], #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lld4_b1_loop
.Lld4_b1_tail:
    add     x0, x6, #4
    b       .Ldeint_scalar_tail

    /* band 2: result in v2 */
.Lld4_b2:
    cmp     x2, #4
    b.lo    .Lld4_b2_tail
.Lld4_b2_loop:
    ld4     {v0.4s, v1.4s, v2.4s, v3.4s}, [x6], #64
    st1     {v2.4s}, [x1], #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lld4_b2_loop
.Lld4_b2_tail:
    add     x0, x6, #8
    b       .Ldeint_scalar_tail

    /* band 3: result in v3 */
.Lld4_b3:
    cmp     x2, #4
    b.lo    .Lld4_b3_tail
.Lld4_b3_loop:
    ld4     {v0.4s, v1.4s, v2.4s, v3.4s}, [x6], #64
    st1     {v3.4s}, [x1], #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lld4_b3_loop
.Lld4_b3_tail:
    add     x0, x6, #12
    b       .Ldeint_scalar_tail

    /* generic path: stride gather */
.Ldeint_generic:
    /* process 4 pixels at a time with stride loads */
    cmp     x2, #4
    b.lo    .Ldeint_scalar_tail

    mov     x6, x5                     /* stride bytes */
    add     x7, x6, x6                /* 2 × stride */
    add     x8, x7, x6                /* 3 × stride */

.Ldeint_gen_loop:
    ldr     s0, [x0]
    ldr     s1, [x0, x6]
    ldr     s2, [x0, x7]
    ldr     s3, [x0, x8]

    add     x0, x0, x6, lsl #2         /* advance by 4 × stride */

    /* combine into v0 and store */
    ins     v0.s[1], v1.s[0]
    ins     v0.s[2], v2.s[0]
    ins     v0.s[3], v3.s[0]
    st1     {v0.4s}, [x1], #16

    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Ldeint_gen_loop

    /* scalar tail for remaining pixels */
.Ldeint_scalar_tail:
    cbz     x2, .Ldeint_done
.Ldeint_scalar_loop:
    ldr     w9, [x0]
    str     w9, [x1], #4
    add     x0, x0, x5
    subs    x2, x2, #1
    b.ne    .Ldeint_scalar_loop

.Ldeint_done:
    ret


/* ──────────────────────────────────────────────────────────────
 * cf_interleave_band(float *bip, const float *plane,
 *                    size_t npixels, int num_bands, int band)
 *
 * x0 = bip, x1 = plane, x2 = npixels, w3 = num_bands, w4 = band
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_interleave_band
    .p2align 4
_cf_interleave_band:
    cbz     x2, .Lint_done

    /* zero-extend 32-bit args */
    uxtw    x4, w4
    uxtw    x3, w3

    /* offset to first sample of this band */
    add     x0, x0, x4, lsl #2
    lsl     x5, x3, #2                 /* stride = num_bands * 4 bytes */

    /* stride scatter: store each plane value at stride intervals */
    /* 4-pixel unroll */
    cmp     x2, #4
    b.lo    .Lint_tail

    mov     x6, x5
    add     x7, x6, x6
    add     x8, x7, x6

.Lint_loop4:
    ld1     {v0.4s}, [x1], #16

    str     s0, [x0]
    mov     w9, v0.s[1]
    str     w9, [x0, x6]
    mov     w9, v0.s[2]
    str     w9, [x0, x7]
    mov     w9, v0.s[3]
    str     w9, [x0, x8]

    add     x0, x0, x6, lsl #2
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lint_loop4

.Lint_tail:
    cbz     x2, .Lint_done
.Lint_tail_loop:
    ldr     w9, [x1], #4
    str     w9, [x0]
    add     x0, x0, x5
    subs    x2, x2, #1
    b.ne    .Lint_tail_loop

.Lint_done:
    ret

#endif /* __aarch64__ */
