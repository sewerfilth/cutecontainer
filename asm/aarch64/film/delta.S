/*
 * delta.S — aarch64 NEON XOR-delta encode/decode
 *
 * Overrides weak C fallbacks in delta_fallback.c.
 * Processes rows with unrolled scalar + NEON where beneficial.
 */

#ifdef __aarch64__

    .text
    .align 4

/* ──────────────────────────────────────────────────────────────
 * cf_delta_encode_row(uint32_t *row, size_t width)
 *
 * XOR-delta encode right-to-left: row[x] ^= row[x-1]
 * Each output is XOR of original adjacent pair — inherently
 * sequential per-direction, so we unroll scalar with good
 * scheduling to keep the pipeline full.
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_delta_encode_row
    .p2align 4
_cf_delta_encode_row:
    /* x0 = row, x1 = width */
    cmp     x1, #2
    b.lo    .Lenc_done

    /* start from the last element, walk left */
    sub     x2, x1, #1             /* x2 = index = width - 1 */
    add     x3, x0, x2, lsl #2    /* x3 = &row[width - 1] */

    /* unroll by 4 */
    cmp     x2, #4
    b.lo    .Lenc_tail

.Lenc_loop4:
    ldp     w4, w5, [x3, #-4]     /* w4 = row[i-1], w5 = row[i] */
    ldp     w6, w7, [x3, #-12]    /* w6 = row[i-3], w7 = row[i-2] */
    ldr     w8, [x3, #-16]        /* w8 = row[i-4] */

    eor     w5, w5, w4             /* row[i]   ^= row[i-1] */
    eor     w4, w4, w7             /* row[i-1] ^= row[i-2] */
    eor     w7, w7, w6             /* row[i-2] ^= row[i-3] */
    eor     w6, w6, w8             /* row[i-3] ^= row[i-4] */

    stp     w6, w7, [x3, #-12]
    stp     w4, w5, [x3, #-4]

    sub     x3, x3, #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Lenc_loop4

.Lenc_tail:
    cbz     x2, .Lenc_done
.Lenc_tail_loop:
    ldr     w4, [x3]
    ldr     w5, [x3, #-4]
    eor     w4, w4, w5
    str     w4, [x3]
    sub     x3, x3, #4
    subs    x2, x2, #1
    b.ne    .Lenc_tail_loop

.Lenc_done:
    ret


/* ──────────────────────────────────────────────────────────────
 * cf_delta_decode_row(uint32_t *row, size_t width)
 *
 * XOR-delta decode left-to-right: row[x] ^= row[x-1]
 * Sequential prefix XOR scan — unrolled scalar for throughput.
 * ────────────────────────────────────────────────────────────── */
    .globl _cf_delta_decode_row
    .p2align 4
_cf_delta_decode_row:
    /* x0 = row, x1 = width */
    cmp     x1, #2
    b.lo    .Ldec_done

    sub     x2, x1, #1             /* remaining count */
    add     x3, x0, #4             /* x3 = &row[1] */
    ldr     w4, [x0]               /* w4 = running value = row[0] */

    /* unroll by 4 */
    cmp     x2, #4
    b.lo    .Ldec_tail

.Ldec_loop4:
    ldr     w5, [x3]
    ldr     w6, [x3, #4]
    ldr     w7, [x3, #8]
    ldr     w8, [x3, #12]

    eor     w4, w4, w5              /* row[x]   = prev ^ delta */
    str     w4, [x3]
    eor     w4, w4, w6
    str     w4, [x3, #4]
    eor     w4, w4, w7
    str     w4, [x3, #8]
    eor     w4, w4, w8
    str     w4, [x3, #12]

    add     x3, x3, #16
    sub     x2, x2, #4
    cmp     x2, #4
    b.hs    .Ldec_loop4

.Ldec_tail:
    cbz     x2, .Ldec_done
.Ldec_tail_loop:
    ldr     w5, [x3]
    eor     w4, w4, w5
    str     w4, [x3]
    add     x3, x3, #4
    subs    x2, x2, #1
    b.ne    .Ldec_tail_loop

.Ldec_done:
    ret

#endif /* __aarch64__ */
