/*
 * cp_find_match + cp_match_insert + cp_memcopy — aarch64
 *
 * Hash-chain match finder with 4-byte minimum, 64KB window.
 *
 * cp_match cp_find_match(
 *     const uint8_t *data,    // x0
 *     size_t data_len,        // x1
 *     size_t pos,             // x2
 *     cp_match_ctx *ctx       // x3
 * )
 * Returns cp_match in x0 (packed: low 16 = offset, high 16 = length)
 *
 * void cp_match_insert(
 *     const uint8_t *data,    // x0
 *     size_t pos,             // x1
 *     cp_match_ctx *ctx       // x2
 * )
 *
 * void cp_memcopy(uint8_t *dst, const uint8_t *src, size_t len)
 */

#ifdef __APPLE__
#define SYM(name) _##name
#else
#define SYM(name) name
#endif

/* cp_match_ctx layout:
 *   +0:       int16_t head[32768]    (CP_HASH_SIZE = 1<<15)  = 65536 bytes
 *   +65536:   int16_t chain[65536]   (CP_WINDOW_SIZE = 64K)  = 131072 bytes
 *   +196608:  int chain_len          (4 bytes)
 */
#define CTX_HEAD        0
#define CTX_CHAIN       65536
#define CTX_CHAIN_LEN   196608

#define HASH_BITS       15
#define HASH_SIZE       (1 << HASH_BITS)
#define WINDOW_SIZE     65536
#define MIN_MATCH       4
#define MAX_MATCH       258

    .text

/* ---- hash4: hash 4 bytes at ptr, result in w_out ---- */
/* uses w_tmp as scratch */
.macro hash4 w_out, x_ptr, w_tmp
    ldr     \w_tmp, [\x_ptr]           /* load 4 bytes (LE) */
    mov     \w_out, #0x9E37
    movk    \w_out, #0x79B1, lsl #16   /* 0x9E3779B1 -- won't work, need full */
    /* actually load the constant properly */
    ldr     \w_out, =0x9E3779B1
    mul     \w_tmp, \w_tmp, \w_out
    lsr     \w_out, \w_tmp, #(32 - HASH_BITS)
.endm

/* ---- cp_find_match ---- */
    .globl SYM(cp_find_match)
    .p2align 4
SYM(cp_find_match):
    stp     x19, x20, [sp, #-80]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x29, x30, [sp, #64]
    mov     x29, sp

    mov     x19, x0             /* data */
    mov     x20, x1             /* data_len */
    mov     x21, x2             /* pos */
    mov     x22, x3             /* ctx */

    /* best = {0, 0} */
    mov     w23, #0             /* best_offset */
    mov     w24, #0             /* best_length */

    /* if pos + MIN_MATCH > data_len, return {0,0} */
    add     x9, x21, #MIN_MATCH
    cmp     x9, x20
    b.hi    .Lfm_insert_and_ret

    /* hash = hash4(data + pos) */
    add     x10, x19, x21
    ldr     w11, [x10]          /* 4 bytes at pos */
    ldr     w12, =0x9E3779B1
    mul     w11, w11, w12
    lsr     w11, w11, #(32 - HASH_BITS)  /* hash in w11 */

    /* chain_pos = ctx->head[hash] */
    add     x12, x22, x11, lsl #1   /* &head[hash] (int16_t) */
    ldrsh   w13, [x12]              /* chain_pos (signed) */

    /* chain_len = ctx->chain_len */
    mov     x25, #CTX_CHAIN_LEN
    ldr     w25, [x22, x25]
    mov     w26, #0                  /* steps = 0 */

.Lfm_chain_loop:
    /* while chain_pos >= 0 && steps < chain_len */
    tbnz    w13, #31, .Lfm_insert_and_ret   /* chain_pos < 0 → done */
    cmp     w26, w25
    b.ge    .Lfm_insert_and_ret

    /* candidate = (uint16_t)chain_pos */
    and     w14, w13, #0xFFFF

    /* dist = pos - candidate (candidate must be < pos) */
    cmp     x21, x14
    b.ls    .Lfm_chain_next

    sub     x15, x21, x14           /* dist */
    cbz     x15, .Lfm_chain_next
    cmp     x15, #WINDOW_SIZE
    b.hi    .Lfm_chain_next

    /* compare bytes at data+pos vs data+candidate */
    add     x16, x19, x21           /* a = data + pos */
    add     x17, x19, x14           /* b = data + candidate */

    sub     x9, x20, x21            /* max_len = data_len - pos */
    cmp     x9, #MAX_MATCH
    b.ls    1f
    mov     x9, #MAX_MATCH
1:
    mov     x10, #0                  /* len = 0 */
.Lfm_compare:
    cmp     x10, x9
    b.ge    .Lfm_check_best
    ldrb    w11, [x16, x10]
    ldrb    w12, [x17, x10]
    cmp     w11, w12
    b.ne    .Lfm_check_best
    add     x10, x10, #1
    b       .Lfm_compare

.Lfm_check_best:
    cmp     x10, #MIN_MATCH
    b.lo    .Lfm_chain_next
    cmp     w10, w24
    b.ls    .Lfm_chain_next

    mov     w23, w15                 /* best_offset = dist */
    mov     w24, w10                 /* best_length = len */
    cmp     w24, #MAX_MATCH
    b.ge    .Lfm_insert_and_ret      /* can't do better */

.Lfm_chain_next:
    /* chain_pos = ctx->chain[candidate % WINDOW_SIZE] */
    and     w14, w14, #(WINDOW_SIZE - 1)
    mov     x9, #CTX_CHAIN
    add     x9, x22, x9
    ldrsh   w13, [x9, x14, lsl #1]
    add     w26, w26, #1
    b       .Lfm_chain_loop

.Lfm_insert_and_ret:
    /* insert pos into hash chain */
    /* hash = hash4(data + pos) — recompute */
    add     x10, x19, x21
    add     x9, x21, #MIN_MATCH
    cmp     x9, x20
    b.hi    .Lfm_ret

    ldr     w11, [x10]
    ldr     w12, =0x9E3779B1
    mul     w11, w11, w12
    lsr     w11, w11, #(32 - HASH_BITS)

    /* ctx->chain[pos % WINDOW_SIZE] = ctx->head[hash] */
    and     w14, w21, #(WINDOW_SIZE - 1)
    add     x9, x22, x11, lsl #1
    ldrsh   w15, [x9]               /* old head */
    mov     x10, #CTX_CHAIN
    add     x10, x22, x10
    strh    w15, [x10, x14, lsl #1]

    /* ctx->head[hash] = pos % WINDOW_SIZE */
    strh    w14, [x9]

.Lfm_ret:
    /* pack result: offset in low 16, length in high 16 */
    and     w0, w23, #0xFFFF
    orr     w0, w0, w24, lsl #16

    ldp     x29, x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #80
    ret

/* ---- cp_match_insert ---- */
    .globl SYM(cp_match_insert)
    .p2align 4
SYM(cp_match_insert):
    /* x0 = data, x1 = pos, x2 = ctx */
    add     x9, x0, x1
    ldr     w10, [x9]
    ldr     w11, =0x9E3779B1
    mul     w10, w10, w11
    lsr     w10, w10, #(32 - HASH_BITS)

    /* ctx->chain[pos % WINDOW_SIZE] = ctx->head[hash] */
    and     w12, w1, #(WINDOW_SIZE - 1)
    add     x13, x2, x10, lsl #1
    ldrsh   w14, [x13]
    mov     x15, #CTX_CHAIN
    add     x15, x2, x15
    strh    w14, [x15, x12, lsl #1]

    /* ctx->head[hash] = pos % WINDOW_SIZE */
    strh    w12, [x13]
    ret

/* ---- cp_memcopy ---- */
    .globl SYM(cp_memcopy)
    .p2align 4
SYM(cp_memcopy):
    /* x0 = dst, x1 = src, x2 = len */
    cbz     x2, .Lmc_done

    /* byte-by-byte for overlap safety */
.Lmc_loop:
    ldrb    w9, [x1], #1
    strb    w9, [x0], #1
    subs    x2, x2, #1
    b.ne    .Lmc_loop

.Lmc_done:
    ret
