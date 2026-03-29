/*
 * AES-256 block encrypt — ARM64 with hardware AES instructions
 *
 * Uses AESE (AES single round encrypt) + AESMC (AES mix columns)
 * Available on ARMv8 with Crypto Extensions (all Apple Silicon).
 *
 * void cc_aes256_block_encrypt(const uint8_t round_keys[240], uint8_t block[16])
 *   x0 = round_keys
 *   x1 = block
 */

#ifdef __aarch64__

.text
.align 4
.globl _cc_aes256_block_encrypt
_cc_aes256_block_encrypt:
    /* Load block into v0 */
    ld1     {v0.16b}, [x1]

    /* Load all 15 round keys (AES-256 = 14 rounds + initial) */
    ld1     {v1.16b},  [x0], #16    /* rk[0]  */
    ld1     {v2.16b},  [x0], #16    /* rk[1]  */
    ld1     {v3.16b},  [x0], #16    /* rk[2]  */
    ld1     {v4.16b},  [x0], #16    /* rk[3]  */
    ld1     {v5.16b},  [x0], #16    /* rk[4]  */
    ld1     {v6.16b},  [x0], #16    /* rk[5]  */
    ld1     {v7.16b},  [x0], #16    /* rk[6]  */
    ld1     {v16.16b}, [x0], #16    /* rk[7]  */
    ld1     {v17.16b}, [x0], #16    /* rk[8]  */
    ld1     {v18.16b}, [x0], #16    /* rk[9]  */
    ld1     {v19.16b}, [x0], #16    /* rk[10] */
    ld1     {v20.16b}, [x0], #16    /* rk[11] */
    ld1     {v21.16b}, [x0], #16    /* rk[12] */
    ld1     {v22.16b}, [x0], #16    /* rk[13] */
    ld1     {v23.16b}, [x0]         /* rk[14] */

    /* Round 0: initial AddRoundKey is folded into first AESE */
    /* AESE does SubBytes + ShiftRows + AddRoundKey */
    /* AESMC does MixColumns */

    aese    v0.16b, v1.16b
    aesmc   v0.16b, v0.16b      /* Round 1 */
    aese    v0.16b, v2.16b
    aesmc   v0.16b, v0.16b      /* Round 2 */
    aese    v0.16b, v3.16b
    aesmc   v0.16b, v0.16b      /* Round 3 */
    aese    v0.16b, v4.16b
    aesmc   v0.16b, v0.16b      /* Round 4 */
    aese    v0.16b, v5.16b
    aesmc   v0.16b, v0.16b      /* Round 5 */
    aese    v0.16b, v6.16b
    aesmc   v0.16b, v0.16b      /* Round 6 */
    aese    v0.16b, v7.16b
    aesmc   v0.16b, v0.16b      /* Round 7 */
    aese    v0.16b, v16.16b
    aesmc   v0.16b, v0.16b      /* Round 8 */
    aese    v0.16b, v17.16b
    aesmc   v0.16b, v0.16b      /* Round 9 */
    aese    v0.16b, v18.16b
    aesmc   v0.16b, v0.16b      /* Round 10 */
    aese    v0.16b, v19.16b
    aesmc   v0.16b, v0.16b      /* Round 11 */
    aese    v0.16b, v20.16b
    aesmc   v0.16b, v0.16b      /* Round 12 */
    aese    v0.16b, v21.16b
    aesmc   v0.16b, v0.16b      /* Round 13 */
    aese    v0.16b, v22.16b      /* Round 14 — no AESMC */
    eor     v0.16b, v0.16b, v23.16b  /* Final AddRoundKey */

    /* Store result */
    st1     {v0.16b}, [x1]
    ret

#endif /* __aarch64__ */
