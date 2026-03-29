#ifndef CUTECONTAINER_CRYPT_CUTEHASH_H
#define CUTECONTAINER_CRYPT_CUTEHASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CuteHash — custom ARX compression for the cascade/fuse system.
 *
 * Inspired by BLAKE3's G function and round structure, but designed
 * specifically for dual-point curve inputs with counter coupling.
 *
 * Properties:
 *   - Fixed 64-byte input (two 32-byte curve points or hash values)
 *   - 32-byte output (usable as scalar, hash, or chain link)
 *   - Counter is first-class (mixed into initial state, not appended)
 *   - Namespace replaces the IV (domain separation is structural)
 *   - Mode byte prevents cross-domain output reuse
 *   - 7-round ARX core, same rotation constants as BLAKE (16,12,8,7)
 *   - Feed-forward XOR: output = compress(state) ⊕ state[0..7]
 *
 * State layout (16 × uint32 = 64 bytes):
 *
 *   ┌──────────┬──────────┬──────────┬──────────┐
 *   │  ns[0]   │  ns[1]   │  ns[2]   │  ns[3]   │  row 0: namespace
 *   ├──────────┼──────────┼──────────┼──────────┤
 *   │  ns[4]   │  ns[5]   │  ns[6]   │  ns[7]   │  row 1: namespace
 *   ├──────────┼──────────┼──────────┼──────────┤
 *   │ ctr_lo   │ ctr_hi   │  mode    │  0xCC    │  row 2: counter + mode + sentinel
 *   ├──────────┼──────────┼──────────┼──────────┤
 *   │ a[0]^b[0]│ a[1]^b[1]│ a[2]^b[2]│ a[3]^b[3]│  row 3: point XOR (first 16B)
 *   └──────────┴──────────┴──────────┴──────────┘
 *
 *   0xCC = "CuteCrypt" sentinel constant (0xCC00CC00)
 *
 * Message (16 × uint32 = 64 bytes):
 *   m[0..7]   = input_a[0..31] as 8 × uint32 LE
 *   m[8..15]  = input_b[0..31] as 8 × uint32 LE
 *
 * After 7 rounds of column + diagonal G mixing:
 *   output[0..7] = state[0..7] ⊕ state[8..15]   (feed-forward)
 *
 * Packed to 32 bytes little-endian.
 */

#define CC_CUTE_HASH_LEN    32
#define CC_CUTE_INPUT_LEN   32  /* each input is 32 bytes */
#define CC_CUTE_NS_LEN      32  /* namespace is 32 bytes (8 × uint32) */

/* Sentinel constant */
#define CC_CUTE_SENTINEL    0xCC00CC00u

/* ---- Modes ---- */

#define CC_CUTE_MODE_DISTORT  0x01   /* cascade epoch distortion */
#define CC_CUTE_MODE_DERIVE   0x02   /* key material derivation */
#define CC_CUTE_MODE_CHAIN    0x03   /* fuse hash chain */
#define CC_CUTE_MODE_BIND     0x04   /* token/claim binding */
#define CC_CUTE_MODE_HASH     0x05   /* general-purpose hash */
#define CC_CUTE_MODE_KDF      0x06   /* key derivation */

/* ---- Namespace ---- */

/*
 * Derive a 32-byte namespace from a context string.
 * Uses a fixed bootstrap: the string is mixed through the ARX core
 * with an all-zero state and mode=0x00 (namespace derivation).
 *
 * This is called once at key-plot time. The result is stored in
 * cc_cascade_key.namespace.
 */
void cc_cute_namespace(
    uint8_t ns[CC_CUTE_NS_LEN],
    const char *context,
    size_t context_len
);

/* ---- Core compression ---- */

/*
 * CuteHash compression function.
 *
 *   ns:      32-byte namespace (replaces IV)
 *   a:       32-byte input A (curve point, hash, or preimage)
 *   b:       32-byte input B (curve point, hash, or counter material)
 *   counter: 64-bit counter (epoch number, fuse index, etc.)
 *   mode:    domain separation mode (CC_CUTE_MODE_*)
 *   out:     32-byte output
 *
 * Entirely implemented in ASM. No heap, no branches on secret data.
 */
void cc_cute_compress(
    const uint8_t ns[CC_CUTE_NS_LEN],
    const uint8_t a[CC_CUTE_INPUT_LEN],
    const uint8_t b[CC_CUTE_INPUT_LEN],
    uint64_t counter,
    uint32_t mode,
    uint8_t out[CC_CUTE_HASH_LEN]
);

/* ---- Convenience wrappers ---- */

/*
 * Hash: general-purpose 32-byte hash of arbitrary data.
 * Internally splits data into 32-byte blocks and chains through
 * the compression function with MODE_HASH and incrementing counter.
 * Pads the final block with zeros.
 */
void cc_cute_hash(
    const uint8_t *data, size_t len,
    uint8_t out[CC_CUTE_HASH_LEN]
);

/*
 * Keyed hash: MAC using a 32-byte key as namespace.
 */
void cc_cute_keyed_hash(
    const uint8_t key[CC_CUTE_NS_LEN],
    const uint8_t *data, size_t len,
    uint8_t out[CC_CUTE_HASH_LEN]
);

/*
 * KDF: derive key material from namespace + input key material.
 * Can produce more than 32 bytes by chaining with incrementing counter.
 */
void cc_cute_kdf(
    const char *context,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t *out, size_t out_len
);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_CUTEHASH_H */
