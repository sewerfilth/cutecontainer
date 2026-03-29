/*
 * cutehash.c — Convenience wrappers around the CuteHash ASM core.
 *
 * The core compression (cc_cute_compress) and namespace derivation
 * (cc_cute_namespace) are implemented entirely in ASM.
 * This file provides higher-level functions that chain multiple
 * compressions: general-purpose hashing, keyed hashing, and KDF.
 */

#include <string.h>
#include <cutecontainer/crypt/cutehash.h>

/* Default namespace for general-purpose hashing */
static const char HASH_NS_CTX[] = "cutecrypt.hash";

/*
 * cc_cute_hash: general-purpose 32-byte hash of arbitrary data.
 *
 * Splits data into 32-byte blocks. Each pair of blocks (a, b) is
 * compressed together. If odd number of blocks, the last block is
 * paired with zeros. Final block is zero-padded.
 *
 * Chain: h₀ = compress(ns, block₀, block₁, 0, HASH)
 *        hᵢ = compress(ns, hᵢ₋₁, blockᵢ, i, HASH)
 */
void cc_cute_hash(
    const uint8_t *data, size_t len,
    uint8_t out[CC_CUTE_HASH_LEN])
{
    uint8_t ns[CC_CUTE_NS_LEN];
    uint8_t a[CC_CUTE_INPUT_LEN];
    uint8_t b[CC_CUTE_INPUT_LEN];
    uint8_t chain[CC_CUTE_HASH_LEN];
    uint64_t counter = 0;
    size_t off = 0;

    cc_cute_namespace(ns, HASH_NS_CTX, sizeof(HASH_NS_CTX) - 1);

    /* Handle empty input */
    if (len == 0) {
        memset(a, 0, CC_CUTE_INPUT_LEN);
        memset(b, 0, CC_CUTE_INPUT_LEN);
        cc_cute_compress(ns, a, b, 0, CC_CUTE_MODE_HASH, out);
        return;
    }

    /* First block pair bootstraps the chain */
    memset(a, 0, CC_CUTE_INPUT_LEN);
    memset(b, 0, CC_CUTE_INPUT_LEN);

    size_t take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
    memcpy(a, data + off, take);
    off += take;

    if (off < len) {
        take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
        memcpy(b, data + off, take);
        off += take;
    }

    cc_cute_compress(ns, a, b, counter++, CC_CUTE_MODE_HASH, chain);

    /* Remaining blocks chain through: compress(ns, chain, block, counter, HASH) */
    while (off < len) {
        memset(b, 0, CC_CUTE_INPUT_LEN);
        take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
        memcpy(b, data + off, take);
        off += take;

        cc_cute_compress(ns, chain, b, counter++, CC_CUTE_MODE_HASH, chain);
    }

    memcpy(out, chain, CC_CUTE_HASH_LEN);
}

/*
 * cc_cute_keyed_hash: MAC using a 32-byte key as namespace.
 * Same chaining as cc_cute_hash but the namespace IS the key.
 */
void cc_cute_keyed_hash(
    const uint8_t key[CC_CUTE_NS_LEN],
    const uint8_t *data, size_t len,
    uint8_t out[CC_CUTE_HASH_LEN])
{
    uint8_t a[CC_CUTE_INPUT_LEN];
    uint8_t b[CC_CUTE_INPUT_LEN];
    uint8_t chain[CC_CUTE_HASH_LEN];
    uint64_t counter = 0;
    size_t off = 0;

    if (len == 0) {
        memset(a, 0, CC_CUTE_INPUT_LEN);
        memset(b, 0, CC_CUTE_INPUT_LEN);
        cc_cute_compress(key, a, b, 0, CC_CUTE_MODE_HASH, out);
        return;
    }

    memset(a, 0, CC_CUTE_INPUT_LEN);
    memset(b, 0, CC_CUTE_INPUT_LEN);

    size_t take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
    memcpy(a, data + off, take);
    off += take;

    if (off < len) {
        take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
        memcpy(b, data + off, take);
        off += take;
    }

    cc_cute_compress(key, a, b, counter++, CC_CUTE_MODE_HASH, chain);

    while (off < len) {
        memset(b, 0, CC_CUTE_INPUT_LEN);
        take = (len - off < CC_CUTE_INPUT_LEN) ? len - off : CC_CUTE_INPUT_LEN;
        memcpy(b, data + off, take);
        off += take;

        cc_cute_compress(key, chain, b, counter++, CC_CUTE_MODE_HASH, chain);
    }

    memcpy(out, chain, CC_CUTE_HASH_LEN);
}

/*
 * cc_cute_kdf: derive key material from namespace + input key material.
 * Can produce more than 32 bytes by chaining with incrementing counter.
 *
 * Each 32-byte output block:
 *   outᵢ = compress(ns, ikm_hash, prev_or_zero, i, KDF)
 *
 * Where ikm_hash = cute_hash(ikm) to normalize variable-length IKM.
 */
void cc_cute_kdf(
    const char *context,
    const uint8_t *ikm, size_t ikm_len,
    uint8_t *out, size_t out_len)
{
    uint8_t ns[CC_CUTE_NS_LEN];
    uint8_t ikm_hash[CC_CUTE_HASH_LEN];
    uint8_t block[CC_CUTE_HASH_LEN];
    uint8_t prev[CC_CUTE_HASH_LEN];
    uint64_t counter = 0;

    cc_cute_namespace(ns, context, strlen(context));
    cc_cute_hash(ikm, ikm_len, ikm_hash);

    memset(prev, 0, CC_CUTE_HASH_LEN);

    while (out_len > 0) {
        cc_cute_compress(ns, ikm_hash, prev, counter++, CC_CUTE_MODE_KDF, block);

        size_t take = (out_len < CC_CUTE_HASH_LEN) ? out_len : CC_CUTE_HASH_LEN;
        memcpy(out, block, take);
        out += take;
        out_len -= take;

        memcpy(prev, block, CC_CUTE_HASH_LEN);
    }
}
