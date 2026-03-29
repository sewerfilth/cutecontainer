/*
 * fuse.c — Hash-chain consumption tokens using CuteHash.
 *
 * Chain construction:
 *   f₀ = random(32)
 *   fᵢ = CuteHash(ns, fᵢ₋₁, zero, i, MODE_CHAIN)
 *   tip = fₙ (published)
 *
 * Consumption: issuer reveals fₙ₋₁, then fₙ₋₂, etc.
 * Verifier checks: CuteHash(ns, preimage, zero, remaining, CHAIN) == tip
 */

#include <stdlib.h>
#include <string.h>
#include <cutecontainer/crypt/fuse.h>
#include <cutecontainer/crypt/cutehash.h>

/* Platform-specific secure random bytes */
#if defined(__APPLE__)
#include <Security/SecRandom.h>
static void cc_randombytes(uint8_t *buf, size_t len) {
    (void)SecRandomCopyBytes(kSecRandomDefault, len, buf);
}
#elif defined(_WIN32)
#include <bcrypt.h>
static void cc_randombytes(uint8_t *buf, size_t len) {
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}
#elif defined(__linux__)
#include <sys/random.h>
static void cc_randombytes(uint8_t *buf, size_t len) {
    getrandom(buf, len, 0);
}
#else
#include <stdio.h>
static void cc_randombytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, len, f); fclose(f); }
}
#endif

static const char FUSE_NS_CTX[] = "cutecrypt.fuse";

int cc_fuse_generate(
    cc_fuse_chain *chain,
    uint16_t depth,
    const char *namespace_str)
{
    if (depth == 0 || depth > CC_FUSE_MAX_DEPTH)
        return -1;

    uint8_t ns[CC_CUTE_NS_LEN];
    uint8_t zero[CC_CUTE_INPUT_LEN];
    memset(zero, 0, CC_CUTE_INPUT_LEN);

    /* Derive the fuse namespace from the context string */
    if (namespace_str) {
        cc_cute_namespace(ns, namespace_str, strlen(namespace_str));
    } else {
        cc_cute_namespace(ns, FUSE_NS_CTX, sizeof(FUSE_NS_CTX) - 1);
    }

    chain->chain = (uint8_t *)malloc((size_t)depth * CC_FUSE_HASH_LEN);
    if (!chain->chain)
        return -1;

    chain->depth = depth;
    chain->remaining = depth;
    memcpy(chain->namespace, ns, CC_CUTE_NS_LEN);

    /* f₀ = random */
    cc_randombytes(chain->chain, CC_FUSE_HASH_LEN);

    /* fᵢ = CuteHash(ns, fᵢ₋₁, zero, i, MODE_CHAIN) */
    for (uint16_t i = 1; i < depth; i++) {
        uint8_t *prev = chain->chain + (size_t)(i - 1) * CC_FUSE_HASH_LEN;
        uint8_t *curr = chain->chain + (size_t)i * CC_FUSE_HASH_LEN;
        cc_cute_compress(ns, prev, zero, (uint64_t)i, CC_CUTE_MODE_CHAIN, curr);
    }

    /* tip = fₙ₋₁ hashed once more (the published value) */
    {
        uint8_t *last = chain->chain + (size_t)(depth - 1) * CC_FUSE_HASH_LEN;
        cc_cute_compress(ns, last, zero, (uint64_t)depth, CC_CUTE_MODE_CHAIN, chain->tip);
    }

    return 0;
}

int cc_fuse_next(
    cc_fuse_chain *chain,
    uint8_t preimage[CC_FUSE_HASH_LEN])
{
    if (chain->remaining == 0)
        return -1;

    /* Reveal fₙ₋remaining (counting from 0) */
    uint16_t idx = chain->depth - chain->remaining;
    /* Actually we reveal in reverse: the issuer reveals the preimage
     * that hashes to the current tip. So we reveal chain[depth-1],
     * then chain[depth-2], etc. */
    idx = chain->remaining - 1;
    memcpy(preimage, chain->chain + (size_t)idx * CC_FUSE_HASH_LEN, CC_FUSE_HASH_LEN);
    chain->remaining--;

    return 0;
}

void cc_fuse_verifier_init(
    cc_fuse_verifier *v,
    const cc_fuse_chain *chain)
{
    memcpy(v->tip, chain->tip, CC_FUSE_HASH_LEN);
    v->remaining = chain->remaining;
    memcpy(v->namespace, chain->namespace, CC_FUSE_HASH_LEN);
}

void cc_fuse_verifier_from_tip(
    cc_fuse_verifier *v,
    const uint8_t tip[CC_FUSE_HASH_LEN],
    uint16_t remaining,
    const char *namespace_str)
{
    memcpy(v->tip, tip, CC_FUSE_HASH_LEN);
    v->remaining = remaining;
    if (namespace_str) {
        cc_cute_namespace(v->namespace, namespace_str, strlen(namespace_str));
    } else {
        cc_cute_namespace(v->namespace, FUSE_NS_CTX, sizeof(FUSE_NS_CTX) - 1);
    }
}

int cc_fuse_verify(
    cc_fuse_verifier *v,
    const uint8_t preimage[CC_FUSE_HASH_LEN])
{
    if (v->remaining == 0)
        return -1;

    uint8_t zero[CC_CUTE_INPUT_LEN];
    uint8_t expected[CC_FUSE_HASH_LEN];
    memset(zero, 0, CC_CUTE_INPUT_LEN);

    /* Check: CuteHash(ns, preimage, zero, remaining, CHAIN) == tip */
    cc_cute_compress(v->namespace, preimage, zero,
                     (uint64_t)v->remaining, CC_CUTE_MODE_CHAIN, expected);

    /* Constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < CC_FUSE_HASH_LEN; i++)
        diff |= expected[i] ^ v->tip[i];

    if (diff != 0)
        return -1;

    /* Advance: tip becomes the preimage, remaining decrements */
    memcpy(v->tip, preimage, CC_FUSE_HASH_LEN);
    v->remaining--;

    return 0;
}

int cc_fuse_is_exhausted(const cc_fuse_verifier *v) {
    return v->remaining == 0 ? 1 : 0;
}

int cc_fuse_split(
    cc_fuse_chain *parent,
    cc_fuse_chain *child,
    uint16_t count)
{
    if (count == 0 || count > parent->remaining)
        return -1;

    child->depth = count;
    child->remaining = count;
    memcpy(child->namespace, parent->namespace, CC_CUTE_NS_LEN);

    child->chain = (uint8_t *)malloc((size_t)count * CC_FUSE_HASH_LEN);
    if (!child->chain)
        return -1;

    /* Copy the last `count` preimages from parent.
     * The child gets the "newest" fuses (closest to the tip). */
    uint16_t start = parent->remaining - count;
    memcpy(child->chain,
           parent->chain + (size_t)start * CC_FUSE_HASH_LEN,
           (size_t)count * CC_FUSE_HASH_LEN);

    /* Child's tip = parent's current tip */
    memcpy(child->tip, parent->tip, CC_FUSE_HASH_LEN);

    /* Parent loses those fuses */
    parent->remaining -= count;

    /* Parent's tip becomes the hash at the split point */
    if (parent->remaining > 0) {
        uint8_t zero[CC_CUTE_INPUT_LEN];
        memset(zero, 0, CC_CUTE_INPUT_LEN);
        uint8_t *split_pre = parent->chain + (size_t)(parent->remaining - 1) * CC_FUSE_HASH_LEN;
        cc_cute_compress(parent->namespace, split_pre, zero,
                         (uint64_t)parent->remaining, CC_CUTE_MODE_CHAIN, parent->tip);
    }

    return 0;
}

void cc_fuse_free(cc_fuse_chain *chain) {
    if (chain->chain) {
        /* Zeroize preimage material */
        memset(chain->chain, 0, (size_t)chain->depth * CC_FUSE_HASH_LEN);
        free(chain->chain);
        chain->chain = NULL;
    }
    chain->depth = 0;
    chain->remaining = 0;
    memset(chain->tip, 0, CC_FUSE_HASH_LEN);
}
