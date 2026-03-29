#ifndef CUTECONTAINER_CRYPT_FUSE_H
#define CUTECONTAINER_CRYPT_FUSE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fuse — hash-chain consumption tokens.
 *
 * A fuse chain of depth N allows exactly N uses.
 * Each use reveals the next preimage in the chain,
 * burning one fuse. Exhausted chains cannot be extended.
 *
 * Chain construction:
 *   f₀ = random(32)
 *   fᵢ = CuteHash(ns="cutecrypt.fuse", a=fᵢ₋₁, b=0, counter=i, mode=CHAIN)
 *   tip = fₙ (published)
 *
 * All operations implemented in ASM (CuteHash compression).
 */

#define CC_FUSE_HASH_LEN  32
#define CC_FUSE_MAX_DEPTH 65535

/* ---- Fuse chain (issuer side — holds all preimages) ---- */

typedef struct {
    uint8_t  *chain;        /* N × 32 bytes: f₀, f₁, ..., fₙ₋₁ */
    uint8_t  tip[CC_FUSE_HASH_LEN]; /* fₙ — the published tip */
    uint16_t depth;         /* total chain length N */
    uint16_t remaining;     /* fuses remaining */
    uint8_t  namespace[CC_FUSE_HASH_LEN]; /* domain separation */
} cc_fuse_chain;

/* ---- Fuse verifier (recipient side — only holds current tip) ---- */

typedef struct {
    uint8_t  tip[CC_FUSE_HASH_LEN]; /* current tip (advances as fuses burn) */
    uint16_t remaining;
    uint8_t  namespace[CC_FUSE_HASH_LEN];
} cc_fuse_verifier;

/* ---- API ---- */

/*
 * Generate a fuse chain of given depth.
 * Allocates chain->chain (caller must free with cc_fuse_free).
 *   depth:     number of uses (1–65535)
 *   namespace: context string for domain separation
 * Returns 0 on success, -1 on error.
 */
int cc_fuse_generate(
    cc_fuse_chain *chain,
    uint16_t depth,
    const char *namespace_str
);

/*
 * Get the next preimage to burn one fuse.
 * Writes 32 bytes to `preimage`.
 * Returns 0 on success, -1 if exhausted.
 */
int cc_fuse_next(
    cc_fuse_chain *chain,
    uint8_t preimage[CC_FUSE_HASH_LEN]
);

/*
 * Initialize a verifier from a chain's current state.
 */
void cc_fuse_verifier_init(
    cc_fuse_verifier *v,
    const cc_fuse_chain *chain
);

/*
 * Initialize a verifier from raw tip + remaining count.
 */
void cc_fuse_verifier_from_tip(
    cc_fuse_verifier *v,
    const uint8_t tip[CC_FUSE_HASH_LEN],
    uint16_t remaining,
    const char *namespace_str
);

/*
 * Verify and consume a fuse preimage.
 * Checks: CuteHash(ns, preimage, 0, remaining, CHAIN) == tip
 * If valid: tip advances to preimage, remaining decrements.
 * Returns 0 on success, -1 on invalid preimage or exhausted.
 */
int cc_fuse_verify(
    cc_fuse_verifier *v,
    const uint8_t preimage[CC_FUSE_HASH_LEN]
);

/*
 * Check if a fuse chain / verifier is exhausted.
 */
int cc_fuse_is_exhausted(const cc_fuse_verifier *v);

/*
 * Split a chain: extract `count` fuses into a sub-chain.
 * The sub-chain's fuses burn before the parent's remaining fuses.
 *   parent:  source chain (remaining decreases by count)
 *   child:   output sub-chain (depth = count)
 *   count:   number of fuses to delegate
 * Returns 0 on success, -1 if count > parent->remaining.
 */
int cc_fuse_split(
    cc_fuse_chain *parent,
    cc_fuse_chain *child,
    uint16_t count
);

/*
 * Free a fuse chain's internal allocation.
 * Zeroizes all preimage material before freeing.
 */
void cc_fuse_free(cc_fuse_chain *chain);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_FUSE_H */
