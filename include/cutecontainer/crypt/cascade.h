#ifndef CUTECONTAINER_CRYPT_CASCADE_H
#define CUTECONTAINER_CRYPT_CASCADE_H

#include <stdint.h>
#include "curve.h"
#include "cutehash.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cascade — time-distorted dual-point key system.
 *
 * A cascade key is two curve points (P₁, P₂) derived from a seed.
 * Over time, the points are "distorted" through the CuteHash ARX
 * compression function that evolves the signing key each epoch.
 *
 * The distortion is one-way: you can advance the cascade forward
 * but cannot recover past states.
 */

#define CC_CASCADE_SEED_LEN     32
#define CC_CASCADE_NAMESPACE_LEN 32

/* ---- Cascade keypair ---- */

typedef struct {
    cc_scalar s1;           /* private scalar for P₁ */
    cc_scalar s2;           /* private scalar for P₂ */
    cc_point  p1;           /* public point P₁ = s₁·G */
    cc_point  p2;           /* public point P₂ = s₂·G */
    uint64_t  plotted_at;   /* seconds since epoch when key was created */
    uint32_t  epoch_len;    /* seconds per cascade epoch */
    uint8_t   namespace[CC_CASCADE_NAMESPACE_LEN]; /* CuteHash namespace */
} cc_cascade_key;

/* Public half only (for verification) */
typedef struct {
    cc_point  p1;
    cc_point  p2;
    uint64_t  plotted_at;
    uint32_t  epoch_len;
    uint8_t   namespace[CC_CASCADE_NAMESPACE_LEN];
} cc_cascade_pubkey;

/* Snapshot of cascade state at a given epoch */
typedef struct {
    cc_point  p1_prime;     /* distorted P₁ at this epoch */
    cc_point  p2_prime;     /* distorted P₂ at this epoch */
    uint32_t  epoch;        /* which epoch this state is for */
    uint8_t   epoch_key[32]; /* derived signing key material for this epoch */
} cc_cascade_state;

/* ---- API ---- */

/*
 * Plot a new cascade keypair from a seed.
 *   seed:       32 bytes of entropy
 *   namespace:  context string (e.g. "cutecrypt.file-integrity")
 *   epoch_len:  seconds per cascade epoch (e.g. 3600 for hourly)
 *   now:        current time in seconds since Unix epoch
 */
int cc_cascade_plot(
    cc_cascade_key *key,
    const uint8_t seed[CC_CASCADE_SEED_LEN],
    const char *namespace_str,
    uint32_t epoch_len,
    uint64_t now
);

/* Extract the public key from a full keypair. */
void cc_cascade_pubkey_from(
    cc_cascade_pubkey *pub,
    const cc_cascade_key *key
);

/*
 * Advance the cascade to a specific epoch.
 * Computes the distorted points and epoch signing key.
 *
 * This replays the cascade from epoch 0, so cost is O(epoch).
 * For frequently-used keys, cache the state and use _advance_from.
 */
int cc_cascade_derive_epoch(
    cc_cascade_state *state,
    const cc_cascade_key *key,
    uint32_t epoch
);

/*
 * Advance from a known state to a later epoch.
 * Cost is O(target_epoch - state->epoch).
 */
int cc_cascade_advance_from(
    cc_cascade_state *state,
    const cc_cascade_key *key,
    const cc_cascade_state *from,
    uint32_t target_epoch
);

/*
 * Compute which epoch corresponds to a given timestamp.
 */
uint32_t cc_cascade_epoch_for(
    const cc_cascade_key *key,
    uint64_t timestamp
);

/*
 * Sign a message using the cascade-derived key at a given epoch.
 *   sig:   output 64-byte signature
 *   msg:   message to sign
 *   len:   message length
 *   key:   full cascade keypair
 *   epoch: which epoch to sign at
 */
int cc_cascade_sign(
    uint8_t sig[64],
    const uint8_t *msg, size_t len,
    const cc_cascade_key *key,
    uint32_t epoch
);

/*
 * Verify a signature against a cascade public key at a given epoch.
 * The verifier replays the cascade to the claimed epoch.
 * Returns 0 on success, -1 on failure.
 */
int cc_cascade_verify(
    const uint8_t sig[64],
    const uint8_t *msg, size_t len,
    const cc_cascade_pubkey *pub,
    uint32_t epoch
);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_CASCADE_H */
