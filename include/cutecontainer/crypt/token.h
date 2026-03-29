#ifndef CUTECONTAINER_CRYPT_TOKEN_H
#define CUTECONTAINER_CRYPT_TOKEN_H

#include <stddef.h>
#include <stdint.h>
#include "cascade.h"
#include "fuse.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CascadeToken — JWT-like primitive combining:
 *   - Cascade (time-bound, epoch-evolving signature)
 *   - Fuses (use-limited hash chain)
 *   - Namespace (CuteHash domain separation)
 *
 * A token is valid only at the intersection of all three axes:
 *   time ∩ uses ∩ scope
 *
 * Wire format:
 *   [1]   version (0x01)
 *   [32]  namespace
 *   [8]   issued_at (LE)
 *   [4]   epoch_len (LE)
 *   [4]   epoch (LE) — epoch at which this token was signed
 *   [32]  P₁ (compressed)
 *   [32]  P₂ (compressed)
 *   [32]  fuse_tip
 *   [2]   max_fuses (LE)
 *   [2]   fuses_remaining (LE)
 *   [2]   claims_len (LE)
 *   [N]   claims (arbitrary bytes)
 *   [64]  signature (over everything above)
 *
 * Total: 215 + claims_len bytes
 */

#define CC_TOKEN_VERSION      1
#define CC_TOKEN_HEADER_LEN   151  /* fixed fields before claims */
#define CC_TOKEN_SIG_LEN      64
#define CC_TOKEN_MAX_CLAIMS   4096

/* ---- Token (full, issuer-side) ---- */

typedef struct {
    uint8_t   version;
    uint8_t   namespace[32];
    uint64_t  issued_at;
    uint32_t  epoch_len;
    uint32_t  epoch;
    cc_point  p1;
    cc_point  p2;
    uint8_t   fuse_tip[32];
    uint16_t  max_fuses;
    uint16_t  fuses_remaining;
    uint8_t  *claims;
    uint16_t  claims_len;
    uint8_t   signature[CC_TOKEN_SIG_LEN];
} cc_token;

/* ---- Token validation result ---- */

typedef struct {
    int      valid;             /* 1 = valid, 0 = invalid */
    int      expired;           /* 1 = outside valid epoch window */
    int      exhausted;         /* 1 = all fuses burned */
    uint32_t current_epoch;     /* epoch at verification time */
    uint16_t fuses_remaining;
} cc_token_status;

/* ---- API ---- */

/*
 * Create a new token.
 *   key:        cascade keypair (signs the token)
 *   fuse_depth: number of fuses (uses allowed)
 *   claims:     arbitrary payload (copied)
 *   claims_len: payload length (max CC_TOKEN_MAX_CLAIMS)
 *   now:        current timestamp
 *
 * The token is signed at the current cascade epoch.
 * A fuse chain of `fuse_depth` is generated internally.
 * Returns the fuse_chain (caller must hold it to issue preimages).
 */
int cc_token_create(
    cc_token *token,
    cc_fuse_chain *fuse_out,
    const cc_cascade_key *key,
    uint16_t fuse_depth,
    const uint8_t *claims, uint16_t claims_len,
    uint64_t now
);

/*
 * Verify a token's signature and time validity.
 * Does NOT consume a fuse — call cc_fuse_verify separately.
 *   pub:    cascade public key
 *   now:    current timestamp
 *   window: how many epochs into the future the token is valid
 *           (0 = only the exact epoch it was signed at)
 */
int cc_token_verify(
    cc_token_status *status,
    const cc_token *token,
    const cc_cascade_pubkey *pub,
    uint64_t now,
    uint32_t window
);

/*
 * Serialize a token to bytes.
 * Writes to `out` (must be at least CC_TOKEN_HEADER_LEN + claims_len + CC_TOKEN_SIG_LEN).
 * Returns total bytes written, or -1 on error.
 */
int cc_token_serialize(
    uint8_t *out, size_t out_cap,
    const cc_token *token
);

/*
 * Deserialize a token from bytes.
 * token->claims is allocated internally (caller must free with cc_token_free).
 * Returns 0 on success, -1 on malformed input.
 */
int cc_token_deserialize(
    cc_token *token,
    const uint8_t *data, size_t len
);

/*
 * Free a token's internal allocations (claims).
 */
void cc_token_free(cc_token *token);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_CRYPT_TOKEN_H */
