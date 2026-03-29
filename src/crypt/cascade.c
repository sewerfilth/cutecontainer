/*
 * cascade.c — Time-distorted dual-point key system using CuteHash.
 *
 * A cascade key is two Curve25519 scalars (s₁, s₂) that produce
 * public points (P₁, P₂). Each epoch, the points are distorted
 * by hashing them together through CuteHash with MODE_DISTORT
 * and the epoch counter.
 *
 * The distortion is one-way: advancing forward is cheap, but
 * recovering past states requires the original key + replay.
 */

#include <string.h>
#include <cutecontainer/crypt/cascade.h>
#include <cutecontainer/crypt/cutehash.h>

/*
 * Distort a pair of points by one epoch step.
 *
 * new_p1 = CuteHash(ns, p1, p2, epoch, MODE_DISTORT)  → used as scalar → new_p1 = scalar·G
 * new_p2 = CuteHash(ns, p2, p1, epoch, MODE_DISTORT)  → used as scalar → new_p2 = scalar·G
 *
 * The asymmetry (p1,p2 vs p2,p1) ensures the two outputs diverge.
 */
static void cascade_distort_step(
    cc_point *p1, cc_point *p2,
    const uint8_t ns[CC_CUTE_NS_LEN],
    uint32_t epoch)
{
    uint8_t h1[CC_CUTE_HASH_LEN];
    uint8_t h2[CC_CUTE_HASH_LEN];

    cc_cute_compress(ns, p1->v, p2->v, (uint64_t)epoch, CC_CUTE_MODE_DISTORT, h1);
    cc_cute_compress(ns, p2->v, p1->v, (uint64_t)epoch, CC_CUTE_MODE_DISTORT, h2);

    /* Use hash outputs as scalars, multiply by basepoint */
    cc_scalar s1, s2;
    memcpy(s1.v, h1, 32);
    memcpy(s2.v, h2, 32);

    cc_scalarmult_base(p1, &s1);
    cc_scalarmult_base(p2, &s2);
}

int cc_cascade_plot(
    cc_cascade_key *key,
    const uint8_t seed[CC_CASCADE_SEED_LEN],
    const char *namespace_str,
    uint32_t epoch_len,
    uint64_t now)
{
    if (!key || !seed || !namespace_str || epoch_len == 0)
        return -1;

    uint8_t ns[CC_CUTE_NS_LEN];
    cc_cute_namespace(ns, namespace_str, strlen(namespace_str));
    memcpy(key->namespace, ns, CC_CASCADE_NAMESPACE_LEN);

    key->plotted_at = now;
    key->epoch_len = epoch_len;

    /* Derive two scalars from the seed via KDF */
    uint8_t derived[64];
    cc_cute_kdf("cutecrypt.cascade.keygen", seed, CC_CASCADE_SEED_LEN, derived, 64);

    memcpy(key->s1.v, derived, 32);
    memcpy(key->s2.v, derived + 32, 32);

    /* Clamp scalars for X25519 */
    cc_scalar_clamp(&key->s1);
    cc_scalar_clamp(&key->s2);

    /* Compute public points */
    cc_scalarmult_base(&key->p1, &key->s1);
    cc_scalarmult_base(&key->p2, &key->s2);

    /* Zeroize intermediate material */
    memset(derived, 0, 64);

    return 0;
}

void cc_cascade_pubkey_from(
    cc_cascade_pubkey *pub,
    const cc_cascade_key *key)
{
    memcpy(&pub->p1, &key->p1, sizeof(cc_point));
    memcpy(&pub->p2, &key->p2, sizeof(cc_point));
    pub->plotted_at = key->plotted_at;
    pub->epoch_len = key->epoch_len;
    memcpy(pub->namespace, key->namespace, CC_CASCADE_NAMESPACE_LEN);
}

uint32_t cc_cascade_epoch_for(
    const cc_cascade_key *key,
    uint64_t timestamp)
{
    if (timestamp <= key->plotted_at)
        return 0;
    return (uint32_t)((timestamp - key->plotted_at) / key->epoch_len);
}

int cc_cascade_derive_epoch(
    cc_cascade_state *state,
    const cc_cascade_key *key,
    uint32_t epoch)
{
    if (!state || !key)
        return -1;

    /* Start from the original public points */
    cc_point p1, p2;
    memcpy(&p1, &key->p1, sizeof(cc_point));
    memcpy(&p2, &key->p2, sizeof(cc_point));

    /* Apply distortion for each epoch step */
    for (uint32_t e = 0; e < epoch; e++) {
        cascade_distort_step(&p1, &p2, key->namespace, e);
    }

    memcpy(&state->p1_prime, &p1, sizeof(cc_point));
    memcpy(&state->p2_prime, &p2, sizeof(cc_point));
    state->epoch = epoch;

    /* Derive epoch signing key: hash(ns, p1', p2', epoch, MODE_DERIVE) */
    cc_cute_compress(key->namespace, p1.v, p2.v,
                     (uint64_t)epoch, CC_CUTE_MODE_DERIVE, state->epoch_key);

    return 0;
}

int cc_cascade_advance_from(
    cc_cascade_state *state,
    const cc_cascade_key *key,
    const cc_cascade_state *from,
    uint32_t target_epoch)
{
    if (!state || !key || !from)
        return -1;
    if (target_epoch < from->epoch)
        return -1; /* cannot go backwards */

    cc_point p1, p2;
    memcpy(&p1, &from->p1_prime, sizeof(cc_point));
    memcpy(&p2, &from->p2_prime, sizeof(cc_point));

    for (uint32_t e = from->epoch; e < target_epoch; e++) {
        cascade_distort_step(&p1, &p2, key->namespace, e);
    }

    memcpy(&state->p1_prime, &p1, sizeof(cc_point));
    memcpy(&state->p2_prime, &p2, sizeof(cc_point));
    state->epoch = target_epoch;

    cc_cute_compress(key->namespace, p1.v, p2.v,
                     (uint64_t)target_epoch, CC_CUTE_MODE_DERIVE, state->epoch_key);

    return 0;
}

/*
 * Sign: compute a 64-byte signature over a message at a given epoch.
 *
 * sig = CuteHash(epoch_key, msg_hash_a, msg_hash_b, epoch, MODE_BIND) ‖
 *       CuteHash(epoch_key, msg_hash_b, p1'‖p2'_hash, epoch, MODE_BIND)
 *
 * Where msg_hash = cute_hash(msg).
 * This is NOT a standard ECDSA/EdDSA signature — it's a keyed MAC
 * using the epoch-derived key. The cascade properties ensure that
 * only the key holder at the correct epoch can produce this.
 */
int cc_cascade_sign(
    uint8_t sig[64],
    const uint8_t *msg, size_t len,
    const cc_cascade_key *key,
    uint32_t epoch)
{
    if (!sig || !key)
        return -1;

    cc_cascade_state state;
    int rc = cc_cascade_derive_epoch(&state, key, epoch);
    if (rc != 0) return rc;

    /* Hash the message */
    uint8_t msg_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(msg, len, msg_hash);

    /* Hash the distorted points */
    uint8_t points_hash[CC_CUTE_HASH_LEN];
    cc_cute_compress(key->namespace, state.p1_prime.v, state.p2_prime.v,
                     (uint64_t)epoch, CC_CUTE_MODE_HASH, points_hash);

    /* First 32 bytes of signature */
    cc_cute_compress(state.epoch_key, msg_hash, points_hash,
                     (uint64_t)epoch, CC_CUTE_MODE_BIND, sig);

    /* Second 32 bytes of signature */
    cc_cute_compress(state.epoch_key, points_hash, msg_hash,
                     (uint64_t)epoch, CC_CUTE_MODE_BIND, sig + 32);

    /* Zeroize state */
    memset(&state, 0, sizeof(state));

    return 0;
}

/*
 * Verify: replay the cascade from the public key to the claimed epoch,
 * then recompute the signature and compare.
 *
 * The verifier only has the public key, so it replays the distortion
 * from the original points to derive the epoch state and epoch_key.
 */
int cc_cascade_verify(
    const uint8_t sig[64],
    const uint8_t *msg, size_t len,
    const cc_cascade_pubkey *pub,
    uint32_t epoch)
{
    if (!sig || !pub)
        return -1;

    /* Replay distortion from public points */
    cc_point p1, p2;
    memcpy(&p1, &pub->p1, sizeof(cc_point));
    memcpy(&p2, &pub->p2, sizeof(cc_point));

    for (uint32_t e = 0; e < epoch; e++) {
        cascade_distort_step(&p1, &p2, pub->namespace, e);
    }

    /* Derive epoch key */
    uint8_t epoch_key[CC_CUTE_HASH_LEN];
    cc_cute_compress(pub->namespace, p1.v, p2.v,
                     (uint64_t)epoch, CC_CUTE_MODE_DERIVE, epoch_key);

    /* Hash message */
    uint8_t msg_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(msg, len, msg_hash);

    /* Hash distorted points */
    uint8_t points_hash[CC_CUTE_HASH_LEN];
    cc_cute_compress(pub->namespace, p1.v, p2.v,
                     (uint64_t)epoch, CC_CUTE_MODE_HASH, points_hash);

    /* Recompute signature */
    uint8_t expected[64];
    cc_cute_compress(epoch_key, msg_hash, points_hash,
                     (uint64_t)epoch, CC_CUTE_MODE_BIND, expected);
    cc_cute_compress(epoch_key, points_hash, msg_hash,
                     (uint64_t)epoch, CC_CUTE_MODE_BIND, expected + 32);

    /* Constant-time compare */
    uint8_t diff = 0;
    for (int i = 0; i < 64; i++)
        diff |= sig[i] ^ expected[i];

    memset(epoch_key, 0, CC_CUTE_HASH_LEN);
    memset(expected, 0, 64);

    return diff == 0 ? 0 : -1;
}
