/*
 * token.c — CascadeToken: JWT-like primitive combining cascade + fuse.
 *
 * A token binds:
 *   - Time (cascade epoch at issuance)
 *   - Uses (fuse chain depth)
 *   - Scope (namespace domain separation)
 *   - Claims (arbitrary payload)
 *
 * The signature covers all fixed fields + claims using the cascade
 * signing mechanism at the token's epoch.
 */

#include <stdlib.h>
#include <string.h>
#include <cutecontainer/crypt/token.h>
#include <cutecontainer/crypt/cutehash.h>

/* Little-endian encode/decode helpers */
static void le16_put(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void le32_put(uint8_t *p, uint32_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void le64_put(uint8_t *p, uint64_t v) { for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

static uint16_t le16_get(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t le32_get(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t le64_get(const uint8_t *p) { uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }

int cc_token_create(
    cc_token *token,
    cc_fuse_chain *fuse_out,
    const cc_cascade_key *key,
    uint16_t fuse_depth,
    const uint8_t *claims, uint16_t claims_len,
    uint64_t now)
{
    if (!token || !key || !fuse_out)
        return -1;
    if (claims_len > CC_TOKEN_MAX_CLAIMS)
        return -1;

    memset(token, 0, sizeof(cc_token));

    token->version = CC_TOKEN_VERSION;
    memcpy(token->namespace, key->namespace, 32);
    token->issued_at = now;
    token->epoch_len = key->epoch_len;

    /* Compute the epoch at issuance */
    token->epoch = cc_cascade_epoch_for(key, now);

    /* Copy public points */
    memcpy(&token->p1, &key->p1, sizeof(cc_point));
    memcpy(&token->p2, &key->p2, sizeof(cc_point));

    /* Generate fuse chain */
    int rc = cc_fuse_generate(fuse_out, fuse_depth, NULL);
    if (rc != 0)
        return -1;
    /* Override namespace to match the cascade key's namespace */
    memcpy(fuse_out->namespace, key->namespace, CC_CUTE_NS_LEN);

    memcpy(token->fuse_tip, fuse_out->tip, CC_FUSE_HASH_LEN);
    token->max_fuses = fuse_depth;
    token->fuses_remaining = fuse_depth;

    /* Copy claims */
    if (claims_len > 0 && claims) {
        token->claims = (uint8_t *)malloc(claims_len);
        if (!token->claims) {
            cc_fuse_free(fuse_out);
            return -1;
        }
        memcpy(token->claims, claims, claims_len);
    } else {
        token->claims = NULL;
    }
    token->claims_len = claims_len;

    /* Serialize the header + claims for signing */
    size_t signable_len = CC_TOKEN_HEADER_LEN + claims_len;
    uint8_t *signable = (uint8_t *)malloc(signable_len);
    if (!signable) {
        cc_fuse_free(fuse_out);
        free(token->claims);
        return -1;
    }

    /* Build the signable content (everything except signature) */
    uint8_t *p = signable;
    *p++ = token->version;
    memcpy(p, token->namespace, 32); p += 32;
    le64_put(p, token->issued_at); p += 8;
    le32_put(p, token->epoch_len); p += 4;
    le32_put(p, token->epoch); p += 4;
    memcpy(p, token->p1.v, 32); p += 32;
    memcpy(p, token->p2.v, 32); p += 32;
    memcpy(p, token->fuse_tip, 32); p += 32;
    le16_put(p, token->max_fuses); p += 2;
    le16_put(p, token->fuses_remaining); p += 2;
    le16_put(p, token->claims_len); p += 2;
    if (claims_len > 0)
        memcpy(p, token->claims, claims_len);

    /* Sign: cascade_sign over the serialized token body */
    rc = cc_cascade_sign(token->signature, signable, signable_len,
                         key, token->epoch);

    memset(signable, 0, signable_len);
    free(signable);

    return rc;
}

int cc_token_verify(
    cc_token_status *status,
    const cc_token *token,
    const cc_cascade_pubkey *pub,
    uint64_t now,
    uint32_t window)
{
    if (!status || !token || !pub)
        return -1;

    memset(status, 0, sizeof(cc_token_status));

    /* Compute current epoch */
    if (now > pub->plotted_at && pub->epoch_len > 0)
        status->current_epoch = (uint32_t)((now - pub->plotted_at) / pub->epoch_len);
    else
        status->current_epoch = 0;

    status->fuses_remaining = token->fuses_remaining;

    /* Check epoch window */
    if (status->current_epoch > token->epoch + window ||
        status->current_epoch < token->epoch) {
        status->expired = 1;
    }

    /* Check fuse exhaustion */
    if (token->fuses_remaining == 0)
        status->exhausted = 1;

    /* Rebuild signable content */
    size_t signable_len = CC_TOKEN_HEADER_LEN + token->claims_len;
    uint8_t *signable = (uint8_t *)malloc(signable_len);
    if (!signable)
        return -1;

    uint8_t *p = signable;
    *p++ = token->version;
    memcpy(p, token->namespace, 32); p += 32;
    le64_put(p, token->issued_at); p += 8;
    le32_put(p, token->epoch_len); p += 4;
    le32_put(p, token->epoch); p += 4;
    memcpy(p, token->p1.v, 32); p += 32;
    memcpy(p, token->p2.v, 32); p += 32;
    memcpy(p, token->fuse_tip, 32); p += 32;
    le16_put(p, token->max_fuses); p += 2;
    le16_put(p, token->fuses_remaining); p += 2;
    le16_put(p, token->claims_len); p += 2;
    if (token->claims_len > 0 && token->claims)
        memcpy(p, token->claims, token->claims_len);

    /* Verify cascade signature */
    int rc = cc_cascade_verify(token->signature, signable, signable_len,
                               pub, token->epoch);

    memset(signable, 0, signable_len);
    free(signable);

    status->valid = (rc == 0 && !status->expired && !status->exhausted) ? 1 : 0;

    return 0;
}

int cc_token_serialize(
    uint8_t *out, size_t out_cap,
    const cc_token *token)
{
    size_t total = CC_TOKEN_HEADER_LEN + token->claims_len + CC_TOKEN_SIG_LEN;
    if (out_cap < total)
        return -1;

    uint8_t *p = out;
    *p++ = token->version;
    memcpy(p, token->namespace, 32); p += 32;
    le64_put(p, token->issued_at); p += 8;
    le32_put(p, token->epoch_len); p += 4;
    le32_put(p, token->epoch); p += 4;
    memcpy(p, token->p1.v, 32); p += 32;
    memcpy(p, token->p2.v, 32); p += 32;
    memcpy(p, token->fuse_tip, 32); p += 32;
    le16_put(p, token->max_fuses); p += 2;
    le16_put(p, token->fuses_remaining); p += 2;
    le16_put(p, token->claims_len); p += 2;
    if (token->claims_len > 0 && token->claims)
        memcpy(p, token->claims, token->claims_len);
    p += token->claims_len;
    memcpy(p, token->signature, CC_TOKEN_SIG_LEN);

    return (int)total;
}

int cc_token_deserialize(
    cc_token *token,
    const uint8_t *data, size_t len)
{
    if (len < CC_TOKEN_HEADER_LEN + CC_TOKEN_SIG_LEN)
        return -1;

    memset(token, 0, sizeof(cc_token));

    const uint8_t *p = data;
    token->version = *p++;
    if (token->version != CC_TOKEN_VERSION)
        return -1;

    memcpy(token->namespace, p, 32); p += 32;
    token->issued_at = le64_get(p); p += 8;
    token->epoch_len = le32_get(p); p += 4;
    token->epoch = le32_get(p); p += 4;
    memcpy(token->p1.v, p, 32); p += 32;
    memcpy(token->p2.v, p, 32); p += 32;
    memcpy(token->fuse_tip, p, 32); p += 32;
    token->max_fuses = le16_get(p); p += 2;
    token->fuses_remaining = le16_get(p); p += 2;
    token->claims_len = le16_get(p); p += 2;

    if (token->claims_len > CC_TOKEN_MAX_CLAIMS)
        return -1;

    size_t expected = CC_TOKEN_HEADER_LEN + token->claims_len + CC_TOKEN_SIG_LEN;
    if (len < expected)
        return -1;

    if (token->claims_len > 0) {
        token->claims = (uint8_t *)malloc(token->claims_len);
        if (!token->claims)
            return -1;
        memcpy(token->claims, p, token->claims_len);
    } else {
        token->claims = NULL;
    }
    p += token->claims_len;

    memcpy(token->signature, p, CC_TOKEN_SIG_LEN);

    return 0;
}

void cc_token_free(cc_token *token) {
    if (token->claims) {
        memset(token->claims, 0, token->claims_len);
        free(token->claims);
        token->claims = NULL;
    }
    token->claims_len = 0;
}
