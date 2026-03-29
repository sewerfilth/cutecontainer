#include "cutecontainer/crypt/pipe.h"
#include "cutecontainer/crypt/aes256.h"
#include "cutecontainer/crypt/sha3.h"
#include "cutecontainer/crypt/kyber.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * cutecrypt pipe — the encryption pipeline
 *
 * Encrypt: Kyber encaps → SHAKE-256 KDF → AES-256-GCM
 * Decrypt: Kyber decaps → SHAKE-256 KDF → AES-256-GCM
 *
 * File format (.cute):
 *   "CUTE"             4 bytes   magic
 *   version            1 byte    0x01
 *   flags              1 byte    reserved
 *   content_hash       32 bytes  SHA3-256 of plaintext
 *   kyber_ct           1088 bytes Kyber ciphertext
 *   nonce              12 bytes  AES-GCM nonce
 *   ciphertext         N bytes   AES-256-GCM (includes 16-byte tag)
 */

struct cc_pipe {
    int mode; /* 0 = encrypt, 1 = decrypt */
    union {
        uint8_t pk[CC_KYBER_PK_LEN];
        uint8_t sk[CC_KYBER_SK_LEN];
    } key;
};

/* Derive AES key + nonce from Kyber shared secret via SHAKE-256 */
static void derive_key_nonce(
    const uint8_t ss[CC_KYBER_SS_LEN],
    uint8_t aes_key[CC_AES256_KEY_LEN],
    uint8_t nonce[CC_AES256_NONCE_LEN]
) {
    cc_sha3_ctx shake;
    cc_shake256_init(&shake);
    /* Domain separation */
    const uint8_t label[] = "cutecrypt-pipe-v1";
    cc_shake256_absorb(&shake, label, sizeof(label) - 1);
    cc_shake256_absorb(&shake, ss, CC_KYBER_SS_LEN);
    cc_shake256_squeeze(&shake, aes_key, CC_AES256_KEY_LEN);
    cc_shake256_squeeze(&shake, nonce, CC_AES256_NONCE_LEN);
}

cc_pipe *cc_pipe_encrypt_new(const uint8_t pk[CC_KYBER_PK_LEN]) {
    cc_pipe *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->mode = 0;
    memcpy(p->key.pk, pk, CC_KYBER_PK_LEN);
    return p;
}

cc_pipe *cc_pipe_decrypt_new(const uint8_t sk[CC_KYBER_SK_LEN]) {
    cc_pipe *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->mode = 1;
    memcpy(p->key.sk, sk, CC_KYBER_SK_LEN);
    return p;
}

int cc_pipe_encrypt(
    cc_pipe *p,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **out, size_t *out_len
) {
    if (!p || p->mode != 0) return -1;

    /* Step 1: SHA3-256 content hash */
    uint8_t content_hash[CC_SHA3_256_HASH_LEN];
    cc_sha3_256(plaintext, plaintext_len, content_hash);

    /* Step 2: Kyber encapsulate → shared secret */
    uint8_t kyber_ct[CC_KYBER_CT_LEN];
    uint8_t ss[CC_KYBER_SS_LEN];
    if (cc_kyber_encaps(p->key.pk, kyber_ct, ss) != 0) return -1;

    /* Step 3: KDF → AES key + nonce */
    uint8_t aes_key[CC_AES256_KEY_LEN];
    uint8_t nonce[CC_AES256_NONCE_LEN];
    derive_key_nonce(ss, aes_key, nonce);

    /* Zeroize shared secret */
    volatile uint8_t *vss = ss;
    for (int i = 0; i < CC_KYBER_SS_LEN; i++) vss[i] = 0;

    /* Step 4: AES-256-GCM encrypt */
    size_t total = CC_PIPE_HEADER_LEN + plaintext_len + CC_AES256_TAG_LEN;
    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;

    /* Write header */
    memcpy(buf, CC_PIPE_MAGIC, 4);
    buf[4] = CC_PIPE_VERSION;
    buf[5] = 0; /* flags */
    memcpy(buf + 6, content_hash, 32);
    memcpy(buf + 38, kyber_ct, CC_KYBER_CT_LEN);
    memcpy(buf + 38 + CC_KYBER_CT_LEN, nonce, CC_AES256_NONCE_LEN);

    /* Copy plaintext into ciphertext region for in-place encryption */
    uint8_t *ct_region = buf + CC_PIPE_HEADER_LEN;
    memcpy(ct_region, plaintext, plaintext_len);

    /* AAD = header (magic + version + flags + hash + kyber_ct + nonce) */
    cc_aes256_ctx *aes = cc_aes256_init(aes_key);
    if (!aes) { free(buf); return -1; }

    int ret = cc_aes256_encrypt(aes, nonce, buf, CC_PIPE_HEADER_LEN, ct_region, plaintext_len);
    cc_aes256_free(aes);

    /* Zeroize AES key */
    volatile uint8_t *vkey = aes_key;
    for (int i = 0; i < CC_AES256_KEY_LEN; i++) vkey[i] = 0;

    if (ret != 0) { free(buf); return -1; }

    *out = buf;
    *out_len = total;
    return 0;
}

int cc_pipe_decrypt(
    cc_pipe *p,
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len
) {
    if (!p || p->mode != 1) return -1;
    if (data_len < CC_PIPE_HEADER_LEN + CC_AES256_TAG_LEN) return -1;

    /* Verify magic */
    if (memcmp(data, CC_PIPE_MAGIC, 4) != 0) return -1;
    if (data[4] != CC_PIPE_VERSION) return -1;

    /* Parse header */
    const uint8_t *content_hash = data + 6;
    const uint8_t *kyber_ct = data + 38;
    const uint8_t *nonce = data + 38 + CC_KYBER_CT_LEN;
    const uint8_t *ct_region = data + CC_PIPE_HEADER_LEN;
    size_t ct_plus_tag_len = data_len - CC_PIPE_HEADER_LEN;

    /* Step 1: Kyber decapsulate */
    uint8_t ss[CC_KYBER_SS_LEN];
    if (cc_kyber_decaps(p->key.sk, kyber_ct, ss) != 0) return -1;

    /* Step 2: KDF */
    uint8_t aes_key[CC_AES256_KEY_LEN];
    uint8_t derived_nonce[CC_AES256_NONCE_LEN];
    derive_key_nonce(ss, aes_key, derived_nonce);

    volatile uint8_t *vss = ss;
    for (int i = 0; i < CC_KYBER_SS_LEN; i++) vss[i] = 0;

    /* Step 3: AES-256-GCM decrypt (in-place on copy) */
    uint8_t *buf = malloc(ct_plus_tag_len);
    if (!buf) return -1;
    memcpy(buf, ct_region, ct_plus_tag_len);

    cc_aes256_ctx *aes = cc_aes256_init(aes_key);
    if (!aes) { free(buf); return -1; }

    int ret = cc_aes256_decrypt(aes, nonce, data, CC_PIPE_HEADER_LEN, buf, ct_plus_tag_len);
    cc_aes256_free(aes);

    volatile uint8_t *vkey = aes_key;
    for (int i = 0; i < CC_AES256_KEY_LEN; i++) vkey[i] = 0;

    if (ret != 0) { free(buf); return -1; }

    /* Step 4: Verify content hash */
    size_t pt_len = ct_plus_tag_len - CC_AES256_TAG_LEN;
    uint8_t check_hash[CC_SHA3_256_HASH_LEN];
    cc_sha3_256(buf, pt_len, check_hash);

    uint8_t diff = 0;
    for (int i = 0; i < CC_SHA3_256_HASH_LEN; i++) diff |= check_hash[i] ^ content_hash[i];
    if (diff) { free(buf); return -1; }

    *out = buf;
    *out_len = pt_len;
    return 0;
}

/* ---- File wrappers ---- */

int cc_pipe_encrypt_file(cc_pipe *p, const char *in_path, const char *out_path) {
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);

    uint8_t *out;
    size_t out_len;
    int ret = cc_pipe_encrypt(p, buf, (size_t)sz, &out, &out_len);
    free(buf);
    if (ret != 0) return -1;

    f = fopen(out_path, "wb");
    if (!f) { cc_pipe_free_buf(out); return -1; }
    size_t written = fwrite(out, 1, out_len, f);
    fclose(f);
    cc_pipe_free_buf(out);

    return (written == out_len) ? 0 : -1;
}

int cc_pipe_decrypt_file(cc_pipe *p, const char *in_path, const char *out_path) {
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);

    uint8_t *out;
    size_t out_len;
    int ret = cc_pipe_decrypt(p, buf, (size_t)sz, &out, &out_len);
    free(buf);
    if (ret != 0) return -1;

    f = fopen(out_path, "wb");
    if (!f) { cc_pipe_free_buf(out); return -1; }
    size_t written = fwrite(out, 1, out_len, f);
    fclose(f);
    cc_pipe_free_buf(out);

    return (written == out_len) ? 0 : -1;
}

void cc_pipe_free_buf(uint8_t *buf) {
    free(buf);
}

void cc_pipe_free(cc_pipe *p) {
    if (p) {
        /* Zeroize all key material */
        volatile uint8_t *v = (volatile uint8_t *)&p->key;
        for (size_t i = 0; i < sizeof(p->key); i++) v[i] = 0;
        free(p);
    }
}
