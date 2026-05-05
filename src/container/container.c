/*
 * container.c — unified .cute container read/write + legacy detection
 */

#include "cutecontainer/container.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt/sha3.h"
#include "cutecontainer/crypt/pipe.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- LE helpers ---- */

static void put_u16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void put_u32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64(uint8_t *p, uint64_t v) { put_u32(p,(uint32_t)v); put_u32(p+4,(uint32_t)(v>>32)); }

static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t get_u64(const uint8_t *p) { return (uint64_t)get_u32(p)|((uint64_t)get_u32(p+4)<<32); }

/* ---- Container struct ---- */

struct cc_container {
    cc_content_type type;
    uint16_t layer_flags;
    uint8_t  version;
    uint8_t *meta;      size_t meta_size;
    uint8_t *payload;   size_t payload_size;
    uint64_t original_size;
    uint8_t  hash[32];
    uint8_t  pk[1184];  int has_pk;
    uint8_t  sk[2400];  int has_sk;
    int owns_meta, owns_payload;
    int compression_level;
};

const char *cc_content_type_name(cc_content_type type) {
    switch (type) {
    case CC_TYPE_RAW:   return "raw";
    case CC_TYPE_PRESS: return "press";
    case CC_TYPE_CRYPT: return "crypt";
    case CC_TYPE_FILM:  return "film";
    case CC_TYPE_DEPO:  return "depo";
    default:            return "unknown";
    }
}

cc_content_type cc_container_detect(const uint8_t *data, size_t data_len) {
    if (!data || data_len < 6) return CC_TYPE_UNKNOWN;
    if (memcmp(data, "CUTE", 4) == 0) {
        uint8_t ver = data[4];
        if (ver >= CC_CONTAINER_VERSION) return (cc_content_type)data[5];
        if (ver == 0x01) return CC_TYPE_CRYPT;
        if (ver >= 0x02 && ver <= 0x04) return CC_TYPE_DEPO;
    }
    if (data_len >= 4 && memcmp(data, "CFSP", 4) == 0) return CC_TYPE_FILM;
    if (data_len >= 4 && memcmp(data, "PRSS", 4) == 0) return CC_TYPE_PRESS;
    return CC_TYPE_UNKNOWN;
}

cc_container *cc_container_create(cc_content_type type) {
    cc_container *c = calloc(1, sizeof(cc_container));
    if (!c) return NULL;
    c->type = type;
    c->version = CC_CONTAINER_VERSION;
    c->compression_level = CP_LEVEL_DEFAULT;
    return c;
}

void cc_container_set_compression_level(cc_container *c, int level) {
    if (!c) return;
    if (level < CP_LEVEL_FAST) level = CP_LEVEL_FAST;
    if (level > CP_LEVEL_MAX)  level = CP_LEVEL_MAX;
    c->compression_level = level;
}

void cc_container_set_meta(cc_container *c, const void *meta, size_t s) {
    if (!c) return;
    if (c->owns_meta) free(c->meta);
    c->meta = malloc(s); if (c->meta) { memcpy(c->meta, meta, s); c->meta_size = s; c->owns_meta = 1; }
}

void cc_container_set_payload(cc_container *c, const void *data, size_t s) {
    if (!c) return;
    if (c->owns_payload) free(c->payload);
    c->payload = malloc(s); if (c->payload) { memcpy(c->payload, data, s); c->payload_size = s; c->original_size = s; c->owns_payload = 1; }
}

void cc_container_set_layers(cc_container *c, uint16_t f) { if (c) c->layer_flags = f; }
void cc_container_set_encrypt_key(cc_container *c, const uint8_t pk[1184]) { if (!c) return; memcpy(c->pk, pk, 1184); c->has_pk = 1; }
void cc_container_set_decrypt_key(cc_container *c, const uint8_t sk[2400]) { if (!c) return; memcpy(c->sk, sk, 2400); c->has_sk = 1; }

int cc_container_write(cc_container *c, uint8_t **out, size_t *out_len) {
    if (!c || !out || !out_len) return CC_ERR_IO;
    uint8_t *payload = c->payload; size_t payload_sz = c->payload_size;
    uint64_t orig_sz = c->original_size; int free_payload = 0;

    cc_sha3_256(c->payload, c->payload_size, c->hash);

    if (c->layer_flags & CC_LAYER_COMPRESSED) {
        size_t bound = cp_compress_bound(payload_sz);
        uint8_t *comp = malloc(bound); if (!comp) return CC_ERR_NOMEM;
        int level = c->compression_level ? c->compression_level : CP_LEVEL_DEFAULT;
        int64_t cs = cp_compress(payload, payload_sz, comp, bound, level);
        if (cs < 0) { free(comp); return CC_ERR_IO; }
        payload = comp; payload_sz = (size_t)cs; free_payload = 1;
    }
    if (c->layer_flags & CC_LAYER_ENCRYPTED) {
        if (!c->has_pk) { if (free_payload) free(payload); return CC_ERR_IO; }
        cc_pipe *pipe = cc_pipe_encrypt_new(c->pk);
        if (!pipe) { if (free_payload) free(payload); return CC_ERR_NOMEM; }
        uint8_t *enc = NULL; size_t enc_len = 0;
        int rc = cc_pipe_encrypt(pipe, payload, payload_sz, &enc, &enc_len);
        cc_pipe_free(pipe);
        if (free_payload) free(payload);
        if (rc != 0) return CC_ERR_IO;
        payload = enc; payload_sz = enc_len; free_payload = 1;
    }

    size_t total = CC_HEADER_SIZE + c->meta_size + payload_sz;
    uint8_t *buf = malloc(total);
    if (!buf) { if (free_payload) free(payload); return CC_ERR_NOMEM; }

    memset(buf, 0, CC_HEADER_SIZE);
    memcpy(buf, CC_MAGIC, 4);
    buf[4] = c->version; buf[5] = (uint8_t)c->type;
    put_u16(buf+6, c->layer_flags);
    put_u64(buf+8, payload_sz);
    put_u64(buf+16, orig_sz);
    put_u32(buf+24, (uint32_t)c->meta_size);
    memcpy(buf+28, c->hash, 32);

    if (c->meta_size > 0) memcpy(buf + CC_HEADER_SIZE, c->meta, c->meta_size);
    memcpy(buf + CC_HEADER_SIZE + c->meta_size, payload, payload_sz);

    if (free_payload) {
        if (c->layer_flags & CC_LAYER_ENCRYPTED) cc_pipe_free_buf(payload);
        else free(payload);
    }
    *out = buf; *out_len = total;
    return CC_OK;
}

int cc_container_write_file(cc_container *c, const char *path) {
    uint8_t *buf = NULL; size_t len = 0;
    int rc = cc_container_write(c, &buf, &len);
    if (rc != CC_OK) return rc;
    FILE *f = fopen(path, "wb"); if (!f) { free(buf); return CC_ERR_IO; }
    size_t wr = fwrite(buf, 1, len, f); fclose(f); free(buf);
    return (wr == len) ? CC_OK : CC_ERR_IO;
}

cc_container *cc_container_open(const uint8_t *data, size_t data_len) {
    if (!data || data_len < CC_HEADER_SIZE) return NULL;
    cc_content_type detected = cc_container_detect(data, data_len);
    if (detected == CC_TYPE_UNKNOWN) return NULL;

    int is_unified = (memcmp(data, "CUTE", 4) == 0 && data[4] >= CC_CONTAINER_VERSION);
    cc_container *c = calloc(1, sizeof(cc_container)); if (!c) return NULL;

    if (is_unified) {
        c->version = data[4]; c->type = (cc_content_type)data[5];
        c->layer_flags = get_u16(data+6);
        uint64_t psz = get_u64(data+8);
        c->original_size = get_u64(data+16);
        uint32_t msz = get_u32(data+24);
        memcpy(c->hash, data+28, 32);
        if (CC_HEADER_SIZE + msz + psz > data_len) { free(c); return NULL; }

        if (msz > 0) {
            c->meta = malloc(msz); if (!c->meta) { free(c); return NULL; }
            memcpy(c->meta, data + CC_HEADER_SIZE, msz);
            c->meta_size = msz; c->owns_meta = 1;
        }

        const uint8_t *raw = data + CC_HEADER_SIZE + msz;
        size_t raw_sz = (size_t)psz;
        uint8_t *cur = malloc(raw_sz); if (!cur) { cc_container_destroy(c); return NULL; }
        memcpy(cur, raw, raw_sz); size_t cur_sz = raw_sz;

        if (c->layer_flags & CC_LAYER_ENCRYPTED) {
            if (!c->has_sk) { c->payload = cur; c->payload_size = cur_sz; c->owns_payload = 1; return c; }
            cc_pipe *pipe = cc_pipe_decrypt_new(c->sk);
            if (!pipe) { free(cur); cc_container_destroy(c); return NULL; }
            uint8_t *dec = NULL; size_t dec_len = 0;
            int rc = cc_pipe_decrypt(pipe, cur, cur_sz, &dec, &dec_len);
            cc_pipe_free(pipe); free(cur);
            if (rc != 0) { cc_container_destroy(c); return NULL; }
            cur = dec; cur_sz = dec_len;
        }
        if (c->layer_flags & CC_LAYER_COMPRESSED) {
            size_t orig = (size_t)c->original_size;
            uint8_t *dec = malloc(orig); if (!dec) { free(cur); cc_container_destroy(c); return NULL; }
            int64_t d = cp_decompress(cur, cur_sz, dec, orig); free(cur);
            if (d < 0 || (size_t)d != orig) { free(dec); cc_container_destroy(c); return NULL; }
            cur = dec; cur_sz = orig;
        }
        c->payload = cur; c->payload_size = cur_sz; c->owns_payload = 1;
    } else {
        c->type = detected; c->version = data[4]; c->layer_flags = CC_LAYER_NONE;
        c->payload = malloc(data_len); if (!c->payload) { free(c); return NULL; }
        memcpy(c->payload, data, data_len);
        c->payload_size = data_len; c->original_size = data_len; c->owns_payload = 1;
    }
    return c;
}

cc_container *cc_container_open_file(const char *path) {
    if (!path) return NULL;
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    if (fsz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)fsz); if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)fsz, f); fclose(f);
    if (rd != (size_t)fsz) { free(buf); return NULL; }
    cc_container *c = cc_container_open(buf, (size_t)fsz); free(buf); return c;
}

cc_content_type cc_container_type(const cc_container *c) { return c ? c->type : CC_TYPE_UNKNOWN; }
const void *cc_container_meta(const cc_container *c, size_t *ms) { if (!c) { if (ms) *ms=0; return NULL; } if (ms) *ms=c->meta_size; return c->meta; }
const void *cc_container_payload(const cc_container *c, size_t *ps) { if (!c) { if (ps) *ps=0; return NULL; } if (ps) *ps=c->payload_size; return c->payload; }
uint16_t cc_container_layers(const cc_container *c) { return c ? c->layer_flags : 0; }
uint64_t cc_container_original_size(const cc_container *c) { return c ? c->original_size : 0; }

void cc_container_destroy(cc_container *c) {
    if (!c) return;
    if (c->owns_meta) free(c->meta);
    if (c->owns_payload) free(c->payload);
    free(c);
}
