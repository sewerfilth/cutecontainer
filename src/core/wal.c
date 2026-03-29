/*
 * wal.c — Write-Ahead Log rail implementation
 *
 * Pure C. No external libraries. Uses the crypt/sha3 module
 * (already in cutecontainer) for hash chaining.
 */

#include "cutecontainer/wal.h"
#include "cutecontainer/crypt/sha3.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── LE helpers ── */

static void w_put16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void w_put32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void w_put64(uint8_t *p, uint64_t v) { w_put32(p,(uint32_t)v); w_put32(p+4,(uint32_t)(v>>32)); }

static uint16_t w_get16(const uint8_t *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t w_get32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t w_get64(const uint8_t *p) { return (uint64_t)w_get32(p)|((uint64_t)w_get32(p+4)<<32); }

/* ── WAL handle ── */

#define WAL_INITIAL_CAP 64

struct cc_wal {
    cc_wal_entry  *entries;
    uint32_t       count;
    uint32_t       cap;
    cc_wal_summary summary;
    uint8_t        last_hash[32];   /* full hash of last entry for chaining */
};

/* ── Hash an entry for chain linking ── */

static void hash_entry(const cc_wal_entry *e, uint8_t out[32])
{
    cc_sha3_256((const uint8_t *)e, sizeof(cc_wal_entry), out);
}

/* ── Now ── */

static uint64_t wal_now(void)
{
    return (uint64_t)time(NULL);
}

/* ── Create ── */

cc_wal *cc_wal_create(void)
{
    cc_wal *w = calloc(1, sizeof(cc_wal));
    if (!w) return NULL;
    w->cap = WAL_INITIAL_CAP;
    w->entries = calloc(w->cap, sizeof(cc_wal_entry));
    if (!w->entries) { free(w); return NULL; }
    memcpy(w->summary.magic, CC_WAL_MAGIC, 4);
    w->summary.version = CC_WAL_VERSION;
    return w;
}

/* ── Open from buffer (find WAL trailer by scanning backward from EOF) ── */

cc_wal *cc_wal_open(const uint8_t *data, size_t data_len)
{
    if (!data || data_len < 8) return NULL;

    /* read footer: last 8 bytes = magic(4) + wal_size(4) */
    const uint8_t *footer = data + data_len - 8;
    if (memcmp(footer, CC_WAL_MAGIC, 4) != 0) return NULL;

    uint32_t wal_size = w_get32(footer + 4);
    if (wal_size > data_len || wal_size < 16) return NULL;

    const uint8_t *wal_start = data + data_len - wal_size;

    /* verify header magic */
    if (memcmp(wal_start, CC_WAL_MAGIC, 4) != 0) return NULL;

    uint32_t header_wal_size = w_get32(wal_start + 4);
    uint32_t entry_count = w_get32(wal_start + 8);
    /* flags at wal_start + 12 */

    if (header_wal_size != wal_size) return NULL;

    /* entries start at offset 16 */
    const uint8_t *entries_start = wal_start + 16;
    size_t entries_bytes = (size_t)entry_count * CC_WAL_ENTRY_SIZE;
    size_t expected = 16 + entries_bytes + CC_WAL_SUMMARY_SIZE + 8;
    if (expected != wal_size) return NULL;

    cc_wal *w = cc_wal_create();
    if (!w) return NULL;

    /* grow if needed */
    if (entry_count > w->cap) {
        free(w->entries);
        w->cap = entry_count + 16;
        w->entries = calloc(w->cap, sizeof(cc_wal_entry));
        if (!w->entries) { free(w); return NULL; }
    }

    /* deserialize entries */
    for (uint32_t i = 0; i < entry_count; i++) {
        const uint8_t *p = entries_start + (size_t)i * CC_WAL_ENTRY_SIZE;
        cc_wal_entry *e = &w->entries[i];

        e->type         = p[0];
        e->version      = p[1];
        e->flags        = w_get16(p + 2);
        e->sequence     = w_get32(p + 4);
        e->timestamp    = w_get64(p + 8);
        e->content_type = (cc_content_type)p[16];
        e->layer_flags  = w_get16(p + 18);
        e->wrap_count   = w_get16(p + 20);
        e->original_size = w_get64(p + 24);
        e->stored_size   = w_get64(p + 32);
        memcpy(e->collection_id, p + 40, 16);
        e->collection_seq = w_get32(p + 56);
        memcpy(e->content_hash, p + 60, 32);
        memcpy(e->prev_hash, p + 92, 8);
    }

    w->count = entry_count;

    /* deserialize summary */
    const uint8_t *sp = entries_start + entries_bytes;
    memcpy(w->summary.magic, sp, 4);
    w->summary.version = sp[4];
    w->summary.flags = w_get16(sp + 6);
    w->summary.entry_count = w_get32(sp + 8);
    w->summary.first_entry_offset = w_get32(sp + 12);
    w->summary.content_type = (cc_content_type)sp[16];
    w->summary.layer_flags = w_get16(sp + 18);
    w->summary.wrap_count = w_get16(sp + 20);
    w->summary.original_size = w_get64(sp + 24);
    w->summary.stored_size = w_get64(sp + 32);
    w->summary.created_at = w_get64(sp + 40);
    w->summary.modified_at = w_get64(sp + 48);
    /* content_hash would be at 56 but summary struct is packed differently */

    /* rebuild last_hash from final entry */
    if (w->count > 0)
        hash_entry(&w->entries[w->count - 1], w->last_hash);

    return w;
}

cc_wal *cc_wal_open_file(const char *path)
{
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    cc_wal *w = (rd == (size_t)sz) ? cc_wal_open(buf, (size_t)sz) : NULL;
    free(buf);
    return w;
}

/* ── Append ── */

int cc_wal_append(cc_wal *w, const cc_wal_entry *entry)
{
    if (!w || !entry) return -1;

    /* grow if needed */
    if (w->count >= w->cap) {
        uint32_t new_cap = w->cap * 2;
        cc_wal_entry *new_entries = realloc(w->entries, new_cap * sizeof(cc_wal_entry));
        if (!new_entries) return -1;
        w->entries = new_entries;
        w->cap = new_cap;
    }

    cc_wal_entry *e = &w->entries[w->count];
    *e = *entry;
    e->sequence = w->count;

    /* chain: prev_hash = truncated hash of previous entry */
    if (w->count > 0) {
        memcpy(e->prev_hash, w->last_hash, 8);
    } else {
        memset(e->prev_hash, 0, 8);
    }

    /* update chain state */
    hash_entry(e, w->last_hash);

    w->count++;

    /* update summary */
    w->summary.entry_count = w->count;
    w->summary.content_type = e->content_type;
    w->summary.layer_flags = e->layer_flags;
    w->summary.wrap_count = e->wrap_count;
    w->summary.original_size = e->original_size;
    w->summary.stored_size = e->stored_size;
    w->summary.modified_at = e->timestamp;
    memcpy(w->summary.content_hash, e->content_hash, 32);
    if (w->count == 1)
        w->summary.created_at = e->timestamp;

    return 0;
}

int cc_wal_log_created(cc_wal *w, cc_content_type type,
                       uint16_t layers, uint64_t orig_size,
                       uint64_t stored_size, const uint8_t hash[32])
{
    cc_wal_entry e;
    memset(&e, 0, sizeof(e));
    e.type = CC_WAL_CREATED;
    e.version = CC_WAL_VERSION;
    e.timestamp = wal_now();
    e.content_type = type;
    e.layer_flags = layers;
    e.original_size = orig_size;
    e.stored_size = stored_size;
    if (hash) memcpy(e.content_hash, hash, 32);
    return cc_wal_append(w, &e);
}

int cc_wal_log_wrapped(cc_wal *w, uint16_t wrap_count)
{
    if (!w || w->count == 0) return -1;
    cc_wal_entry e;
    memset(&e, 0, sizeof(e));
    e.type = CC_WAL_WRAPPED;
    e.version = CC_WAL_VERSION;
    e.timestamp = wal_now();
    /* inherit current state */
    const cc_wal_entry *last = &w->entries[w->count - 1];
    e.content_type = last->content_type;
    e.layer_flags = last->layer_flags;
    e.wrap_count = wrap_count;
    e.original_size = last->original_size;
    e.stored_size = last->stored_size;
    memcpy(e.content_hash, last->content_hash, 32);
    return cc_wal_append(w, &e);
}

int cc_wal_log_collection(cc_wal *w, const uint8_t collection_id[16],
                          uint32_t seq)
{
    if (!w || w->count == 0) return -1;
    cc_wal_entry e;
    memset(&e, 0, sizeof(e));
    e.type = CC_WAL_COLLECTION;
    e.version = CC_WAL_VERSION;
    e.timestamp = wal_now();
    const cc_wal_entry *last = &w->entries[w->count - 1];
    e.content_type = last->content_type;
    e.layer_flags = last->layer_flags;
    e.wrap_count = last->wrap_count;
    e.original_size = last->original_size;
    e.stored_size = last->stored_size;
    memcpy(e.content_hash, last->content_hash, 32);
    memcpy(e.collection_id, collection_id, 16);
    e.collection_seq = seq;
    return cc_wal_append(w, &e);
}

/* ── Read ── */

uint32_t cc_wal_count(const cc_wal *w) { return w ? w->count : 0; }

const cc_wal_entry *cc_wal_get(const cc_wal *w, uint32_t index)
{
    if (!w || index >= w->count) return NULL;
    return &w->entries[index];
}

const cc_wal_summary *cc_wal_summary_get(const cc_wal *w)
{
    return w ? &w->summary : NULL;
}

cc_content_type cc_wal_content_type(const cc_wal *w) { return w ? w->summary.content_type : CC_TYPE_UNKNOWN; }
uint64_t cc_wal_original_size(const cc_wal *w) { return w ? w->summary.original_size : 0; }
uint64_t cc_wal_stored_size(const cc_wal *w) { return w ? w->summary.stored_size : 0; }
uint16_t cc_wal_layer_flags(const cc_wal *w) { return w ? w->summary.layer_flags : 0; }
uint16_t cc_wal_wrap_count(const cc_wal *w) { return w ? w->summary.wrap_count : 0; }
uint64_t cc_wal_created_at(const cc_wal *w) { return w ? w->summary.created_at : 0; }
uint64_t cc_wal_modified_at(const cc_wal *w) { return w ? w->summary.modified_at : 0; }

/* ── Serialize ── */

static void serialize_entry(const cc_wal_entry *e, uint8_t out[CC_WAL_ENTRY_SIZE])
{
    memset(out, 0, CC_WAL_ENTRY_SIZE);
    out[0] = e->type;
    out[1] = e->version;
    w_put16(out + 2, e->flags);
    w_put32(out + 4, e->sequence);
    w_put64(out + 8, e->timestamp);
    out[16] = (uint8_t)e->content_type;
    w_put16(out + 18, e->layer_flags);
    w_put16(out + 20, e->wrap_count);
    w_put64(out + 24, e->original_size);
    w_put64(out + 32, e->stored_size);
    memcpy(out + 40, e->collection_id, 16);
    w_put32(out + 56, e->collection_seq);
    memcpy(out + 60, e->content_hash, 32);
    memcpy(out + 92, e->prev_hash, 8);
}

int cc_wal_serialize(const cc_wal *w, uint8_t **out, size_t *out_len)
{
    if (!w || !out || !out_len) return -1;

    size_t entries_bytes = (size_t)w->count * CC_WAL_ENTRY_SIZE;
    size_t total = 16 + entries_bytes + CC_WAL_SUMMARY_SIZE + 8;

    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;

    /* header */
    memcpy(buf, CC_WAL_MAGIC, 4);
    w_put32(buf + 4, (uint32_t)total);
    w_put32(buf + 8, w->count);
    w_put32(buf + 12, 0); /* flags */

    /* entries */
    for (uint32_t i = 0; i < w->count; i++)
        serialize_entry(&w->entries[i], buf + 16 + (size_t)i * CC_WAL_ENTRY_SIZE);

    /* summary */
    uint8_t *sp = buf + 16 + entries_bytes;
    memcpy(sp, CC_WAL_MAGIC, 4);
    sp[4] = w->summary.version;
    w_put16(sp + 6, w->summary.flags);
    w_put32(sp + 8, w->summary.entry_count);
    w_put32(sp + 12, 16); /* first_entry_offset */
    sp[16] = (uint8_t)w->summary.content_type;
    w_put16(sp + 18, w->summary.layer_flags);
    w_put16(sp + 20, w->summary.wrap_count);
    w_put64(sp + 24, w->summary.original_size);
    w_put64(sp + 32, w->summary.stored_size);
    w_put64(sp + 40, w->summary.created_at);
    w_put64(sp + 48, w->summary.modified_at);
    /* pad to CC_WAL_SUMMARY_SIZE */

    /* footer (mirror of header for backward scan) */
    uint8_t *fp = buf + total - 8;
    memcpy(fp, CC_WAL_MAGIC, 4);
    w_put32(fp + 4, (uint32_t)total);

    *out = buf;
    *out_len = total;
    return 0;
}

int cc_wal_write_file(const cc_wal *w, const char *path)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = cc_wal_serialize(w, &buf, &len);
    if (rc != 0) return rc;
    FILE *f = fopen(path, "wb");
    if (!f) { free(buf); return -1; }
    size_t wr = fwrite(buf, 1, len, f);
    fclose(f);
    free(buf);
    return (wr == len) ? 0 : -1;
}

/* ── Integrity ── */

int cc_wal_verify_chain(const cc_wal *w)
{
    if (!w) return -1;
    if (w->count == 0) return 0;

    /* first entry should have zero prev_hash */
    uint8_t zero[8] = {0};
    if (memcmp(w->entries[0].prev_hash, zero, 8) != 0) return -1;

    uint8_t h[32];
    for (uint32_t i = 1; i < w->count; i++) {
        hash_entry(&w->entries[i - 1], h);
        if (memcmp(w->entries[i].prev_hash, h, 8) != 0) return -1;
    }

    return 0;
}

/* ── Collection ── */

int cc_wal_merge(cc_wal *dst, const cc_wal *src)
{
    if (!dst || !src) return -1;
    for (uint32_t i = 0; i < src->count; i++) {
        int rc = cc_wal_append(dst, &src->entries[i]);
        if (rc != 0) return rc;
    }
    return 0;
}

int cc_wal_find_collection(const cc_wal *w, const uint8_t collection_id[16],
                           uint32_t *out, int max)
{
    if (!w || !collection_id || !out) return 0;
    int found = 0;
    for (uint32_t i = 0; i < w->count && found < max; i++) {
        if (w->entries[i].type == CC_WAL_COLLECTION &&
            memcmp(w->entries[i].collection_id, collection_id, 16) == 0) {
            out[found++] = i;
        }
    }
    return found;
}

/* ── Destroy ── */

void cc_wal_destroy(cc_wal *w)
{
    if (!w) return;
    free(w->entries);
    free(w);
}
