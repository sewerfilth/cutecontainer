/*
 * volume.c — Game asset volume implementation
 *
 * Pure C. Uses press module for per-asset compression,
 * SHA3 for content hashing, WAL for the table of contents.
 */

#include "cutecontainer/volume.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt/sha3.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
extern char **environ;
#else
#include <windows.h>
#endif

/* ── LE helpers ── */

static void v_put16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void v_put32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void v_put64(uint8_t *p, uint64_t v) { v_put32(p,(uint32_t)v); v_put32(p+4,(uint32_t)(v>>32)); }

static uint16_t v_get16(const uint8_t *p) { return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t v_get32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t v_get64(const uint8_t *p) { return (uint64_t)v_get32(p)|((uint64_t)v_get32(p+4)<<32); }

/* ── Entry serialization (fixed 328 bytes per entry) ── */

#define VOL_ENTRY_DISK_SIZE 328  /* 256 path + 8+8+8 sizes + 4 flags + 2+2 type/group + 32 hash + 8 pad */

static void serialize_entry(const cc_vol_entry *e, uint8_t out[VOL_ENTRY_DISK_SIZE])
{
    memset(out, 0, VOL_ENTRY_DISK_SIZE);
    memcpy(out, e->path, 256);
    v_put64(out + 256, e->offset);
    v_put64(out + 264, e->stored_size);
    v_put64(out + 272, e->original_size);
    v_put32(out + 280, e->flags);
    v_put16(out + 284, e->wrap_type);
    v_put16(out + 286, e->group);
    memcpy(out + 288, e->hash, 32);
}

static void deserialize_entry(const uint8_t in[VOL_ENTRY_DISK_SIZE], cc_vol_entry *e)
{
    memset(e, 0, sizeof(*e));
    memcpy(e->path, in, 256);
    e->path[255] = '\0';
    e->offset        = v_get64(in + 256);
    e->stored_size   = v_get64(in + 264);
    e->original_size = v_get64(in + 272);
    e->flags         = v_get32(in + 280);
    e->wrap_type     = v_get16(in + 284);
    e->group         = v_get16(in + 286);
    memcpy(e->hash, in + 288, 32);
}

/* ── Manifest format ──
 *
 *   [4]  "VOLM" magic
 *   [4]  entry_count
 *   [entry_count × VOL_ENTRY_DISK_SIZE]  entries
 */

#define VOL_MANIFEST_MAGIC "VOLM"

/* ── Volume struct ── */

struct cc_volume {
    cc_vol_entry *entries;
    int           entry_count;
    /* file-backed: keep the fd/mmap for on-demand loading */
    uint8_t      *file_data;
    size_t        file_len;
    size_t        payload_offset;  /* byte offset to start of payload section */
    int           owns_data;
    char          source_path[512]; /* path the volume was mounted from */
    char          overlay_path[512]; /* writable user data dir */
    int           overlay_init;
    /* exec manifest (NULL if not executable) */
    cc_exec_manifest *exec;
};

/* ── Mount ── */

cc_volume *cc_vol_mount_mem(const uint8_t *data, size_t len)
{
    if (!data || len < CC_HEADER_SIZE + 8) return NULL;

    /* parse container header to find meta section */
    if (memcmp(data, "CUTE", 4) != 0) return NULL;

    uint64_t payload_sz = v_get64(data + 8);
    uint32_t meta_sz    = v_get32(data + 24);

    const uint8_t *meta = data + CC_HEADER_SIZE;
    if (CC_HEADER_SIZE + meta_sz + payload_sz > len) return NULL;

    /* parse manifest from meta */
    if (meta_sz < 8 || memcmp(meta, VOL_MANIFEST_MAGIC, 4) != 0) return NULL;

    uint32_t ec = v_get32(meta + 4);
    if (8 + (size_t)ec * VOL_ENTRY_DISK_SIZE > meta_sz) return NULL;

    cc_volume *vol = calloc(1, sizeof(cc_volume));
    if (!vol) return NULL;

    vol->entry_count = (int)ec;
    vol->entries = calloc(ec, sizeof(cc_vol_entry));
    if (!vol->entries) { free(vol); return NULL; }

    for (uint32_t i = 0; i < ec; i++)
        deserialize_entry(meta + 8 + (size_t)i * VOL_ENTRY_DISK_SIZE, &vol->entries[i]);

    vol->file_data = (uint8_t *)data;
    vol->file_len = len;
    vol->payload_offset = CC_HEADER_SIZE + meta_sz;
    vol->owns_data = 0;

    return vol;
}

cc_volume *cc_vol_mount(const char *path)
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
    if (rd != (size_t)sz) { free(buf); return NULL; }

    cc_volume *vol = cc_vol_mount_mem(buf, (size_t)sz);
    if (!vol) { free(buf); return NULL; }
    vol->owns_data = 1;
    strncpy(vol->source_path, path, sizeof(vol->source_path) - 1);
    return vol;
}

void cc_vol_unmount(cc_volume *vol)
{
    if (!vol) return;
    free(vol->entries);
    if (vol->owns_data) free(vol->file_data);
    free(vol);
}

/* ── Query ── */

int cc_vol_asset_count(const cc_volume *vol) { return vol ? vol->entry_count : 0; }

const char *cc_vol_asset_path(const cc_volume *vol, int index)
{
    if (!vol || index < 0 || index >= vol->entry_count) return NULL;
    return vol->entries[index].path;
}

const cc_vol_entry *cc_vol_asset_entry(const cc_volume *vol, int index)
{
    if (!vol || index < 0 || index >= vol->entry_count) return NULL;
    return &vol->entries[index];
}

int cc_vol_find(const cc_volume *vol, const char *path)
{
    if (!vol || !path) return -1;
    for (int i = 0; i < vol->entry_count; i++)
        if (strcmp(vol->entries[i].path, path) == 0) return i;
    return -1;
}

int cc_vol_find_group(const cc_volume *vol, uint16_t group, int *out, int max)
{
    if (!vol || !out) return 0;
    int n = 0;
    for (int i = 0; i < vol->entry_count && n < max; i++)
        if (vol->entries[i].group == group) out[n++] = i;
    return n;
}

int cc_vol_find_prefix(const cc_volume *vol, const char *prefix, int *out, int max)
{
    if (!vol || !prefix || !out) return 0;
    size_t plen = strlen(prefix);
    int n = 0;
    for (int i = 0; i < vol->entry_count && n < max; i++)
        if (strncmp(vol->entries[i].path, prefix, plen) == 0) out[n++] = i;
    return n;
}

int cc_vol_find_type(const cc_volume *vol, uint16_t wrap_type, int *out, int max)
{
    if (!vol || !out) return 0;
    int n = 0;
    for (int i = 0; i < vol->entry_count && n < max; i++)
        if (vol->entries[i].wrap_type == wrap_type) out[n++] = i;
    return n;
}

uint64_t cc_vol_total_stored(const cc_volume *vol)
{
    if (!vol) return 0;
    uint64_t t = 0;
    for (int i = 0; i < vol->entry_count; i++) t += vol->entries[i].stored_size;
    return t;
}

uint64_t cc_vol_total_original(const cc_volume *vol)
{
    if (!vol) return 0;
    uint64_t t = 0;
    for (int i = 0; i < vol->entry_count; i++) t += vol->entries[i].original_size;
    return t;
}

/* ── Load ── */

void *cc_vol_load_index(cc_volume *vol, int index, size_t *out_len)
{
    if (!vol || index < 0 || index >= vol->entry_count) return NULL;
    const cc_vol_entry *e = &vol->entries[index];

    const uint8_t *src = vol->file_data + vol->payload_offset + e->offset;

    /* bounds check */
    if (vol->payload_offset + e->offset + e->stored_size > vol->file_len)
        return NULL;

    if (e->flags & CC_VOL_COMPRESS) {
        /* decompress */
        uint8_t *buf = malloc((size_t)e->original_size);
        if (!buf) return NULL;
        int64_t ds = cp_decompress(src, (size_t)e->stored_size,
                                   buf, (size_t)e->original_size);
        if (ds < 0 || (uint64_t)ds != e->original_size) { free(buf); return NULL; }
        if (out_len) *out_len = (size_t)e->original_size;
        return buf;
    } else {
        /* raw copy */
        uint8_t *buf = malloc((size_t)e->stored_size);
        if (!buf) return NULL;
        memcpy(buf, src, (size_t)e->stored_size);
        if (out_len) *out_len = (size_t)e->stored_size;
        return buf;
    }
}

void *cc_vol_load(cc_volume *vol, const char *path, size_t *out_len)
{
    int idx = cc_vol_find(vol, path);
    if (idx < 0) return NULL;
    return cc_vol_load_index(vol, idx, out_len);
}

int cc_vol_load_into(cc_volume *vol, int index, void *buf, size_t buf_len)
{
    if (!vol || !buf || index < 0 || index >= vol->entry_count) return -1;
    const cc_vol_entry *e = &vol->entries[index];

    if (buf_len < e->original_size) return -1;

    const uint8_t *src = vol->file_data + vol->payload_offset + e->offset;
    if (vol->payload_offset + e->offset + e->stored_size > vol->file_len)
        return -1;

    if (e->flags & CC_VOL_COMPRESS) {
        int64_t ds = cp_decompress(src, (size_t)e->stored_size,
                                   (uint8_t *)buf, (size_t)e->original_size);
        return (ds >= 0 && (uint64_t)ds == e->original_size) ? 0 : -1;
    } else {
        memcpy(buf, src, (size_t)e->stored_size);
        return 0;
    }
}

void cc_vol_free(void *buf) { free(buf); }

/* ── Builder ── */

#define BUILDER_INITIAL_CAP 256

struct cc_vol_builder {
    char          out_path[512];
    cc_vol_entry *entries;
    int           count;
    int           cap;
    /* payload accumulator */
    uint8_t      *payload;
    size_t        payload_len;
    size_t        payload_cap;
    int           finished;
    cc_exec_manifest *exec;
};

cc_vol_builder *cc_vol_builder_create(const char *out_path)
{
    cc_vol_builder *b = calloc(1, sizeof(cc_vol_builder));
    if (!b) return NULL;
    strncpy(b->out_path, out_path, sizeof(b->out_path) - 1);
    b->cap = BUILDER_INITIAL_CAP;
    b->entries = calloc(b->cap, sizeof(cc_vol_entry));
    b->payload_cap = 1024 * 1024;
    b->payload = malloc(b->payload_cap);
    if (!b->entries || !b->payload) {
        free(b->entries); free(b->payload); free(b);
        return NULL;
    }
    return b;
}

static int builder_grow_payload(cc_vol_builder *b, size_t need)
{
    if (b->payload_len + need <= b->payload_cap) return 0;
    size_t new_cap = b->payload_cap * 2;
    while (new_cap < b->payload_len + need) new_cap *= 2;
    uint8_t *np = realloc(b->payload, new_cap);
    if (!np) return -1;
    b->payload = np;
    b->payload_cap = new_cap;
    return 0;
}

int cc_vol_builder_add_buf(cc_vol_builder *b, const char *asset_path,
                           const void *data, size_t len, uint32_t flags)
{
    if (!b || !asset_path || !data || b->finished) return -1;

    /* grow entry array */
    if (b->count >= b->cap) {
        int new_cap = b->cap * 2;
        cc_vol_entry *ne = realloc(b->entries, new_cap * sizeof(cc_vol_entry));
        if (!ne) return -1;
        b->entries = ne;
        b->cap = new_cap;
    }

    cc_vol_entry *e = &b->entries[b->count];
    memset(e, 0, sizeof(*e));
    strncpy(e->path, asset_path, sizeof(e->path) - 1);
    e->flags = flags;
    e->original_size = len;

    /* hash original data */
    cc_sha3_256((const uint8_t *)data, len, e->hash);

    if (flags & CC_VOL_COMPRESS) {
        /* compress */
        size_t bound = cp_compress_bound(len);
        if (builder_grow_payload(b, bound) != 0) return -1;

        int64_t cs = cp_compress((const uint8_t *)data, len,
                                 b->payload + b->payload_len, bound, 5);
        if (cs < 0) return -1;
        e->offset = b->payload_len;
        e->stored_size = (uint64_t)cs;
        b->payload_len += (size_t)cs;
    } else {
        /* raw */
        if (builder_grow_payload(b, len) != 0) return -1;
        e->offset = b->payload_len;
        e->stored_size = len;
        memcpy(b->payload + b->payload_len, data, len);
        b->payload_len += len;
    }

    b->count++;
    return 0;
}

int cc_vol_builder_add_file(cc_vol_builder *b, const char *asset_path,
                            const char *disk_path, uint32_t flags)
{
    if (!disk_path) return -1;
    FILE *f = fopen(disk_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return -1; }
    int rc = cc_vol_builder_add_buf(b, asset_path, buf, (size_t)sz, flags);
    free(buf);
    return rc;
}

void cc_vol_builder_set_wrap(cc_vol_builder *b, uint16_t wrap_type)
{
    if (b && b->count > 0) b->entries[b->count - 1].wrap_type = wrap_type;
}

void cc_vol_builder_set_group(cc_vol_builder *b, uint16_t group)
{
    if (b && b->count > 0) b->entries[b->count - 1].group = group;
}

int cc_vol_builder_finish(cc_vol_builder *b)
{
    if (!b || b->finished) return -1;
    b->finished = 1;

    /* build manifest */
    size_t manifest_sz = 8 + (size_t)b->count * VOL_ENTRY_DISK_SIZE;
    uint8_t *manifest = calloc(1, manifest_sz);
    if (!manifest) return -1;

    memcpy(manifest, VOL_MANIFEST_MAGIC, 4);
    v_put32(manifest + 4, (uint32_t)b->count);

    for (int i = 0; i < b->count; i++)
        serialize_entry(&b->entries[i], manifest + 8 + (size_t)i * VOL_ENTRY_DISK_SIZE);

    /* build WAL */
    cc_wal *w = cc_wal_create();
    uint8_t vol_hash[32];
    cc_sha3_256(b->payload, b->payload_len, vol_hash);

    uint64_t total_orig = 0;
    for (int i = 0; i < b->count; i++) total_orig += b->entries[i].original_size;

    cc_wal_log_created(w, CC_TYPE_RAW, CC_LAYER_NONE, total_orig, b->payload_len, vol_hash);

    /* log each asset as a collection entry with volume-wide UUID */
    uint8_t vol_id[16];
    memcpy(vol_id, vol_hash, 16); /* use first 16 bytes of hash as volume UUID */
    for (int i = 0; i < b->count; i++)
        cc_wal_log_collection(w, vol_id, (uint32_t)i);

    uint8_t *wal_buf = NULL; size_t wal_len = 0;
    cc_wal_serialize(w, &wal_buf, &wal_len);
    cc_wal_destroy(w);

    /* assemble: container header + manifest + payload + WAL */
    size_t total = CC_HEADER_SIZE + manifest_sz + b->payload_len + wal_len;
    uint8_t *out = calloc(1, total);
    if (!out) { free(manifest); free(wal_buf); return -1; }

    /* header */
    memcpy(out, "CUTE", 4);
    out[4] = 0x05; /* version */
    out[5] = CC_TYPE_RAW; /* content type */
    v_put64(out + 8, b->payload_len + wal_len); /* payload_size includes WAL */
    v_put64(out + 16, total_orig); /* original size */
    v_put32(out + 24, (uint32_t)manifest_sz);
    memcpy(out + 28, vol_hash, 32);

    /* manifest */
    memcpy(out + CC_HEADER_SIZE, manifest, manifest_sz);
    free(manifest);

    /* payload */
    memcpy(out + CC_HEADER_SIZE + manifest_sz, b->payload, b->payload_len);

    /* WAL trailer */
    memcpy(out + CC_HEADER_SIZE + manifest_sz + b->payload_len, wal_buf, wal_len);
    free(wal_buf);

    /* write file */
    FILE *f = fopen(b->out_path, "wb");
    if (!f) { free(out); return -1; }
    size_t wr = fwrite(out, 1, total, f);
    fclose(f);
    free(out);

    return (wr == total) ? 0 : -1;
}

void cc_vol_builder_destroy(cc_vol_builder *b)
{
    if (!b) return;
    if (!b->finished) cc_vol_builder_finish(b);
    free(b->entries);
    free(b->payload);
    free(b->exec);
    free(b);
}

/* ══════════════════════════════════════════════════════════════
 * Overlay filesystem — writable user data dir
 * ══════════════════════════════════════════════════════════════ */

static void ensure_dir(const char *path)
{
#ifndef _WIN32
    mkdir(path, 0755);
#else
    CreateDirectoryA(path, NULL);
#endif
}

/* cross-platform setenv */
static void xsetenv(const char *key, const char *val)
{
#ifndef _WIN32
    setenv(key, val, 1);
#else
    SetEnvironmentVariableA(key, val);
#endif
}

/* cross-platform access check */
static int xexists(const char *path)
{
#ifndef _WIN32
    return access(path, F_OK) == 0;
#else
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#endif
}

/* cross-platform chmod (no-op on Windows) */
static void xchmod(const char *path, int executable)
{
#ifndef _WIN32
    if (executable) chmod(path, 0755);
#else
    (void)path; (void)executable;
#endif
}

static void ensure_parent_dirs(const char *full_path)
{
    char buf[1024];
    strncpy(buf, full_path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *p = buf;
    while ((p = strchr(p + 1, '/')) != NULL) {
        *p = '\0';
        ensure_dir(buf);
        *p = '/';
    }
}

const char *cc_vol_overlay_path(cc_volume *vol)
{
    if (!vol) return NULL;
    if (vol->overlay_init) return vol->overlay_path[0] ? vol->overlay_path : NULL;
    vol->overlay_init = 1;

    /* need a bundle_id from exec manifest, or derive from source path */
    const char *bid = NULL;
    if (vol->exec && vol->exec->bundle_id[0])
        bid = vol->exec->bundle_id;

    if (!bid) {
        /* derive from filename */
        const char *slash = strrchr(vol->source_path, '/');
        bid = slash ? slash + 1 : vol->source_path;
    }

    if (!bid || !bid[0]) return NULL;

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

#if defined(__APPLE__)
    snprintf(vol->overlay_path, sizeof(vol->overlay_path),
             "%s/Library/Application Support/%s", home, bid);
#elif defined(_WIN32)
    const char *appdata = getenv("APPDATA");
    if (!appdata) appdata = home;
    snprintf(vol->overlay_path, sizeof(vol->overlay_path), "%s/%s", appdata, bid);
#else
    snprintf(vol->overlay_path, sizeof(vol->overlay_path),
             "%s/.local/share/%s", home, bid);
#endif

    ensure_dir(vol->overlay_path);

    /* create standard subdirs */
    char sub[1024];
    const char *dirs[] = { "saves", "config", "mods", "cache", "logs", NULL };
    for (int i = 0; dirs[i]; i++) {
        snprintf(sub, sizeof(sub), "%s/%s", vol->overlay_path, dirs[i]);
        ensure_dir(sub);
    }

    return vol->overlay_path;
}

void *cc_vol_load_overlay(cc_volume *vol, const char *path, size_t *out_len)
{
    if (!vol || !path) return NULL;

    /* check overlay first */
    const char *ovl = cc_vol_overlay_path(vol);
    if (ovl) {
        char full[1024];
        snprintf(full, sizeof(full), "%s/%s", ovl, path);
        FILE *f = fopen(full, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0) {
                uint8_t *buf = malloc((size_t)sz);
                if (buf && fread(buf, 1, (size_t)sz, f) == (size_t)sz) {
                    fclose(f);
                    if (out_len) *out_len = (size_t)sz;
                    return buf;
                }
                free(buf);
            }
            fclose(f);
        }
    }

    /* fall back to volume */
    return cc_vol_load(vol, path, out_len);
}

int cc_vol_write_overlay(cc_volume *vol, const char *path,
                         const void *data, size_t len)
{
    if (!vol || !path || !data) return -1;
    const char *ovl = cc_vol_overlay_path(vol);
    if (!ovl) return -1;

    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", ovl, path);
    ensure_parent_dirs(full);

    FILE *f = fopen(full, "wb");
    if (!f) return -1;
    size_t wr = fwrite(data, 1, len, f);
    fclose(f);
    return (wr == len) ? 0 : -1;
}

int cc_vol_delete_overlay(cc_volume *vol, const char *path)
{
    if (!vol || !path) return -1;
    const char *ovl = cc_vol_overlay_path(vol);
    if (!ovl) return -1;

    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", ovl, path);
    return remove(full);
}

int cc_vol_list_overlay(cc_volume *vol, const char *subdir,
                        char out[][256], int max)
{
    if (!vol || !out) return 0;
    const char *ovl = cc_vol_overlay_path(vol);
    if (!ovl) return 0;

    char dir_path[1024];
    if (subdir)
        snprintf(dir_path, sizeof(dir_path), "%s/%s", ovl, subdir);
    else
        snprintf(dir_path, sizeof(dir_path), "%s", ovl);

#ifndef _WIN32
    DIR *d = opendir(dir_path);
    if (!d) return 0;
    int n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && n < max) {
        if (ent->d_name[0] == '.') continue;
        strncpy(out[n], ent->d_name, 255);
        out[n][255] = '\0';
        n++;
    }
    closedir(d);
    return n;
#else
    /* Windows: FindFirstFile */
    return 0;
#endif
}

int cc_vol_overlay_exists(cc_volume *vol, const char *path)
{
    if (!vol || !path) return 0;
    const char *ovl = cc_vol_overlay_path(vol);
    if (!ovl) return 0;
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", ovl, path);
#ifndef _WIN32
    return xexists(full);
#else
    return GetFileAttributesA(full) != INVALID_FILE_ATTRIBUTES;
#endif
}

uint64_t cc_vol_overlay_size(cc_volume *vol)
{
    /* simplified — just stat the top-level overlay dir entries */
    if (!vol) return 0;
    const char *ovl = cc_vol_overlay_path(vol);
    if (!ovl) return 0;

    uint64_t total = 0;
#ifndef _WIN32
    {
        DIR *d = opendir(ovl);
        if (!d) return 0;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", ovl, ent->d_name);
            struct stat st;
            if (stat(full, &st) == 0) total += (uint64_t)st.st_size;
        }
        closedir(d);
    }
#else
    (void)ovl;
#endif
    return total;
}

/* ══════════════════════════════════════════════════════════════
 * Executable volume — launch support
 * ══════════════════════════════════════════════════════════════ */

/* ── Exec manifest: serialize as "EXEC" section in manifest ── */

#define EXEC_MAGIC "EXEC"
#define EXEC_ENTRY_DISK_SIZE 1000  /* generous fixed size per entry */

/* ── Builder: set exec manifest ── */

void cc_vol_builder_set_exec(cc_vol_builder *b, const cc_exec_manifest *manifest)
{
    if (!b || !manifest) return;
    if (!b->exec) b->exec = calloc(1, sizeof(cc_exec_manifest));
    if (b->exec) *b->exec = *manifest;
}

void cc_vol_builder_add_entry_point(cc_vol_builder *b,
                                     cc_platform platform,
                                     cc_interpreter interpreter,
                                     const char *asset_path,
                                     const char *args,
                                     uint32_t flags)
{
    if (!b || !asset_path) return;
    if (!b->exec) {
        b->exec = calloc(1, sizeof(cc_exec_manifest));
        if (!b->exec) return;
    }
    if (b->exec->entry_count >= CC_EXEC_MAX_ENTRIES) return;

    cc_exec_entry *e = &b->exec->entries[b->exec->entry_count++];
    memset(e, 0, sizeof(*e));
    e->platform = platform;
    e->interpreter = interpreter;
    strncpy(e->asset_path, asset_path, sizeof(e->asset_path) - 1);
    if (args) strncpy(e->args, args, sizeof(e->args) - 1);
    e->flags = flags;
}

void cc_vol_builder_set_bundle(cc_vol_builder *b,
                                const char *author,
                                const char *bundle_id,
                                const char *display_name,
                                const char *version)
{
    if (!b) return;
    if (!b->exec) {
        b->exec = calloc(1, sizeof(cc_exec_manifest));
        if (!b->exec) return;
    }
    if (author) strncpy(b->exec->author, author, sizeof(b->exec->author) - 1);
    if (bundle_id) strncpy(b->exec->bundle_id, bundle_id, sizeof(b->exec->bundle_id) - 1);
    if (display_name && b->exec->entry_count > 0)
        strncpy(b->exec->entries[0].display_name, display_name, 63);
    if (version && b->exec->entry_count > 0)
        strncpy(b->exec->entries[0].version, version, 31);
}

/* ── Runtime: detect current platform ── */

static cc_platform detect_platform(void)
{
#if defined(__APPLE__)
    #if TARGET_OS_IPHONE
    return CC_PLAT_IOS;
    #else
    return CC_PLAT_MACOS;
    #endif
#elif defined(__linux__) && defined(__ANDROID__)
    return CC_PLAT_ANDROID;
#elif defined(__linux__)
    return CC_PLAT_LINUX;
#elif defined(_WIN32)
    return CC_PLAT_WINDOWS;
#elif defined(__EMSCRIPTEN__)
    return CC_PLAT_WASM;
#else
    return CC_PLAT_ANY;
#endif
}

/* ── Runtime: query ── */

const cc_exec_manifest *cc_vol_exec_manifest(const cc_volume *vol)
{
    return vol ? vol->exec : NULL;
}

const cc_exec_entry *cc_vol_exec_entry_for_platform(const cc_volume *vol)
{
    if (!vol || !vol->exec) return NULL;
    cc_platform plat = detect_platform();
    const cc_exec_manifest *m = vol->exec;

    /* exact match first */
    for (uint32_t i = 0; i < m->entry_count; i++)
        if (m->entries[i].platform == plat) return &m->entries[i];

    /* fallback to CC_PLAT_ANY */
    for (uint32_t i = 0; i < m->entry_count; i++)
        if (m->entries[i].platform == CC_PLAT_ANY) return &m->entries[i];

    return NULL;
}

int cc_vol_exec_can_run(const cc_exec_entry *entry)
{
    if (!entry) return 0;
    if (entry->interpreter == CC_INTERP_NONE) return 1; /* native binary */

#ifndef _WIN32
    const char *cmd = NULL;
    switch (entry->interpreter) {
    case CC_INTERP_SHELL:  cmd = "/bin/sh"; break;
    case CC_INTERP_LUA:    cmd = "lua"; break;
    case CC_INTERP_PYTHON: cmd = "python3"; break;
    case CC_INTERP_NODE:   cmd = "node"; break;
    case CC_INTERP_RUBY:   cmd = "ruby"; break;
    case CC_INTERP_PERL:   cmd = "perl"; break;
    case CC_INTERP_WASM:   cmd = "wasmtime"; break;
    case CC_INTERP_JAVA:   cmd = "java"; break;
    case CC_INTERP_DOTNET: cmd = "dotnet"; break;
    case CC_INTERP_CUSTOM: cmd = entry->custom_interp; break;
    default: return 0;
    }
    /* check if interpreter exists on PATH */
    char check[256];
    snprintf(check, sizeof(check), "command -v %s > /dev/null 2>&1", cmd);
    return system(check) == 0;
#else
    /* Windows: check via WHERE */
    return 1; /* simplified — assume available */
#endif
}

/* ── Runtime: execute ── */

static int make_sandbox(char *sandbox_path, size_t cap)
{
#ifndef _WIN32
    snprintf(sandbox_path, cap, "/tmp/cute-exec-XXXXXX");
    return mkdtemp(sandbox_path) ? 0 : -1;
#else
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(sandbox_path, cap, "%scute-exec-%u", tmp, (unsigned)GetCurrentProcessId());
    CreateDirectoryA(sandbox_path, NULL);
    return 0;
#endif
}

static int extract_asset_to(cc_volume *vol, int index, const char *dir)
{
    const cc_vol_entry *e = cc_vol_asset_entry(vol, index);
    if (!e) return -1;

    size_t len = 0;
    void *data = cc_vol_load_index(vol, index, &len);
    if (!data) return -1;

    /* create subdirectories if needed */
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s/%s", dir, e->path);

    /* ensure parent dirs exist */
    char *slash = full_path;
    while ((slash = strchr(slash + 1, '/')) != NULL) {
        *slash = '\0';
#ifndef _WIN32
        mkdir(full_path, 0755);
#else
        CreateDirectoryA(full_path, NULL);
#endif
        *slash = '/';
    }

    FILE *f = fopen(full_path, "wb");
    if (!f) { cc_vol_free(data); return -1; }
    fwrite(data, 1, len, f);
    fclose(f);
    cc_vol_free(data);

    xchmod(full_path, 1);

    return 0;
}

static void cleanup_sandbox(const char *path)
{
#ifndef _WIN32
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    system(cmd);
#else
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rmdir /s /q \"%s\"", path);
    system(cmd);
#endif
}

int cc_vol_exec_args(cc_volume *vol, const char **extra_argv, int extra_argc)
{
    if (!vol || !vol->exec) return -1;

    const cc_exec_entry *entry = cc_vol_exec_entry_for_platform(vol);
    if (!entry) return -1;

    /* create sandbox */
    char sandbox[512];
    if (make_sandbox(sandbox, sizeof(sandbox)) != 0) return -1;

    /* extract entry point asset */
    int ep_idx = cc_vol_find(vol, entry->asset_path);
    if (ep_idx < 0) { cleanup_sandbox(sandbox); return -1; }
    if (extract_asset_to(vol, ep_idx, sandbox) != 0) {
        cleanup_sandbox(sandbox);
        return -1;
    }

    /* extract PRELOAD assets */
    if (entry->flags & CC_EXEC_PRELOAD_ALL) {
        for (int i = 0; i < vol->entry_count; i++) {
            if (i == ep_idx) continue;
            extract_asset_to(vol, i, sandbox);
        }
    } else {
        /* extract only CC_VOL_PRELOAD-flagged assets */
        for (int i = 0; i < vol->entry_count; i++) {
            if (i == ep_idx) continue;
            if (vol->entries[i].flags & CC_VOL_PRELOAD)
                extract_asset_to(vol, i, sandbox);
        }
    }

    /* build command */
    char ep_path[1024];
    snprintf(ep_path, sizeof(ep_path), "%s/%s", sandbox, entry->asset_path);

    xchmod(ep_path, 1);

    /* set environment (cross-platform) */
    const char *ovl = cc_vol_overlay_path(vol);
    xsetenv("CUTE_VOLUME", vol->source_path);
    xsetenv("CUTE_SANDBOX", sandbox);
    if (ovl) xsetenv("CUTE_USERDATA", ovl);
    if (ovl) { char sp[1024]; snprintf(sp, sizeof(sp), "%s/saves", ovl); xsetenv("CUTE_SAVES", sp); }
    if (ovl) { char mp[1024]; snprintf(mp, sizeof(mp), "%s/mods", ovl); xsetenv("CUTE_MODS", mp); }
    if (entry->display_name[0])
        xsetenv("CUTE_APP_NAME", entry->display_name);

    /* build argv */
    const char *argv_buf[64];
    int argc = 0;

    if (entry->interpreter != CC_INTERP_NONE) {
        switch (entry->interpreter) {
        case CC_INTERP_SHELL:  argv_buf[argc++] = "/bin/sh"; break;
        case CC_INTERP_LUA:    argv_buf[argc++] = "lua"; break;
        case CC_INTERP_PYTHON: argv_buf[argc++] = "python3"; break;
        case CC_INTERP_NODE:   argv_buf[argc++] = "node"; break;
        case CC_INTERP_RUBY:   argv_buf[argc++] = "ruby"; break;
        case CC_INTERP_PERL:   argv_buf[argc++] = "perl"; break;
        case CC_INTERP_WASM:   argv_buf[argc++] = "wasmtime"; break;
        case CC_INTERP_JAVA:   argv_buf[argc++] = "java"; argv_buf[argc++] = "-jar"; break;
        case CC_INTERP_DOTNET: argv_buf[argc++] = "dotnet"; break;
        case CC_INTERP_CUSTOM: argv_buf[argc++] = entry->custom_interp; break;
        default: break;
        }
    }

    argv_buf[argc++] = ep_path;

    /* manifest args (simple space-split) */
    char args_copy[512];
    if (entry->args[0]) {
        strncpy(args_copy, entry->args, sizeof(args_copy) - 1);
        args_copy[sizeof(args_copy) - 1] = '\0';
        char *tok = strtok(args_copy, " ");
        while (tok && argc < 60) {
            argv_buf[argc++] = tok;
            tok = strtok(NULL, " ");
        }
    }

    /* extra args from caller */
    for (int i = 0; i < extra_argc && argc < 62; i++)
        argv_buf[argc++] = extra_argv[i];

    argv_buf[argc] = NULL;

    /* exec */
    int exit_code = -1;

#ifndef _WIN32
    pid_t pid;
    int rc = posix_spawn(&pid, argv_buf[0], NULL, NULL,
                         (char *const *)argv_buf, environ);
    if (rc == 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) exit_code = WEXITSTATUS(status);
    }
#else
    /* Windows: use CreateProcess */
    char cmdline[4096] = {0};
    for (int i = 0; i < argc; i++) {
        if (i > 0) strcat(cmdline, " ");
        strcat(cmdline, "\"");
        strcat(cmdline, argv_buf[i]);
        strcat(cmdline, "\"");
    }
    STARTUPINFOA si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, sandbox, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code;
        GetExitCodeProcess(pi.hProcess, &code);
        exit_code = (int)code;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
#endif

    /* cleanup */
    if (entry->flags & CC_EXEC_CLEANUP)
        cleanup_sandbox(sandbox);

    return exit_code;
}

int cc_vol_exec(cc_volume *vol)
{
    return cc_vol_exec_args(vol, NULL, 0);
}
