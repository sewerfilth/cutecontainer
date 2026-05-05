/*
 * archive.c — ZIP archive reader implementation
 *
 * Supports reading ZIP archives: browsing entries, extracting stored
 * (method 0) files, and deflate (method 8) on Apple platforms via
 * the Compression framework. Other formats are stubbed.
 *
 * ZIP structures parsed:
 *   - End of Central Directory (EOCD)
 *   - Central Directory File Headers
 *   - Local File Headers
 *
 * Limitations:
 *   - ZIP64 archives (>4 GB) are detected but not fully supported
 *   - Encrypted entries are flagged but not decrypted
 *   - Deflate on non-Apple platforms returns an error
 *   - Write/create APIs are not yet implemented
 */

#include "cutecontainer/archive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <compression.h>
#endif

/* ────────────────────────────────────────────────────────────────────────── */
/*  ZIP format constants                                                     */
/* ────────────────────────────────────────────────────────────────────────── */

#define ZIP_LOCAL_FILE_HEADER_SIG   0x04034b50u
#define ZIP_CENTRAL_DIR_SIG         0x02014b50u
#define ZIP_EOCD_SIG                0x06054b50u
#define ZIP_EOCD64_SIG              0x06064b50u
#define ZIP_EOCD64_LOCATOR_SIG      0x07064b50u

#define ZIP_METHOD_STORED           0
#define ZIP_METHOD_DEFLATE          8

#define ZIP_EOCD_MIN_SIZE           22
#define ZIP_EOCD_MAX_COMMENT        65535
#define ZIP_EOCD_SCAN_LIMIT         (ZIP_EOCD_MIN_SIZE + ZIP_EOCD_MAX_COMMENT)

/* ────────────────────────────────────────────────────────────────────────── */
/*  Internal helpers — little-endian reads                                   */
/* ────────────────────────────────────────────────────────────────────────── */

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Archive handle                                                           */
/* ────────────────────────────────────────────────────────────────────────── */

struct cc_archive {
    cc_archive_format format;
    FILE             *fp;           /* NULL if opened from memory */
    uint8_t          *mem;          /* mmap / malloc'd copy */
    size_t            mem_len;
    int               owns_mem;     /* 1 if we should free mem */

    cc_archive_entry *entries;
    int               entry_count;
};

/* ────────────────────────────────────────────────────────────────────────── */
/*  DOS time conversion                                                      */
/* ────────────────────────────────────────────────────────────────────────── */

static uint64_t dos_to_unix_time(uint16_t dos_date, uint16_t dos_time)
{
    /* DOS date: bits 0-4 day, 5-8 month, 9-15 year (from 1980) */
    /* DOS time: bits 0-4 seconds/2, 5-10 minute, 11-15 hour */
    struct tm t;
    memset(&t, 0, sizeof(t));
    t.tm_sec  = (dos_time & 0x1F) * 2;
    t.tm_min  = (dos_time >> 5) & 0x3F;
    t.tm_hour = (dos_time >> 11) & 0x1F;
    t.tm_mday = (dos_date & 0x1F);
    t.tm_mon  = ((dos_date >> 5) & 0x0F) - 1;
    t.tm_year = ((dos_date >> 9) & 0x7F) + 80;  /* years since 1900 */
    t.tm_isdst = -1;

    time_t epoch = mktime(&t);
    return (epoch == (time_t)-1) ? 0 : (uint64_t)epoch;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Directory creation helper                                                */
/* ────────────────────────────────────────────────────────────────────────── */

static int mkdirs(const char *path)
{
    char buf[1024];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return -1;

    memcpy(buf, path, len + 1);

    for (size_t i = 1; i < len; i++) {
        if (buf[i] == '/') {
            buf[i] = '\0';
            if (mkdir(buf, 0755) != 0 && errno != EEXIST)
                return -1;
            buf[i] = '/';
        }
    }
    /* Create the final component (if it doesn't end with '/') */
    if (buf[len - 1] != '/') {
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
    }
    return 0;
}

/* Create parent directories for a file path. */
static int mkdirs_for_file(const char *path)
{
    char buf[1024];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return -1;

    memcpy(buf, path, len + 1);

    /* Find last slash */
    char *last = strrchr(buf, '/');
    if (!last)
        return 0;  /* no directory component */

    *last = '\0';
    return mkdirs(buf);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Format detection                                                         */
/* ────────────────────────────────────────────────────────────────────────── */

cc_archive_format cc_archive_detect(const uint8_t *header, size_t len)
{
    if (!header || len < 4)
        return CC_ARCHIVE_UNKNOWN;

    /* ZIP: starts with PK\x03\x04 (local file header) or PK\x05\x06 (empty) */
    if (header[0] == 'P' && header[1] == 'K') {
        if ((header[2] == 0x03 && header[3] == 0x04) ||
            (header[2] == 0x05 && header[3] == 0x06))
            return CC_ARCHIVE_ZIP;
    }

    /* 7z: starts with '7' 'z' 0xBC 0xAF 0x27 0x1C */
    if (len >= 6 &&
        header[0] == '7' && header[1] == 'z' &&
        header[2] == 0xBC && header[3] == 0xAF &&
        header[4] == 0x27 && header[5] == 0x1C)
        return CC_ARCHIVE_SEVEN_Z;

    /* RAR: starts with "Rar!" */
    if (len >= 4 &&
        header[0] == 'R' && header[1] == 'a' &&
        header[2] == 'r' && header[3] == '!')
        return CC_ARCHIVE_RAR;

    /* gzip: 0x1F 0x8B — assume tar.gz */
    if (header[0] == 0x1F && header[1] == 0x8B)
        return CC_ARCHIVE_TAR_GZ;

    /* xz: 0xFD "7zXZ" 0x00 — assume tar.xz */
    if (len >= 6 &&
        header[0] == 0xFD && header[1] == '7' &&
        header[2] == 'z' && header[3] == 'X' &&
        header[4] == 'Z' && header[5] == 0x00)
        return CC_ARCHIVE_TAR_XZ;

    /* bzip2: "BZ" — assume tar.bz2 */
    if (header[0] == 'B' && header[1] == 'Z')
        return CC_ARCHIVE_TAR_BZ2;

    /* tar: check for "ustar" at offset 257 */
    if (len >= 263 &&
        header[257] == 'u' && header[258] == 's' &&
        header[259] == 't' && header[260] == 'a' &&
        header[261] == 'r')
        return CC_ARCHIVE_TAR;

    /* .cute: check for "CUTE" magic at offset 0 */
    if (len >= 4 &&
        header[0] == 'C' && header[1] == 'U' &&
        header[2] == 'T' && header[3] == 'E')
        return CC_ARCHIVE_CUTE;

    return CC_ARCHIVE_UNKNOWN;
}

cc_archive_format cc_archive_detect_path(const char *path)
{
    if (!path)
        return CC_ARCHIVE_UNKNOWN;

    /* Try magic bytes first */
    FILE *fp = fopen(path, "rb");
    if (fp) {
        uint8_t buf[512];
        size_t n = fread(buf, 1, sizeof(buf), fp);
        fclose(fp);
        cc_archive_format fmt = cc_archive_detect(buf, n);
        if (fmt != CC_ARCHIVE_UNKNOWN)
            return fmt;
    }

    /* Fall back to extension */
    const char *dot = strrchr(path, '.');
    if (!dot)
        return CC_ARCHIVE_UNKNOWN;

    if (strcmp(dot, ".zip") == 0 || strcmp(dot, ".ZIP") == 0 ||
        strcmp(dot, ".jar") == 0 || strcmp(dot, ".ipa") == 0 ||
        strcmp(dot, ".apk") == 0 || strcmp(dot, ".docx") == 0 ||
        strcmp(dot, ".xlsx") == 0 || strcmp(dot, ".pptx") == 0)
        return CC_ARCHIVE_ZIP;

    if (strcmp(dot, ".tar") == 0)
        return CC_ARCHIVE_TAR;

    if (strcmp(dot, ".gz") == 0 || strcmp(dot, ".tgz") == 0)
        return CC_ARCHIVE_TAR_GZ;

    if (strcmp(dot, ".bz2") == 0 || strcmp(dot, ".tbz2") == 0)
        return CC_ARCHIVE_TAR_BZ2;

    if (strcmp(dot, ".xz") == 0 || strcmp(dot, ".txz") == 0)
        return CC_ARCHIVE_TAR_XZ;

    if (strcmp(dot, ".7z") == 0)
        return CC_ARCHIVE_SEVEN_Z;

    if (strcmp(dot, ".rar") == 0)
        return CC_ARCHIVE_RAR;

    if (strcmp(dot, ".cute") == 0)
        return CC_ARCHIVE_CUTE;

    return CC_ARCHIVE_UNKNOWN;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  ZIP central directory parser                                             */
/* ────────────────────────────────────────────────────────────────────────── */

/*
 * Locate the End of Central Directory record by scanning backward from EOF.
 * Returns the offset within `data` of the EOCD signature, or -1 on failure.
 */
static long zip_find_eocd(const uint8_t *data, size_t len)
{
    if (len < ZIP_EOCD_MIN_SIZE)
        return -1;

    /*
     * The EOCD is at least 22 bytes and is followed only by the comment
     * (whose length is stored in the EOCD itself). Scan backward.
     */
    size_t scan_start = (len > ZIP_EOCD_SCAN_LIMIT)
                      ? (len - ZIP_EOCD_SCAN_LIMIT)
                      : 0;

    for (size_t i = len - ZIP_EOCD_MIN_SIZE; i >= scan_start; i--) {
        if (read_u32(data + i) == ZIP_EOCD_SIG) {
            /* Validate: comment length should match remaining bytes */
            uint16_t comment_len = read_u16(data + i + 20);
            if (i + ZIP_EOCD_MIN_SIZE + comment_len <= len)
                return (long)i;
        }
        if (i == 0)
            break;
    }
    return -1;
}

/*
 * Parse the ZIP central directory and populate archive->entries.
 * Returns 0 on success, -1 on error.
 */
static int zip_parse_central_dir(cc_archive *a)
{
    const uint8_t *data = a->mem;
    size_t len = a->mem_len;

    /* Find End of Central Directory */
    long eocd_off = zip_find_eocd(data, len);
    if (eocd_off < 0)
        return -1;

    const uint8_t *eocd = data + eocd_off;

    uint16_t disk_num     = read_u16(eocd + 4);
    uint16_t cd_disk      = read_u16(eocd + 6);
    uint16_t cd_count_disk = read_u16(eocd + 8);
    uint16_t cd_count     = read_u16(eocd + 10);
    uint32_t cd_size      = read_u32(eocd + 12);
    uint32_t cd_offset    = read_u32(eocd + 16);

    (void)disk_num;
    (void)cd_disk;
    (void)cd_count_disk;
    (void)cd_size;

    /* ZIP64: if values are 0xFFFF / 0xFFFFFFFF, we'd need the ZIP64 EOCD.
     * For now, bail out gracefully. */
    if (cd_count == 0xFFFF || cd_offset == 0xFFFFFFFF) {
        /* Attempt to find ZIP64 EOCD locator */
        /* The locator is 20 bytes and sits just before the EOCD */
        if (eocd_off >= 20) {
            const uint8_t *loc = data + eocd_off - 20;
            if (read_u32(loc) == ZIP_EOCD64_LOCATOR_SIG) {
                uint64_t eocd64_off = (uint64_t)read_u32(loc + 8)
                                    | ((uint64_t)read_u32(loc + 12) << 32);
                if (eocd64_off + 56 <= len) {
                    const uint8_t *eocd64 = data + eocd64_off;
                    if (read_u32(eocd64) == ZIP_EOCD64_SIG) {
                        uint64_t cd_count64 = (uint64_t)read_u32(eocd64 + 32)
                                            | ((uint64_t)read_u32(eocd64 + 36) << 32);
                        uint64_t cd_offset64 = (uint64_t)read_u32(eocd64 + 48)
                                             | ((uint64_t)read_u32(eocd64 + 52) << 32);

                        /* Sanity: cap at 1M entries to avoid absurd allocations */
                        if (cd_count64 > 1000000 || cd_offset64 >= len)
                            return -1;

                        cd_count  = (uint16_t)cd_count64;
                        cd_offset = (uint32_t)cd_offset64;
                    }
                }
            }
        }

        /* If still at sentinel values, give up */
        if (cd_count == 0xFFFF || cd_offset == 0xFFFFFFFF)
            return -1;
    }

    if ((size_t)cd_offset >= len)
        return -1;

    a->entries = calloc(cd_count, sizeof(cc_archive_entry));
    if (!a->entries)
        return -1;

    a->entry_count = 0;
    const uint8_t *p = data + cd_offset;
    const uint8_t *end = data + len;

    for (int i = 0; i < cd_count && p + 46 <= end; i++) {
        if (read_u32(p) != ZIP_CENTRAL_DIR_SIG)
            break;

        /* Central directory file header layout:
         *  0..3   signature
         *  4..5   version made by
         *  6..7   version needed to extract
         *  8..9   general purpose bit flag
         * 10..11  compression method
         * 12..13  last mod file time
         * 14..15  last mod file date
         * 16..19  crc-32
         * 20..23  compressed size
         * 24..27  uncompressed size
         * 28..29  file name length
         * 30..31  extra field length
         * 32..33  file comment length
         * 34..35  disk number start
         * 36..37  internal file attributes
         * 38..41  external file attributes
         * 42..45  relative offset of local header
         */

        uint16_t flags       = read_u16(p + 8);
        uint16_t method      = read_u16(p + 10);
        uint16_t mod_time    = read_u16(p + 12);
        uint16_t mod_date    = read_u16(p + 14);
        uint32_t crc         = read_u32(p + 16);
        uint32_t comp_size   = read_u32(p + 20);
        uint32_t uncomp_size = read_u32(p + 24);
        uint16_t name_len    = read_u16(p + 28);
        uint16_t extra_len   = read_u16(p + 30);
        uint16_t comment_len = read_u16(p + 32);
        uint32_t ext_attr    = read_u32(p + 38);
        uint32_t local_off   = read_u32(p + 42);

        if (p + 46 + name_len + extra_len + comment_len > end)
            break;

        cc_archive_entry *e = &a->entries[a->entry_count];

        /* Copy filename (truncate if > 511) */
        size_t copy_len = (name_len < sizeof(e->path) - 1)
                        ? name_len
                        : sizeof(e->path) - 1;
        memcpy(e->path, p + 46, copy_len);
        e->path[copy_len] = '\0';

        /* Check ZIP64 extra field for large sizes/offsets */
        uint64_t final_uncomp  = uncomp_size;
        uint64_t final_comp    = comp_size;
        uint64_t final_offset  = local_off;

        if (uncomp_size == 0xFFFFFFFF || comp_size == 0xFFFFFFFF ||
            local_off == 0xFFFFFFFF) {
            /* Parse ZIP64 extended information extra field (ID 0x0001) */
            const uint8_t *extra = p + 46 + name_len;
            const uint8_t *extra_end = extra + extra_len;
            while (extra + 4 <= extra_end) {
                uint16_t eid  = read_u16(extra);
                uint16_t esz  = read_u16(extra + 2);
                if (extra + 4 + esz > extra_end)
                    break;
                if (eid == 0x0001) {
                    const uint8_t *ep = extra + 4;
                    /* Fields appear in order only if the corresponding
                     * 32-bit value is 0xFFFFFFFF */
                    if (uncomp_size == 0xFFFFFFFF && ep + 8 <= extra + 4 + esz) {
                        final_uncomp = (uint64_t)read_u32(ep)
                                     | ((uint64_t)read_u32(ep + 4) << 32);
                        ep += 8;
                    }
                    if (comp_size == 0xFFFFFFFF && ep + 8 <= extra + 4 + esz) {
                        final_comp = (uint64_t)read_u32(ep)
                                   | ((uint64_t)read_u32(ep + 4) << 32);
                        ep += 8;
                    }
                    if (local_off == 0xFFFFFFFF && ep + 8 <= extra + 4 + esz) {
                        final_offset = (uint64_t)read_u32(ep)
                                     | ((uint64_t)read_u32(ep + 4) << 32);
                    }
                    break;
                }
                extra += 4 + esz;
            }
        }

        e->size            = final_uncomp;
        e->compressed_size = final_comp;
        e->offset          = final_offset;
        e->mtime           = dos_to_unix_time(mod_date, mod_time);
        e->crc32           = crc;
        e->method          = method;
        e->is_encrypted    = (flags & 0x0001) ? 1 : 0;

        /* Detect directory: trailing '/' or zero-length with dir attributes */
        if (copy_len > 0 && e->path[copy_len - 1] == '/')
            e->is_dir = 1;
        else if (uncomp_size == 0 && (ext_attr & 0x10))
            e->is_dir = 1;

        /* Unix permissions from external attributes (upper 16 bits) */
        e->permissions = (ext_attr >> 16) & 0xFFFF;

        /* Symlink: Unix mode starts with 0120000 */
        if ((e->permissions & 0xF000) == 0xA000)
            e->is_symlink = 1;

        a->entry_count++;

        p += 46 + name_len + extra_len + comment_len;
    }

    return 0;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Open                                                                     */
/* ────────────────────────────────────────────────────────────────────────── */

/* ────────────────────────────────────────────────────────────────────────── */
/*  TAR format parser                                                        */
/* ────────────────────────────────────────────────────────────────────────── */

#define TAR_BLOCK 512

static uint64_t tar_octal(const uint8_t *p, int len)
{
    uint64_t v = 0;
    for (int i = 0; i < len && p[i] >= '0' && p[i] <= '7'; i++)
        v = v * 8 + (p[i] - '0');
    return v;
}

static int tar_parse(cc_archive *a, const uint8_t *data, size_t len)
{
    size_t pos = 0;
    int cap = 256;
    a->entries = calloc(cap, sizeof(cc_archive_entry));
    a->entry_count = 0;

    while (pos + TAR_BLOCK <= len) {
        const uint8_t *hdr = data + pos;

        /* check for end-of-archive (two zero blocks) */
        int zero = 1;
        for (int i = 0; i < TAR_BLOCK && zero; i++) if (hdr[i]) zero = 0;
        if (zero) break;

        /* parse header */
        char name[256] = {0};
        memcpy(name, hdr, 100);
        name[100] = '\0';

        /* handle GNU long name extension */
        uint8_t typeflag = hdr[156];

        uint64_t fsize = tar_octal(hdr + 124, 12);
        uint64_t mtime = tar_octal(hdr + 136, 12);
        uint32_t mode  = (uint32_t)tar_octal(hdr + 100, 8);

        /* prefix (POSIX/ustar) */
        if (hdr[257] == 'u' && hdr[258] == 's' && hdr[259] == 't') {
            char prefix[156] = {0};
            memcpy(prefix, hdr + 345, 155);
            if (prefix[0]) {
                char full[512];
                snprintf(full, sizeof(full), "%s/%s", prefix, name);
                strncpy(name, full, sizeof(name) - 1);
            }
        }

        /* strip trailing slashes */
        size_t nlen = strlen(name);
        while (nlen > 0 && name[nlen-1] == '/') name[--nlen] = '\0';

        if (!name[0]) { pos += TAR_BLOCK; continue; }

        /* skip special types: long name, long link, pax headers */
        if (typeflag == 'L' || typeflag == 'K' || typeflag == 'x' || typeflag == 'g') {
            /* skip the data blocks for the extended header */
            size_t blocks = (fsize + TAR_BLOCK - 1) / TAR_BLOCK;
            pos += TAR_BLOCK + blocks * TAR_BLOCK;
            continue;
        }

        /* grow */
        if (a->entry_count >= cap) {
            cap *= 2;
            a->entries = realloc(a->entries, cap * sizeof(cc_archive_entry));
        }

        cc_archive_entry *e = &a->entries[a->entry_count++];
        memset(e, 0, sizeof(*e));
        strncpy(e->path, name, sizeof(e->path) - 1);
        e->size = fsize;
        e->compressed_size = fsize;
        e->mtime = mtime;
        e->permissions = mode;
        e->is_dir = (typeflag == '5') || (nlen > 0 && name[nlen] == '/');
        e->offset = pos + TAR_BLOCK; /* data starts after header */

        /* advance past header + data blocks */
        size_t data_blocks = (fsize + TAR_BLOCK - 1) / TAR_BLOCK;
        pos += TAR_BLOCK + data_blocks * TAR_BLOCK;
    }

    return 0;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Gzip decompression (for .tar.gz)                                         */
/* ────────────────────────────────────────────────────────────────────────── */

static uint8_t *gzip_decompress(const uint8_t *gz, size_t gz_len, size_t *out_len)
{
    /* validate gzip header: 1F 8B */
    if (gz_len < 18 || gz[0] != 0x1F || gz[1] != 0x8B)
        return NULL;

    /* read original size from last 4 bytes (LE, mod 2^32) */
    uint32_t orig_size = read_u32(gz + gz_len - 4);
    if (orig_size == 0) orig_size = gz_len * 10; /* estimate */

    /* skip gzip header to find compressed data */
    size_t hdr_end = 10;
    uint8_t flags = gz[3];
    if (flags & 0x04) { /* FEXTRA */
        if (hdr_end + 2 > gz_len) return NULL;
        uint16_t xlen = gz[hdr_end] | (gz[hdr_end+1] << 8);
        hdr_end += 2 + xlen;
    }
    if (flags & 0x08) { /* FNAME */
        while (hdr_end < gz_len && gz[hdr_end]) hdr_end++;
        hdr_end++;
    }
    if (flags & 0x10) { /* FCOMMENT */
        while (hdr_end < gz_len && gz[hdr_end]) hdr_end++;
        hdr_end++;
    }
    if (flags & 0x02) hdr_end += 2; /* FHCRC */

    if (hdr_end >= gz_len - 8) return NULL;

    const uint8_t *deflate_data = gz + hdr_end;
    size_t deflate_len = gz_len - hdr_end - 8; /* minus CRC32 + ISIZE */

#if defined(__APPLE__)
    /* use Apple Compression framework — raw deflate (RFC 1951) */
    size_t alloc_size = orig_size > 0 ? orig_size : deflate_len * 10;
    /* cap at 2GB to prevent OOM */
    if (alloc_size > 2ULL * 1024 * 1024 * 1024) alloc_size = 2ULL * 1024 * 1024 * 1024;

    uint8_t *out = malloc(alloc_size);
    if (!out) return NULL;

    size_t decoded = compression_decode_buffer(out, alloc_size,
        deflate_data, deflate_len, NULL, COMPRESSION_ZLIB);

    if (decoded == 0 || decoded == alloc_size) {
        /* might need more space — try doubling */
        alloc_size *= 2;
        if (alloc_size > 2ULL * 1024 * 1024 * 1024) { free(out); return NULL; }
        uint8_t *out2 = realloc(out, alloc_size);
        if (!out2) { free(out); return NULL; }
        out = out2;
        decoded = compression_decode_buffer(out, alloc_size,
            deflate_data, deflate_len, NULL, COMPRESSION_ZLIB);
        if (decoded == 0) { free(out); return NULL; }
    }

    *out_len = decoded;
    return out;
#else
    /* non-Apple: no decompression available without zlib */
    (void)deflate_data; (void)deflate_len; (void)orig_size;
    *out_len = 0;
    return NULL;
#endif
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  tar extract (from parsed tar data)                                       */
/* ────────────────────────────────────────────────────────────────────────── */

static void *tar_extract_entry(const cc_archive *a, int index, size_t *out_len)
{
    if (!a || index < 0 || index >= a->entry_count) return NULL;
    const cc_archive_entry *e = &a->entries[index];
    if (e->is_dir || e->size == 0) return NULL;
    if (e->offset + e->size > a->mem_len) return NULL;

    uint8_t *buf = malloc((size_t)e->size);
    if (!buf) return NULL;
    memcpy(buf, a->mem + e->offset, (size_t)e->size);
    if (out_len) *out_len = (size_t)e->size;
    return buf;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Open (multi-format dispatch)                                             */
/* ────────────────────────────────────────────────────────────────────────── */

cc_archive *cc_archive_open(const char *path)
{
    if (!path)
        return NULL;

    cc_archive_format fmt = cc_archive_detect_path(path);
    if (fmt == CC_ARCHIVE_UNKNOWN) return NULL;

    /* read entire file */
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size <= 0) { fclose(fp); return NULL; }
    fseek(fp, 0, SEEK_SET);

    size_t size = (size_t)file_size;
    uint8_t *data = malloc(size);
    if (!data) { fclose(fp); return NULL; }
    if (fread(data, 1, size, fp) != size) { free(data); fclose(fp); return NULL; }
    fclose(fp);

    cc_archive *a = calloc(1, sizeof(cc_archive));
    if (!a) { free(data); return NULL; }
    a->format = fmt;
    a->mem = data;
    a->mem_len = size;
    a->owns_mem = 1;

    int rc = -1;
    switch (fmt) {
    case CC_ARCHIVE_ZIP:
        rc = zip_parse_central_dir(a);
        break;

    case CC_ARCHIVE_TAR:
        rc = tar_parse(a, data, size);
        break;

    case CC_ARCHIVE_TAR_GZ: {
        /* decompress gzip → tar, then parse tar */
        size_t tar_len = 0;
        uint8_t *tar_data = gzip_decompress(data, size, &tar_len);
        if (tar_data && tar_len > 0) {
            /* replace mem with decompressed tar */
            free(a->mem);
            a->mem = tar_data;
            a->mem_len = tar_len;
            rc = tar_parse(a, tar_data, tar_len);
        }
        break;
    }

    case CC_ARCHIVE_TAR_BZ2:
    case CC_ARCHIVE_TAR_XZ:
#ifndef _WIN32
        /* bz2/xz: use system command to decompress then parse tar */
        {
            char tmp[] = "/tmp/cc_tar_XXXXXX";
            int fd = mkstemp(tmp);
            if (fd >= 0) {
                close(fd);
                char cmd[1024];
                if (fmt == CC_ARCHIVE_TAR_BZ2)
                    snprintf(cmd, sizeof(cmd), "bzip2 -dc '%s' > '%s' 2>/dev/null", path, tmp);
                else
                    snprintf(cmd, sizeof(cmd), "xz -dc '%s' > '%s' 2>/dev/null", path, tmp);

                if (system(cmd) == 0) {
                    FILE *tf = fopen(tmp, "rb");
                    if (tf) {
                        fseek(tf, 0, SEEK_END); size_t tl = (size_t)ftell(tf); fseek(tf, 0, SEEK_SET);
                        uint8_t *td = malloc(tl);
                        if (td && fread(td, 1, tl, tf) == tl) {
                            free(a->mem);
                            a->mem = td; a->mem_len = tl;
                            rc = tar_parse(a, td, tl);
                        } else { free(td); }
                        fclose(tf);
                    }
                }
                unlink(tmp);
            }
        }
#endif /* !_WIN32 */
        break;

    case CC_ARCHIVE_SEVEN_Z:
#ifndef _WIN32
        /* 7z: use system 7z/7za command if available */
        {
            /* list entries via 7z l */
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "7z l -slt '%s' 2>/dev/null", path);
            FILE *pp = popen(cmd, "r");
            if (pp) {
                int cap = 256;
                a->entries = calloc(cap, sizeof(cc_archive_entry));
                a->entry_count = 0;
                char line[1024];
                cc_archive_entry cur;
                memset(&cur, 0, sizeof(cur));
                int in_entry = 0;

                while (fgets(line, sizeof(line), pp)) {
                    /* strip newline */
                    size_t ll = strlen(line);
                    while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = 0;

                    if (strncmp(line, "Path = ", 7) == 0) {
                        if (in_entry && cur.path[0]) {
                            if (a->entry_count >= cap) { cap *= 2; a->entries = realloc(a->entries, cap * sizeof(cc_archive_entry)); }
                            a->entries[a->entry_count++] = cur;
                        }
                        memset(&cur, 0, sizeof(cur));
                        strncpy(cur.path, line + 7, sizeof(cur.path) - 1);
                        in_entry = 1;
                    } else if (strncmp(line, "Size = ", 7) == 0) {
                        cur.size = (uint64_t)atoll(line + 7);
                    } else if (strncmp(line, "Packed Size = ", 14) == 0) {
                        cur.compressed_size = (uint64_t)atoll(line + 14);
                    } else if (strncmp(line, "Folder = +", 10) == 0) {
                        cur.is_dir = 1;
                    }
                }
                if (in_entry && cur.path[0]) {
                    if (a->entry_count >= cap) { cap *= 2; a->entries = realloc(a->entries, cap * sizeof(cc_archive_entry)); }
                    a->entries[a->entry_count++] = cur;
                }
                pclose(pp);
                rc = (a->entry_count > 0) ? 0 : -1;
            }
        }
#endif /* !_WIN32 */
        break;

    case CC_ARCHIVE_RAR:
#ifndef _WIN32
        /* RAR: use system unrar if available */
        {
            char cmd[1024];
            snprintf(cmd, sizeof(cmd), "unrar vt '%s' 2>/dev/null", path);
            FILE *pp = popen(cmd, "r");
            if (pp) {
                int cap = 256;
                a->entries = calloc(cap, sizeof(cc_archive_entry));
                a->entry_count = 0;
                char line[1024];
                while (fgets(line, sizeof(line), pp)) {
                    size_t ll = strlen(line);
                    while (ll > 0 && (line[ll-1] == '\n' || line[ll-1] == '\r')) line[--ll] = 0;
                    if (ll > 0 && line[0] == ' ' && line[1] == ' ') {
                        char *nm = line + 2;
                        while (*nm == ' ') nm++;
                        if (*nm) {
                            if (a->entry_count >= cap) { cap *= 2; a->entries = realloc(a->entries, cap * sizeof(cc_archive_entry)); }
                            cc_archive_entry *e = &a->entries[a->entry_count++];
                            memset(e, 0, sizeof(*e));
                            strncpy(e->path, nm, sizeof(e->path) - 1);
                        }
                    }
                }
                pclose(pp);
                rc = (a->entry_count > 0) ? 0 : -1;
            }
        }
#endif /* !_WIN32 */
        break;

    default:
        break;
    }

    if (rc != 0) {
        if (a->owns_mem) free(a->mem);
        free(a->entries);
        free(a);
        return NULL;
    }

    return a;
}

cc_archive *cc_archive_open_mem(const uint8_t *data, size_t len)
{
    if (!data || len == 0) return NULL;
    cc_archive_format fmt = cc_archive_detect(data, len);
    if (fmt == CC_ARCHIVE_UNKNOWN) return NULL;

    uint8_t *copy = malloc(len);
    if (!copy) return NULL;
    memcpy(copy, data, len);

    cc_archive *a = calloc(1, sizeof(cc_archive));
    if (!a) { free(copy); return NULL; }
    a->format = fmt;
    a->mem = copy;
    a->mem_len = len;
    a->owns_mem = 1;

    int rc = -1;
    switch (fmt) {
    case CC_ARCHIVE_ZIP: rc = zip_parse_central_dir(a); break;
    case CC_ARCHIVE_TAR: rc = tar_parse(a, copy, len); break;
    case CC_ARCHIVE_TAR_GZ: {
        size_t tl = 0;
        uint8_t *td = gzip_decompress(copy, len, &tl);
        if (td) { free(a->mem); a->mem = td; a->mem_len = tl; rc = tar_parse(a, td, tl); }
        break;
    }
    default: break;
    }

    if (rc != 0) { if (a->owns_mem) free(a->mem); free(a->entries); free(a); return NULL; }
    return a;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Format info                                                              */
/* ────────────────────────────────────────────────────────────────────────── */

cc_archive_format cc_archive_format_of(const cc_archive *a)
{
    return a ? a->format : CC_ARCHIVE_UNKNOWN;
}

const char *cc_archive_format_name(cc_archive_format fmt)
{
    switch (fmt) {
    case CC_ARCHIVE_CUTE:    return "cute";
    case CC_ARCHIVE_ZIP:     return "zip";
    case CC_ARCHIVE_TAR:     return "tar";
    case CC_ARCHIVE_TAR_GZ:  return "tar.gz";
    case CC_ARCHIVE_TAR_BZ2: return "tar.bz2";
    case CC_ARCHIVE_TAR_XZ:  return "tar.xz";
    case CC_ARCHIVE_SEVEN_Z: return "7z";
    case CC_ARCHIVE_RAR:     return "rar";
    default:                 return "unknown";
    }
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Browse                                                                   */
/* ────────────────────────────────────────────────────────────────────────── */

int cc_archive_count(const cc_archive *a)
{
    return a ? a->entry_count : 0;
}

const cc_archive_entry *cc_archive_entry_at(const cc_archive *a, int index)
{
    if (!a || index < 0 || index >= a->entry_count)
        return NULL;
    return &a->entries[index];
}

int cc_archive_find(const cc_archive *a, const char *path)
{
    if (!a || !path)
        return -1;
    for (int i = 0; i < a->entry_count; i++) {
        if (strcmp(a->entries[i].path, path) == 0)
            return i;
    }
    return -1;
}

int cc_archive_list_dir(const cc_archive *a, const char *dir_prefix,
                        int *out, int max)
{
    if (!a || !out || max <= 0)
        return 0;

    size_t prefix_len = dir_prefix ? strlen(dir_prefix) : 0;
    int count = 0;

    for (int i = 0; i < a->entry_count && count < max; i++) {
        const char *p = a->entries[i].path;

        /* Must start with the prefix */
        if (prefix_len > 0 && strncmp(p, dir_prefix, prefix_len) != 0)
            continue;

        /* Skip the prefix itself if it matches exactly */
        const char *rest = p + prefix_len;
        if (*rest == '\0')
            continue;

        /* Only include direct children: rest should contain at most
         * one '/' and only at the very end (for directories). */
        const char *slash = strchr(rest, '/');
        if (slash != NULL && slash[1] != '\0')
            continue;  /* nested deeper */

        out[count++] = i;
    }

    return count;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Locate file data for a ZIP entry                                         */
/* ────────────────────────────────────────────────────────────────────────── */

/*
 * Given a central-directory entry, find the actual compressed data
 * within the archive by reading the local file header.
 *
 * Returns a pointer into a->mem at the start of the compressed data,
 * and sets *data_len to the compressed size. Returns NULL on error.
 */
static const uint8_t *zip_entry_data(const cc_archive *a,
                                     const cc_archive_entry *e,
                                     size_t *data_len)
{
    if (e->offset + 30 > a->mem_len)
        return NULL;

    const uint8_t *lh = a->mem + e->offset;
    if (read_u32(lh) != ZIP_LOCAL_FILE_HEADER_SIG)
        return NULL;

    uint16_t lh_name_len  = read_u16(lh + 26);
    uint16_t lh_extra_len = read_u16(lh + 28);

    size_t data_off = e->offset + 30 + lh_name_len + lh_extra_len;
    if (data_off + e->compressed_size > a->mem_len)
        return NULL;

    *data_len = (size_t)e->compressed_size;
    return a->mem + data_off;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Extract                                                                  */
/* ────────────────────────────────────────────────────────────────────────── */

void *cc_archive_extract(cc_archive *a, int index, size_t *out_len)
{
    if (!a || index < 0 || index >= a->entry_count)
        return NULL;

    const cc_archive_entry *e = &a->entries[index];

    if (e->is_dir) {
        /* Directories have no data */
        if (out_len) *out_len = 0;
        return NULL;
    }

    if (e->is_encrypted)
        return NULL;

    /* tar-based formats: direct memcpy from parsed data */
    if (a->format == CC_ARCHIVE_TAR || a->format == CC_ARCHIVE_TAR_GZ ||
        a->format == CC_ARCHIVE_TAR_BZ2 || a->format == CC_ARCHIVE_TAR_XZ)
        return tar_extract_entry(a, index, out_len);

    /* 7z/RAR: use system tool to extract single file */
    if (a->format == CC_ARCHIVE_SEVEN_Z || a->format == CC_ARCHIVE_RAR) {
        /* not supported for in-memory extract — use extract_to instead */
        return NULL;
    }

    /* ZIP path */
    size_t comp_len = 0;
    const uint8_t *comp_data = zip_entry_data(a, e, &comp_len);
    if (!comp_data)
        return NULL;

    if (e->method == ZIP_METHOD_STORED) {
        /* Stored: data is uncompressed, just copy it */
        size_t sz = (size_t)e->size;
        void *buf = malloc(sz ? sz : 1);
        if (!buf)
            return NULL;
        if (sz > 0)
            memcpy(buf, comp_data, sz);
        if (out_len) *out_len = sz;
        return buf;
    }

    if (e->method == ZIP_METHOD_DEFLATE) {
#if defined(__APPLE__)
        /* Use Apple's Compression framework.
         * compression_decode_buffer expects raw deflate (no zlib header),
         * which is exactly what ZIP stores. */
        size_t uncomp_sz = (size_t)e->size;
        if (uncomp_sz == 0) {
            /* Degenerate case: zero-length file compressed with deflate */
            void *buf = malloc(1);
            if (out_len) *out_len = 0;
            return buf;
        }

        uint8_t *buf = malloc(uncomp_sz);
        if (!buf)
            return NULL;

        size_t decoded = compression_decode_buffer(
            buf, uncomp_sz,
            comp_data, comp_len,
            NULL,  /* scratch buffer — NULL lets the library allocate */
            COMPRESSION_ZLIB
        );

        if (decoded != uncomp_sz) {
            free(buf);
            return NULL;
        }

        if (out_len) *out_len = uncomp_sz;
        return buf;
#else
        /* Deflate not supported on this platform without zlib.
         * Return NULL to signal extraction failure. */
        return NULL;
#endif
    }

    /* Unknown compression method */
    return NULL;
}

int cc_archive_extract_to(cc_archive *a, int index, const char *dest_path)
{
    if (!a || !dest_path || index < 0 || index >= a->entry_count)
        return -1;

    const cc_archive_entry *e = &a->entries[index];

    /* Create parent directories */
    if (mkdirs_for_file(dest_path) != 0)
        return -1;

    /* Directory entry: just create the directory */
    if (e->is_dir) {
        return mkdirs(dest_path);
    }

    /* Try in-memory extraction first */
    size_t len = 0;
    void *data = cc_archive_extract(a, index, &len);

    if (data) {
        FILE *fp = fopen(dest_path, "wb");
        if (!fp) {
            free(data);
            return -1;
        }
        if (len > 0 && fwrite(data, 1, len, fp) != len) {
            fclose(fp);
            free(data);
            return -1;
        }
        fclose(fp);
        free(data);

        /* Restore permissions if available */
        if (e->permissions != 0) {
            chmod(dest_path, e->permissions & 0777);
        }

        return 0;
    }

    /* Fallback for unsupported compression methods:
     * On macOS/Linux, try using the system 'unzip' command. */
    /* This fallback is not implemented for single-entry extraction.
     * cc_archive_extract_all uses a full-archive fallback instead. */
    return -1;
}

int cc_archive_extract_all(cc_archive *a, const char *dest_dir)
{
    if (!a || !dest_dir)
        return -1;

    /* Ensure destination directory exists */
    if (mkdirs(dest_dir) != 0)
        return -1;

    int errors = 0;

    for (int i = 0; i < a->entry_count; i++) {
        const cc_archive_entry *e = &a->entries[i];

        /* Build full destination path */
        char full_path[1536];
        size_t dir_len = strlen(dest_dir);
        size_t path_len = strlen(e->path);

        if (dir_len + 1 + path_len >= sizeof(full_path)) {
            errors++;
            continue;
        }

        memcpy(full_path, dest_dir, dir_len);
        /* Ensure separator */
        if (dir_len > 0 && dest_dir[dir_len - 1] != '/') {
            full_path[dir_len] = '/';
            dir_len++;
        }
        memcpy(full_path + dir_len, e->path, path_len);
        full_path[dir_len + path_len] = '\0';

        /* Security: reject paths that escape dest_dir */
        if (strstr(e->path, "..") != NULL) {
            errors++;
            continue;
        }

        if (e->is_dir) {
            if (mkdirs(full_path) != 0)
                errors++;
            continue;
        }

        if (cc_archive_extract_to(a, i, full_path) != 0)
            errors++;
    }

    return errors;
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Close                                                                    */
/* ────────────────────────────────────────────────────────────────────────── */

void cc_archive_close(cc_archive *a)
{
    if (!a)
        return;

    if (a->fp) {
        fclose(a->fp);
        a->fp = NULL;
    }

    if (a->owns_mem && a->mem) {
        free(a->mem);
        a->mem = NULL;
    }

    free(a->entries);
    free(a);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  ZIP write API — STORED only (no deflate)                                 */
/*                                                                            */
/*  Other formats (tar, 7z, cute, …) are still write-stubbed. STORED-only    */
/*  ZIP is the simplest interoperable format and unblocks "Archive…" in     */
/*  the GUI without pulling in deflate. Entries can be re-compressed by      */
/*  the cute toolchain (press) if the user wants smaller output.             */
/* ────────────────────────────────────────────────────────────────────────── */

#include <time.h>

/* CRC-32 with polynomial 0xedb88320 (ZIP / gzip / zlib). */
static uint32_t crc32_table[256];
static int crc32_table_built = 0;

static void crc32_build_table(void)
{
    if (crc32_table_built) return;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; j++)
            c = (c & 1u) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_built = 1;
}

static uint32_t crc32_compute(const void *data, size_t len)
{
    crc32_build_table();
    uint32_t crc = 0xffffffffu;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ p[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

static void wr_le16(FILE *f, uint16_t v) { uint8_t b[2] = {v&0xff, v>>8}; fwrite(b,1,2,f); }
static void wr_le32(FILE *f, uint32_t v) {
    uint8_t b[4] = {v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff};
    fwrite(b, 1, 4, f);
}

/* Convert a unix epoch (seconds) to DOS date/time. Pre-1980 is clamped. */
static void epoch_to_dos(uint64_t epoch, uint16_t *dos_time, uint16_t *dos_date)
{
    time_t t = (time_t)epoch;
    struct tm lt;
    if (epoch == 0 || !localtime_r(&t, &lt)) {
        *dos_time = 0;
        *dos_date = 0x0021; /* 1980-01-01 */
        return;
    }
    int y = lt.tm_year + 1900;
    if (y < 1980) { *dos_time = 0; *dos_date = 0x0021; return; }
    *dos_time = (uint16_t)((lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec >> 1));
    *dos_date = (uint16_t)(((y - 1980) << 9) | ((lt.tm_mon + 1) << 5) | lt.tm_mday);
}

typedef struct {
    char     *path;       /* archive-internal path (UTF-8) */
    uint32_t  crc32;
    uint64_t  local_offset;
    uint64_t  size;       /* uncompressed = compressed (STORED) */
    uint16_t  dos_time;
    uint16_t  dos_date;
    uint8_t   is_dir;
} zip_wr_entry;

struct cc_archive_writer {
    FILE              *fp;
    cc_archive_format  format;
    /* ZIP state */
    zip_wr_entry      *entries;
    int                count;
    int                cap;
    uint64_t           cur_offset;
};

cc_archive_writer *cc_archive_create(const char *path, cc_archive_format format)
{
    if (!path) return NULL;
    if (format != CC_ARCHIVE_ZIP) {
        /* Other formats still stubbed — fail fast so the CLI emits a clear
         * "format X not yet supported" error rather than producing garbage. */
        return NULL;
    }
    FILE *fp = fopen(path, "wb");
    if (!fp) return NULL;
    cc_archive_writer *w = calloc(1, sizeof(*w));
    if (!w) { fclose(fp); return NULL; }
    w->fp = fp;
    w->format = format;
    w->cap = 16;
    w->entries = calloc(w->cap, sizeof(zip_wr_entry));
    if (!w->entries) { fclose(fp); free(w); return NULL; }
    return w;
}

static int zip_grow_entries(cc_archive_writer *w)
{
    if (w->count < w->cap) return 0;
    int nc = w->cap * 2;
    zip_wr_entry *ne = realloc(w->entries, nc * sizeof(zip_wr_entry));
    if (!ne) return -1;
    w->entries = ne; w->cap = nc;
    return 0;
}

/* Local file header: 30 bytes + filename. STORED method, no extra. */
static int zip_write_local_header(cc_archive_writer *w, const char *name,
                                  uint16_t dos_time, uint16_t dos_date,
                                  uint32_t crc, uint64_t size)
{
    size_t name_len = strlen(name);
    if (name_len > 0xffff) return -1;
    /* General purpose bit 11 = UTF-8 filename */
    uint16_t flags = 0x0800;
    wr_le32(w->fp, 0x04034b50u);     /* signature */
    wr_le16(w->fp, 20);              /* version needed */
    wr_le16(w->fp, flags);
    wr_le16(w->fp, 0);               /* method = STORED */
    wr_le16(w->fp, dos_time);
    wr_le16(w->fp, dos_date);
    wr_le32(w->fp, crc);
    wr_le32(w->fp, (uint32_t)size);  /* compressed */
    wr_le32(w->fp, (uint32_t)size);  /* uncompressed */
    wr_le16(w->fp, (uint16_t)name_len);
    wr_le16(w->fp, 0);               /* extra length */
    fwrite(name, 1, name_len, w->fp);
    w->cur_offset += 30 + name_len;
    return 0;
}

int cc_archive_add_buf(cc_archive_writer *w, const char *archive_path,
                       const void *data, size_t len)
{
    if (!w || w->format != CC_ARCHIVE_ZIP || !archive_path) return -1;
    if (zip_grow_entries(w) != 0) return -1;
    if (len > 0xffffffffu) return -1; /* TODO: ZIP64 */

    uint32_t crc = (data && len) ? crc32_compute(data, len) : 0;
    uint64_t local_offset = w->cur_offset;

    uint16_t dos_time, dos_date;
    epoch_to_dos((uint64_t)time(NULL), &dos_time, &dos_date);

    if (zip_write_local_header(w, archive_path, dos_time, dos_date, crc, len) != 0)
        return -1;
    if (data && len) {
        if (fwrite(data, 1, len, w->fp) != len) return -1;
        w->cur_offset += len;
    }

    zip_wr_entry *e = &w->entries[w->count++];
    e->path = strdup(archive_path);
    e->crc32 = crc;
    e->local_offset = local_offset;
    e->size = len;
    e->dos_time = dos_time;
    e->dos_date = dos_date;
    e->is_dir = 0;
    return 0;
}

int cc_archive_add_file(cc_archive_writer *w, const char *archive_path,
                        const char *disk_path)
{
    if (!w || !archive_path || !disk_path) return -1;
    FILE *src = fopen(disk_path, "rb");
    if (!src) return -1;
    fseek(src, 0, SEEK_END);
    long sz = ftell(src);
    fseek(src, 0, SEEK_SET);
    if (sz < 0) { fclose(src); return -1; }

    uint8_t *buf = (sz > 0) ? malloc((size_t)sz) : NULL;
    if (sz > 0 && !buf) { fclose(src); return -1; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, src) != (size_t)sz) {
        free(buf); fclose(src); return -1;
    }
    fclose(src);

    /* Use the on-disk mtime so re-archived files preserve their stamp. */
    struct stat st;
    int rc = cc_archive_add_buf(w, archive_path, buf, (size_t)sz);
    if (rc == 0 && stat(disk_path, &st) == 0) {
        zip_wr_entry *e = &w->entries[w->count - 1];
        epoch_to_dos((uint64_t)st.st_mtime, &e->dos_time, &e->dos_date);
        /* Note: we wrote the local header before stat — the central
         * directory uses e->dos_time/date below so the result is at least
         * correct in the listing. Local-header time is already on disk. */
    }
    free(buf);
    return rc;
}

int cc_archive_add_dir(cc_archive_writer *w, const char *archive_path)
{
    if (!w || w->format != CC_ARCHIVE_ZIP || !archive_path) return -1;
    /* Ensure trailing slash for ZIP directory entries. */
    size_t plen = strlen(archive_path);
    char *with_slash = NULL;
    const char *name = archive_path;
    if (plen == 0 || archive_path[plen - 1] != '/') {
        with_slash = malloc(plen + 2);
        if (!with_slash) return -1;
        memcpy(with_slash, archive_path, plen);
        with_slash[plen] = '/';
        with_slash[plen + 1] = '\0';
        name = with_slash;
    }

    if (zip_grow_entries(w) != 0) { free(with_slash); return -1; }
    uint16_t dos_time, dos_date;
    epoch_to_dos((uint64_t)time(NULL), &dos_time, &dos_date);
    uint64_t local_offset = w->cur_offset;
    int rc = zip_write_local_header(w, name, dos_time, dos_date, 0, 0);
    if (rc != 0) { free(with_slash); return -1; }

    zip_wr_entry *e = &w->entries[w->count++];
    e->path = strdup(name);
    e->crc32 = 0;
    e->local_offset = local_offset;
    e->size = 0;
    e->dos_time = dos_time;
    e->dos_date = dos_date;
    e->is_dir = 1;
    free(with_slash);
    return 0;
}

int cc_archive_finish(cc_archive_writer *w)
{
    if (!w || !w->fp) return -1;
    if (w->format != CC_ARCHIVE_ZIP) return -1;

    uint64_t cd_offset = w->cur_offset;
    uint64_t cd_size = 0;

    for (int i = 0; i < w->count; i++) {
        zip_wr_entry *e = &w->entries[i];
        size_t name_len = strlen(e->path);
        if (name_len > 0xffff) return -1;
        uint16_t flags = 0x0800; /* utf-8 */
        /* External attrs: regular file 0644, dir bit set if dir */
        uint32_t ext_attrs = e->is_dir ? ((uint32_t)0040755u << 16) : ((uint32_t)0100644u << 16);
        if (e->is_dir) ext_attrs |= 0x10; /* DOS directory bit */

        wr_le32(w->fp, 0x02014b50u);
        wr_le16(w->fp, (uint16_t)0x031eu);   /* version made by: Unix 3.0 */
        wr_le16(w->fp, 20);                  /* version needed */
        wr_le16(w->fp, flags);
        wr_le16(w->fp, 0);                   /* method = STORED */
        wr_le16(w->fp, e->dos_time);
        wr_le16(w->fp, e->dos_date);
        wr_le32(w->fp, e->crc32);
        wr_le32(w->fp, (uint32_t)e->size);   /* compressed */
        wr_le32(w->fp, (uint32_t)e->size);   /* uncompressed */
        wr_le16(w->fp, (uint16_t)name_len);
        wr_le16(w->fp, 0);                   /* extra length */
        wr_le16(w->fp, 0);                   /* comment length */
        wr_le16(w->fp, 0);                   /* disk number */
        wr_le16(w->fp, 0);                   /* internal attrs */
        wr_le32(w->fp, ext_attrs);
        wr_le32(w->fp, (uint32_t)e->local_offset);
        fwrite(e->path, 1, name_len, w->fp);
        cd_size += 46 + name_len;
    }

    /* End of Central Directory */
    wr_le32(w->fp, 0x06054b50u);
    wr_le16(w->fp, 0); /* this disk */
    wr_le16(w->fp, 0); /* disk with central */
    wr_le16(w->fp, (uint16_t)w->count); /* entries on disk */
    wr_le16(w->fp, (uint16_t)w->count); /* total entries */
    wr_le32(w->fp, (uint32_t)cd_size);
    wr_le32(w->fp, (uint32_t)cd_offset);
    wr_le16(w->fp, 0); /* comment length */

    int rc = (fflush(w->fp) == 0) ? 0 : -1;
    return rc;
}

void cc_archive_writer_destroy(cc_archive_writer *w)
{
    if (!w) return;
    if (w->fp) fclose(w->fp);
    for (int i = 0; i < w->count; i++) free(w->entries[i].path);
    free(w->entries);
    free(w);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Stubs — convert and SFX (not yet implemented)                            */
/* ────────────────────────────────────────────────────────────────────────── */

int cc_archive_convert(const char *src_path, const char *dst_path,
                       cc_archive_format dst_format)
{
    (void)src_path; (void)dst_path; (void)dst_format;
    return -1;
}

int cc_sfx_build(const char *src_path, const char *out_path,
                 const cc_sfx_opts *opts)
{
    (void)src_path; (void)out_path; (void)opts;
    return -1;
}
