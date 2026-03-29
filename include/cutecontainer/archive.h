/*
 * archive.h — multi-format archive reader/writer
 *
 * Reads and writes: .cute, .zip, .tar, .tar.gz, .7z
 * Provides a unified API to browse, extract, and create archives
 * in any supported format. The native .cute format gets full
 * cutecontainer features (WAL, encryption, spectral, volumes).
 * External formats get read/write interop.
 *
 * This is the engine behind the file manager GUI.
 */

#ifndef CUTECONTAINER_ARCHIVE_H
#define CUTECONTAINER_ARCHIVE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Supported archive formats ── */

typedef enum {
    CC_ARCHIVE_CUTE    = 0,     /* native .cute volume */
    CC_ARCHIVE_ZIP     = 1,     /* PKZIP / ZIP64 */
    CC_ARCHIVE_TAR     = 2,     /* POSIX tar */
    CC_ARCHIVE_TAR_GZ  = 3,     /* tar + gzip */
    CC_ARCHIVE_TAR_BZ2 = 4,     /* tar + bzip2 */
    CC_ARCHIVE_TAR_XZ  = 5,     /* tar + xz/lzma2 */
    CC_ARCHIVE_SEVEN_Z = 6,     /* 7z (LZMA/LZMA2) */
    CC_ARCHIVE_RAR     = 7,     /* RAR (read-only) */
    CC_ARCHIVE_UNKNOWN = 0xFF,
} cc_archive_format;

/* ── Archive entry (one file/dir inside an archive) ── */

typedef struct {
    char        path[512];          /* relative path */
    uint64_t    size;               /* uncompressed size */
    uint64_t    compressed_size;    /* compressed size (0 = stored) */
    uint64_t    offset;             /* internal offset */
    uint64_t    mtime;              /* modification time (unix) */
    uint32_t    crc32;              /* CRC-32 (zip) or 0 */
    uint32_t    permissions;        /* Unix permissions (tar) or 0 */
    uint16_t    method;             /* compression method ID */
    uint8_t     is_dir;
    uint8_t     is_encrypted;
    uint8_t     is_symlink;
    uint8_t     reserved[5];
} cc_archive_entry;

/* ── Archive handle ── */

typedef struct cc_archive cc_archive;

/* ── Detect format from file path or first bytes ── */

cc_archive_format cc_archive_detect(const uint8_t *header, size_t len);
cc_archive_format cc_archive_detect_path(const char *path);

/* ── Open (read) ── */

cc_archive *cc_archive_open(const char *path);
cc_archive *cc_archive_open_mem(const uint8_t *data, size_t len);

cc_archive_format cc_archive_format_of(const cc_archive *a);
const char       *cc_archive_format_name(cc_archive_format fmt);

/* ── Browse ── */

int                    cc_archive_count(const cc_archive *a);
const cc_archive_entry *cc_archive_entry_at(const cc_archive *a, int index);
int                    cc_archive_find(const cc_archive *a, const char *path);

/* Find entries matching a prefix (directory listing). */
int cc_archive_list_dir(const cc_archive *a, const char *dir_prefix,
                        int *out, int max);

/* ── Extract ── */

/* Extract one entry by index. Caller frees with free(). */
void *cc_archive_extract(cc_archive *a, int index, size_t *out_len);

/* Extract one entry to a file on disk. */
int cc_archive_extract_to(cc_archive *a, int index, const char *dest_path);

/* Extract all entries to a directory. */
int cc_archive_extract_all(cc_archive *a, const char *dest_dir);

/* ── Create (write) ── */

typedef struct cc_archive_writer cc_archive_writer;

/* Create a new archive in the given format. */
cc_archive_writer *cc_archive_create(const char *path, cc_archive_format format);

/* Add a file from disk. */
int cc_archive_add_file(cc_archive_writer *w, const char *archive_path,
                        const char *disk_path);

/* Add from memory. */
int cc_archive_add_buf(cc_archive_writer *w, const char *archive_path,
                       const void *data, size_t len);

/* Add a directory entry. */
int cc_archive_add_dir(cc_archive_writer *w, const char *archive_path);

/* Finalize and close. */
int cc_archive_finish(cc_archive_writer *w);
void cc_archive_writer_destroy(cc_archive_writer *w);

/* ── Convert between formats ── */

/* Convert any archive to any other format. */
int cc_archive_convert(const char *src_path, const char *dst_path,
                       cc_archive_format dst_format);

/* ── Self-extracting executable builder ──
 *
 * Creates a native executable that contains the archive payload.
 * When run, it extracts contents and optionally launches an entry point.
 *
 * Supported output:
 *   CC_SFX_EXE   — Windows PE (.exe)
 *   CC_SFX_APP   — macOS .app bundle
 *   CC_SFX_ELF   — Linux ELF binary
 *   CC_SFX_SHELL — Universal shell script with appended payload
 */

typedef enum {
    CC_SFX_SHELL   = 0,    /* #!/bin/sh + payload (portable) */
    CC_SFX_EXE     = 1,    /* Windows PE */
    CC_SFX_APP     = 2,    /* macOS .app bundle */
    CC_SFX_ELF     = 3,    /* Linux ELF */
} cc_sfx_type;

typedef struct {
    cc_sfx_type     type;
    char            entry_point[256];   /* what to run after extraction */
    char            display_name[64];
    char            icon_path[256];     /* icon file (for .app/.exe) */
    int             auto_extract;       /* 1 = extract + run, 0 = just extract */
    int             cleanup;            /* 1 = delete extracted files after exit */
    int             silent;             /* 1 = no progress UI */
} cc_sfx_opts;

/* Build a self-extracting executable from an archive or directory. */
int cc_sfx_build(const char *src_path, const char *out_path, const cc_sfx_opts *opts);

/* ── Close ── */

void cc_archive_close(cc_archive *a);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_ARCHIVE_H */
