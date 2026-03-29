/*
 * wal.h — Write-Ahead Log rail for high-speed container reads
 *
 * The WAL rail is a cleartext, append-only index that lives alongside
 * (or inside) encrypted/compressed containers. It answers every
 * question about what's in a .cute file without touching the payload:
 *
 *   "What type is this?"        — one 4-byte read
 *   "How big is the original?"  — one 8-byte read
 *   "What wrappers are inside?" — scan the WAL entries
 *   "When was it written?"      — timestamps in every entry
 *   "Is it part of a set?"      — collection ID + sequence
 *
 * No decrypt. No decompress. No seek into payload. Just a flat
 * sequential scan of fixed-size entries at a known offset.
 *
 * ── On-disk layout ──
 *
 * The WAL rail is appended after the container payload as a trailer:
 *
 *   [container header 64]
 *   [meta N]
 *   [payload M]
 *   [WAL trailer]:
 *     [4]   magic "WALR"
 *     [4]   wal_size (total WAL trailer bytes including this header)
 *     [4]   entry_count
 *     [4]   flags
 *     [entry_count × cc_wal_entry]
 *     [cc_wal_summary]  — fixed summary at the end for O(1) tail read
 *     [4]   magic "WALR" (footer — enables backward scan)
 *     [4]   wal_size     (footer — enables backward seek from EOF)
 *
 * The WAL can also be stored as a sidecar file (.cute.wal) for
 * collection-level indexing across many containers.
 *
 * ── Design principles ──
 *
 * 1. Never encrypted — the WAL is public metadata
 * 2. Append-only — entries are never modified, only appended
 * 3. Fixed-size entries — O(1) random access by index
 * 4. Tail-readable — summary at EOF for backward scan from end
 * 5. Hash-chained — each entry includes prev_hash for tamper detection
 * 6. Collection-aware — entries can span multiple .cute files
 */

#ifndef CUTECONTAINER_WAL_H
#define CUTECONTAINER_WAL_H

#include "container.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_WAL_MAGIC        "WALR"
#define CC_WAL_VERSION      1
#define CC_WAL_ENTRY_SIZE   128     /* fixed, padded for alignment */
#define CC_WAL_SUMMARY_SIZE 64

/* ── WAL entry types ── */

typedef enum {
    CC_WAL_CREATED     = 0x01,  /* container was created */
    CC_WAL_MODIFIED    = 0x02,  /* payload was replaced */
    CC_WAL_WRAPPED     = 0x03,  /* wrapper metadata added/changed */
    CC_WAL_LAYERED     = 0x04,  /* compression/encryption layer applied */
    CC_WAL_ACCESSED    = 0x05,  /* read access logged */
    CC_WAL_LINKED      = 0x06,  /* asset reference added */
    CC_WAL_VARIANT     = 0x07,  /* variant added */
    CC_WAL_COLLECTION  = 0x08,  /* collection membership */
    CC_WAL_SEALED      = 0x09,  /* container finalized (no more writes) */
    CC_WAL_CUSTOM      = 0xFF,  /* user-defined */
} cc_wal_entry_type;

/* ── WAL entry (128 bytes, fixed size) ── */

typedef struct {
    uint8_t             type;           /* cc_wal_entry_type */
    uint8_t             version;
    uint16_t            flags;
    uint32_t            sequence;       /* monotonic entry index */
    uint64_t            timestamp;      /* unix seconds */

    /* what this entry describes */
    cc_content_type     content_type;   /* container content type at this point */
    uint16_t            layer_flags;    /* CC_LAYER_* at this point */
    uint16_t            wrap_count;     /* number of wrappers at this point */

    uint64_t            original_size;  /* uncompressed payload size */
    uint64_t            stored_size;    /* on-disk payload size (after layers) */

    /* collection tracking */
    uint8_t             collection_id[16]; /* UUID for multi-file sets (zero = standalone) */
    uint32_t            collection_seq;    /* index within collection */

    /* integrity chain */
    uint8_t             content_hash[32]; /* SHA3-256 of payload (cleartext copy from header) */
    uint8_t             prev_hash[8];     /* truncated hash of previous entry (tamper detect) */

    uint8_t             reserved[6];
} cc_wal_entry;

/* ── WAL summary (64 bytes, at end for O(1) tail read) ── */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif
typedef struct
#if defined(__GNUC__) || defined(__clang__)
__attribute__((packed))
#endif
{
    uint8_t             magic[4];       /* "WALR" */
    uint8_t             version;
    uint8_t             reserved_1;
    uint16_t            flags;
    uint32_t            entry_count;
    uint32_t            first_entry_offset; /* byte offset from WAL start to first entry */

    cc_content_type     content_type;   /* current content type */
    uint16_t            layer_flags;    /* current layers */
    uint16_t            wrap_count;     /* current wrapper count */

    uint64_t            original_size;
    uint64_t            stored_size;
    uint64_t            created_at;     /* timestamp of first entry */
    uint64_t            modified_at;    /* timestamp of last entry */

    uint8_t             content_hash[32]; /* current content hash */

    /* intentionally NOT padded to 64 — let the footer magic/size follow */
}
#ifdef _MSC_VER
#pragma pack(pop)
#endif
cc_wal_summary;

/* ── WAL handle ── */

typedef struct cc_wal cc_wal;

/* ── Create / open ── */

/* Create a new WAL (in-memory, write with cc_wal_write). */
cc_wal *cc_wal_create(void);

/* Open WAL from a buffer (reads the trailer from a .cute file).
 * data/len is the FULL file — the WAL is found by scanning backward
 * from EOF for the footer magic. */
cc_wal *cc_wal_open(const uint8_t *data, size_t data_len);

/* Open WAL from a sidecar file (.cute.wal). */
cc_wal *cc_wal_open_file(const char *path);

/* ── Append ── */

/* Append an entry. Entries are never modified after append.
 * The prev_hash chain is maintained automatically. */
int cc_wal_append(cc_wal *w, const cc_wal_entry *entry);

/* Convenience: append a CREATED entry from container state. */
int cc_wal_log_created(cc_wal *w, cc_content_type type,
                       uint16_t layers, uint64_t orig_size,
                       uint64_t stored_size, const uint8_t hash[32]);

/* Convenience: append a WRAPPED entry. */
int cc_wal_log_wrapped(cc_wal *w, uint16_t wrap_count);

/* Convenience: append a COLLECTION entry. */
int cc_wal_log_collection(cc_wal *w, const uint8_t collection_id[16],
                          uint32_t seq);

/* ── Read (fast path — no decrypt needed) ── */

/* Number of entries. */
uint32_t cc_wal_count(const cc_wal *w);

/* Get entry by index (O(1) — fixed-size entries). */
const cc_wal_entry *cc_wal_get(const cc_wal *w, uint32_t index);

/* Get the summary (latest state snapshot). */
const cc_wal_summary *cc_wal_summary_get(const cc_wal *w);

/* Quick queries — answered from summary, no iteration: */
cc_content_type cc_wal_content_type(const cc_wal *w);
uint64_t        cc_wal_original_size(const cc_wal *w);
uint64_t        cc_wal_stored_size(const cc_wal *w);
uint16_t        cc_wal_layer_flags(const cc_wal *w);
uint16_t        cc_wal_wrap_count(const cc_wal *w);
uint64_t        cc_wal_created_at(const cc_wal *w);
uint64_t        cc_wal_modified_at(const cc_wal *w);

/* ── Serialize ── */

/* Write WAL to buffer (for embedding as container trailer).
 * Caller must free *out. */
int cc_wal_serialize(const cc_wal *w, uint8_t **out, size_t *out_len);

/* Write WAL to sidecar file. */
int cc_wal_write_file(const cc_wal *w, const char *path);

/* ── Integrity ── */

/* Verify the hash chain (all prev_hash links are consistent). */
int cc_wal_verify_chain(const cc_wal *w);

/* ── Collection index (multi-file) ──
 *
 * A collection WAL indexes many .cute files as one logical set.
 * Each file gets a COLLECTION entry with a shared UUID. The
 * collection WAL can be scanned to find any file by sequence
 * number without opening individual containers. */

/* Merge another WAL's entries into this one (for building collection indexes). */
int cc_wal_merge(cc_wal *dst, const cc_wal *src);

/* Find all entries matching a collection ID. Writes indices to out[].
 * Returns number found. */
int cc_wal_find_collection(const cc_wal *w, const uint8_t collection_id[16],
                           uint32_t *out, int max);

/* ── Destroy ── */

void cc_wal_destroy(cc_wal *w);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_WAL_H */
