/*
 * depo.h — encrypted container management (lock modes, archives, ledger)
 *
 * Handles the .cute v4 binary format with:
 *   - Password-based AES-256-GCM encryption
 *   - Temporal locks (epoch windows)
 *   - Fuse-limited access (hash-chain tokens)
 *   - Self-purging containers
 *   - Keychain binding (anti-copy-replay)
 *   - Remote fuse verification
 *   - Role-based archives (ARCV trailer)
 *   - Append-only ledger (audit log)
 *   - Trailer system (PMSG, ENGR, TOTP, PKEY, FBOX, CLAM)
 */

#ifndef CUTECONTAINER_DEPO_H
#define CUTECONTAINER_DEPO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Format constants ---- */

#define DEPO_MAGIC          "CUTE"
#define DEPO_VERSION        0x04
#define DEPO_HDR_SIZE       220

/* Lock mode flags (combinable) */
#define DEPO_FLAG_FOLDER        0x01
#define DEPO_FLAG_TIMED         0x02
#define DEPO_FLAG_DELAYED       0x04
#define DEPO_FLAG_FUSED         0x08
#define DEPO_FLAG_PURGE         0x10
#define DEPO_FLAG_CONTAINER     0x20
#define DEPO_FLAG_KEYCHAIN      0x40
#define DEPO_FLAG_REMOTE_FUSE   0x80

/* Roles */
#define DEPO_ROLE_ROOT     0
#define DEPO_ROLE_ADMIN    1
#define DEPO_ROLE_AUDITOR  2
#define DEPO_ROLE_READER   3
#define DEPO_ROLE_COUNT    4

/* Ledger actions */
#define DEPO_LEDGER_CREATED    0
#define DEPO_LEDGER_HEARTBEAT  1
#define DEPO_LEDGER_ATTEMPT    2
#define DEPO_LEDGER_CONSUMED   3
#define DEPO_LEDGER_EXPIRED    4

/* ---- Options for encrypt/decrypt operations ---- */

typedef struct {
    const char *password;
    const char *password_confirm;

    /* lock modes */
    uint8_t     flags;
    uint32_t    valid_epochs;       /* timed: duration in epochs */
    uint32_t    delay_epochs;       /* delayed: epochs before unlock */
    uint16_t    fuses;              /* fused: max decryptions */
    uint32_t    epoch_len;          /* seconds per epoch (default 3600) */
    uint32_t    kdf_rounds;         /* password stretching (default 100000) */
    int         purge;              /* self-delete after expiry/exhaustion */

    /* keychain */
    int         keychain;           /* bind to OS keychain */

    /* remote fuse */
    const char *remote_url;         /* fuse verification server */

    /* delegated fuse refresh */
    const char *refresh_key;        /* assign refresh key at lock time
                                       (master only, set once) */
    int         fuse_box;           /* renounce master key — only the
                                       fuse box (and refresh key) can open */

    /* archive */
    int         archive;            /* create ARCV archive */
    const char **archive_paths;     /* files/folders to archive */
    int          archive_count;

    /* trailers */
    const char *public_message;     /* PMSG cleartext message */
    const char *engrave_text;       /* ENGR role-gated message */
    uint8_t     engrave_role;       /* role level for engraving */

    /* TOTP */
    const char *totp_secret;        /* Base32-encoded TOTP secret */
    const char *totp_code;          /* TOTP code for verification */

    /* output */
    const char *output_path;        /* explicit output path (NULL = auto) */
    int         force;              /* overwrite existing */
    int         headless;           /* no interactive prompts */
    int         verbose;
} depo_opts;

/* ---- Primary operations ---- */

/* Encrypt a file or buffer into a .cute container.
 * Returns 0 on success, negative on error. */
int depo_encrypt_file(const char *in_path, const char *out_path,
                      const depo_opts *opts);

int depo_encrypt_buf(const uint8_t *in, size_t in_len,
                     uint8_t **out, size_t *out_len,
                     const depo_opts *opts);

/* Decrypt a .cute container.
 * Returns 0 on success, negative on error. */
int depo_decrypt_file(const char *in_path, const char *out_path,
                      const depo_opts *opts);

int depo_decrypt_buf(const uint8_t *in, size_t in_len,
                     uint8_t **out, size_t *out_len,
                     const depo_opts *opts);

/* ---- Archive operations ---- */

int depo_archive_encrypt(const char **paths, int count,
                         const char *out_path, const depo_opts *opts);

int depo_archive_decrypt(const char *in_path, const char *out_dir,
                         const depo_opts *opts);

int depo_archive_list(const char *path, char *buf, size_t cap);

/* ---- Info / verification ---- */

int depo_info(const uint8_t *data, size_t len, char *buf, size_t cap);
int depo_verify(const uint8_t *data, size_t len);

/* ---- Compress (press layer in unlocked container) ---- */

int depo_compress_file(const char *in_path, const char *out_path);
int depo_decompress_file(const char *in_path, const char *out_path);

/* ---- Split / Join ---- */

int depo_split(const char *path, size_t part_size_mb);
int depo_join(const char *part0_path, const char *out_path);

/* ---- Fuse management ---- */

/* Refill fuses on a fuse-box-locked file using its delegated refresh key.
 *
 * INCOMPLETE — this rewrites the fuse chain in the header but does not
 * re-encrypt the payload, so the file becomes unreadable until the full
 * refresh implementation lands (it needs to decrypt the payload with the
 * current chain, generate a new chain, then re-encrypt under the new
 * chain — i.e. the lock path replayed). The wire-up is in place so the
 * GUI flow is testable end-to-end once that's done.
 *
 * new_fuses=0 restores to the file's original max_fuses. */
int depo_fuse_refresh(const char *path,
                      const char *refresh_key,
                      uint16_t new_fuses);

/* ---- Security helpers ---- */

void depo_secure_zero(void *ptr, size_t len);
void depo_harden_process(void);
void *depo_secure_alloc(size_t len);
void  depo_secure_free(void *ptr, size_t len);

/* ---- Default options ---- */

depo_opts depo_opts_default(void);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_DEPO_H */
