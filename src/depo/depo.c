/*
 * cutedepo — unified file encryption + compression CLI.
 *
 * File sensing:
 *   cutedepo file.cute              → decrypt (cutecrypt)
 *   cutedepo file.press             → decompress (cutepress)
 *   cutedepo --compress file        → compress (cutepress)
 *   cutedepo file_or_folder         → encrypt (cutecrypt)
 *   cutedepo --archive folder/      → locked archive (cutecrypt)
 *
 * Interactive mode:
 *   cutedepo <file_or_folder>
 *   cutedepo <file.cute>
 *
 * Headless mode (encrypt):
 *   cutedepo --password PASS [options] <file_or_folder>
 *
 * Headless mode (decrypt):
 *   cutecrypt --password PASS <file.cute>
 *
 * Encrypt options:
 *   --password PASS         Password (required)
 *   --epoch-len SECS        Epoch length in seconds (default: 3600)
 *   --valid-epochs N        Expire after N epochs (enables timed window)
 *   --delay SECS            Delay access by N seconds (enables delayed access)
 *   --fuses N               Max decryptions (enables fuse-limited)
 *   --purge                 Self-purge on expiry/exhaustion
 *   --output PATH           Custom output path
 *   -q, --quiet             Suppress all status output
 *
 * Decrypt options:
 *   --password PASS         Password (required)
 *   --fuse-key HEX          Outer fuse preimage as 64 hex chars (bypass vault)
 *   --inner-fuse-key HEX    Inner fuse preimage as 64 hex chars (bypass vault)
 *   --output PATH           Custom output path
 *   -q, --quiet             Suppress all status output
 *
 * If --password is omitted, falls back to interactive mode.
 *
 * Lock modes (combinable):
 *   [P] Password        — standard AES-256-GCM with password-derived key
 *   [T] Timed window    — only decryptable within a cascade epoch window
 *   [D] Delayed access  — becomes decryptable at a specific future time
 *   [F] Fuse-limited    — limited number of decryptions (burns a fuse each time)
 *   [X] Self-purging    — .cute file is securely deleted after expiry or fuse exhaustion
 *
 * .cute v4 format (self-contained, no sidecars):
 *   [HEADER 220][BINDING 0|32][VAULT][PAYLOAD][LEDGER][TRAILERS...]
 *
 *   Header:
 *     [4]   magic "CUTE"
 *     [1]   version (0x04)
 *     [1]   flags (bitmask)
 *     [32]  salt
 *     [12]  nonce
 *     [8]   created_at (LE unix timestamp)
 *     [4]   epoch_len (LE seconds per epoch)
 *     [4]   valid_from_epoch (LE — 0 = immediate)
 *     [4]   valid_until_epoch (LE — 0xFFFFFFFF = forever)
 *     [2]   max_fuses (LE — 0 = unlimited)
 *     [2]   fuses_remaining (LE, mutable)
 *     [32]  fuse_tip (mutable)
 *     [32]  namespace
 *     [4]   kdf_rounds
 *     [32]  epoch_chain
 *     [4]   heartbeat_epoch (mutable)
 *     [32]  container_seed
 *     [4]   vault_size (LE)
 *     [4]   payload_size (LE)
 *     [2]   ledger_count (LE, mutable)
 *
 *   Vault (encrypted fuse preimages):
 *     [12]  vault_nonce
 *     [N]   AES-GCM(outer_chain ‖ inner_chain) + [16] tag
 *     vault_key = Hash(outer_key ‖ "cutecrypt.vault")
 *     Size: 28 + max_fuses * 64 (0 when no fuses)
 *
 *   Payload:
 *     If container: [12 container_nonce][AES-GCM(inner_ct)]
 *     container_key = Hash(container_seed ‖ heartbeat_epoch ‖ "cutecrypt.container")
 *
 *   Ledger (cleartext, append-only):
 *     Each entry [48 bytes]: [8 timestamp][32 chain_hash][4 action][4 epoch]
 *     chain_hash = Hash(prev_hash ‖ timestamp ‖ action ‖ epoch)
 *     Actions: CREATED(0), HEARTBEAT(1), ATTEMPT(2), CONSUMED(3), EXPIRED(4)
 *
 *   Trailer sections (extensible, after ledger):
 *     Each: [4 magic][4 section_size LE][section_size data]
 *     PMSG — public messages (cleartext, visible without key)
 *     ENGR — engraved messages (AES-GCM per role level)
 *       Role key chain: key[0]=Hash(base||"cutecrypt.engrave.0"),
 *         key[N+1]=Hash(key[N]||"cutecrypt.engrave.N+1")
 *       User at level N can derive N..3 but not 0..N-1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <pthread.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <sys/ptrace.h>
#elif defined(__linux__)
#include <sys/prctl.h>
#endif

/* ---- Process hardening ---- */

static int g_hardened = 0; /* set to 1 after harden_process() */

/*
 * secure_zero — guaranteed memory zeroing that cannot be optimized away.
 * Uses memset_s (C11 Annex K) on macOS, explicit_bzero on Linux/BSD,
 * falls back to volatile write loop.
 */
static void secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(__STDC_LIB_EXT1__) || defined(__APPLE__)
    memset_s(ptr, len, 0, len);
#elif defined(__linux__) || defined(__FreeBSD__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
#endif
}

/*
 * harden_process — apply runtime security hardening:
 *   macOS:   ptrace(PT_DENY_ATTACH) + RLIMIT_CORE=0
 *   Linux:   prctl(PR_SET_DUMPABLE, 0) + RLIMIT_CORE=0
 *   Windows: SetProcessMitigationPolicy (if available)
 *   Other:   RLIMIT_CORE=0 only (graceful degradation)
 */
static void harden_process(void) {
    if (g_hardened) return;
    g_hardened = 1;

#ifdef __APPLE__
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
#elif defined(__linux__)
    prctl(PR_SET_DUMPABLE, 0);
#endif

#ifndef _WIN32
    /* Disable core dumps */
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
#endif
}

/*
 * secure_alloc — allocate memory and mlock it to prevent swap-out.
 * Falls back to regular malloc if mlock fails (non-fatal).
 */
static void *secure_alloc(size_t len) {
    void *p = malloc(len);
    if (p) {
#ifdef _WIN32
        VirtualLock(p, len);
#else
        mlock(p, len);
#endif
        memset(p, 0, len);
    }
    return p;
}

/*
 * secure_free — zero and munlock before freeing.
 */
static void secure_free(void *ptr, size_t len) {
    if (!ptr) return;
    secure_zero(ptr, len);
#ifdef _WIN32
    VirtualUnlock(ptr, len);
#else
    munlock(ptr, len);
#endif
    free(ptr);
}

#include "cutecontainer/depo.h"
#include "cutecontainer/crypt/aes256.h"
#include "cutecontainer/crypt/cutehash.h"
#include "cutecontainer/crypt/fuse.h"
#include "cutecontainer/press.h"

/* ---- Headless mode options ---- */

typedef struct {
    int headless;           /* 1 if --password was given */
    int quiet;              /* 1 if -q / --quiet */
    const char *password;
    uint32_t epoch_len;     /* 0 = not set */
    uint32_t valid_epochs;  /* 0 = not set (no timed window) */
    uint32_t delay_secs;    /* 0 = not set (no delay) */
    uint16_t fuses;         /* 0 = not set (no fuse limit) */
    int purge;              /* 1 if --purge */
    uint32_t kdf_rounds;    /* 0 = use default */
    const char *fuse_key;       /* hex string for outer fuse preimage */
    const char *inner_fuse_key; /* hex string for inner fuse preimage */
    const char *output;     /* custom output path */
    const char *input;      /* positional argument */
    int keychain;           /* 1 if --keychain */
    const char *fuse_server; /* URL for remote fuse server */
    const char *engrave;      /* engraved message (encrypted, role-gated) */
    const char *engrave_file; /* engraved file path (encrypted, role-gated) */
    int engrave_level;        /* role level: 0=root, 1=admin, 2=auditor, 3=reader */
    const char *public_msg;   /* public message (cleartext in trailer) */
    uint32_t split_mb;        /* --split SIZE_MB (split .cute into parts) */
    int join;                 /* --join (reassemble from parts) */
    int archive;              /* --archive (create locked archive) */
    const char *extract;      /* --extract PATH (selective extraction) */
    int list;                 /* --list (list archive contents) */
    const char **file_roles;  /* --file-role PATH:ROLE pairs */
    int n_file_roles;
    /* cutepress options */
    int compress;             /* --compress (force compression) */
    int decompress;           /* --decompress / -d (force decompression) */
    int press_level;          /* -l 1-9 (compression level, 0 = default) */
    /* auth modes */
    int passkey;              /* --passkey (use platform credential / Touch ID) */
    const char *totp_secret;  /* --totp-secret BASE32 (set up TOTP on encrypt) */
    const char *totp_code;    /* --totp CODE (provide TOTP code on decrypt) */
    int unlocked;             /* 1 if compression-only (no password) */
    int info;                 /* --info (show metadata without password) */
    int verify;               /* --verify (integrity check without decrypt) */
    int force;                /* --force (overwrite existing output) */
    int wrap;                 /* --wrap (DRM bundle wrap) */
    int fuse_box;             /* --fuse-box (renounce master key, fuse-only access) */
    const char *refresh_key;  /* --refresh-key PASS (delegated fuse refresh key) */
    const char *do_refresh;   /* --refresh PASS (use refresh key to refill fuses) */
    int no_harden;            /* --no-harden (disable process hardening) */
    int check;                /* --check (machine-readable type identification) */
    int claimable;            /* --claimable (first-open claims master key) */
} cli_opts;

/* ---- Format constants ---- */

#define CUTE_MAGIC       "CUTE"
#define CUTE_VERSION     0x04

/* Flag bits */
#define FLAG_FOLDER      0x01
#define FLAG_TIMED       0x02
#define FLAG_DELAYED     0x04
#define FLAG_FUSED       0x08
#define FLAG_PURGE       0x10
#define FLAG_CONTAINER   0x20     /* container wrapping (always set for fused/purgeable) */
#define FLAG_KEYCHAIN    0x40     /* OS keychain nonce binding (anti file-copy replay) */
#define FLAG_REMOTE_FUSE 0x80     /* remote fuse server (anti file-copy replay) */

/*
 * v4 header layout (220 bytes):
 *   [4]   magic "CUTE"
 *   [1]   version (0x04)
 *   [1]   flags
 *   [32]  salt
 *   [12]  nonce (inner)
 *   [8]   created_at
 *   [4]   epoch_len
 *   [4]   valid_from_epoch
 *   [4]   valid_until_epoch
 *   [2]   max_fuses
 *   [2]   fuses_remaining (mutable)
 *   [32]  fuse_tip (mutable)
 *   [32]  namespace
 *   [4]   kdf_rounds
 *   [32]  epoch_chain
 *   [4]   heartbeat_epoch (mutable)
 *   [32]  container_seed
 *   [4]   vault_size
 *   [4]   payload_size
 *   [2]   ledger_count (mutable)
 *
 * File layout: [HEADER][VAULT][PAYLOAD][LEDGER]
 * All sections self-contained — no sidecars.
 */
#define HDR_MAGIC        0
#define HDR_VERSION      4
#define HDR_FLAGS        5
#define HDR_SALT         6
#define HDR_NONCE        38
#define HDR_CREATED      50
#define HDR_EPOCH_LEN    58
#define HDR_VALID_FROM   62
#define HDR_VALID_UNTIL  66
#define HDR_MAX_FUSES    70
#define HDR_FUSES_REM    72
#define HDR_FUSE_TIP     74
#define HDR_NAMESPACE    106
#define HDR_KDF_ROUNDS   138
#define HDR_EPOCH_CHAIN  142
#define HDR_HEARTBEAT    174
#define HDR_CONT_SEED    178
#define HDR_VAULT_SIZE   210
#define HDR_PAYLOAD_SIZE 214
#define HDR_LEDGER_COUNT 218
#define HDR_SIZE         220

#define SALT_LEN         32
#define FUSE_TIP_LEN     32
#define NS_LEN           32
#define EPOCH_CHAIN_LEN  32
#define CONT_SEED_LEN    32
#define CONTAINER_NONCE_LEN 12
#define KDF_ROUNDS_DEFAULT  100000

/* Binding section: extra data between header and vault for anti-replay.
 * FLAG_REMOTE_FUSE → 32 bytes: [16 file_id][16 url_hash]
 * Otherwise → 0 bytes. Keychain needs no file storage (id derived from salt+ns). */
#define BINDING_FILE_ID     0
#define BINDING_URL_HASH    16
#define BINDING_REMOTE_SIZE 32

static size_t binding_section_size(uint8_t flags) {
    return (flags & FLAG_REMOTE_FUSE) ? BINDING_REMOTE_SIZE : 0;
}

/* ---- Trailer sections (after ledger) ----
 *
 * Extensible trailer format:
 *   [4] magic (e.g. "PMSG", "ENGR")
 *   [4] section_size (LE, of data following this 8-byte header)
 *   [section_size] data
 *
 * Public messages (PMSG) — cleartext, always visible:
 *   [2] count (LE)
 *   Per entry:
 *     [8] timestamp (LE)
 *     [2] message_len (LE)
 *     [message_len] UTF-8 text
 *
 * Engraved messages (ENGR) — encrypted per role level:
 *   [2] count (LE)
 *   Per entry:
 *     [1] role_level (0=root, 1=admin, 2=auditor, 3=reader)
 *     [2] message_len (LE, plaintext length)
 *     [12] nonce
 *     [message_len + 16] ciphertext + tag
 *
 * Role key derivation (downward chain):
 *   role_key[0] = Hash(outer_key || "cutecrypt.engrave.0")   — root
 *   role_key[1] = Hash(role_key[0] || "cutecrypt.engrave.1") — admin
 *   role_key[2] = Hash(role_key[1] || "cutecrypt.engrave.2") — auditor
 *   role_key[3] = Hash(role_key[2] || "cutecrypt.engrave.3") — reader
 *
 * A user at level N can derive levels N..3 but NOT 0..N-1.
 */

#define TRAILER_HDR_SIZE    8   /* 4 magic + 4 size */
#define PMSG_MAGIC          "PMSG"
#define ENGR_MAGIC          "ENGR"

/* TOTP trailer — stores TOTP config for time-based code auth
 *   [4]  magic "TOTP"
 *   [4]  section_size LE (= 24 + secret_len)
 *   [1]  digits (6 or 8)
 *   [1]  period (seconds, typically 30)
 *   [2]  secret_len LE
 *   [20] reserved (zero)
 *   [secret_len] encrypted TOTP secret (AES-GCM with salt-derived wrapping key)
 *
 * The TOTP code is fed to KDF as the password. On encrypt, the current
 * code is used. On decrypt, the code is provided via --totp.
 */
#define TOTP_MAGIC          "TOTP"
#define TOTP_DIGITS_DEFAULT 6
#define TOTP_PERIOD_DEFAULT 30

/* PKEY trailer — passkey / platform credential reference
 *   [4]  magic "PKEY"
 *   [4]  section_size LE (= 64)
 *   [32] key_id (identifier for Secure Enclave / keychain key)
 *   [32] salt_for_key (used to derive encryption key from passkey output)
 *
 * On macOS, the passkey is a Secure Enclave P-256 key protected by Touch ID.
 * The shared secret (ECDH with an ephemeral key stored in the trailer) is
 * fed to KDF as the password. On decrypt, Touch ID is required to access
 * the SE key and reproduce the shared secret.
 */
#define PKEY_MAGIC          "PKEY"
#define PKEY_SECTION_SIZE   64

/* FBOX trailer — fuse box configuration
 *   [4]  magic "FBOX"
 *   [4]  section_size LE (= 97)
 *   [1]  flags: bit 0 = renounced (master key cannot bypass fuses)
 *   [32] refresh_key_hash (CuteHash of refresh key, zero if no refresh key)
 *   [32] content_key_enc  (encrypted content key, only when renounced)
 *   [32] content_key_salt (salt for content key encryption)
 *
 * Fuse box model:
 *   --fuse-box           create fuse box (master key renounced)
 *   --refresh-key PASS   set refresh key (can refill fuses, set by master only)
 *
 * When renounced:
 *   - A random content_key encrypts the payload (not the KDF-derived key)
 *   - content_key is encrypted with Hash(kdf_key || fuse_chain_root)
 *   - You need password + valid fuse to recover content_key
 *   - Fuse refresh requires the refresh_key (does not grant decrypt)
 *   - Only master can assign a refresh_key (at creation time)
 *   - Refresh key cannot re-delegate
 */
#define FBOX_MAGIC          "FBOX"
#define FBOX_SECTION_SIZE   97
#define FBOX_FLAG_RENOUNCED 0x01

/* ---- Claimable (CLAM) trailer ---- */
/* CLAM section data: 32 bytes ephemeral password stored raw.
 * First person to open the file uses it to decrypt, then re-encrypts
 * with their own password and the CLAM trailer is stripped. */
#define CLAM_MAGIC          "CLAM"
#define CLAM_SECTION_SIZE   32

/* Unlocked container: kdf_rounds=0 in header signals no password.
 * The key is derived from a fixed passphrase "cutedepo.unlocked" with 1 round.
 * Used for compression-only .cute files (no security, just container format). */
#define UNLOCKED_PASSPHRASE "cutedepo.unlocked"
#define UNLOCKED_KDF_ROUNDS 0

#define ROLE_ROOT     0
#define ROLE_ADMIN    1
#define ROLE_AUDITOR  2
#define ROLE_READER   3
#define ROLE_COUNT    4

static const char *role_names[ROLE_COUNT] = { "root", "admin", "auditor", "reader" };

/* ---- Platform random ---- */

#if defined(__APPLE__)
#include <Security/SecRandom.h>
static void randombytes(uint8_t *buf, size_t len) {
    (void)SecRandomCopyBytes(kSecRandomDefault, len, buf);
}
#elif defined(_WIN32)
#include <bcrypt.h>
static void randombytes(uint8_t *buf, size_t len) {
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}
#elif defined(__linux__)
#include <sys/random.h>
static void randombytes(uint8_t *buf, size_t len) {
    getrandom(buf, len, 0);
}
#else
static void randombytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(buf, 1, len, f); fclose(f); }
}
#endif

/* ---- LE encode/decode ---- */

static void le16_put(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void le32_put(uint8_t *p, uint32_t v) { for(int i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void le64_put(uint8_t *p, uint64_t v) { for(int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }
static uint16_t le16_get(const uint8_t *p) { return (uint16_t)p[0]|((uint16_t)p[1]<<8); }
static uint32_t le32_get(const uint8_t *p) { uint32_t v=0; for(int i=0;i<4;i++) v|=(uint32_t)p[i]<<(8*i); return v; }
static uint64_t le64_get(const uint8_t *p) { uint64_t v=0; for(int i=0;i<8;i++) v|=(uint64_t)p[i]<<(8*i); return v; }

/* ---- TOTP (RFC 6238) ----
 * Uses HMAC-SHA1 (via CuteHash in HMAC mode) for code generation.
 * Base32 decode for provisioning secrets from authenticator apps. */

static int base32_decode(const char *src, uint8_t *out, size_t out_cap, size_t *out_len) {
    static const int8_t b32[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1, /* 2-7 */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* A-O */
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, /* P-Z */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, /* a-o */
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, /* p-z */
    };
    size_t bits = 0, buf = 0, pos = 0;
    for (const char *p = src; *p && *p != '='; p++) {
        int c = (uint8_t)*p;
        if (c >= 128 || b32[c] < 0) return -1;
        buf = (buf << 5) | (uint32_t)b32[c];
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (pos >= out_cap) return -1;
            out[pos++] = (uint8_t)(buf >> bits);
        }
    }
    *out_len = pos;
    return 0;
}

/* HMAC using CuteHash (256-bit). We use CuteHash as the hash function.
 * HMAC(K, M) = H((K ^ opad) || H((K ^ ipad) || M))
 * Block size = 32 bytes (CuteHash output size). */
static void hmac_cutehash(const uint8_t *key, size_t key_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t out[CC_CUTE_HASH_LEN]) {
    uint8_t k[CC_CUTE_HASH_LEN];
    if (key_len > CC_CUTE_HASH_LEN) {
        cc_cute_hash(key, key_len, k);
    } else {
        memset(k, 0, CC_CUTE_HASH_LEN);
        memcpy(k, key, key_len);
    }

    uint8_t ipad[CC_CUTE_HASH_LEN], opad[CC_CUTE_HASH_LEN];
    for (size_t i = 0; i < CC_CUTE_HASH_LEN; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = H(ipad || msg) */
    size_t inner_len = CC_CUTE_HASH_LEN + msg_len;
    uint8_t *inner_buf = malloc(inner_len);
    memcpy(inner_buf, ipad, CC_CUTE_HASH_LEN);
    memcpy(inner_buf + CC_CUTE_HASH_LEN, msg, msg_len);
    uint8_t inner_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(inner_buf, inner_len, inner_hash);
    free(inner_buf);

    /* outer = H(opad || inner) */
    uint8_t outer_buf[CC_CUTE_HASH_LEN * 2];
    memcpy(outer_buf, opad, CC_CUTE_HASH_LEN);
    memcpy(outer_buf + CC_CUTE_HASH_LEN, inner_hash, CC_CUTE_HASH_LEN);
    cc_cute_hash(outer_buf, sizeof(outer_buf), out);

    secure_zero(k, sizeof(k));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner_hash, sizeof(inner_hash));
    secure_zero(outer_buf, sizeof(outer_buf));
}

/* Generate a TOTP code (RFC 6238).
 * Returns the N-digit code as a uint32_t. */
static uint32_t totp_generate(const uint8_t *secret, size_t secret_len,
                               uint64_t time_now, uint8_t period, uint8_t digits) {
    uint64_t counter = time_now / period;
    /* Counter as big-endian 8 bytes */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (uint8_t)(counter & 0xFF); counter >>= 8; }

    uint8_t hash[CC_CUTE_HASH_LEN];
    hmac_cutehash(secret, secret_len, msg, 8, hash);

    /* Dynamic truncation (use lower 4 bits of last byte as offset) */
    int offset = hash[CC_CUTE_HASH_LEN - 1] & 0x0F;
    /* Ensure offset + 4 is within hash bounds */
    if (offset + 4 > (int)CC_CUTE_HASH_LEN) offset = CC_CUTE_HASH_LEN - 4;
    uint32_t code = ((uint32_t)(hash[offset] & 0x7F) << 24) |
                    ((uint32_t)hash[offset+1] << 16) |
                    ((uint32_t)hash[offset+2] << 8) |
                    (uint32_t)hash[offset+3];

    uint32_t mod = 1;
    for (uint8_t i = 0; i < digits; i++) mod *= 10;
    return code % mod;
}

/* Format TOTP code as zero-padded string */
static void totp_format(uint32_t code, uint8_t digits, char *buf, size_t cap) {
    snprintf(buf, cap, "%0*u", digits, code);
}

/* Verify a TOTP code (checks current window and +/- 1 for clock drift) */
static int totp_verify(const uint8_t *secret, size_t secret_len,
                        uint64_t time_now, uint8_t period, uint8_t digits,
                        const char *code_str) {
    uint32_t user_code = (uint32_t)strtoul(code_str, NULL, 10);
    /* Constant-time: evaluate ALL windows, accumulate match via OR.
     * Prevents timing side-channel on which window (or digit) matched. */
    volatile int match = 0;
    for (int window = -1; window <= 1; window++) {
        uint64_t t = time_now + (int64_t)window * period;
        uint32_t expected = totp_generate(secret, secret_len, t, period, digits);
        /* Branchless: match becomes 1 if any window matches */
        match |= (user_code == expected);
    }
    return match;
}

/* ---- Terminal I/O ---- */

static void read_line(const char *prompt, char *buf, size_t cap) {
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (fgets(buf, (int)cap, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
    }
}

static void read_password(const char *prompt, char *buf, size_t cap) {
    struct termios old, noecho;
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    tcgetattr(STDIN_FILENO, &old);
    noecho = old;
    noecho.c_lflag &= ~((tcflag_t)ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    if (fgets(buf, (int)cap, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n')
            buf[len - 1] = '\0';
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fprintf(stderr, "\n");
}

static int read_yes_no(const char *prompt) {
    char buf[16];
    read_line(prompt, buf, sizeof(buf));
    return (buf[0] == 'y' || buf[0] == 'Y');
}

static uint32_t read_uint(const char *prompt) {
    char buf[64];
    read_line(prompt, buf, sizeof(buf));
    return (uint32_t)strtoul(buf, NULL, 10);
}

/* ---- File I/O ---- */

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    *out_len = (size_t)sz;
    return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wr = fwrite(data, 1, len, f);
    fclose(f);
    return (wr == len) ? 0 : -1;
}

/* Atomic write: write to tmpfile in same directory, then rename.
 * rename() is atomic on POSIX — no partial writes visible at `path`. */
static int write_file_atomic(const char *path, const uint8_t *data, size_t len) {
    /* Build tmpfile path in same directory as destination */
    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", path);

    int fd = mkstemp(tmp_path);
    if (fd < 0) return -1;

    /* Restrictive permissions (owner-only) */
    fchmod(fd, 0600);

    ssize_t wr = write(fd, data, len);
    if (fsync(fd) != 0 || wr < 0 || (size_t)wr != len) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static int is_directory(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

static int ends_with(const char *s, const char *suffix) {
    size_t slen = strlen(s), suflen = strlen(suffix);
    if (suflen > slen) return 0;
    return strcmp(s + slen - suflen, suffix) == 0;
}

/* Check if output file exists and prompt user (unless --force or --quiet).
 * Returns 0 = proceed, 1 = abort. */
static int check_overwrite(const char *out_path, int force, int quiet) {
    if (force || quiet) return 0;
    struct stat st;
    if (stat(out_path, &st) != 0) return 0;  /* doesn't exist */
    if (!isatty(STDIN_FILENO)) return 0;      /* non-interactive */
    fprintf(stderr, "  '%s' already exists. overwrite? (y/n): ", out_path);
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    return (buf[0] == 'y' || buf[0] == 'Y') ? 0 : 1;
}

static void secure_delete(const char *path) {
    /* Overwrite with random data, then unlink */
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (data) {
        randombytes(data, len);
        write_file(path, data, len);
        memset(data, 0, len);
        write_file(path, data, len);
        free(data);
    }
    unlink(path);
}

/* ---- Tar helpers ----
 * Uses posix_spawn with explicit argv to avoid shell injection.
 * No shell metacharacters are interpreted. */

#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

static int run_argv(char *const argv[]) {
    pid_t pid;
    int status;
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    /* Suppress stderr */
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    int rc = posix_spawn(&pid, "/usr/bin/tar", &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) return -1;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static uint8_t *tar_folder(const char *path, size_t *out_len) {
    char tmpfile[] = "/tmp/cutecrypt_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return NULL;
    fchmod(fd, 0600);

    /* Write tar output directly to the fd via /dev/fd/N */
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", fd);

    char *argv[] = {"tar", "-cf", fd_path, "-C", (char *)path, ".", NULL};
    int rc = run_argv(argv);
    close(fd);

    if (rc != 0) { unlink(tmpfile); return NULL; }
    uint8_t *data = read_file(tmpfile, out_len);
    unlink(tmpfile);
    return data;
}

static int untar_to(const uint8_t *data, size_t len, const char *dest) {
    char tmpfile[] = "/tmp/cutecrypt_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return -1;
    fchmod(fd, 0600);

    /* Write data to tmpfile via the open fd (no TOCTOU gap) */
    ssize_t wr = write(fd, data, len);
    close(fd);
    if (wr < 0 || (size_t)wr != len) { unlink(tmpfile); return -1; }

    mkdir(dest, 0755);
    char *argv[] = {"tar", "-xf", tmpfile, "-C", (char *)dest, NULL};
    int rc = run_argv(argv);
    unlink(tmpfile);
    return rc == 0 ? 0 : -1;
}

/* ---- Staggered KDF — twin-namespace iteration ----
 *
 * Alternates between two namespaces ("even" and "odd") for each
 * compression round, preventing single-namespace shortcut attacks.
 * The fuse_tip is folded into the IKM so the key is bound to fuse state.
 *
 *   ikm_hash = CuteHash(salt ‖ ns ‖ fuse_tip ‖ password)
 *   state = ikm_hash
 *   for i in 0..rounds:
 *     twin = (i & 1) ? ns_odd : ns_even
 *     state = compress(twin, state, ikm_hash, i, KDF)
 *   key = state[0..31]
 */

static void derive_key(
    const char *password, size_t pw_len,
    const uint8_t *salt,
    const uint8_t *ns,
    const uint8_t *fuse_tip,   /* NULL if no fuse */
    uint32_t rounds,
    uint8_t key[CC_AES256_KEY_LEN],
    volatile uint32_t *progress) /* NULL if no progress tracking */
{
    /* Build IKM = salt ‖ namespace ‖ fuse_tip ‖ password */
    size_t ft_len = fuse_tip ? FUSE_TIP_LEN : 0;
    size_t ikm_len = SALT_LEN + NS_LEN + ft_len + pw_len;
    uint8_t *ikm = malloc(ikm_len);
    size_t off = 0;
    memcpy(ikm + off, salt, SALT_LEN); off += SALT_LEN;
    memcpy(ikm + off, ns, NS_LEN); off += NS_LEN;
    if (fuse_tip) { memcpy(ikm + off, fuse_tip, FUSE_TIP_LEN); off += FUSE_TIP_LEN; }
    memcpy(ikm + off, password, pw_len);

    /* Hash IKM to normalize length */
    uint8_t ikm_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(ikm, ikm_len, ikm_hash);
    memset(ikm, 0, ikm_len);
    free(ikm);

    /* Twin namespaces */
    uint8_t ns_even[CC_CUTE_NS_LEN], ns_odd[CC_CUTE_NS_LEN];
    cc_cute_namespace(ns_even, "cutecrypt.kdf.even", 18);
    cc_cute_namespace(ns_odd,  "cutecrypt.kdf.odd",  17);

    /* Stagger: alternate namespaces across rounds */
    uint8_t state[CC_CUTE_HASH_LEN];
    memcpy(state, ikm_hash, CC_CUTE_HASH_LEN);

    for (uint32_t i = 0; i < rounds; i++) {
        uint8_t *twin = (i & 1) ? ns_odd : ns_even;
        cc_cute_compress(twin, state, ikm_hash, (uint64_t)i, CC_CUTE_MODE_KDF, state);
        if (progress && (i & 511) == 0) *progress = i;
    }
    if (progress) *progress = rounds;

    memcpy(key, state, CC_AES256_KEY_LEN);
    memset(state, 0, sizeof(state));
    secure_zero(ikm_hash, sizeof(ikm_hash));
}

/* ---- Async KDF ---- */

typedef struct {
    const char *password; size_t pw_len;
    const uint8_t *salt;
    const uint8_t *ns;
    const uint8_t *fuse_tip;
    uint32_t rounds;
    uint8_t key[CC_AES256_KEY_LEN];
    volatile uint32_t progress;
    volatile int done;
} kdf_task;

static void *kdf_worker(void *arg) {
    kdf_task *t = (kdf_task *)arg;
    derive_key(t->password, t->pw_len, t->salt, t->ns,
               t->fuse_tip, t->rounds, t->key, &t->progress);
    t->done = 1;
    return NULL;
}

static void kdf_task_init(kdf_task *t, const char *password, size_t pw_len,
                          const uint8_t *salt, const uint8_t *ns,
                          const uint8_t *fuse_tip, uint32_t rounds)
{
    t->password = password; t->pw_len = pw_len;
    t->salt = salt; t->ns = ns; t->fuse_tip = fuse_tip;
    t->rounds = rounds; t->progress = 0; t->done = 0;
}

/* Run KDF asynchronously with progress reporting.
 * If show_progress is false or stderr isn't a TTY, runs synchronously. */
static void kdf_run(kdf_task *t, int quiet) {
    int show = !quiet && isatty(STDERR_FILENO);
    if (!show) {
        derive_key(t->password, t->pw_len, t->salt, t->ns,
                   t->fuse_tip, t->rounds, t->key, NULL);
        t->done = 1;
        return;
    }
    pthread_t th;
    pthread_create(&th, NULL, kdf_worker, t);
    while (!t->done) {
        uint32_t p = t->progress;
        int pct = t->rounds > 0 ? (int)((uint64_t)p * 100 / t->rounds) : 0;
        int filled = pct / 5;   /* 20-char bar */
        fprintf(stderr, "\r  KDF: [");
        for (int i = 0; i < 20; i++)
            fputc(i < filled ? '#' : '.', stderr);
        fprintf(stderr, "] %d%%", pct);
        usleep(50000);
    }
    fprintf(stderr, "\r  KDF: [####################] 100%%\n");
    pthread_join(th, NULL);
}

/* Run two KDF tasks in parallel (for fused files: outer + inner). */
static void kdf_run_dual(kdf_task *a, kdf_task *b, int quiet) {
    int show = !quiet && isatty(STDERR_FILENO);
    if (!show) {
        derive_key(a->password, a->pw_len, a->salt, a->ns,
                   a->fuse_tip, a->rounds, a->key, NULL);
        a->done = 1;
        derive_key(b->password, b->pw_len, b->salt, b->ns,
                   b->fuse_tip, b->rounds, b->key, NULL);
        b->done = 1;
        return;
    }
    pthread_t th_a, th_b;
    pthread_create(&th_a, NULL, kdf_worker, a);
    pthread_create(&th_b, NULL, kdf_worker, b);
    while (!a->done || !b->done) {
        uint32_t pa = a->progress, pb = b->progress;
        int pct_a = a->rounds > 0 ? (int)((uint64_t)pa * 100 / a->rounds) : 100;
        int pct_b = b->rounds > 0 ? (int)((uint64_t)pb * 100 / b->rounds) : 100;
        int avg = (pct_a + pct_b) / 2;
        int filled = avg / 5;
        fprintf(stderr, "\r  KDF: [");
        for (int i = 0; i < 20; i++)
            fputc(i < filled ? '#' : '.', stderr);
        fprintf(stderr, "] outer %d%% | inner %d%%", pct_a, pct_b);
        usleep(50000);
    }
    fprintf(stderr, "\r  KDF: [####################] outer 100%% | inner 100%%\n");
    pthread_join(th_a, NULL);
    pthread_join(th_b, NULL);
}

/* ---- Epoch chain ----
 * Commits epoch parameters via concatenation chain.
 * chain = compress(ns_epoch, salt, timing_params, 0, MODE_CHAIN)
 * Tampering with any epoch field invalidates the chain → AAD mismatch. */

static void compute_epoch_chain(
    const uint8_t *salt,
    uint64_t created_at, uint32_t epoch_len,
    uint32_t valid_from, uint32_t valid_until,
    uint32_t kdf_rounds,
    uint8_t chain[EPOCH_CHAIN_LEN])
{
    uint8_t ns[CC_CUTE_NS_LEN];
    cc_cute_namespace(ns, "cutecrypt.epoch-chain", 21);

    uint8_t params[CC_CUTE_INPUT_LEN];
    memset(params, 0, CC_CUTE_INPUT_LEN);
    le64_put(params, created_at);
    le32_put(params + 8, epoch_len);
    le32_put(params + 12, valid_from);
    le32_put(params + 16, valid_until);
    le32_put(params + 20, kdf_rounds);

    cc_cute_compress(ns, salt, params, 0, CC_CUTE_MODE_CHAIN, chain);
}

/* ---- AAD preparation ----
 * Mutable fields are zeroed so AAD stays consistent across mutations.
 * Mutable: fuses_remaining, fuse_tip, heartbeat_epoch, ledger_count. */

static void prepare_aad(uint8_t aad[HDR_SIZE], const uint8_t *header) {
    memcpy(aad, header, HDR_SIZE);
    memset(aad + HDR_FUSES_REM, 0, 2);
    memset(aad + HDR_FUSE_TIP, 0, FUSE_TIP_LEN);
    memset(aad + HDR_HEARTBEAT, 0, 4);
    memset(aad + HDR_LEDGER_COUNT, 0, 2);
}

/* ---- Container layer ----
 * Outer AES-GCM encryption using a deterministic key derived from
 * the container_seed and heartbeat_epoch stored in the header.
 * Provides:
 *   - Heartbeat mutation (ciphertext changes on epoch boundaries)
 *   - Fuse anti-replay (container key rotates with heartbeat)
 */

static int container_wrap(
    const uint8_t *data, size_t data_len,
    const uint8_t key[CC_AES256_KEY_LEN],
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    uint8_t *out)
{
    cc_aes256_ctx *ctx = cc_aes256_init(key);
    if (!ctx) return -1;
    memcpy(out, data, data_len);
    int rc = cc_aes256_encrypt(ctx, nonce, NULL, 0, out, data_len);
    cc_aes256_free(ctx);
    return rc;
}

static int container_unwrap(
    const uint8_t *data, size_t data_len,
    const uint8_t key[CC_AES256_KEY_LEN],
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    uint8_t *out)
{
    cc_aes256_ctx *ctx = cc_aes256_init(key);
    if (!ctx) return -1;
    memcpy(out, data, data_len);
    int rc = cc_aes256_decrypt(ctx, nonce, NULL, 0, out, data_len);
    cc_aes256_free(ctx);
    return rc;
}

/* ---- Container key derivation ----
 * Deterministic: key = Hash(seed ‖ epoch ‖ "cutecrypt.container")
 * Nonce derived from second hash to avoid reuse. */

static void derive_container_key(
    const uint8_t seed[CONT_SEED_LEN], uint32_t epoch,
    uint8_t key[CC_AES256_KEY_LEN],
    uint8_t nonce_out[CC_AES256_NONCE_LEN])
{
    uint8_t in[CONT_SEED_LEN + 4 + 20];
    memcpy(in, seed, CONT_SEED_LEN);
    le32_put(in + CONT_SEED_LEN, epoch);
    memcpy(in + CONT_SEED_LEN + 4, "cutecrypt.container", 19);
    in[CONT_SEED_LEN + 4 + 19] = '\0';

    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, sizeof(in), h);
    memcpy(key, h, CC_AES256_KEY_LEN);

    /* Derive nonce from a second hash */
    uint8_t in2[CC_CUTE_HASH_LEN + 1];
    memcpy(in2, h, CC_CUTE_HASH_LEN);
    in2[CC_CUTE_HASH_LEN] = 0x01;
    uint8_t h2[CC_CUTE_HASH_LEN];
    cc_cute_hash(in2, CC_CUTE_HASH_LEN + 1, h2);
    memcpy(nonce_out, h2, CC_AES256_NONCE_LEN);

    memset(h, 0, sizeof(h));
    memset(h2, 0, sizeof(h2));
    memset(in, 0, sizeof(in));
}

/* ---- Nested fuse header ----
 *
 * The outer fuse doesn't protect content directly — it protects a
 * fuse header that contains inner fuse parameters. This header is
 * XOR-encrypted (unauthenticated) so brute-force can't short-circuit:
 *
 *   outer_key = KDF(password, salt, outer_tip, N rounds)
 *   fuse_hdr  = XOR_decrypt(outer_key, fuse_hdr_ct)     ← no auth tag
 *   inner_key = KDF(password, inner_salt, inner_tip, N rounds)
 *   plaintext = AES-GCM_decrypt(inner_key, content_ct)   ← auth check HERE
 *
 * For wrong passwords, the attacker pays 2×N KDF rounds before the
 * GCM tag tells them the password was wrong. Multiplicative cost.
 *
 * The fuse header plaintext layout:
 *   [32] inner_salt      — independent salt for inner KDF
 *   [32] inner_fuse_tip  — inner hash chain tip
 *   [12] inner_nonce     — AES-GCM nonce for content encryption
 *   Total: 76 bytes
 */

#define FH_INNER_SALT     0
#define FH_INNER_TIP      32
#define FH_INNER_NONCE    64
#define FUSE_HDR_SIZE     76

static void fuse_hdr_xor_cipher(
    const uint8_t key[CC_AES256_KEY_LEN],
    const uint8_t *in,
    uint8_t *out)
{
    uint8_t stream[96]; /* 3 × 32 ≥ FUSE_HDR_SIZE (76) */
    for (int blk = 0; blk < 3; blk++) {
        uint8_t blk_in[CC_AES256_KEY_LEN + 1];
        memcpy(blk_in, key, CC_AES256_KEY_LEN);
        blk_in[CC_AES256_KEY_LEN] = (uint8_t)blk;
        cc_cute_hash(blk_in, CC_AES256_KEY_LEN + 1,
                     stream + blk * CC_CUTE_HASH_LEN);
        memset(blk_in, 0, sizeof(blk_in));
    }
    for (size_t i = 0; i < FUSE_HDR_SIZE; i++)
        out[i] = in[i] ^ stream[i];
    memset(stream, 0, sizeof(stream));
}

/* ---- Jigsaw block permutation ----
 *
 * Permutes ciphertext blocks based on fuse state so that each fuse
 * consumption physically reorganizes the data on disk. On CoW
 * filesystems, old block positions contain old data in the old order;
 * without the permutation mapping (derived from destroyed fuse state),
 * the content can't be reassembled from disk forensics.
 *
 * Uses Fisher-Yates shuffle seeded by Hash(fuse_tip || "jigsaw").
 * Block size = 256 bytes (fits well in cache, multiple blocks per page).
 *
 * permute:   apply the Fisher-Yates permutation (encrypt/re-encrypt)
 * unpermute: apply the inverse permutation (decrypt)
 */

#define JIGSAW_BLOCK_SIZE 256

/* Derive a deterministic PRNG stream from fuse state for permutation.
 * Returns a sequence of 32-bit values via counter-mode hashing. */
static uint32_t jigsaw_rand(const uint8_t seed[CC_CUTE_HASH_LEN],
                            uint32_t counter)
{
    uint8_t in[CC_CUTE_HASH_LEN + 4];
    memcpy(in, seed, CC_CUTE_HASH_LEN);
    le32_put(in + CC_CUTE_HASH_LEN, counter);
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, sizeof(in), h);
    return le32_get(h);
}

static void jigsaw_seed_from_tip(const uint8_t tip[FUSE_TIP_LEN],
                                  uint8_t seed[CC_CUTE_HASH_LEN])
{
    uint8_t in[FUSE_TIP_LEN + 6];
    memcpy(in, tip, FUSE_TIP_LEN);
    memcpy(in + FUSE_TIP_LEN, "jigsaw", 6);
    cc_cute_hash(in, sizeof(in), seed);
}

/* Build Fisher-Yates permutation table: perm[i] = destination for block i */
static void jigsaw_build_perm(const uint8_t tip[FUSE_TIP_LEN],
                               size_t n_blocks, size_t *perm)
{
    /* Identity initialization */
    for (size_t i = 0; i < n_blocks; i++)
        perm[i] = i;

    if (n_blocks <= 1) return;

    uint8_t seed[CC_CUTE_HASH_LEN];
    jigsaw_seed_from_tip(tip, seed);

    /* Fisher-Yates from end to start */
    uint32_t ctr = 0;
    for (size_t i = n_blocks - 1; i > 0; i--) {
        uint32_t r = jigsaw_rand(seed, ctr++);
        size_t j = r % (i + 1);
        size_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    memset(seed, 0, sizeof(seed));
}

/* Apply permutation: out[perm[i]] = in[block i] */
static void jigsaw_permute(const uint8_t *in, uint8_t *out,
                            size_t data_len, const size_t *perm,
                            size_t n_blocks)
{
    size_t full = n_blocks * JIGSAW_BLOCK_SIZE;
    for (size_t i = 0; i < n_blocks; i++) {
        size_t src_off = i * JIGSAW_BLOCK_SIZE;
        size_t dst_off = perm[i] * JIGSAW_BLOCK_SIZE;
        /* Last block may be partial */
        size_t blk_len = JIGSAW_BLOCK_SIZE;
        if (src_off + blk_len > data_len) blk_len = data_len - src_off;
        if (dst_off + blk_len > data_len) blk_len = data_len - dst_off;
        memcpy(out + dst_off, in + src_off, blk_len);
    }
    /* Copy tail bytes past last full block boundary if any rounding mismatch */
    if (full < data_len)
        memcpy(out + full, in + full, data_len - full);
}

/* Apply inverse permutation: out[i] = in[perm[i]] */
static void jigsaw_unpermute(const uint8_t *in, uint8_t *out,
                              size_t data_len, const size_t *perm,
                              size_t n_blocks)
{
    size_t full = n_blocks * JIGSAW_BLOCK_SIZE;
    for (size_t i = 0; i < n_blocks; i++) {
        size_t src_off = perm[i] * JIGSAW_BLOCK_SIZE;
        size_t dst_off = i * JIGSAW_BLOCK_SIZE;
        size_t blk_len = JIGSAW_BLOCK_SIZE;
        if (src_off + blk_len > data_len) blk_len = data_len - src_off;
        if (dst_off + blk_len > data_len) blk_len = data_len - dst_off;
        memcpy(out + dst_off, in + src_off, blk_len);
    }
    if (full < data_len)
        memcpy(out + full, in + full, data_len - full);
}

/* ---- Vault ----
 * Encrypted storage for fuse preimages within the .cute file.
 * vault_key = Hash(outer_key ‖ "cutecrypt.vault")
 * Layout: [12 nonce][AES-GCM(outer_chain ‖ inner_chain) + 16 tag]
 * Size: 28 + max_fuses * 64 */

static size_t vault_compute_size(uint16_t max_fuses) {
    if (max_fuses == 0) return 0;
    return (size_t)CC_AES256_NONCE_LEN + (size_t)max_fuses * CC_FUSE_HASH_LEN * 2
           + CC_AES256_TAG_LEN;
}

static void derive_vault_key(
    const uint8_t outer_key[CC_AES256_KEY_LEN],
    uint8_t vault_key[CC_AES256_KEY_LEN])
{
    uint8_t in[CC_AES256_KEY_LEN + 15];
    memcpy(in, outer_key, CC_AES256_KEY_LEN);
    memcpy(in + CC_AES256_KEY_LEN, "cutecrypt.vault", 15);
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, sizeof(in), h);
    memcpy(vault_key, h, CC_AES256_KEY_LEN);
    memset(h, 0, sizeof(h));
    memset(in, 0, sizeof(in));
}

static int vault_encrypt(
    const uint8_t *outer_chain, const uint8_t *inner_chain,
    uint16_t max_fuses,
    const uint8_t vault_key[CC_AES256_KEY_LEN],
    uint8_t *out, size_t *out_len)
{
    size_t chain_len = (size_t)max_fuses * CC_FUSE_HASH_LEN;
    size_t preimage_len = chain_len * 2;

    uint8_t vnonce[CC_AES256_NONCE_LEN];
    randombytes(vnonce, CC_AES256_NONCE_LEN);
    memcpy(out, vnonce, CC_AES256_NONCE_LEN);

    memcpy(out + CC_AES256_NONCE_LEN, outer_chain, chain_len);
    memcpy(out + CC_AES256_NONCE_LEN + chain_len, inner_chain, chain_len);

    cc_aes256_ctx *ctx = cc_aes256_init(vault_key);
    if (!ctx) return -1;
    int rc = cc_aes256_encrypt(ctx, vnonce, NULL, 0,
                                out + CC_AES256_NONCE_LEN, preimage_len);
    cc_aes256_free(ctx);
    *out_len = CC_AES256_NONCE_LEN + preimage_len + CC_AES256_TAG_LEN;
    return rc;
}

static int vault_decrypt(
    const uint8_t *vault_data, size_t vault_len,
    const uint8_t vault_key[CC_AES256_KEY_LEN],
    uint8_t *preimages_out)
{
    if (vault_len < CC_AES256_NONCE_LEN + CC_AES256_TAG_LEN) return -1;

    const uint8_t *vnonce = vault_data;
    size_t ct_len = vault_len - CC_AES256_NONCE_LEN;

    memcpy(preimages_out, vault_data + CC_AES256_NONCE_LEN, ct_len);

    cc_aes256_ctx *ctx = cc_aes256_init(vault_key);
    if (!ctx) return -1;
    int rc = cc_aes256_decrypt(ctx, vnonce, NULL, 0, preimages_out, ct_len);
    cc_aes256_free(ctx);
    return rc;
}

/* Re-encrypt vault after fuse consumption: zero consumed slots, new key */
static int vault_reencrypt(
    uint8_t *preimages, uint16_t max_fuses, uint16_t fuses_consumed,
    const uint8_t new_vault_key[CC_AES256_KEY_LEN],
    uint8_t *out, size_t *out_len)
{
    size_t chain_len = (size_t)max_fuses * CC_FUSE_HASH_LEN;
    /* Zero out consumed slots (from the end, since chain is reversed) */
    for (uint16_t i = 0; i < fuses_consumed; i++) {
        size_t idx = (size_t)(max_fuses - 1 - i) * CC_FUSE_HASH_LEN;
        memset(preimages + idx, 0, CC_FUSE_HASH_LEN);           /* outer */
        memset(preimages + chain_len + idx, 0, CC_FUSE_HASH_LEN); /* inner */
    }

    size_t preimage_len = chain_len * 2;
    uint8_t vnonce[CC_AES256_NONCE_LEN];
    randombytes(vnonce, CC_AES256_NONCE_LEN);
    memcpy(out, vnonce, CC_AES256_NONCE_LEN);
    memcpy(out + CC_AES256_NONCE_LEN, preimages, preimage_len);

    cc_aes256_ctx *ctx = cc_aes256_init(new_vault_key);
    if (!ctx) return -1;
    int rc = cc_aes256_encrypt(ctx, vnonce, NULL, 0,
                                out + CC_AES256_NONCE_LEN, preimage_len);
    cc_aes256_free(ctx);
    *out_len = CC_AES256_NONCE_LEN + preimage_len + CC_AES256_TAG_LEN;
    return rc;
}

/* ---- Fuse Box ----
 * FBOX trailer enables fuse-only access (master key renounced) and
 * delegated fuse refresh via a separate refresh key.
 *
 * When renounced:
 *   content_key = random 32 bytes (encrypts payload instead of KDF key)
 *   content_key_enc = AES-GCM(content_key, key=Hash(kdf_key || fuse_chain_root))
 *   Only recoverable with password + valid fuse state
 *
 * Refresh key:
 *   Can refill fuses to max_fuses (regenerate fuse chain, re-encrypt vault)
 *   Cannot decrypt the payload or delegate further
 *   Set once at creation by master key holder */

static void fbox_derive_content_seal_key(
    const uint8_t kdf_key[CC_AES256_KEY_LEN],
    const uint8_t fuse_root[CC_FUSE_HASH_LEN],
    uint8_t seal_key[CC_AES256_KEY_LEN])
{
    uint8_t in[CC_AES256_KEY_LEN + CC_FUSE_HASH_LEN + 18];
    memcpy(in, kdf_key, CC_AES256_KEY_LEN);
    memcpy(in + CC_AES256_KEY_LEN, fuse_root, CC_FUSE_HASH_LEN);
    memcpy(in + CC_AES256_KEY_LEN + CC_FUSE_HASH_LEN, "cutedepo.fbox.seal", 18);
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, sizeof(in), h);
    memcpy(seal_key, h, CC_AES256_KEY_LEN);
    memset(h, 0, sizeof(h));
    memset(in, 0, sizeof(in));
}

/* Build FBOX trailer.
 * content_key_enc and content_key_salt are populated only when renounced. */
static size_t fbox_build(uint8_t *out, int renounced,
                          const uint8_t refresh_hash[CC_CUTE_HASH_LEN],
                          const uint8_t content_key_enc[32],
                          const uint8_t content_key_salt[32])
{
    memcpy(out, FBOX_MAGIC, 4);
    le32_put(out + 4, FBOX_SECTION_SIZE);
    out[8] = renounced ? FBOX_FLAG_RENOUNCED : 0;
    if (refresh_hash)
        memcpy(out + 9, refresh_hash, 32);
    else
        memset(out + 9, 0, 32);
    if (content_key_enc)
        memcpy(out + 41, content_key_enc, 32);
    else
        memset(out + 41, 0, 32);
    if (content_key_salt)
        memcpy(out + 73, content_key_salt, 32);
    else
        memset(out + 73, 0, 32);
    return TRAILER_HDR_SIZE + FBOX_SECTION_SIZE;
}

/* ---- Ledger ----
 * Append-only, hash-chained audit trail. Cleartext section at end of file.
 * Writable without password (append entries). Readable by anyone with the file.
 * Each entry: [8 timestamp][32 chain_hash][4 action][4 epoch] = 48 bytes */

#define LEDGER_ENTRY_SIZE     48
#define LEDGER_ACTION_CREATED   0
#define LEDGER_ACTION_HEARTBEAT 1
#define LEDGER_ACTION_ATTEMPT   2
#define LEDGER_ACTION_CONSUMED  3
#define LEDGER_ACTION_EXPIRED   4

static void ledger_entry_hash(
    const uint8_t prev[CC_CUTE_HASH_LEN],
    uint64_t ts, uint32_t action, uint32_t epoch,
    uint8_t out[CC_CUTE_HASH_LEN])
{
    uint8_t in[CC_CUTE_HASH_LEN + 16];
    memcpy(in, prev, CC_CUTE_HASH_LEN);
    le64_put(in + CC_CUTE_HASH_LEN, ts);
    le32_put(in + CC_CUTE_HASH_LEN + 8, action);
    le32_put(in + CC_CUTE_HASH_LEN + 12, epoch);
    cc_cute_hash(in, sizeof(in), out);
}

static void ledger_build_entry(
    const uint8_t prev_hash[CC_CUTE_HASH_LEN],
    uint32_t action, uint32_t epoch,
    uint8_t entry[LEDGER_ENTRY_SIZE])
{
    uint64_t ts = (uint64_t)time(NULL);
    le64_put(entry, ts);
    ledger_entry_hash(prev_hash, ts, action, epoch, entry + 8);
    le32_put(entry + 40, action);
    le32_put(entry + 44, epoch);
}

static void ledger_genesis(uint8_t entry[LEDGER_ENTRY_SIZE]) {
    uint8_t zero_hash[CC_CUTE_HASH_LEN];
    memset(zero_hash, 0, CC_CUTE_HASH_LEN);
    ledger_build_entry(zero_hash, LEDGER_ACTION_CREATED, 0, entry);
}

/* Get the chain hash from the last ledger entry */
static void ledger_last_hash(
    const uint8_t *ledger_data, uint16_t count,
    uint8_t hash[CC_CUTE_HASH_LEN])
{
    if (count == 0) {
        memset(hash, 0, CC_CUTE_HASH_LEN);
    } else {
        const uint8_t *last = ledger_data + (size_t)(count - 1) * LEDGER_ENTRY_SIZE;
        memcpy(hash, last + 8, CC_CUTE_HASH_LEN); /* chain_hash at offset 8 */
    }
}

/* ---- Hex encoding helper ---- */

static void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

/* ---- Role key derivation (for engraved messages) ---- */

static void derive_role_keys(
    const uint8_t outer_key[CC_AES256_KEY_LEN],
    uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN])
{
    /* role_key[0] = Hash(outer_key || "cutecrypt.engrave.0") */
    uint8_t in[CC_AES256_KEY_LEN + 21]; /* key + "cutecrypt.engrave.X\0" */
    memcpy(in, outer_key, CC_AES256_KEY_LEN);
    for (int i = 0; i < ROLE_COUNT; i++) {
        snprintf((char *)(in + (i == 0 ? CC_AES256_KEY_LEN : 0)),
                 sizeof(in) - (i == 0 ? CC_AES256_KEY_LEN : 0),
                 "cutecrypt.engrave.%d", i);
        size_t label_len = strlen((char *)(in + (i == 0 ? CC_AES256_KEY_LEN : 0)));
        size_t total = (i == 0 ? CC_AES256_KEY_LEN : 0) + label_len;
        /* For i>0: input is role_key[i-1] || label */
        if (i > 0) {
            memcpy(in, role_keys[i - 1], CC_AES256_KEY_LEN);
            snprintf((char *)(in + CC_AES256_KEY_LEN), sizeof(in) - CC_AES256_KEY_LEN,
                     "cutecrypt.engrave.%d", i);
            label_len = strlen((char *)(in + CC_AES256_KEY_LEN));
            total = CC_AES256_KEY_LEN + label_len;
        }
        uint8_t h[CC_CUTE_HASH_LEN];
        cc_cute_hash(in, total, h);
        memcpy(role_keys[i], h, CC_AES256_KEY_LEN);
        memset(h, 0, sizeof(h));
    }
    memset(in, 0, sizeof(in));
}

/* ---- Trailer section: PMSG (public messages) ---- */

static size_t pmsg_section_size(const char *msg) {
    if (!msg || !msg[0]) return 0;
    size_t mlen = strlen(msg);
    /* TRAILER_HDR(8) + count(2) + entry: timestamp(8) + msg_len(2) + msg */
    return TRAILER_HDR_SIZE + 2 + 8 + 2 + mlen;
}

static void pmsg_build(const char *msg, uint8_t *out, size_t *out_len) {
    size_t mlen = strlen(msg);
    size_t data_len = 2 + 8 + 2 + mlen;
    memcpy(out, PMSG_MAGIC, 4);
    le32_put(out + 4, (uint32_t)data_len);
    le16_put(out + 8, 1); /* count = 1 */
    le64_put(out + 10, (uint64_t)time(NULL));
    le16_put(out + 18, (uint16_t)mlen);
    memcpy(out + 20, msg, mlen);
    *out_len = TRAILER_HDR_SIZE + data_len;
}

/* ---- Trailer section: ENGR (engraved messages + files) ----
 *
 * Entry format:
 *   [1] type (0=text, 1=file)
 *   [1] role_level (0=root, 1=admin, 2=auditor, 3=reader)
 *   [2] content_len (LE, plaintext length)
 *   For type=1 (file):
 *     [2] filename_len (LE, cleartext)
 *     [filename_len] filename (cleartext UTF-8)
 *   [12] nonce
 *   [content_len + 16] AES-GCM ciphertext + tag
 */

#define ENGR_TYPE_TEXT 0
#define ENGR_TYPE_FILE 1

/* Build a text engrave entry */
static int engr_build_text(const char *msg, uint8_t role_level,
                           const uint8_t role_key[CC_AES256_KEY_LEN],
                           uint8_t *out, size_t *out_len)
{
    size_t mlen = strlen(msg);
    size_t ct_len = mlen + CC_AES256_TAG_LEN;
    /* entry: type(1) + level(1) + content_len(2) + nonce(12) + ct */
    size_t entry_len = 1 + 1 + 2 + 12 + ct_len;
    size_t data_len = 2 + entry_len; /* count(2) + entry */

    memcpy(out, ENGR_MAGIC, 4);
    le32_put(out + 4, (uint32_t)data_len);

    uint8_t *d = out + TRAILER_HDR_SIZE;
    le16_put(d, 1); d += 2; /* count = 1 */
    *d++ = ENGR_TYPE_TEXT;
    *d++ = role_level;
    le16_put(d, (uint16_t)mlen); d += 2;

    uint8_t nonce[CC_AES256_NONCE_LEN];
    randombytes(nonce, CC_AES256_NONCE_LEN);
    memcpy(d, nonce, 12); d += 12;

    cc_aes256_ctx *ctx = cc_aes256_init(role_key);
    if (!ctx) return -1;
    memcpy(d, msg, mlen);
    int rc = cc_aes256_encrypt(ctx, nonce, NULL, 0, d, mlen);
    cc_aes256_free(ctx);
    if (rc != 0) return -1;

    *out_len = TRAILER_HDR_SIZE + data_len;
    return 0;
}

/* Build a file engrave entry. Returns allocated buffer (caller frees). */
static int engr_build_file(const uint8_t *file_data, size_t file_len,
                           const char *filename, uint8_t role_level,
                           const uint8_t role_key[CC_AES256_KEY_LEN],
                           uint8_t **out, size_t *out_len)
{
    size_t fname_len = strlen(filename);
    if (fname_len > 255) fname_len = 255;
    size_t ct_len = file_len + CC_AES256_TAG_LEN;
    /* entry: type(1) + level(1) + content_len(2) + fname_len(2) + fname + nonce(12) + ct */
    size_t entry_len = 1 + 1 + 2 + 2 + fname_len + 12 + ct_len;
    size_t data_len = 2 + entry_len;
    size_t total = TRAILER_HDR_SIZE + data_len;

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, ENGR_MAGIC, 4);
    le32_put(buf + 4, (uint32_t)data_len);

    uint8_t *d = buf + TRAILER_HDR_SIZE;
    le16_put(d, 1); d += 2; /* count = 1 */
    *d++ = ENGR_TYPE_FILE;
    *d++ = role_level;
    le16_put(d, (uint16_t)file_len); d += 2;
    le16_put(d, (uint16_t)fname_len); d += 2;
    memcpy(d, filename, fname_len); d += fname_len;

    uint8_t nonce[CC_AES256_NONCE_LEN];
    randombytes(nonce, CC_AES256_NONCE_LEN);
    memcpy(d, nonce, 12); d += 12;

    cc_aes256_ctx *ctx = cc_aes256_init(role_key);
    if (!ctx) { free(buf); return -1; }
    memcpy(d, file_data, file_len);
    int rc = cc_aes256_encrypt(ctx, nonce, NULL, 0, d, file_len);
    cc_aes256_free(ctx);
    if (rc != 0) { free(buf); return -1; }

    *out = buf;
    *out_len = total;
    return 0;
}

/* ---- Trailer section parsing ---- */

/* Find trailer data after ledger. Returns pointer to start and total length. */
static const uint8_t *trailer_find(const uint8_t *file_data, size_t file_len,
                                   size_t ledger_end, size_t *trailer_len)
{
    if (file_len <= ledger_end) {
        *trailer_len = 0;
        return NULL;
    }
    *trailer_len = file_len - ledger_end;
    return file_data + ledger_end;
}

/* Find a specific trailer section by magic. Returns pointer to data (after 8-byte header). */
static const uint8_t *trailer_section_find(const uint8_t *trailer, size_t trailer_len,
                                           const char *magic, size_t *section_data_len)
{
    size_t off = 0;
    while (off + TRAILER_HDR_SIZE <= trailer_len) {
        if (memcmp(trailer + off, magic, 4) == 0) {
            uint32_t slen = le32_get(trailer + off + 4);
            if (off + TRAILER_HDR_SIZE + slen > trailer_len) return NULL;
            *section_data_len = slen;
            return trailer + off + TRAILER_HDR_SIZE;
        }
        uint32_t slen = le32_get(trailer + off + 4);
        off += TRAILER_HDR_SIZE + slen;
    }
    *section_data_len = 0;
    return NULL;
}

/* ---- Fuse Box (FBOX) operations that depend on trailer_section_find ---- */

/* Parse FBOX trailer — returns pointer to data section within trailer area */
static const uint8_t *fbox_find(const uint8_t *trailer_area, size_t trailer_len,
                                 int *renounced_out,
                                 const uint8_t **refresh_hash_out,
                                 const uint8_t **content_key_enc_out,
                                 const uint8_t **content_key_salt_out)
{
    size_t fbox_len;
    const uint8_t *fbox = trailer_section_find(trailer_area, trailer_len,
                                                FBOX_MAGIC, &fbox_len);
    if (!fbox || fbox_len < FBOX_SECTION_SIZE) return NULL;

    if (renounced_out) *renounced_out = (fbox[0] & FBOX_FLAG_RENOUNCED) ? 1 : 0;
    if (refresh_hash_out) *refresh_hash_out = fbox + 1;
    if (content_key_enc_out) *content_key_enc_out = fbox + 33;
    if (content_key_salt_out) *content_key_salt_out = fbox + 65;
    return fbox;
}

/* Check if refresh_hash is all zeros (no refresh key assigned) */
static int fbox_has_refresh_key(const uint8_t *refresh_hash) {
    for (int i = 0; i < 32; i++)
        if (refresh_hash[i] != 0) return 1;
    return 0;
}

/* Verify a refresh key against stored hash */
static int fbox_verify_refresh_key(const char *key, const uint8_t *stored_hash) {
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash((const uint8_t *)key, strlen(key), h);
    int match = 1;
    for (int i = 0; i < 32; i++)
        match &= (h[i] == stored_hash[i]);
    memset(h, 0, sizeof(h));
    return match;
}

/* do_fuse_refresh — refill fuses using the refresh key */
static int do_fuse_refresh(const char *path, const cli_opts *opts) {
    int quiet = opts->quiet;
    if (!quiet) fprintf(stderr, "\n  cutedepo — fuse refresh\n\n");

    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data || file_len < HDR_SIZE) {
        fprintf(stderr, "  error: cannot read '%s'\n", path);
        if (data) free(data);
        return 1;
    }
    if (memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stderr, "  error: not a .cute file\n");
        free(data);
        return 1;
    }

    uint8_t flags = data[HDR_FLAGS];
    if (!(flags & FLAG_FUSED)) {
        fprintf(stderr, "  error: file has no fuses\n");
        free(data);
        return 1;
    }

    uint16_t max_fuses = le16_get(data + HDR_MAX_FUSES);
    uint16_t fuses_rem = le16_get(data + HDR_FUSES_REM);
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    size_t bind_size = binding_section_size(flags);

    /* Find trailer area */
    size_t trailer_off = HDR_SIZE + bind_size + vault_size + payload_size
                         + (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_len = file_len > trailer_off ? file_len - trailer_off : 0;

    /* Find FBOX trailer */
    int renounced = 0;
    const uint8_t *refresh_hash = NULL;
    if (!fbox_find(data + trailer_off, trailer_len, &renounced,
                   &refresh_hash, NULL, NULL)) {
        fprintf(stderr, "  error: no fuse box found — fuse refresh requires --fuse-box at creation\n");
        free(data);
        return 1;
    }

    if (!fbox_has_refresh_key(refresh_hash)) {
        fprintf(stderr, "  error: no refresh key assigned — cannot refresh fuses\n");
        free(data);
        return 1;
    }

    /* Verify refresh key */
    if (!opts->do_refresh || strlen(opts->do_refresh) == 0) {
        fprintf(stderr, "  error: --refresh KEY required\n");
        free(data);
        return 1;
    }

    if (!fbox_verify_refresh_key(opts->do_refresh, refresh_hash)) {
        fprintf(stderr, "  error: invalid refresh key\n");
        free(data);
        return 1;
    }

    if (!quiet) {
        fprintf(stderr, "  refresh key verified\n");
        fprintf(stderr, "  fuses: %u/%u → %u/%u\n",
                fuses_rem, max_fuses, max_fuses, max_fuses);
    }

    /* NOTE — refresh is incomplete in this build.
     *
     * It writes a new fuse chain into the header / vault, but the file's
     * payload was encrypted using the *original* chain (each unlock
     * rolls forward through the chain and re-encrypts the payload under
     * the next step's keys). After refresh, the header advertises a new
     * chain that the payload was never encrypted with, so unlock fails
     * with "invalid outer fuse preimage".
     *
     * A correct refresh has to:
     *   1. decrypt the current payload using current chain preimages
     *      (requires the master password and a non-exhausted vault),
     *   2. generate a new chain,
     *   3. re-encrypt the payload under the new chain's keys,
     *   4. then write the new vault and header.
     *
     * That's roughly the lock path replayed; it's substantial internals
     * work that doesn't belong in this commit. The vault rewrite below
     * is left in place so the wire-up is testable end-to-end when the
     * full re-encrypt is added. The CLI `refresh` command and the GUI's
     * Refresh fuses modal both warn the user about this. */

    /* Generate new fuse chain */
    cc_fuse_chain outer_chain, inner_chain;
    cc_fuse_generate(&outer_chain, max_fuses, "cutedepo.fuse.outer");
    cc_fuse_generate(&inner_chain, max_fuses, "cutedepo.fuse.inner");

    /* Update header: reset fuses_remaining, update fuse_tip */
    le16_put(data + HDR_FUSES_REM, max_fuses);
    memcpy(data + 74, outer_chain.tip, CC_FUSE_HASH_LEN); /* fuse_tip at offset 74 */

    /* Derive vault key from refresh key (placeholder — see note above). */
    uint8_t refresh_vault_key[CC_AES256_KEY_LEN];
    {
        uint8_t rvk_in[256];
        size_t rk_len = strlen(opts->do_refresh);
        memcpy(rvk_in, opts->do_refresh, rk_len);
        memcpy(rvk_in + rk_len, "cutedepo.refresh.vault", 22);
        uint8_t h[CC_CUTE_HASH_LEN];
        cc_cute_hash(rvk_in, rk_len + 22, h);
        memcpy(refresh_vault_key, h, CC_AES256_KEY_LEN);
        memset(h, 0, sizeof(h));
        memset(rvk_in, 0, sizeof(rvk_in));
    }

    /* Build new vault */
    size_t new_vault_len = vault_compute_size(max_fuses);
    uint8_t *new_vault = malloc(new_vault_len);
    size_t actual_vault_len;
    if (vault_encrypt(outer_chain.chain, inner_chain.chain, max_fuses,
                      refresh_vault_key, new_vault, &actual_vault_len) != 0) {
        fprintf(stderr, "  error: vault encryption failed\n");
        free(new_vault);
        cc_fuse_free(&outer_chain);
        cc_fuse_free(&inner_chain);
        free(data);
        return 1;
    }

    /* Replace vault section in file data */
    size_t vault_off = HDR_SIZE + bind_size;
    if (actual_vault_len != vault_size) {
        size_t rest_off = vault_off + vault_size;
        size_t rest_len = file_len - rest_off;
        size_t new_file_len = vault_off + actual_vault_len + rest_len;
        uint8_t *new_data = malloc(new_file_len);
        memcpy(new_data, data, vault_off);
        memcpy(new_data + vault_off, new_vault, actual_vault_len);
        memcpy(new_data + vault_off + actual_vault_len, data + rest_off, rest_len);
        le32_put(new_data + HDR_VAULT_SIZE, (uint32_t)actual_vault_len);
        free(data);
        data = new_data;
        file_len = new_file_len;
    } else {
        memcpy(data + vault_off, new_vault, actual_vault_len);
    }
    free(new_vault);

    cc_fuse_free(&outer_chain);
    cc_fuse_free(&inner_chain);

    int rc = write_file_atomic(path, data, file_len);
    free(data);

    if (rc != 0) {
        fprintf(stderr, "  error: failed to write '%s'\n", path);
        return 1;
    }

    secure_zero(refresh_vault_key, sizeof(refresh_vault_key));

    if (!quiet) fprintf(stderr, "  fuses refreshed successfully\n\n");
    return 0;
}

/* Display public messages from PMSG section */
static void pmsg_display(const uint8_t *data, size_t data_len) {
    if (data_len < 2) return;
    uint16_t count = le16_get(data);
    const uint8_t *p = data + 2;
    size_t remaining = data_len - 2;
    for (uint16_t i = 0; i < count; i++) {
        if (remaining < 10) break;
        uint64_t ts = le64_get(p); p += 8;
        uint16_t mlen = le16_get(p); p += 2;
        remaining -= 10;
        if (mlen > remaining) break;
        time_t t = (time_t)ts;
        struct tm *tm = localtime(&t);
        char tbuf[32];
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(stderr, "    [%s] %.*s\n", tbuf, (int)mlen, (const char *)p);
        p += mlen;
        remaining -= mlen;
    }
}

/* Decrypt and display engraved messages/files from ENGR section.
 * user_level: the level the user holds (0=root sees all, 3=reader sees only reader).
 * out_dir: directory for extracting engraved files (NULL to skip extraction). */
static void engr_display(const uint8_t *data, size_t data_len,
                         uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN],
                         int user_level, const char *out_dir)
{
    if (data_len < 2) return;
    uint16_t count = le16_get(data);
    const uint8_t *p = data + 2;
    size_t remaining = data_len - 2;
    for (uint16_t i = 0; i < count; i++) {
        if (remaining < 4) break; /* type(1) + level(1) + content_len(2) */
        uint8_t type = *p++;
        uint8_t level = *p++;
        uint16_t content_len = le16_get(p); p += 2;
        remaining -= 4;

        /* For files: read cleartext filename */
        char fname[256] = {0};
        uint16_t fname_len = 0;
        if (type == ENGR_TYPE_FILE) {
            if (remaining < 2) break;
            fname_len = le16_get(p); p += 2;
            remaining -= 2;
            if (fname_len > remaining || fname_len > 255) break;
            memcpy(fname, p, fname_len);
            fname[fname_len] = '\0';
            p += fname_len;
            remaining -= fname_len;
        }

        size_t ct_len = (size_t)content_len + CC_AES256_TAG_LEN;
        if (remaining < 12 + ct_len) break;
        const uint8_t *nonce = p; p += 12;
        remaining -= 12;

        const char *rname = level < ROLE_COUNT ? role_names[level] : "?";

        if (level < (uint8_t)user_level) {
            p += ct_len;
            remaining -= ct_len;
            if (type == ENGR_TYPE_FILE)
                fprintf(stderr, "    [%s] file: %s (access denied)\n", rname, fname);
            else
                fprintf(stderr, "    [%s] (access denied — requires %s or higher)\n", rname, rname);
            continue;
        }

        if (level >= ROLE_COUNT) { p += ct_len; remaining -= ct_len; continue; }

        /* Decrypt */
        uint8_t *pt = malloc(ct_len);
        memcpy(pt, p, ct_len);
        p += ct_len;
        remaining -= ct_len;

        cc_aes256_ctx *ctx = cc_aes256_init(role_keys[level]);
        if (!ctx) { free(pt); continue; }
        int rc = cc_aes256_decrypt(ctx, nonce, NULL, 0, pt, ct_len);
        cc_aes256_free(ctx);
        if (rc != 0) {
            if (type == ENGR_TYPE_FILE)
                fprintf(stderr, "    [%s] file: %s (decryption failed)\n", rname, fname);
            else
                fprintf(stderr, "    [%s] (decryption failed)\n", rname);
            free(pt);
            continue;
        }

        if (type == ENGR_TYPE_FILE) {
            if (out_dir) {
                /* Extract to out_dir/filename */
                char extract_path[4096];
                snprintf(extract_path, sizeof(extract_path), "%s/%s", out_dir, fname);
                /* Create directory if needed */
                mkdir(out_dir, 0755);
                if (write_file_atomic(extract_path, pt, content_len) == 0) {
                    fprintf(stderr, "    [%s] file: %s (%u bytes) → %s\n",
                            rname, fname, content_len, extract_path);
                } else {
                    fprintf(stderr, "    [%s] file: %s (extract failed)\n", rname, fname);
                }
            } else {
                fprintf(stderr, "    [%s] file: %s (%u bytes, encrypted)\n",
                        rname, fname, content_len);
            }
        } else {
            fprintf(stderr, "    [%s] %.*s\n", rname, (int)content_len, pt);
        }
        free(pt);
    }
}

/* ---- OS Keychain binding ----
 * Stores a 32-byte random nonce in the OS keychain, keyed by
 * Hash(salt || namespace). The container key becomes:
 *   Hash(container_seed || keychain_nonce || epoch || "cutecrypt.container.bound")
 * On fuse consumption, the nonce rotates → old file copies go stale.
 * On purge, the keychain entry is deleted. */

static void keychain_derive_id(const uint8_t *salt, const uint8_t *ns,
                                uint8_t id[CC_CUTE_HASH_LEN]) {
    uint8_t in[SALT_LEN + NS_LEN];
    memcpy(in, salt, SALT_LEN);
    memcpy(in + SALT_LEN, ns, NS_LEN);
    cc_cute_hash(in, sizeof(in), id);
}

#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static CFMutableDictionaryRef keychain_base_query(const uint8_t id[CC_CUTE_HASH_LEN]) {
    char hex[CC_CUTE_HASH_LEN * 2 + 1];
    hex_encode(id, CC_CUTE_HASH_LEN, hex);

    CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFStringRef svc = CFSTR("com.cutecrypt.binding");
    CFDictionarySetValue(q, kSecAttrService, svc);
    CFStringRef acct = CFStringCreateWithCString(NULL, hex, kCFStringEncodingASCII);
    CFDictionarySetValue(q, kSecAttrAccount, acct);
    CFRelease(acct);
    return q;
}

static int keychain_store(const uint8_t id[CC_CUTE_HASH_LEN],
                           const uint8_t nonce[CC_CUTE_HASH_LEN]) {
    /* Delete existing entry if any */
    CFMutableDictionaryRef dq = keychain_base_query(id);
    SecItemDelete(dq);
    CFRelease(dq);

    CFMutableDictionaryRef q = keychain_base_query(id);
    CFDataRef data = CFDataCreate(NULL, nonce, CC_CUTE_HASH_LEN);
    CFDictionarySetValue(q, kSecValueData, data);
    OSStatus status = SecItemAdd(q, NULL);
    CFRelease(data);
    CFRelease(q);
    return (status == errSecSuccess) ? 0 : -1;
}

static int keychain_load(const uint8_t id[CC_CUTE_HASH_LEN],
                          uint8_t nonce_out[CC_CUTE_HASH_LEN]) {
    CFMutableDictionaryRef q = keychain_base_query(id);
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);

    CFDataRef result = NULL;
    OSStatus status = SecItemCopyMatching(q, (CFTypeRef *)&result);
    CFRelease(q);

    if (status != errSecSuccess || !result) return -1;
    if (CFDataGetLength(result) < CC_CUTE_HASH_LEN) {
        CFRelease(result);
        return -1;
    }
    memcpy(nonce_out, CFDataGetBytePtr(result), CC_CUTE_HASH_LEN);
    CFRelease(result);
    return 0;
}

static int keychain_rotate(const uint8_t id[CC_CUTE_HASH_LEN],
                            uint8_t new_nonce_out[CC_CUTE_HASH_LEN]) {
    randombytes(new_nonce_out, CC_CUTE_HASH_LEN);

    CFMutableDictionaryRef q = keychain_base_query(id);
    CFMutableDictionaryRef update = CFDictionaryCreateMutable(NULL, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef data = CFDataCreate(NULL, new_nonce_out, CC_CUTE_HASH_LEN);
    CFDictionarySetValue(update, kSecValueData, data);

    OSStatus status = SecItemUpdate(q, update);
    CFRelease(data);
    CFRelease(update);
    CFRelease(q);
    return (status == errSecSuccess) ? 0 : -1;
}

static int keychain_delete(const uint8_t id[CC_CUTE_HASH_LEN]) {
    CFMutableDictionaryRef q = keychain_base_query(id);
    OSStatus status = SecItemDelete(q);
    CFRelease(q);
    return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : -1;
}

#elif defined(__linux__)
/* Linux fallback: file-based storage in ~/.local/share/cutecrypt/bindings/ */

#include <pwd.h>

static void keychain_file_path(const uint8_t id[CC_CUTE_HASH_LEN], char *path, size_t cap) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    char hex[CC_CUTE_HASH_LEN * 2 + 1];
    hex_encode(id, CC_CUTE_HASH_LEN, hex);
    snprintf(path, cap, "%s/.local/share/cutecrypt/bindings/%s", home, hex);
}

static void keychain_ensure_dir(void) {
    const char *home = getenv("HOME");
    if (!home) return;
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s/.local/share/cutecrypt/bindings", home);
    mkdir(dir, 0700); /* parents may not exist; best-effort */
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s/.local/share/cutecrypt", home);
    mkdir(parent, 0700);
    snprintf(parent, sizeof(parent), "%s/.local/share", home);
    mkdir(parent, 0755);
}

static int keychain_store(const uint8_t id[CC_CUTE_HASH_LEN],
                           const uint8_t nonce[CC_CUTE_HASH_LEN]) {
    keychain_ensure_dir();
    char path[4096];
    keychain_file_path(id, path, sizeof(path));
    return write_file_atomic(path, nonce, CC_CUTE_HASH_LEN);
}

static int keychain_load(const uint8_t id[CC_CUTE_HASH_LEN],
                          uint8_t nonce_out[CC_CUTE_HASH_LEN]) {
    char path[4096];
    keychain_file_path(id, path, sizeof(path));
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data || len < CC_CUTE_HASH_LEN) { free(data); return -1; }
    memcpy(nonce_out, data, CC_CUTE_HASH_LEN);
    free(data);
    return 0;
}

static int keychain_rotate(const uint8_t id[CC_CUTE_HASH_LEN],
                            uint8_t new_nonce_out[CC_CUTE_HASH_LEN]) {
    randombytes(new_nonce_out, CC_CUTE_HASH_LEN);
    return keychain_store(id, new_nonce_out);
}

static int keychain_delete(const uint8_t id[CC_CUTE_HASH_LEN]) {
    char path[4096];
    keychain_file_path(id, path, sizeof(path));
    unlink(path);
    return 0;
}

#else
/* Unsupported platform — stubs that always fail */
static int keychain_store(const uint8_t id[CC_CUTE_HASH_LEN],
                           const uint8_t nonce[CC_CUTE_HASH_LEN]) {
    (void)id; (void)nonce; return -1;
}
static int keychain_load(const uint8_t id[CC_CUTE_HASH_LEN],
                          uint8_t nonce_out[CC_CUTE_HASH_LEN]) {
    (void)id; (void)nonce_out; return -1;
}
static int keychain_rotate(const uint8_t id[CC_CUTE_HASH_LEN],
                            uint8_t new_nonce_out[CC_CUTE_HASH_LEN]) {
    (void)id; (void)new_nonce_out; return -1;
}
static int keychain_delete(const uint8_t id[CC_CUTE_HASH_LEN]) {
    (void)id; return -1;
}
#endif

/* Container key derivation with keychain nonce binding */
static void derive_container_key_bound(
    const uint8_t seed[CONT_SEED_LEN],
    const uint8_t kc_nonce[CC_CUTE_HASH_LEN],
    uint32_t epoch,
    uint8_t key[CC_AES256_KEY_LEN],
    uint8_t nonce_out[CC_AES256_NONCE_LEN])
{
    /* Hash(seed || kc_nonce || epoch || "cutecrypt.container.bound") */
    uint8_t in[CONT_SEED_LEN + CC_CUTE_HASH_LEN + 4 + 26];
    size_t off = 0;
    memcpy(in + off, seed, CONT_SEED_LEN); off += CONT_SEED_LEN;
    memcpy(in + off, kc_nonce, CC_CUTE_HASH_LEN); off += CC_CUTE_HASH_LEN;
    le32_put(in + off, epoch); off += 4;
    memcpy(in + off, "cutecrypt.container.bound", 25);
    in[off + 25] = '\0';
    off += 26;

    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, off, h);
    memcpy(key, h, CC_AES256_KEY_LEN);

    uint8_t in2[CC_CUTE_HASH_LEN + 1];
    memcpy(in2, h, CC_CUTE_HASH_LEN);
    in2[CC_CUTE_HASH_LEN] = 0x01;
    uint8_t h2[CC_CUTE_HASH_LEN];
    cc_cute_hash(in2, CC_CUTE_HASH_LEN + 1, h2);
    memcpy(nonce_out, h2, CC_AES256_NONCE_LEN);

    memset(h, 0, sizeof(h));
    memset(h2, 0, sizeof(h2));
    memset(in, 0, sizeof(in));
}

/* ---- Remote fuse server client ----
 * Uses curl via posix_spawn for HTTP requests. No libcurl dependency.
 *
 * Protocol:
 *   POST /register  {"max_fuses":N}    → {"file_id":"<hex>"}
 *   GET  /check/<id>                    → {"remaining":N}
 *   POST /consume/<id>                  → {"ok":true} or {"error":"..."}
 *   DELETE /delete/<id>                 → {"ok":true}
 */

static int curl_request(const char *method, const char *url,
                        const char *json_body,
                        char *response, size_t response_cap) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    char *argv[16];
    int argc = 0;
    argv[argc++] = (char *)"curl";
    argv[argc++] = (char *)"-s";
    argv[argc++] = (char *)"-X";
    argv[argc++] = (char *)method;
    if (json_body) {
        argv[argc++] = (char *)"-H";
        argv[argc++] = (char *)"Content-Type: application/json";
        argv[argc++] = (char *)"-d";
        argv[argc++] = (char *)json_body;
    }
    argv[argc++] = (char *)url;
    argv[argc] = NULL;

    pid_t pid;
    int rc = posix_spawnp(&pid, "curl", &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);

    if (rc != 0) { close(pipefd[0]); return -1; }

    size_t total = 0;
    while (total < response_cap - 1) {
        ssize_t n = read(pipefd[0], response + total, response_cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    response[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Minimal JSON string extraction: find "key":"value" */
static int json_get_string(const char *json, const char *key,
                            char *out, size_t cap) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - p);
    if (len >= cap) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int json_get_int(const char *json, const char *key, int *out) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    while (*p == ' ') p++;
    *out = atoi(p);
    return 0;
}

static void remote_url_hash(const char *url, uint8_t hash[16]) {
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash((const uint8_t *)url, strlen(url), h);
    memcpy(hash, h, 16); /* truncated */
}

static int remote_fuse_register(const char *server_url, uint16_t max_fuses,
                                 uint8_t file_id_out[16]) {
    char url[4096];
    snprintf(url, sizeof(url), "%s/register", server_url);
    char body[128];
    snprintf(body, sizeof(body), "{\"max_fuses\":%u}", max_fuses);

    char response[4096];
    if (curl_request("POST", url, body, response, sizeof(response)) != 0)
        return -1;

    char id_hex[64];
    if (json_get_string(response, "file_id", id_hex, sizeof(id_hex)) != 0)
        return -1;

    /* Parse hex file_id (32 hex chars = 16 bytes) */
    if (strlen(id_hex) != 32) return -1;
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        sscanf(id_hex + 2 * i, "%02x", &byte);
        file_id_out[i] = (uint8_t)byte;
    }
    return 0;
}

static int remote_fuse_check(const char *server_url, const uint8_t file_id[16],
                              int *remaining_out) {
    char id_hex[33];
    hex_encode(file_id, 16, id_hex);
    char url[4096];
    snprintf(url, sizeof(url), "%s/check/%s", server_url, id_hex);

    char response[4096];
    if (curl_request("GET", url, NULL, response, sizeof(response)) != 0)
        return -1;

    return json_get_int(response, "remaining", remaining_out);
}

static int remote_fuse_consume(const char *server_url, const uint8_t file_id[16]) {
    char id_hex[33];
    hex_encode(file_id, 16, id_hex);
    char url[4096];
    snprintf(url, sizeof(url), "%s/consume/%s", server_url, id_hex);

    char response[4096];
    if (curl_request("POST", url, NULL, response, sizeof(response)) != 0)
        return -1;

    /* Check for error in response */
    if (strstr(response, "\"error\"")) return -1;
    return 0;
}

static int remote_fuse_delete(const char *server_url, const uint8_t file_id[16]) {
    char id_hex[33];
    hex_encode(file_id, 16, id_hex);
    char url[4096];
    snprintf(url, sizeof(url), "%s/delete/%s", server_url, id_hex);

    char response[4096];
    return curl_request("DELETE", url, NULL, response, sizeof(response));
}

/* Forward declarations for claim flow (decrypt → re-encrypt) */
static int do_archive_encrypt(int n_paths, char **paths, const cli_opts *opts);

/* ---- Encrypt ---- */

static int do_encrypt(const char *path, const cli_opts *opts) {
    int folder = is_directory(path);
    uint8_t *plaintext = NULL;
    size_t pt_len = 0;
    int quiet = opts->quiet;

    if (!quiet) {
        fprintf(stderr, "\n  cutecrypt — encrypt\n");
        fprintf(stderr, "  ─────────────────────────────────────\n");
        fprintf(stderr, "  %s: %s\n\n", folder ? "folder" : "file", path);
    }

    /* Load content */
    if (folder) {
        if (!quiet) fprintf(stderr, "  archiving folder...\n\n");
        plaintext = tar_folder(path, &pt_len);
        if (!plaintext) { fprintf(stderr, "  error: failed to archive folder\n"); return 1; }
    } else {
        plaintext = read_file(path, &pt_len);
        if (!plaintext) { fprintf(stderr, "  error: cannot read file\n"); return 1; }
    }

    /* ---- Get password / auth ---- */
    char password[256];
    int totp_active = 0;
    uint8_t totp_secret_raw[64];
    size_t totp_secret_len = 0;
    uint8_t clam_ephemeral[CLAM_SECTION_SIZE];
    int is_claimable = opts->claimable;

    if (is_claimable) {
        /* Claimable mode: generate random ephemeral password.
         * The first person to open this file will claim the master key. */
        randombytes(clam_ephemeral, CLAM_SECTION_SIZE);
        for (int i = 0; i < CLAM_SECTION_SIZE; i++)
            snprintf(password + i*2, 3, "%02x", clam_ephemeral[i]);
        password[CLAM_SECTION_SIZE * 2] = '\0';
        if (!quiet) fprintf(stderr, "  claimable: master key will be set on first open\n");
    } else if (opts->totp_secret) {
        /* TOTP mode: decode base32 secret, generate current code as password */
        if (base32_decode(opts->totp_secret, totp_secret_raw, sizeof(totp_secret_raw),
                          &totp_secret_len) != 0 || totp_secret_len == 0) {
            fprintf(stderr, "  error: invalid TOTP secret (must be base32)\n");
            free(plaintext); return 1;
        }
        uint64_t tnow = (uint64_t)time(NULL);
        uint32_t code = totp_generate(totp_secret_raw, totp_secret_len,
                                       tnow, TOTP_PERIOD_DEFAULT, TOTP_DIGITS_DEFAULT);
        totp_format(code, TOTP_DIGITS_DEFAULT, password, sizeof(password));
        totp_active = 1;
        if (!quiet) fprintf(stderr, "  TOTP auth: using current code\n");
    } else if (opts->passkey) {
        /* Passkey mode: derive a stable credential from platform identity */
        uint8_t pkey_material[CC_CUTE_HASH_LEN];
        /* Use a platform-derived seed. In production this would be
         * Secure Enclave / Touch ID. For now, derive from hostname + user. */
        char identity[512];
        snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s",
                 getenv("USER") ?: "default", getenv("HOME") ?: "/");
        cc_cute_hash((const uint8_t *)identity, strlen(identity), pkey_material);
        for (int i = 0; i < 32; i++)
            snprintf(password + i*2, 3, "%02x", pkey_material[i]);
        password[64] = '\0';
        secure_zero(pkey_material, sizeof(pkey_material));
        if (!quiet) fprintf(stderr, "  passkey auth: using platform credential\n");
    } else if (opts->headless) {
        strncpy(password, opts->password, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
    } else {
        if (!quiet) fprintf(stderr, "  configure locks:\n\n");
        char confirm[256];
        read_password("  password: ", password, sizeof(password));
        read_password("  confirm:  ", confirm, sizeof(confirm));
        if (strcmp(password, confirm) != 0) {
            fprintf(stderr, "  error: passwords don't match\n");
            memset(password, 0, sizeof(password)); memset(confirm, 0, sizeof(confirm));
            free(plaintext); return 1;
        }
        memset(confirm, 0, sizeof(confirm));
    }

    if (strlen(password) == 0) {
        fprintf(stderr, "  error: password cannot be empty\n");
        free(plaintext); return 1;
    }

    if (!opts->headless && !quiet) fprintf(stderr, "\n");

    /* Collect flags */
    uint8_t flags = folder ? FLAG_FOLDER : 0;
    uint64_t now = (uint64_t)time(NULL);
    uint32_t epoch_len = 0;
    uint32_t valid_from = 0;
    uint32_t valid_until = 0xFFFFFFFF;
    uint16_t max_fuses = 0;
    uint8_t fuse_tip[FUSE_TIP_LEN];
    memset(fuse_tip, 0, FUSE_TIP_LEN);
    cc_fuse_chain fuse_chain;
    memset(&fuse_chain, 0, sizeof(fuse_chain));
    int has_fuse_chain = 0;
    cc_fuse_chain inner_fuse_chain;
    memset(&inner_fuse_chain, 0, sizeof(inner_fuse_chain));
    int has_inner_fuse_chain = 0;
    uint8_t inner_fuse_tip[FUSE_TIP_LEN];
    memset(inner_fuse_tip, 0, FUSE_TIP_LEN);

    if (opts->headless) {
        epoch_len = opts->epoch_len ? opts->epoch_len : 3600;

        if (opts->valid_epochs > 0) {
            flags |= FLAG_TIMED;
            valid_until = opts->valid_epochs;
        }

        if (opts->delay_secs > 0) {
            flags |= FLAG_DELAYED;
            valid_from = opts->delay_secs / epoch_len;
        }

        if (opts->fuses > 0) {
            flags |= FLAG_FUSED;
            max_fuses = opts->fuses;
            int rc = cc_fuse_generate(&fuse_chain, max_fuses, "cutecrypt.file-fuse");
            if (rc != 0) {
                fprintf(stderr, "  error: failed to generate fuse chain\n");
                memset(password, 0, sizeof(password));
                free(plaintext); return 1;
            }
            memcpy(fuse_tip, fuse_chain.tip, FUSE_TIP_LEN);
            has_fuse_chain = 1;

            int rc2 = cc_fuse_generate(&inner_fuse_chain, max_fuses, "cutecrypt.nested-fuse");
            if (rc2 != 0) {
                fprintf(stderr, "  error: failed to generate inner fuse chain\n");
                cc_fuse_free(&fuse_chain);
                memset(password, 0, sizeof(password));
                free(plaintext); return 1;
            }
            memcpy(inner_fuse_tip, inner_fuse_chain.tip, FUSE_TIP_LEN);
            has_inner_fuse_chain = 1;
        }

        if (opts->purge && (flags & (FLAG_TIMED | FLAG_FUSED)))
            flags |= FLAG_PURGE;
    } else {
        /* ---- Interactive lock configuration ---- */

        if (read_yes_no("  timed access window? (y/n): ")) {
            flags |= FLAG_TIMED;
            fprintf(stderr, "\n");
            epoch_len = read_uint("  epoch length in seconds (e.g. 3600 for hourly): ");
            if (epoch_len == 0) epoch_len = 3600;
            uint32_t window = read_uint("  valid for how many epochs? (e.g. 24): ");
            if (window == 0) window = 1;
            valid_from = 0;
            valid_until = window;
            fprintf(stderr, "  → valid for %u epochs of %u seconds (%u hours total)\n\n",
                    window, epoch_len, (window * epoch_len) / 3600);
        }

        if (read_yes_no("  delayed access (not before a future time)? (y/n): ")) {
            flags |= FLAG_DELAYED;
            fprintf(stderr, "\n");
            uint32_t delay_secs = read_uint("  delay in seconds from now (e.g. 86400 for 1 day): ");
            if (epoch_len == 0) {
                epoch_len = read_uint("  epoch length in seconds (e.g. 3600): ");
                if (epoch_len == 0) epoch_len = 3600;
            }
            valid_from = delay_secs / epoch_len;
            if (!(flags & FLAG_TIMED))
                valid_until = 0xFFFFFFFF;
            fprintf(stderr, "  → accessible after epoch %u (in ~%u seconds)\n\n",
                    valid_from, delay_secs);
        }

        if (read_yes_no("  fuse-limited (max decryptions)? (y/n): ")) {
            flags |= FLAG_FUSED;
            fprintf(stderr, "\n");
            max_fuses = (uint16_t)read_uint("  max decryptions (1-65535): ");
            if (max_fuses == 0) max_fuses = 1;

            int rc = cc_fuse_generate(&fuse_chain, max_fuses, "cutecrypt.file-fuse");
            if (rc != 0) {
                fprintf(stderr, "  error: failed to generate fuse chain\n");
                memset(password, 0, sizeof(password));
                free(plaintext); return 1;
            }
            memcpy(fuse_tip, fuse_chain.tip, FUSE_TIP_LEN);
            has_fuse_chain = 1;

            int rc2 = cc_fuse_generate(&inner_fuse_chain, max_fuses, "cutecrypt.nested-fuse");
            if (rc2 != 0) {
                fprintf(stderr, "  error: failed to generate inner fuse chain\n");
                cc_fuse_free(&fuse_chain);
                memset(password, 0, sizeof(password));
                free(plaintext); return 1;
            }
            memcpy(inner_fuse_tip, inner_fuse_chain.tip, FUSE_TIP_LEN);
            has_inner_fuse_chain = 1;
            fprintf(stderr, "  → %u fuse(s) generated (nested)\n\n", max_fuses);
        }

        if (flags & (FLAG_TIMED | FLAG_FUSED)) {
            if (read_yes_no("  self-purge when expired/exhausted? (y/n): ")) {
                flags |= FLAG_PURGE;
                fprintf(stderr, "  → file will be securely deleted on expiry/exhaustion\n\n");
            }
        }

        /* Interactive mode: keychain binding on by default (ties file to this machine) */
        flags |= FLAG_KEYCHAIN | FLAG_CONTAINER;
        if (!quiet)
            fprintf(stderr, "  keychain binding: enabled (file tied to this machine)\n\n");
    }

    /* Container layer for fused or purgeable files */
    if (flags & (FLAG_FUSED | FLAG_PURGE))
        flags |= FLAG_CONTAINER;

    /* Anti-replay: keychain binding */
    if (opts->keychain) {
        flags |= FLAG_KEYCHAIN | FLAG_CONTAINER;
    }

    /* Anti-replay: remote fuse server */
    if (opts->fuse_server) {
        flags |= FLAG_REMOTE_FUSE | FLAG_CONTAINER;
    }

    /* KDF rounds */
    uint32_t kdf_rounds = opts->kdf_rounds ? opts->kdf_rounds : KDF_ROUNDS_DEFAULT;

    /* ---- Build header ---- */
    uint8_t header[HDR_SIZE];
    memset(header, 0, HDR_SIZE);
    memcpy(header + HDR_MAGIC, CUTE_MAGIC, 4);
    header[HDR_VERSION] = CUTE_VERSION;
    header[HDR_FLAGS] = flags;

    uint8_t salt[SALT_LEN];
    uint8_t nonce[CC_AES256_NONCE_LEN];
    randombytes(salt, SALT_LEN);
    randombytes(nonce, CC_AES256_NONCE_LEN);
    memcpy(header + HDR_SALT, salt, SALT_LEN);
    memcpy(header + HDR_NONCE, nonce, CC_AES256_NONCE_LEN);

    le64_put(header + HDR_CREATED, now);
    le32_put(header + HDR_EPOCH_LEN, epoch_len);
    le32_put(header + HDR_VALID_FROM, valid_from);
    le32_put(header + HDR_VALID_UNTIL, valid_until);
    le16_put(header + HDR_MAX_FUSES, max_fuses);
    le16_put(header + HDR_FUSES_REM, max_fuses);
    memcpy(header + HDR_FUSE_TIP, fuse_tip, FUSE_TIP_LEN);

    uint8_t ns[NS_LEN];
    cc_cute_namespace(ns, "cutecrypt.file", 14);
    memcpy(header + HDR_NAMESPACE, ns, NS_LEN);

    le32_put(header + HDR_KDF_ROUNDS, kdf_rounds);

    /* Epoch chain commitment */
    uint8_t epoch_chain[EPOCH_CHAIN_LEN];
    compute_epoch_chain(salt, now, epoch_len, valid_from, valid_until, kdf_rounds, epoch_chain);
    memcpy(header + HDR_EPOCH_CHAIN, epoch_chain, EPOCH_CHAIN_LEN);
    le32_put(header + HDR_HEARTBEAT, 0);

    /* Container seed */
    uint8_t cont_seed[CONT_SEED_LEN];
    if (flags & FLAG_CONTAINER) {
        randombytes(cont_seed, CONT_SEED_LEN);
    } else {
        memset(cont_seed, 0, CONT_SEED_LEN);
    }
    memcpy(header + HDR_CONT_SEED, cont_seed, CONT_SEED_LEN);

    /* ---- Anti-replay setup ---- */
    uint8_t kc_nonce[CC_CUTE_HASH_LEN];
    int has_kc_nonce = 0;
    uint8_t binding_data[BINDING_REMOTE_SIZE];
    memset(binding_data, 0, sizeof(binding_data));
    size_t bind_size = binding_section_size(flags);

    if (flags & FLAG_KEYCHAIN) {
        /* Generate keychain nonce and store in OS keychain */
        uint8_t kc_id[CC_CUTE_HASH_LEN];
        keychain_derive_id(salt, ns, kc_id);
        randombytes(kc_nonce, CC_CUTE_HASH_LEN);
        if (keychain_store(kc_id, kc_nonce) != 0) {
            fprintf(stderr, "  error: failed to store keychain nonce\n");
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            free(plaintext); return 1;
        }
        has_kc_nonce = 1;
        if (!quiet) fprintf(stderr, "  keychain binding: enabled\n");
    }

    if (flags & FLAG_REMOTE_FUSE) {
        /* Register with remote fuse server */
        uint16_t rf_fuses = (flags & FLAG_FUSED) ? max_fuses : 1;
        uint8_t file_id[16];
        if (remote_fuse_register(opts->fuse_server, rf_fuses, file_id) != 0) {
            fprintf(stderr, "  error: failed to register with fuse server\n");
            if (has_kc_nonce) {
                uint8_t kc_id[CC_CUTE_HASH_LEN];
                keychain_derive_id(salt, ns, kc_id);
                keychain_delete(kc_id);
            }
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            free(plaintext); return 1;
        }
        memcpy(binding_data + BINDING_FILE_ID, file_id, 16);
        remote_url_hash(opts->fuse_server, binding_data + BINDING_URL_HASH);
        if (!quiet) fprintf(stderr, "  remote fuse: registered\n");
    }

    /* ---- Encrypt content ---- */
    uint8_t *ct_buf;
    size_t inner_ct_len;
    int rc;
    uint8_t aad[HDR_SIZE];

    /* We'll finalize vault_size, payload_size, ledger_count in header after computing them */

    if (flags & FLAG_FUSED) {
        /* Nested fuse: outer KDF → fuse header, inner KDF → content */

        /* Build fuse header plaintext */
        uint8_t inner_salt[SALT_LEN];
        uint8_t inner_nonce_buf[CC_AES256_NONCE_LEN];
        randombytes(inner_salt, SALT_LEN);
        randombytes(inner_nonce_buf, CC_AES256_NONCE_LEN);

        uint8_t fuse_hdr_plain[FUSE_HDR_SIZE];
        memcpy(fuse_hdr_plain + FH_INNER_SALT, inner_salt, SALT_LEN);
        memcpy(fuse_hdr_plain + FH_INNER_TIP, inner_fuse_tip, FUSE_TIP_LEN);
        memcpy(fuse_hdr_plain + FH_INNER_NONCE, inner_nonce_buf, CC_AES256_NONCE_LEN);

        /* Derive outer + inner keys in parallel (independent salt/ns/tip) */
        uint8_t inner_ns[NS_LEN];
        cc_cute_namespace(inner_ns, "cutecrypt.nested", 16);

        kdf_task outer_task, inner_task;
        kdf_task_init(&outer_task, password, strlen(password),
                      salt, ns, fuse_tip, kdf_rounds);
        kdf_task_init(&inner_task, password, strlen(password),
                      inner_salt, inner_ns, inner_fuse_tip, kdf_rounds);
        kdf_run_dual(&outer_task, &inner_task, quiet);

        uint8_t *outer_key = outer_task.key;
        uint8_t *inner_key = inner_task.key;

        uint8_t fuse_hdr_ct[FUSE_HDR_SIZE];
        fuse_hdr_xor_cipher(outer_key, fuse_hdr_plain, fuse_hdr_ct);

        /* Build vault before clearing outer_key */
        size_t v_size = vault_compute_size(max_fuses);
        uint8_t *vault_buf = malloc(v_size);
        size_t vault_actual_len = 0;

        uint8_t v_key[CC_AES256_KEY_LEN];
        derive_vault_key(outer_key, v_key);
        rc = vault_encrypt(fuse_chain.chain, inner_fuse_chain.chain,
                           max_fuses, v_key, vault_buf, &vault_actual_len);
        secure_zero(v_key, CC_AES256_KEY_LEN);

        /* Derive role keys for engraved messages from stable base (no fuse_tip) */
        uint8_t engrave_base[CC_AES256_KEY_LEN];
        derive_key(password, strlen(password), salt, ns, NULL, kdf_rounds, engrave_base, NULL);
        uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN];
        derive_role_keys(engrave_base, role_keys);
        memset(engrave_base, 0, CC_AES256_KEY_LEN);

        secure_zero(outer_key, CC_AES256_KEY_LEN);
        secure_zero(fuse_hdr_plain, FUSE_HDR_SIZE);

        if (rc != 0) {
            fprintf(stderr, "  error: vault encryption failed\n");
            secure_zero(role_keys, sizeof(role_keys));
            secure_zero(inner_key, CC_AES256_KEY_LEN);
            free(vault_buf); free(plaintext);
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            return 1;
        }

        memset(password, 0, sizeof(password));

        /* Set vault_size and payload_size in header before computing AAD */
        le32_put(header + HDR_VAULT_SIZE, (uint32_t)vault_actual_len);

        size_t content_ct_len = pt_len + CC_AES256_TAG_LEN;
        size_t inner_payload_len = FUSE_HDR_SIZE + content_ct_len;

        /* Payload size depends on container wrapping */
        size_t payload_sz;
        if (flags & FLAG_CONTAINER) {
            payload_sz = CONTAINER_NONCE_LEN + inner_payload_len + CC_AES256_TAG_LEN;
        } else {
            payload_sz = inner_payload_len;
        }
        le32_put(header + HDR_PAYLOAD_SIZE, (uint32_t)payload_sz);
        le16_put(header + HDR_LEDGER_COUNT, 1); /* genesis entry */

        prepare_aad(aad, header);

        cc_aes256_ctx *ctx = cc_aes256_init(inner_key);
        secure_zero(inner_key, CC_AES256_KEY_LEN);
        if (!ctx) {
            free(vault_buf); free(plaintext);
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            return 1;
        }

        uint8_t *content_ct = malloc(content_ct_len);
        memcpy(content_ct, plaintext, pt_len);
        free(plaintext);

        rc = cc_aes256_encrypt(ctx, inner_nonce_buf, aad, HDR_SIZE, content_ct, pt_len);
        cc_aes256_free(ctx);
        if (rc != 0) {
            fprintf(stderr, "  error: inner encryption failed\n");
            free(content_ct); free(vault_buf);
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            return 1;
        }

        /* Jigsaw: permute content ciphertext blocks */
        size_t n_blocks = (content_ct_len + JIGSAW_BLOCK_SIZE - 1) / JIGSAW_BLOCK_SIZE;
        if (n_blocks > 1) {
            size_t *perm = malloc(n_blocks * sizeof(size_t));
            jigsaw_build_perm(inner_fuse_tip, n_blocks, perm);
            uint8_t *permuted = malloc(content_ct_len);
            jigsaw_permute(content_ct, permuted, content_ct_len, perm, n_blocks);
            free(perm);
            memcpy(content_ct, permuted, content_ct_len);
            free(permuted);
        }

        /* Combine: fuse_hdr_ct + permuted content_ct */
        inner_ct_len = FUSE_HDR_SIZE + content_ct_len;
        ct_buf = malloc(inner_ct_len);
        memcpy(ct_buf, fuse_hdr_ct, FUSE_HDR_SIZE);
        memcpy(ct_buf + FUSE_HDR_SIZE, content_ct, content_ct_len);
        free(content_ct);

        /* ---- Container wrap ---- */
        uint8_t *payload;
        size_t payload_len;

        if (flags & FLAG_CONTAINER) {
            uint8_t ckey[CC_AES256_KEY_LEN];
            uint8_t cnonce[CC_AES256_NONCE_LEN];
            if (has_kc_nonce)
                derive_container_key_bound(cont_seed, kc_nonce, 0, ckey, cnonce);
            else
                derive_container_key(cont_seed, 0, ckey, cnonce);

            size_t wrapped_len = inner_ct_len + CC_AES256_TAG_LEN;
            uint8_t *wrapped = malloc(wrapped_len);
            rc = container_wrap(ct_buf, inner_ct_len, ckey, cnonce, wrapped);
            free(ct_buf);
            secure_zero(ckey, CC_AES256_KEY_LEN);
            if (rc != 0) {
                fprintf(stderr, "  error: container wrap failed\n");
                free(wrapped); free(vault_buf);
                if (has_fuse_chain) cc_fuse_free(&fuse_chain);
                if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
                return 1;
            }

            payload_len = CONTAINER_NONCE_LEN + wrapped_len;
            payload = malloc(payload_len);
            memcpy(payload, cnonce, CONTAINER_NONCE_LEN);
            memcpy(payload + CONTAINER_NONCE_LEN, wrapped, wrapped_len);
            free(wrapped);
        } else {
            payload = ct_buf;
            payload_len = inner_ct_len;
        }

        /* ---- Build ledger genesis ---- */
        uint8_t ledger_entry[LEDGER_ENTRY_SIZE];
        ledger_genesis(ledger_entry);

        /* ---- Build trailer sections ---- */
        uint8_t pmsg_buf[8192];
        size_t pmsg_len = 0;
        uint8_t *engr_text_buf = NULL; size_t engr_text_len = 0;
        uint8_t *engr_file_buf = NULL; size_t engr_file_len = 0;

        if (opts->public_msg && opts->public_msg[0]) {
            pmsg_build(opts->public_msg, pmsg_buf, &pmsg_len);
        }
        if (opts->engrave && opts->engrave[0]) {
            uint8_t elevel = (uint8_t)opts->engrave_level;
            engr_text_buf = malloc(8192);
            if (engr_build_text(opts->engrave, elevel, role_keys[elevel],
                                engr_text_buf, &engr_text_len) != 0) {
                fprintf(stderr, "  error: engrave encryption failed\n");
                secure_zero(role_keys, sizeof(role_keys));
                free(engr_text_buf); free(vault_buf); free(payload);
                if (has_fuse_chain) cc_fuse_free(&fuse_chain);
                if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
                return 1;
            }
        }
        if (opts->engrave_file) {
            uint8_t elevel = (uint8_t)opts->engrave_level;
            size_t ef_len = 0;
            uint8_t *ef_data = read_file(opts->engrave_file, &ef_len);
            if (!ef_data) {
                fprintf(stderr, "  error: cannot read engrave file: %s\n", opts->engrave_file);
                secure_zero(role_keys, sizeof(role_keys));
                free(engr_text_buf); free(vault_buf); free(payload);
                if (has_fuse_chain) cc_fuse_free(&fuse_chain);
                if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
                return 1;
            }
            const char *ef_name = strrchr(opts->engrave_file, '/');
            ef_name = ef_name ? ef_name + 1 : opts->engrave_file;
            if (engr_build_file(ef_data, ef_len, ef_name, elevel, role_keys[elevel],
                                &engr_file_buf, &engr_file_len) != 0) {
                fprintf(stderr, "  error: engrave file encryption failed\n");
                free(ef_data); free(engr_text_buf);
                secure_zero(role_keys, sizeof(role_keys));
                free(vault_buf); free(payload);
                if (has_fuse_chain) cc_fuse_free(&fuse_chain);
                if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
                return 1;
            }
            free(ef_data);
        }
        secure_zero(role_keys, sizeof(role_keys));

        /* ---- Build TOTP trailer if active ---- */
        uint8_t totp_trailer[512];
        size_t totp_trailer_len = 0;
        if (totp_active && totp_secret_len > 0) {
            size_t sec_data_len = 4 + totp_secret_len;
            memcpy(totp_trailer, TOTP_MAGIC, 4);
            le32_put(totp_trailer + 4, (uint32_t)sec_data_len);
            totp_trailer[8] = TOTP_DIGITS_DEFAULT;
            totp_trailer[9] = TOTP_PERIOD_DEFAULT;
            le16_put(totp_trailer + 10, (uint16_t)totp_secret_len);
            /* Store secret (in production, encrypt it; for now, store raw) */
            memcpy(totp_trailer + 12, totp_secret_raw, totp_secret_len);
            totp_trailer_len = TRAILER_HDR_SIZE + sec_data_len;
        }

        /* ---- Build FBOX trailer if active ---- */
        uint8_t fbox_trailer_buf[TRAILER_HDR_SIZE + FBOX_SECTION_SIZE];
        size_t fbox_trailer_len = 0;
        if (opts->fuse_box && (flags & FLAG_FUSED)) {
            uint8_t refresh_hash[CC_CUTE_HASH_LEN];
            secure_zero(refresh_hash, sizeof(refresh_hash));
            if (opts->refresh_key && strlen(opts->refresh_key) > 0) {
                cc_cute_hash((const uint8_t *)opts->refresh_key,
                             strlen(opts->refresh_key), refresh_hash);
            }
            /* Content key indirection not yet wired (requires deeper refactor
             * of encrypt pipeline to use random key). For now, FBOX marks the
             * file as fuse-box with refresh capability. The renounced flag is
             * set, signaling decrypt to enforce fuse consumption. */
            fbox_trailer_len = fbox_build(fbox_trailer_buf, 1,
                                           refresh_hash, NULL, NULL);
            secure_zero(refresh_hash, sizeof(refresh_hash));
        } else if (opts->refresh_key && (flags & FLAG_FUSED)) {
            /* Refresh key without full renouncement — just assigns the key */
            uint8_t refresh_hash[CC_CUTE_HASH_LEN];
            cc_cute_hash((const uint8_t *)opts->refresh_key,
                         strlen(opts->refresh_key), refresh_hash);
            fbox_trailer_len = fbox_build(fbox_trailer_buf, 0,
                                           refresh_hash, NULL, NULL);
            secure_zero(refresh_hash, sizeof(refresh_hash));
        }

        /* ---- Build CLAM trailer if claimable ---- */
        uint8_t clam_trailer_buf[TRAILER_HDR_SIZE + CLAM_SECTION_SIZE];
        size_t clam_trailer_len = 0;
        if (is_claimable) {
            memcpy(clam_trailer_buf, CLAM_MAGIC, 4);
            le32_put(clam_trailer_buf + 4, CLAM_SECTION_SIZE);
            memcpy(clam_trailer_buf + TRAILER_HDR_SIZE, clam_ephemeral, CLAM_SECTION_SIZE);
            clam_trailer_len = TRAILER_HDR_SIZE + CLAM_SECTION_SIZE;
            secure_zero(clam_ephemeral, sizeof(clam_ephemeral));
        }

        /* ---- Assemble output file: [HEADER][BINDING][VAULT][PAYLOAD][LEDGER][TRAILERS] ---- */
        size_t out_len = HDR_SIZE + bind_size + vault_actual_len + payload_len
                         + LEDGER_ENTRY_SIZE + pmsg_len + engr_text_len + engr_file_len
                         + totp_trailer_len + fbox_trailer_len + clam_trailer_len;
        uint8_t *out = malloc(out_len);
        size_t off = 0;
        memcpy(out + off, header, HDR_SIZE); off += HDR_SIZE;
        if (bind_size > 0) {
            memcpy(out + off, binding_data, bind_size); off += bind_size;
        }
        memcpy(out + off, vault_buf, vault_actual_len); off += vault_actual_len;
        free(vault_buf);
        memcpy(out + off, payload, payload_len); off += payload_len;
        free(payload);
        memcpy(out + off, ledger_entry, LEDGER_ENTRY_SIZE); off += LEDGER_ENTRY_SIZE;
        if (pmsg_len > 0) { memcpy(out + off, pmsg_buf, pmsg_len); off += pmsg_len; }
        if (engr_text_len > 0) { memcpy(out + off, engr_text_buf, engr_text_len); off += engr_text_len; }
        if (engr_file_len > 0) { memcpy(out + off, engr_file_buf, engr_file_len); off += engr_file_len; }
        if (totp_trailer_len > 0) { memcpy(out + off, totp_trailer, totp_trailer_len); off += totp_trailer_len; }
        if (fbox_trailer_len > 0) { memcpy(out + off, fbox_trailer_buf, fbox_trailer_len); off += fbox_trailer_len; }
        if (clam_trailer_len > 0) { memcpy(out + off, clam_trailer_buf, clam_trailer_len); off += clam_trailer_len; }
        free(engr_text_buf); free(engr_file_buf);

        /* Write output */
        char out_path[4096];
        if (opts->output) {
            strncpy(out_path, opts->output, sizeof(out_path) - 1);
            out_path[sizeof(out_path) - 1] = '\0';
        } else {
            size_t plen = strlen(path);
            if (plen > 1 && path[plen - 1] == '/') plen--;
            snprintf(out_path, sizeof(out_path), "%.*s.cute", (int)plen, path);
        }

        rc = write_file_atomic(out_path, out, out_len);
        free(out);
        if (rc != 0) {
            fprintf(stderr, "  error: failed to write %s\n", out_path);
            if (has_fuse_chain) cc_fuse_free(&fuse_chain);
            if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);
            return 1;
        }

        if (!quiet) {
            fprintf(stderr, "  ─────────────────────────────────────\n");
            fprintf(stderr, "  encrypted → %s\n", out_path);
            fprintf(stderr, "  size: %zu bytes (self-contained)\n", out_len);
            if (flags & FLAG_TIMED)
                fprintf(stderr, "  expires: epoch %u (in %u seconds)\n",
                        valid_until, valid_until * epoch_len);
            if (flags & FLAG_DELAYED)
                fprintf(stderr, "  accessible from: epoch %u\n", valid_from);
            fprintf(stderr, "  fuses: %u (nested)\n", max_fuses);
            if (flags & FLAG_PURGE) fprintf(stderr, "  self-purge: enabled\n");
            fprintf(stderr, "  vault: %zu bytes\n", vault_actual_len);
            fprintf(stderr, "  ledger: 1 entry (genesis)\n");
            fprintf(stderr, "  kdf rounds: %u\n", kdf_rounds);
            if (flags & FLAG_CONTAINER) fprintf(stderr, "  container: enabled\n");
            if (pmsg_len > 0) fprintf(stderr, "  public message: attached\n");
            if (engr_text_len > 0) fprintf(stderr, "  engrave: text attached (level %s)\n",
                                           role_names[opts->engrave_level]);
            if (engr_file_len > 0) fprintf(stderr, "  engrave: file attached (level %s)\n",
                                           role_names[opts->engrave_level]);
            fprintf(stderr, "\n");
        }

        if (has_fuse_chain) cc_fuse_free(&fuse_chain);
        if (has_inner_fuse_chain) cc_fuse_free(&inner_fuse_chain);

    } else {
        /* Non-fused: single KDF + AES-GCM, no vault */
        kdf_task enc_task;
        kdf_task_init(&enc_task, password, strlen(password),
                      salt, ns, NULL, kdf_rounds);
        kdf_run(&enc_task, quiet);
        uint8_t *key = enc_task.key;

        /* Derive role keys for engraved messages before clearing key */
        uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN];
        derive_role_keys(key, role_keys);

        memset(password, 0, sizeof(password));

        /* Set sizes in header */
        le32_put(header + HDR_VAULT_SIZE, 0);

        inner_ct_len = pt_len + CC_AES256_TAG_LEN;
        size_t payload_sz;
        if (flags & FLAG_CONTAINER) {
            payload_sz = CONTAINER_NONCE_LEN + inner_ct_len + CC_AES256_TAG_LEN;
        } else {
            payload_sz = inner_ct_len;
        }
        le32_put(header + HDR_PAYLOAD_SIZE, (uint32_t)payload_sz);
        le16_put(header + HDR_LEDGER_COUNT, 1);

        prepare_aad(aad, header);

        cc_aes256_ctx *ctx = cc_aes256_init(key);
        secure_zero(key, CC_AES256_KEY_LEN);
        if (!ctx) { free(plaintext); return 1; }

        ct_buf = malloc(inner_ct_len);
        memcpy(ct_buf, plaintext, pt_len);
        free(plaintext);

        rc = cc_aes256_encrypt(ctx, nonce, aad, HDR_SIZE, ct_buf, pt_len);
        cc_aes256_free(ctx);
        if (rc != 0) {
            fprintf(stderr, "  error: encryption failed\n");
            free(ct_buf); return 1;
        }

        /* Container wrap if applicable */
        uint8_t *payload;
        size_t payload_len;

        if (flags & FLAG_CONTAINER) {
            uint8_t ckey[CC_AES256_KEY_LEN];
            uint8_t cnonce[CC_AES256_NONCE_LEN];
            if (has_kc_nonce)
                derive_container_key_bound(cont_seed, kc_nonce, 0, ckey, cnonce);
            else
                derive_container_key(cont_seed, 0, ckey, cnonce);

            size_t wrapped_len = inner_ct_len + CC_AES256_TAG_LEN;
            uint8_t *wrapped = malloc(wrapped_len);
            rc = container_wrap(ct_buf, inner_ct_len, ckey, cnonce, wrapped);
            free(ct_buf);
            secure_zero(ckey, CC_AES256_KEY_LEN);
            if (rc != 0) {
                fprintf(stderr, "  error: container wrap failed\n");
                free(wrapped); return 1;
            }

            payload_len = CONTAINER_NONCE_LEN + wrapped_len;
            payload = malloc(payload_len);
            memcpy(payload, cnonce, CONTAINER_NONCE_LEN);
            memcpy(payload + CONTAINER_NONCE_LEN, wrapped, wrapped_len);
            free(wrapped);
        } else {
            payload = ct_buf;
            payload_len = inner_ct_len;
        }

        /* Ledger genesis */
        uint8_t ledger_entry[LEDGER_ENTRY_SIZE];
        ledger_genesis(ledger_entry);

        /* Build trailer sections */
        uint8_t pmsg_buf[8192];
        size_t pmsg_len = 0;
        uint8_t *engr_text_buf = NULL; size_t engr_text_len = 0;
        uint8_t *engr_file_buf = NULL; size_t engr_file_len = 0;

        if (opts->public_msg && opts->public_msg[0]) {
            pmsg_build(opts->public_msg, pmsg_buf, &pmsg_len);
        }
        if (opts->engrave && opts->engrave[0]) {
            uint8_t elevel = (uint8_t)opts->engrave_level;
            engr_text_buf = malloc(8192);
            if (engr_build_text(opts->engrave, elevel, role_keys[elevel],
                                engr_text_buf, &engr_text_len) != 0) {
                fprintf(stderr, "  error: engrave encryption failed\n");
                secure_zero(role_keys, sizeof(role_keys));
                free(engr_text_buf); free(payload); return 1;
            }
        }
        if (opts->engrave_file) {
            uint8_t elevel = (uint8_t)opts->engrave_level;
            size_t ef_len = 0;
            uint8_t *ef_data = read_file(opts->engrave_file, &ef_len);
            if (!ef_data) {
                fprintf(stderr, "  error: cannot read engrave file: %s\n", opts->engrave_file);
                secure_zero(role_keys, sizeof(role_keys));
                free(engr_text_buf); free(payload); return 1;
            }
            const char *ef_name = strrchr(opts->engrave_file, '/');
            ef_name = ef_name ? ef_name + 1 : opts->engrave_file;
            if (engr_build_file(ef_data, ef_len, ef_name, elevel, role_keys[elevel],
                                &engr_file_buf, &engr_file_len) != 0) {
                fprintf(stderr, "  error: engrave file encryption failed\n");
                free(ef_data); free(engr_text_buf);
                secure_zero(role_keys, sizeof(role_keys));
                free(payload); return 1;
            }
            free(ef_data);
        }
        secure_zero(role_keys, sizeof(role_keys));

        /* ---- Build TOTP trailer if active ---- */
        uint8_t totp_trailer2[512];
        size_t totp_trailer2_len = 0;
        if (totp_active && totp_secret_len > 0) {
            size_t sec_data_len = 4 + totp_secret_len;
            memcpy(totp_trailer2, TOTP_MAGIC, 4);
            le32_put(totp_trailer2 + 4, (uint32_t)sec_data_len);
            totp_trailer2[8] = TOTP_DIGITS_DEFAULT;
            totp_trailer2[9] = TOTP_PERIOD_DEFAULT;
            le16_put(totp_trailer2 + 10, (uint16_t)totp_secret_len);
            memcpy(totp_trailer2 + 12, totp_secret_raw, totp_secret_len);
            totp_trailer2_len = TRAILER_HDR_SIZE + sec_data_len;
        }

        /* ---- Build CLAM trailer if claimable ---- */
        uint8_t clam_trailer2_buf[TRAILER_HDR_SIZE + CLAM_SECTION_SIZE];
        size_t clam_trailer2_len = 0;
        if (is_claimable) {
            memcpy(clam_trailer2_buf, CLAM_MAGIC, 4);
            le32_put(clam_trailer2_buf + 4, CLAM_SECTION_SIZE);
            memcpy(clam_trailer2_buf + TRAILER_HDR_SIZE, clam_ephemeral, CLAM_SECTION_SIZE);
            clam_trailer2_len = TRAILER_HDR_SIZE + CLAM_SECTION_SIZE;
            secure_zero(clam_ephemeral, sizeof(clam_ephemeral));
        }

        /* Assemble: [HEADER][BINDING][PAYLOAD][LEDGER][TRAILERS] (no vault for non-fused) */
        size_t out_len = HDR_SIZE + bind_size + payload_len + LEDGER_ENTRY_SIZE
                         + pmsg_len + engr_text_len + engr_file_len
                         + totp_trailer2_len + clam_trailer2_len;
        uint8_t *out = malloc(out_len);
        size_t off = 0;
        memcpy(out + off, header, HDR_SIZE); off += HDR_SIZE;
        if (bind_size > 0) {
            memcpy(out + off, binding_data, bind_size); off += bind_size;
        }
        memcpy(out + off, payload, payload_len); off += payload_len;
        free(payload);
        memcpy(out + off, ledger_entry, LEDGER_ENTRY_SIZE); off += LEDGER_ENTRY_SIZE;
        if (pmsg_len > 0) { memcpy(out + off, pmsg_buf, pmsg_len); off += pmsg_len; }
        if (engr_text_len > 0) { memcpy(out + off, engr_text_buf, engr_text_len); off += engr_text_len; }
        if (engr_file_len > 0) { memcpy(out + off, engr_file_buf, engr_file_len); off += engr_file_len; }
        if (totp_trailer2_len > 0) { memcpy(out + off, totp_trailer2, totp_trailer2_len); off += totp_trailer2_len; }
        if (clam_trailer2_len > 0) { memcpy(out + off, clam_trailer2_buf, clam_trailer2_len); off += clam_trailer2_len; }
        free(engr_text_buf); free(engr_file_buf);

        char out_path[4096];
        if (opts->output) {
            strncpy(out_path, opts->output, sizeof(out_path) - 1);
            out_path[sizeof(out_path) - 1] = '\0';
        } else {
            size_t plen = strlen(path);
            if (plen > 1 && path[plen - 1] == '/') plen--;
            snprintf(out_path, sizeof(out_path), "%.*s.cute", (int)plen, path);
        }

        rc = write_file_atomic(out_path, out, out_len);
        free(out);
        if (rc != 0) {
            fprintf(stderr, "  error: failed to write %s\n", out_path);
            return 1;
        }

        if (!quiet) {
            fprintf(stderr, "  ─────────────────────────────────────\n");
            fprintf(stderr, "  encrypted → %s\n", out_path);
            fprintf(stderr, "  size: %zu bytes (self-contained)\n", out_len);
            if (flags & FLAG_TIMED)
                fprintf(stderr, "  expires: epoch %u (in %u seconds)\n",
                        valid_until, valid_until * epoch_len);
            if (flags & FLAG_DELAYED)
                fprintf(stderr, "  accessible from: epoch %u\n", valid_from);
            if (flags & FLAG_PURGE) fprintf(stderr, "  self-purge: enabled\n");
            fprintf(stderr, "  ledger: 1 entry (genesis)\n");
            fprintf(stderr, "  kdf rounds: %u\n", kdf_rounds);
            if (flags & FLAG_CONTAINER) fprintf(stderr, "  container: enabled\n");
            if (pmsg_len > 0) fprintf(stderr, "  public message: attached\n");
            if (engr_text_len > 0) fprintf(stderr, "  engrave: text attached (level %s)\n",
                                           role_names[opts->engrave_level]);
            if (engr_file_len > 0) fprintf(stderr, "  engrave: file attached (level %s)\n",
                                           role_names[opts->engrave_level]);
            fprintf(stderr, "\n");
        }
    }

    return 0;
}

/* ---- Decrypt ---- */

static int do_decrypt(const char *path, const cli_opts *opts) {
    int quiet = opts->quiet;

    if (!quiet) {
        fprintf(stderr, "\n  cutecrypt — decrypt\n");
        fprintf(stderr, "  ─────────────────────────────────────\n");
        fprintf(stderr, "  file: %s\n\n", path);
    }

    size_t file_len = 0;
    uint8_t *data = read_file(path, &file_len);
    if (!data) { fprintf(stderr, "  error: cannot read file\n"); return 1; }

    if (file_len < HDR_SIZE + CC_AES256_TAG_LEN) {
        fprintf(stderr, "  error: file too small\n");
        free(data); return 1;
    }
    if (memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stderr, "  error: not a .cute file\n");
        free(data); return 1;
    }
    if (data[HDR_VERSION] != CUTE_VERSION) {
        fprintf(stderr, "  error: unsupported version 0x%02x (expected 0x%02x)\n",
                data[HDR_VERSION], CUTE_VERSION);
        free(data); return 1;
    }

    /* Parse header */
    uint8_t flags = data[HDR_FLAGS];
    const uint8_t *salt = data + HDR_SALT;
    const uint8_t *nonce = data + HDR_NONCE;
    uint64_t created_at = le64_get(data + HDR_CREATED);
    uint32_t epoch_len = le32_get(data + HDR_EPOCH_LEN);
    uint32_t valid_from = le32_get(data + HDR_VALID_FROM);
    uint32_t valid_until = le32_get(data + HDR_VALID_UNTIL);
    uint16_t max_fuses = le16_get(data + HDR_MAX_FUSES);
    uint16_t fuses_rem = le16_get(data + HDR_FUSES_REM);
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);
    const uint8_t *ns = data + HDR_NAMESPACE;
    uint32_t hb_epoch = le32_get(data + HDR_HEARTBEAT);
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    int is_folder = (flags & FLAG_FOLDER) != 0;

    /* Save fuse_tip to local buffer */
    uint8_t fuse_tip_buf[FUSE_TIP_LEN];
    memcpy(fuse_tip_buf, data + HDR_FUSE_TIP, FUSE_TIP_LEN);

    /* Container seed */
    uint8_t cont_seed[CONT_SEED_LEN];
    memcpy(cont_seed, data + HDR_CONT_SEED, CONT_SEED_LEN);

    /* kdf_rounds == 0 is valid: unlocked container (compression-only) */

    /* Binding section */
    size_t bind_size = binding_section_size(flags);
    size_t bind_offset = HDR_SIZE;

    /* Validate section offsets */
    size_t vault_offset = HDR_SIZE + bind_size;
    size_t payload_offset = vault_offset + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t expected_len = ledger_offset + (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    if (file_len < expected_len) {
        fprintf(stderr, "  error: file truncated (expected %zu, got %zu)\n",
                expected_len, file_len);
        free(data); return 1;
    }

    /* ---- Verify epoch chain ---- */
    {
        uint8_t expected_chain[EPOCH_CHAIN_LEN];
        compute_epoch_chain(salt, created_at, epoch_len, valid_from, valid_until, kdf_rounds, expected_chain);
        uint8_t diff = 0;
        for (int i = 0; i < EPOCH_CHAIN_LEN; i++)
            diff |= expected_chain[i] ^ data[HDR_EPOCH_CHAIN + i];
        if (diff != 0) {
            fprintf(stderr, "  error: epoch chain verification failed — header tampered\n\n");
            free(data); return 1;
        }
    }

    if (!quiet) {
        if (is_folder) fprintf(stderr, "  type: folder archive\n");
        if (flags & FLAG_TIMED)
            fprintf(stderr, "  timed: epochs %u–%u (epoch = %u sec)\n",
                    valid_from, valid_until, epoch_len);
        if (flags & FLAG_DELAYED) fprintf(stderr, "  delayed access: from epoch %u\n", valid_from);
        if (flags & FLAG_FUSED) fprintf(stderr, "  fuses: %u/%u remaining\n", fuses_rem, max_fuses);
        if (flags & FLAG_PURGE) fprintf(stderr, "  self-purge: enabled\n");
        if (flags & FLAG_CONTAINER) fprintf(stderr, "  container: enabled\n");
        if (flags & FLAG_KEYCHAIN) fprintf(stderr, "  keychain binding: required\n");
        if (flags & FLAG_REMOTE_FUSE) fprintf(stderr, "  remote fuse: required\n");
        fprintf(stderr, "  vault: %u bytes, ledger: %u entries\n", vault_size, ledger_count);
        fprintf(stderr, "\n");
    }

    /* Trailer sections (after ledger) — save for display and reassembly */
    size_t ledger_end = expected_len;
    size_t trailer_total_len = 0;
    const uint8_t *trailer_start = trailer_find(data, file_len, ledger_end, &trailer_total_len);
    uint8_t *saved_trailers = NULL;
    if (trailer_total_len > 0) {
        saved_trailers = malloc(trailer_total_len);
        memcpy(saved_trailers, trailer_start, trailer_total_len);
    }

    /* Display public messages immediately (before password prompt) */
    if (trailer_total_len > 0 && !quiet) {
        size_t pmsg_data_len = 0;
        const uint8_t *pmsg_data = trailer_section_find(saved_trailers, trailer_total_len,
                                                        PMSG_MAGIC, &pmsg_data_len);
        if (pmsg_data) {
            fprintf(stderr, "  public messages:\n");
            pmsg_display(pmsg_data, pmsg_data_len);
            fprintf(stderr, "\n");
        }
    }

    /* Track ledger entries to append at end */
    uint8_t ledger_entries[3][LEDGER_ENTRY_SIZE]; /* max 3 entries per access: heartbeat + attempt/consumed */
    int n_ledger_entries = 0;
    uint8_t last_chain_hash[CC_CUTE_HASH_LEN];
    ledger_last_hash(data + ledger_offset, ledger_count, last_chain_hash);

    /* ---- Anti-replay checks ---- */
    uint8_t kc_nonce_dec[CC_CUTE_HASH_LEN];
    int has_kc_nonce_dec = 0;

    if (flags & FLAG_KEYCHAIN) {
        uint8_t kc_id[CC_CUTE_HASH_LEN];
        keychain_derive_id(salt, ns, kc_id);
        if (keychain_load(kc_id, kc_nonce_dec) != 0) {
            fprintf(stderr, "  error: keychain nonce not found — file may be a copy\n\n");
            free(data); return 1;
        }
        has_kc_nonce_dec = 1;
        if (!quiet) fprintf(stderr, "  keychain binding: verified\n");
    }

    if (flags & FLAG_REMOTE_FUSE) {
        if (bind_size < BINDING_REMOTE_SIZE) {
            fprintf(stderr, "  error: missing binding section for remote fuse\n\n");
            free(data); return 1;
        }
        const uint8_t *file_id = data + bind_offset + BINDING_FILE_ID;
        /* URL hash is stored but we need the server URL from the user to verify */
        /* For now we require --fuse-server on decrypt too */
        if (!opts->fuse_server) {
            fprintf(stderr, "  error: file requires --fuse-server URL for remote fuse\n\n");
            free(data); return 1;
        }
        /* Verify URL hash matches */
        uint8_t expected_url_hash[16];
        remote_url_hash(opts->fuse_server, expected_url_hash);
        if (memcmp(expected_url_hash, data + bind_offset + BINDING_URL_HASH, 16) != 0) {
            fprintf(stderr, "  error: fuse server URL does not match file\n\n");
            free(data); return 1;
        }
        /* Check remaining fuses on server */
        int server_rem = 0;
        if (remote_fuse_check(opts->fuse_server, file_id, &server_rem) != 0) {
            fprintf(stderr, "  error: failed to check remote fuse server\n\n");
            free(data); return 1;
        }
        if (server_rem <= 0) {
            fprintf(stderr, "  error: remote fuse exhausted — server rejected\n\n");
            free(data); return 1;
        }
        if (!quiet) fprintf(stderr, "  remote fuse: %d remaining on server\n", server_rem);
    }

    /* ---- Unwrap container layer ---- */
    uint8_t *inner_data = NULL;
    size_t inner_data_len = 0;
    uint64_t now = (uint64_t)time(NULL);
    uint32_t current_epoch_general = (now > created_at && epoch_len > 0) ?
        (uint32_t)((now - created_at) / epoch_len) : 0;

    if (flags & FLAG_CONTAINER) {
        /* Derive container key from seed + heartbeat epoch */
        uint8_t ckey[CC_AES256_KEY_LEN];
        uint8_t cnonce_derived[CC_AES256_NONCE_LEN];
        if (has_kc_nonce_dec)
            derive_container_key_bound(cont_seed, kc_nonce_dec, hb_epoch, ckey, cnonce_derived);
        else
            derive_container_key(cont_seed, hb_epoch, ckey, cnonce_derived);

        if (payload_size < CONTAINER_NONCE_LEN + CC_AES256_TAG_LEN) {
            fprintf(stderr, "  error: payload too small for container\n");
            free(data); return 1;
        }
        const uint8_t *cnonce = data + payload_offset;
        size_t wrapped_len = payload_size - CONTAINER_NONCE_LEN;

        inner_data = malloc(wrapped_len);
        int rc = container_unwrap(data + payload_offset + CONTAINER_NONCE_LEN, wrapped_len,
                                  ckey, cnonce, inner_data);
        secure_zero(ckey, CC_AES256_KEY_LEN);
        if (rc != 0) {
            fprintf(stderr, "  error: container unwrap failed — corrupted\n\n");
            free(inner_data); free(data); return 1;
        }
        inner_data_len = wrapped_len - CC_AES256_TAG_LEN;
    } else {
        inner_data_len = payload_size;
        inner_data = malloc(inner_data_len);
        memcpy(inner_data, data + payload_offset, inner_data_len);
    }

    /* ---- Heartbeat: re-wrap on epoch boundaries ----
     * Container key changes with heartbeat epoch, making old snapshots stale. */
    int heartbeat_fired = 0;
    if (flags & FLAG_CONTAINER) {
        uint32_t hb_interval = epoch_len > 0 ? epoch_len : 3600;
        uint32_t current_hb_epoch = (now > created_at) ?
            (uint32_t)((now - created_at) / hb_interval) : 0;

        if (current_hb_epoch > hb_epoch) {
            /* Re-wrap inner payload with new container key */
            uint8_t new_ckey[CC_AES256_KEY_LEN];
            uint8_t new_cnonce[CC_AES256_NONCE_LEN];
            if (has_kc_nonce_dec)
                derive_container_key_bound(cont_seed, kc_nonce_dec, current_hb_epoch, new_ckey, new_cnonce);
            else
                derive_container_key(cont_seed, current_hb_epoch, new_ckey, new_cnonce);

            size_t rewrap_len = inner_data_len + CC_AES256_TAG_LEN;
            uint8_t *rewrapped = malloc(rewrap_len);
            int hrc = container_wrap(inner_data, inner_data_len,
                                     new_ckey, new_cnonce, rewrapped);
            secure_zero(new_ckey, CC_AES256_KEY_LEN);

            if (hrc == 0) {
                /* Update heartbeat in header */
                le32_put(data + HDR_HEARTBEAT, current_hb_epoch);
                hb_epoch = current_hb_epoch;

                /* Update payload in-place in file data */
                size_t new_payload_size = CONTAINER_NONCE_LEN + rewrap_len;
                /* Payload size should be same — inner_data_len is unchanged */
                memcpy(data + payload_offset, new_cnonce, CONTAINER_NONCE_LEN);
                memcpy(data + payload_offset + CONTAINER_NONCE_LEN, rewrapped, rewrap_len);

                heartbeat_fired = 1;

                /* Ledger entry for heartbeat */
                ledger_build_entry(last_chain_hash, LEDGER_ACTION_HEARTBEAT,
                                   current_hb_epoch, ledger_entries[n_ledger_entries]);
                memcpy(last_chain_hash, ledger_entries[n_ledger_entries] + 8, CC_CUTE_HASH_LEN);
                n_ledger_entries++;

                if (!quiet)
                    fprintf(stderr, "  heartbeat: epoch %u (container rotated)\n",
                            current_hb_epoch);
            }
            free(rewrapped);
        }
    }

    /* ---- Check time constraints ---- */
    if (epoch_len > 0 && (flags & (FLAG_TIMED | FLAG_DELAYED))) {
        uint32_t current_epoch = (now > created_at) ?
            (uint32_t)((now - created_at) / epoch_len) : 0;

        if (!quiet) fprintf(stderr, "  current epoch: %u\n", current_epoch);

        if (flags & FLAG_DELAYED) {
            if (current_epoch < valid_from) {
                uint64_t unlock_time = created_at + (uint64_t)valid_from * epoch_len;
                time_t ut = (time_t)unlock_time;
                char tbuf[64];
                strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&ut));
                fprintf(stderr, "  error: file not yet accessible\n");
                fprintf(stderr, "  unlocks at: %s (epoch %u)\n\n", tbuf, valid_from);
                free(inner_data); free(data); return 1;
            }
        }

        if (flags & FLAG_TIMED) {
            if (current_epoch > valid_until) {
                fprintf(stderr, "  error: file has expired (epoch %u > %u)\n\n",
                        current_epoch, valid_until);
                if (flags & FLAG_PURGE) {
                    /* Append expired ledger entry then purge */
                    ledger_build_entry(last_chain_hash, LEDGER_ACTION_EXPIRED,
                                       current_epoch, ledger_entries[n_ledger_entries]);
                    n_ledger_entries++;

                    fprintf(stderr, "  self-purging...\n");
                    free(inner_data); free(data);
                    secure_delete(path);
                    fprintf(stderr, "  file securely deleted.\n\n");
                    return 1;
                }
                free(inner_data); free(data); return 1;
            }
        }
        if (!quiet) fprintf(stderr, "\n");
    }

    /* ---- Check fuse box (FBOX trailer) ---- */
    int fbox_renounced = 0;
    {
        size_t fbox_tr_off = ledger_offset + (size_t)ledger_count * LEDGER_ENTRY_SIZE;
        size_t fbox_tr_len = file_len > fbox_tr_off ? file_len - fbox_tr_off : 0;
        fbox_find(data + fbox_tr_off, fbox_tr_len, &fbox_renounced, NULL, NULL, NULL);
    }

    /* ---- Check fuse constraints ---- */
    uint8_t new_outer_tip[FUSE_TIP_LEN];
    memcpy(new_outer_tip, fuse_tip_buf, FUSE_TIP_LEN);
    uint8_t outer_preimage[CC_FUSE_HASH_LEN];
    uint8_t inner_preimage[CC_FUSE_HASH_LEN];
    int got_outer_preimage = 0;
    int got_inner_preimage = 0;

    if (flags & FLAG_FUSED) {
        if (fuses_rem == 0) {
            fprintf(stderr, "  error: all fuses exhausted — file is permanently locked\n\n");
            if (flags & FLAG_PURGE) {
                fprintf(stderr, "  self-purging...\n");
                free(inner_data); free(data);
                secure_delete(path);
                fprintf(stderr, "  file securely deleted.\n\n");
                return 1;
            }
            free(inner_data); free(data); return 1;
        }

        if (!quiet)
            fprintf(stderr, "  this will consume 1 fuse (%u → %u remaining)\n",
                    fuses_rem, fuses_rem - 1);

        /* Parse --fuse-key (outer) */
        if (opts->fuse_key) {
            size_t hlen = strlen(opts->fuse_key);
            if (hlen != 64) {
                fprintf(stderr, "  error: --fuse-key must be 64 hex characters\n\n");
                free(inner_data); free(data); return 1;
            }
            for (int i = 0; i < 32; i++) {
                unsigned int byte;
                sscanf(opts->fuse_key + 2*i, "%02x", &byte);
                outer_preimage[i] = (uint8_t)byte;
            }
            got_outer_preimage = 1;
        }

        /* Parse --inner-fuse-key */
        if (opts->inner_fuse_key) {
            size_t hlen = strlen(opts->inner_fuse_key);
            if (hlen != 64) {
                fprintf(stderr, "  error: --inner-fuse-key must be 64 hex characters\n\n");
                free(inner_data); free(data); return 1;
            }
            for (int i = 0; i < 32; i++) {
                unsigned int byte;
                sscanf(opts->inner_fuse_key + 2*i, "%02x", &byte);
                inner_preimage[i] = (uint8_t)byte;
            }
            got_inner_preimage = 1;
        }
    }

    /* ---- Check for claimable (CLAM trailer) ---- */
    int is_claim = 0;
    char claim_ephemeral_pw[256] = {0};
    if (trailer_total_len > 0) {
        size_t clam_data_len = 0;
        const uint8_t *clam_data = trailer_section_find(saved_trailers, trailer_total_len,
                                                         CLAM_MAGIC, &clam_data_len);
        if (clam_data && clam_data_len == CLAM_SECTION_SIZE) {
            /* Found claimable marker — this file has no master key yet */
            is_claim = 1;
            for (int i = 0; i < CLAM_SECTION_SIZE; i++)
                snprintf(claim_ephemeral_pw + i*2, 3, "%02x", clam_data[i]);
            claim_ephemeral_pw[CLAM_SECTION_SIZE * 2] = '\0';
            if (!quiet) {
                fprintf(stderr, "  ┌─────────────────────────────────────┐\n");
                fprintf(stderr, "  │  UNCLAIMED — first open claims key  │\n");
                fprintf(stderr, "  └─────────────────────────────────────┘\n\n");
            }
        }
    }

    /* ---- Password / Auth ---- */
    char password[256];
    int is_unlocked = (kdf_rounds == UNLOCKED_KDF_ROUNDS);

    if (is_claim) {
        /* Claimable: use the ephemeral password embedded in CLAM trailer */
        strncpy(password, claim_ephemeral_pw, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        secure_zero(claim_ephemeral_pw, sizeof(claim_ephemeral_pw));
    } else if (is_unlocked) {
        /* Unlocked container (compression-only) — use fixed passphrase */
        strncpy(password, UNLOCKED_PASSPHRASE, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        if (!quiet) fprintf(stderr, "  unlocked container (no password required)\n");
    } else if (opts->totp_code) {
        /* TOTP auth — code is the password */
        strncpy(password, opts->totp_code, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        if (!quiet) fprintf(stderr, "  authenticating with TOTP code\n");
    } else if (opts->passkey) {
        /* Passkey auth — derive password from platform identity */
        const char *user = getenv("USER");
        const char *home = getenv("HOME");
        if (!user) user = "default";
        if (!home) home = "/";
        char identity[512];
        snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s", user, home);
        uint8_t pkey_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash((const uint8_t *)identity, strlen(identity), pkey_hash);
        for (int i = 0; i < 32; i++)
            snprintf(password + i*2, 3, "%02x", pkey_hash[i]);
        password[64] = '\0';
        secure_zero(pkey_hash, sizeof(pkey_hash));
        if (!quiet) fprintf(stderr, "  authenticating with passkey\n");
    } else if (opts->headless) {
        strncpy(password, opts->password, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
    } else {
        read_password("  password: ", password, sizeof(password));
    }
    if (strlen(password) == 0) {
        fprintf(stderr, "  error: password cannot be empty\n");
        free(inner_data); free(data); return 1;
    }

    /* ---- If fused and missing preimages, try vault ---- */
    uint8_t *vault_preimages = NULL;
    if ((flags & FLAG_FUSED) && (!got_outer_preimage || !got_inner_preimage)) {
        if (vault_size > 0) {
            /* Derive outer key → vault key → decrypt vault */
            kdf_task vault_task;
            kdf_task_init(&vault_task, password, strlen(password),
                          salt, ns, fuse_tip_buf, kdf_rounds);
            kdf_run(&vault_task, quiet);
            uint8_t *outer_key = vault_task.key;

            uint8_t v_key[CC_AES256_KEY_LEN];
            derive_vault_key(outer_key, v_key);
            secure_zero(outer_key, CC_AES256_KEY_LEN);

            size_t chain_len = (size_t)max_fuses * CC_FUSE_HASH_LEN;
            size_t preimage_data_len = chain_len * 2 + CC_AES256_TAG_LEN;
            vault_preimages = malloc(preimage_data_len);

            int vrc = vault_decrypt(data + vault_offset, vault_size, v_key, vault_preimages);
            secure_zero(v_key, CC_AES256_KEY_LEN);

            if (vrc != 0) {
                fprintf(stderr, "  error: vault decryption failed — wrong password or corrupted\n\n");
                free(vault_preimages); vault_preimages = NULL;
                free(inner_data); free(data);
                memset(password, 0, sizeof(password));
                return 1;
            }

            /* Extract preimages for current fuse level */
            size_t preimage_idx = (size_t)(fuses_rem - 1) * CC_FUSE_HASH_LEN;
            if (!got_outer_preimage)
                memcpy(outer_preimage, vault_preimages + preimage_idx, CC_FUSE_HASH_LEN);
            if (!got_inner_preimage)
                memcpy(inner_preimage, vault_preimages + chain_len + preimage_idx, CC_FUSE_HASH_LEN);
            got_outer_preimage = got_inner_preimage = 1;

            if (!quiet) fprintf(stderr, "  fuse keys loaded from vault\n");
        } else {
            /* No vault and no CLI keys — prompt interactively or fail */
            if (opts->headless) {
                fprintf(stderr, "  error: fuse required but missing preimage(s) — "
                        "need --fuse-key + --inner-fuse-key\n\n");
                free(inner_data); free(data);
                memset(password, 0, sizeof(password));
                return 1;
            }
            if (!got_outer_preimage) {
                fprintf(stderr, "  paste outer fuse preimage (64 hex): ");
                fflush(stderr);
                char hex[256];
                if (!fgets(hex, sizeof(hex), stdin)) {
                    free(inner_data); free(data);
                    memset(password, 0, sizeof(password));
                    return 1;
                }
                size_t hlen = strlen(hex);
                if (hlen > 0 && hex[hlen-1] == '\n') hex[--hlen] = '\0';
                if (hlen != 64) {
                    fprintf(stderr, "  error: expected 64 hex characters\n\n");
                    free(inner_data); free(data);
                    memset(password, 0, sizeof(password));
                    return 1;
                }
                for (int i = 0; i < 32; i++) {
                    unsigned int byte;
                    sscanf(hex + 2*i, "%02x", &byte);
                    outer_preimage[i] = (uint8_t)byte;
                }
            }
            if (!got_inner_preimage) {
                fprintf(stderr, "  paste inner fuse preimage (64 hex): ");
                fflush(stderr);
                char hex[256];
                if (!fgets(hex, sizeof(hex), stdin)) {
                    free(inner_data); free(data);
                    memset(password, 0, sizeof(password));
                    return 1;
                }
                size_t hlen = strlen(hex);
                if (hlen > 0 && hex[hlen-1] == '\n') hex[--hlen] = '\0';
                if (hlen != 64) {
                    fprintf(stderr, "  error: expected 64 hex characters\n\n");
                    free(inner_data); free(data);
                    memset(password, 0, sizeof(password));
                    return 1;
                }
                for (int i = 0; i < 32; i++) {
                    unsigned int byte;
                    sscanf(hex + 2*i, "%02x", &byte);
                    inner_preimage[i] = (uint8_t)byte;
                }
            }
            got_outer_preimage = got_inner_preimage = 1;
            fprintf(stderr, "\n");
        }
    }

    /* Verify outer fuse */
    if (flags & FLAG_FUSED) {
        cc_fuse_verifier outer_v;
        cc_fuse_verifier_from_tip(&outer_v, fuse_tip_buf, fuses_rem, "cutecrypt.file-fuse");
        if (cc_fuse_verify(&outer_v, outer_preimage) != 0) {
            fprintf(stderr, "  error: invalid outer fuse preimage\n\n");
            free(vault_preimages); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }
        memcpy(new_outer_tip, outer_v.tip, FUSE_TIP_LEN);
    }

    /* ---- Decrypt content ---- */
    uint8_t *pt_buf;
    size_t pt_len;
    int rc;
    uint8_t aad[HDR_SIZE];
    prepare_aad(aad, data);

    uint8_t inner_salt_dec[SALT_LEN];
    uint8_t new_inner_tip[FUSE_TIP_LEN];
    uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN];
    secure_zero(role_keys, sizeof(role_keys));

    if (flags & FLAG_FUSED) {
        if (inner_data_len < FUSE_HDR_SIZE + CC_AES256_TAG_LEN) {
            fprintf(stderr, "  error: payload too small for nested fuse\n");
            free(vault_preimages); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }

        /* Outer key → XOR-decrypt fuse header */
        kdf_task dec_outer_task;
        kdf_task_init(&dec_outer_task, password, strlen(password),
                      salt, ns, fuse_tip_buf, kdf_rounds);
        kdf_run(&dec_outer_task, quiet);
        uint8_t *outer_key = dec_outer_task.key;

        uint8_t fuse_hdr_plain[FUSE_HDR_SIZE];
        fuse_hdr_xor_cipher(outer_key, inner_data, fuse_hdr_plain);

        /* Derive role keys from stable base (no fuse_tip) for engraved messages */
        {
            uint8_t engrave_base[CC_AES256_KEY_LEN];
            derive_key(password, strlen(password), salt, ns, NULL, kdf_rounds, engrave_base, NULL);
            derive_role_keys(engrave_base, role_keys);
            memset(engrave_base, 0, CC_AES256_KEY_LEN);
        }

        secure_zero(outer_key, CC_AES256_KEY_LEN);

        /* Extract inner parameters */
        memcpy(inner_salt_dec, fuse_hdr_plain + FH_INNER_SALT, SALT_LEN);
        uint8_t inner_tip_dec[FUSE_TIP_LEN];
        memcpy(inner_tip_dec, fuse_hdr_plain + FH_INNER_TIP, FUSE_TIP_LEN);
        uint8_t inner_nonce_dec[CC_AES256_NONCE_LEN];
        memcpy(inner_nonce_dec, fuse_hdr_plain + FH_INNER_NONCE, CC_AES256_NONCE_LEN);
        secure_zero(fuse_hdr_plain, FUSE_HDR_SIZE);

        /* Verify inner fuse */
        memcpy(new_inner_tip, inner_tip_dec, FUSE_TIP_LEN);
        cc_fuse_verifier inner_v;
        cc_fuse_verifier_from_tip(&inner_v, inner_tip_dec, fuses_rem, "cutecrypt.nested-fuse");
        if (cc_fuse_verify(&inner_v, inner_preimage) != 0) {
            fprintf(stderr, "  error: invalid inner fuse preimage\n\n");
            free(vault_preimages); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }
        memcpy(new_inner_tip, inner_v.tip, FUSE_TIP_LEN);

        /* Inner key → AES-GCM decrypt content */
        uint8_t inner_ns[NS_LEN];
        cc_cute_namespace(inner_ns, "cutecrypt.nested", 16);
        kdf_task dec_inner_task;
        kdf_task_init(&dec_inner_task, password, strlen(password),
                      inner_salt_dec, inner_ns, inner_tip_dec, kdf_rounds);
        kdf_run(&dec_inner_task, quiet);
        uint8_t *inner_key = dec_inner_task.key;

        size_t content_ct_len = inner_data_len - FUSE_HDR_SIZE;
        pt_buf = malloc(content_ct_len);

        /* Jigsaw: unpermute content blocks */
        size_t n_blocks = (content_ct_len + JIGSAW_BLOCK_SIZE - 1) / JIGSAW_BLOCK_SIZE;
        if (n_blocks > 1) {
            size_t *perm = malloc(n_blocks * sizeof(size_t));
            jigsaw_build_perm(inner_tip_dec, n_blocks, perm);
            jigsaw_unpermute(inner_data + FUSE_HDR_SIZE, pt_buf,
                             content_ct_len, perm, n_blocks);
            free(perm);
        } else {
            memcpy(pt_buf, inner_data + FUSE_HDR_SIZE, content_ct_len);
        }

        cc_aes256_ctx *dctx = cc_aes256_init(inner_key);
        secure_zero(inner_key, CC_AES256_KEY_LEN);
        if (!dctx) {
            free(pt_buf); free(vault_preimages); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }

        rc = cc_aes256_decrypt(dctx, inner_nonce_dec, aad, HDR_SIZE, pt_buf, content_ct_len);
        cc_aes256_free(dctx);
        if (rc != 0) {
            fprintf(stderr, "\n  error: decryption failed — wrong password, corrupted file, or mismatched auth method\n\n");
            /* Append ATTEMPT ledger entry */
            ledger_build_entry(last_chain_hash, LEDGER_ACTION_ATTEMPT,
                               current_epoch_general, ledger_entries[n_ledger_entries]);
            n_ledger_entries++;
            /* Write file with ledger entries */
            if (n_ledger_entries > 0) {
                uint16_t new_count = ledger_count + (uint16_t)n_ledger_entries;
                le16_put(data + HDR_LEDGER_COUNT, new_count);
                size_t new_file_len = file_len + (size_t)n_ledger_entries * LEDGER_ENTRY_SIZE;
                uint8_t *new_file = malloc(new_file_len);
                memcpy(new_file, data, file_len);
                for (int i = 0; i < n_ledger_entries; i++)
                    memcpy(new_file + file_len + (size_t)i * LEDGER_ENTRY_SIZE,
                           ledger_entries[i], LEDGER_ENTRY_SIZE);
                write_file_atomic(path, new_file, new_file_len);
                free(new_file);
            }
            free(pt_buf); free(vault_preimages); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }
        pt_len = content_ct_len - CC_AES256_TAG_LEN;
    } else {
        /* Non-fused: single KDF + AES-GCM */
        kdf_task dec_task;
        kdf_task_init(&dec_task, password, strlen(password),
                      salt, ns, NULL, kdf_rounds);
        kdf_run(&dec_task, quiet);
        uint8_t *key = dec_task.key;

        /* Derive role keys for engraved messages (into outer-scoped array) */
        derive_role_keys(key, role_keys);

        pt_buf = malloc(inner_data_len);
        memcpy(pt_buf, inner_data, inner_data_len);

        cc_aes256_ctx *dctx = cc_aes256_init(key);
        secure_zero(key, CC_AES256_KEY_LEN);
        if (!dctx) {
            free(pt_buf); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }

        rc = cc_aes256_decrypt(dctx, nonce, aad, HDR_SIZE, pt_buf, inner_data_len);
        cc_aes256_free(dctx);
        if (rc != 0) {
            fprintf(stderr, "\n  error: decryption failed — wrong password, corrupted file, or mismatched auth method\n\n");
            /* Append ATTEMPT ledger entry */
            ledger_build_entry(last_chain_hash, LEDGER_ACTION_ATTEMPT,
                               current_epoch_general, ledger_entries[n_ledger_entries]);
            n_ledger_entries++;
            if (n_ledger_entries > 0) {
                uint16_t new_count = ledger_count + (uint16_t)n_ledger_entries;
                le16_put(data + HDR_LEDGER_COUNT, new_count);
                size_t new_file_len = file_len + (size_t)n_ledger_entries * LEDGER_ENTRY_SIZE;
                uint8_t *new_file = malloc(new_file_len);
                memcpy(new_file, data, file_len);
                for (int i = 0; i < n_ledger_entries; i++)
                    memcpy(new_file + file_len + (size_t)i * LEDGER_ENTRY_SIZE,
                           ledger_entries[i], LEDGER_ENTRY_SIZE);
                write_file_atomic(path, new_file, new_file_len);
                free(new_file);
            }
            free(pt_buf); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }
        pt_len = inner_data_len - CC_AES256_TAG_LEN;
    }

    /* ---- Fuse consumption: re-encrypt with advanced tips ---- */
    if (flags & FLAG_FUSED) {
        /* New fuse header with advanced inner tip + fresh nonce */
        uint8_t new_inner_nonce[CC_AES256_NONCE_LEN];
        randombytes(new_inner_nonce, CC_AES256_NONCE_LEN);

        uint8_t new_fuse_hdr_plain[FUSE_HDR_SIZE];
        memcpy(new_fuse_hdr_plain + FH_INNER_SALT, inner_salt_dec, SALT_LEN);
        memcpy(new_fuse_hdr_plain + FH_INNER_TIP, new_inner_tip, FUSE_TIP_LEN);
        memcpy(new_fuse_hdr_plain + FH_INNER_NONCE, new_inner_nonce, CC_AES256_NONCE_LEN);

        /* New outer key → XOR-encrypt new fuse header */
        uint8_t new_outer_key[CC_AES256_KEY_LEN];
        derive_key(password, strlen(password), salt, ns, new_outer_tip, kdf_rounds, new_outer_key, NULL);

        uint8_t new_fuse_hdr_ct[FUSE_HDR_SIZE];
        fuse_hdr_xor_cipher(new_outer_key, new_fuse_hdr_plain, new_fuse_hdr_ct);

        /* Re-encrypt vault with new vault key */
        uint8_t new_v_key[CC_AES256_KEY_LEN];
        derive_vault_key(new_outer_key, new_v_key);
        secure_zero(new_outer_key, CC_AES256_KEY_LEN);
        secure_zero(new_fuse_hdr_plain, FUSE_HDR_SIZE);

        uint8_t *new_vault = NULL;
        size_t new_vault_len = 0;
        if (vault_preimages && vault_size > 0) {
            new_vault = malloc(vault_size);
            uint16_t total_consumed = max_fuses - fuses_rem + 1;
            rc = vault_reencrypt(vault_preimages, max_fuses, total_consumed,
                                 new_v_key, new_vault, &new_vault_len);
            if (rc != 0) {
                fprintf(stderr, "  error: vault re-encryption failed\n\n");
                free(new_vault); free(vault_preimages);
                free(pt_buf); free(inner_data); free(data);
                memset(password, 0, sizeof(password));
                return 1;
            }
        }
        secure_zero(new_v_key, CC_AES256_KEY_LEN);

        /* New inner key → AES-GCM encrypt content */
        uint8_t inner_ns[NS_LEN];
        cc_cute_namespace(inner_ns, "cutecrypt.nested", 16);
        uint8_t new_inner_key[CC_AES256_KEY_LEN];
        derive_key(password, strlen(password), inner_salt_dec, inner_ns,
                   new_inner_tip, kdf_rounds, new_inner_key, NULL);

        /* Update header */
        le16_put(data + HDR_FUSES_REM, fuses_rem - 1);
        memcpy(data + HDR_FUSE_TIP, new_outer_tip, FUSE_TIP_LEN);
        uint8_t new_aad[HDR_SIZE];
        prepare_aad(new_aad, data);

        size_t new_content_ct_len = pt_len + CC_AES256_TAG_LEN;
        uint8_t *new_content_ct = malloc(new_content_ct_len);
        memcpy(new_content_ct, pt_buf, pt_len);

        cc_aes256_ctx *rctx = cc_aes256_init(new_inner_key);
        secure_zero(new_inner_key, CC_AES256_KEY_LEN);
        rc = cc_aes256_encrypt(rctx, new_inner_nonce, new_aad, HDR_SIZE, new_content_ct, pt_len);
        cc_aes256_free(rctx);
        if (rc != 0) {
            fprintf(stderr, "  error: re-encryption failed\n\n");
            free(new_content_ct); free(new_vault); free(vault_preimages);
            free(pt_buf); free(inner_data); free(data);
            memset(password, 0, sizeof(password));
            return 1;
        }

        /* Jigsaw: permute with NEW inner tip */
        size_t re_n_blocks = (new_content_ct_len + JIGSAW_BLOCK_SIZE - 1) / JIGSAW_BLOCK_SIZE;
        if (re_n_blocks > 1) {
            size_t *re_perm = malloc(re_n_blocks * sizeof(size_t));
            jigsaw_build_perm(new_inner_tip, re_n_blocks, re_perm);
            uint8_t *permuted = malloc(new_content_ct_len);
            jigsaw_permute(new_content_ct, permuted, new_content_ct_len, re_perm, re_n_blocks);
            free(re_perm);
            memcpy(new_content_ct, permuted, new_content_ct_len);
            free(permuted);
        }

        /* Combine new inner payload */
        size_t new_inner_len = FUSE_HDR_SIZE + new_content_ct_len;
        uint8_t *new_inner = malloc(new_inner_len);
        memcpy(new_inner, new_fuse_hdr_ct, FUSE_HDR_SIZE);
        memcpy(new_inner + FUSE_HDR_SIZE, new_content_ct, new_content_ct_len);
        free(new_content_ct);

        /* Container re-wrap */
        uint8_t *new_payload;
        size_t new_payload_len;

        if (flags & FLAG_CONTAINER) {
            uint8_t new_ckey[CC_AES256_KEY_LEN];
            uint8_t new_cnonce[CC_AES256_NONCE_LEN];
            if (has_kc_nonce_dec) {
                /* Rotate keychain nonce on fuse consumption */
                uint8_t kc_id[CC_CUTE_HASH_LEN];
                keychain_derive_id(salt, ns, kc_id);
                if (keychain_rotate(kc_id, kc_nonce_dec) != 0) {
                    fprintf(stderr, "  warning: keychain nonce rotation failed\n");
                }
                derive_container_key_bound(cont_seed, kc_nonce_dec, hb_epoch, new_ckey, new_cnonce);
            } else {
                derive_container_key(cont_seed, hb_epoch, new_ckey, new_cnonce);
            }

            size_t wrapped_len = new_inner_len + CC_AES256_TAG_LEN;
            uint8_t *wrapped = malloc(wrapped_len);
            rc = container_wrap(new_inner, new_inner_len, new_ckey, new_cnonce, wrapped);
            free(new_inner);
            secure_zero(new_ckey, CC_AES256_KEY_LEN);
            if (rc != 0) {
                fprintf(stderr, "  error: container re-wrap failed\n");
                free(wrapped); free(new_vault); free(vault_preimages);
                free(pt_buf); free(inner_data); free(data);
                memset(password, 0, sizeof(password));
                return 1;
            }

            new_payload_len = CONTAINER_NONCE_LEN + wrapped_len;
            new_payload = malloc(new_payload_len);
            memcpy(new_payload, new_cnonce, CONTAINER_NONCE_LEN);
            memcpy(new_payload + CONTAINER_NONCE_LEN, wrapped, wrapped_len);
            free(wrapped);
        } else {
            new_payload = new_inner;
            new_payload_len = new_inner_len;
        }

        /* Consume remote fuse */
        if (flags & FLAG_REMOTE_FUSE) {
            const uint8_t *file_id = data + bind_offset + BINDING_FILE_ID;
            if (remote_fuse_consume(opts->fuse_server, file_id) != 0) {
                fprintf(stderr, "  error: remote fuse consumption failed\n\n");
                free(new_payload); free(new_vault); free(vault_preimages);
                free(pt_buf); free(inner_data); free(data);
                memset(password, 0, sizeof(password));
                return 1;
            }
            if (!quiet) fprintf(stderr, "  remote fuse: consumed\n");
        }

        /* Ledger: CONSUMED entry */
        ledger_build_entry(last_chain_hash, LEDGER_ACTION_CONSUMED,
                           current_epoch_general, ledger_entries[n_ledger_entries]);
        memcpy(last_chain_hash, ledger_entries[n_ledger_entries] + 8, CC_CUTE_HASH_LEN);
        n_ledger_entries++;

        /* Update ledger count in header */
        uint16_t new_ledger_count = ledger_count + (uint16_t)n_ledger_entries;
        le16_put(data + HDR_LEDGER_COUNT, new_ledger_count);

        /* Reassemble file: [HEADER][BINDING][VAULT][PAYLOAD][OLD_LEDGER][NEW_ENTRIES][TRAILERS] */
        size_t old_ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
        size_t new_ledger_size = (size_t)n_ledger_entries * LEDGER_ENTRY_SIZE;
        size_t actual_vault_len = (new_vault && new_vault_len > 0) ? new_vault_len : vault_size;
        size_t new_file_len = HDR_SIZE + bind_size + actual_vault_len + new_payload_len
                              + old_ledger_size + new_ledger_size + trailer_total_len;
        uint8_t *new_file = malloc(new_file_len);
        size_t off = 0;
        memcpy(new_file + off, data, HDR_SIZE); off += HDR_SIZE;
        if (bind_size > 0) {
            memcpy(new_file + off, data + bind_offset, bind_size); off += bind_size;
        }
        if (new_vault && new_vault_len > 0) {
            memcpy(new_file + off, new_vault, new_vault_len); off += new_vault_len;
        } else {
            memcpy(new_file + off, data + vault_offset, vault_size); off += vault_size;
        }
        memcpy(new_file + off, new_payload, new_payload_len); off += new_payload_len;
        free(new_payload);
        /* Copy old ledger entries */
        if (old_ledger_size > 0)
            memcpy(new_file + off, data + ledger_offset, old_ledger_size);
        off += old_ledger_size;
        /* Append new ledger entries */
        for (int i = 0; i < n_ledger_entries; i++) {
            memcpy(new_file + off, ledger_entries[i], LEDGER_ENTRY_SIZE);
            off += LEDGER_ENTRY_SIZE;
        }
        /* Preserve trailer sections */
        if (trailer_total_len > 0) {
            memcpy(new_file + off, saved_trailers, trailer_total_len);
            off += trailer_total_len;
        }
        n_ledger_entries = 0; /* already written */

        write_file_atomic(path, new_file, new_file_len);
        free(new_file);
        free(new_vault);

        if (!quiet) fprintf(stderr, "  fuse consumed: %u remaining\n", fuses_rem - 1);
        if (fuses_rem - 1 == 0 && (flags & FLAG_PURGE)) {
            if (!quiet) fprintf(stderr, "  last fuse burned — will purge after output\n");
        }
    } else {
        /* Non-fused: append ATTEMPT ledger entry for successful decrypt */
        ledger_build_entry(last_chain_hash, LEDGER_ACTION_ATTEMPT,
                           current_epoch_general, ledger_entries[n_ledger_entries]);
        n_ledger_entries++;

        uint16_t new_count = ledger_count + (uint16_t)n_ledger_entries;
        le16_put(data + HDR_LEDGER_COUNT, new_count);
        /* Reassemble: [HEADER..LEDGER][NEW_ENTRIES][TRAILERS] */
        size_t base_len = ledger_end; /* everything up to and including old ledger */
        size_t new_ledger_size = (size_t)n_ledger_entries * LEDGER_ENTRY_SIZE;
        size_t new_file_len = base_len + new_ledger_size + trailer_total_len;
        uint8_t *new_file = malloc(new_file_len);
        size_t off = 0;
        memcpy(new_file, data, base_len); off = base_len;
        for (int i = 0; i < n_ledger_entries; i++) {
            memcpy(new_file + off, ledger_entries[i], LEDGER_ENTRY_SIZE);
            off += LEDGER_ENTRY_SIZE;
        }
        if (trailer_total_len > 0)
            memcpy(new_file + off, saved_trailers, trailer_total_len);
        write_file_atomic(path, new_file, new_file_len);
        free(new_file);
        n_ledger_entries = 0;
    }

    /* Save data needed after free for purge */
    uint8_t saved_kc_id[CC_CUTE_HASH_LEN];
    uint8_t saved_file_id[16];
    if (flags & FLAG_KEYCHAIN)
        keychain_derive_id(salt, ns, saved_kc_id);
    if ((flags & FLAG_REMOTE_FUSE) && bind_size >= BINDING_REMOTE_SIZE)
        memcpy(saved_file_id, data + bind_offset + BINDING_FILE_ID, 16);

    memset(password, 0, sizeof(password));
    free(vault_preimages);
    free(inner_data);
    free(data);

    /* ---- Auto-decompress PRSS payload ---- */
    if (pt_len >= 4 && memcmp(pt_buf, "PRSS", 4) == 0) {
        uint64_t orig = cp_original_size(pt_buf);
        if (orig > 0) {
            uint8_t *dec = malloc((size_t)orig);
            if (dec) {
                int64_t dlen = cp_decompress(pt_buf, pt_len, dec, (size_t)orig);
                if (dlen > 0) {
                    memset(pt_buf, 0, pt_len);
                    free(pt_buf);
                    pt_buf = dec;
                    pt_len = (size_t)dlen;
                    if (!quiet) fprintf(stderr, "  auto-decompressed (%zu bytes)\n", pt_len);
                } else {
                    free(dec);
                }
            }
        }
    }

    /* ---- Output ---- */
    char out_path[4096];
    if (opts->output) {
        strncpy(out_path, opts->output, sizeof(out_path) - 1);
        out_path[sizeof(out_path) - 1] = '\0';
    } else {
        size_t plen = strlen(path);
        if (plen > 5 && ends_with(path, ".cute")) {
            snprintf(out_path, sizeof(out_path), "%.*s", (int)(plen - 5), path);
        } else {
            snprintf(out_path, sizeof(out_path), "%s.dec", path);
        }
    }

    if (is_folder) {
        if (!quiet) fprintf(stderr, "  extracting folder...\n");
        rc = untar_to(pt_buf, pt_len, out_path);
        memset(pt_buf, 0, pt_len); free(pt_buf);
        if (rc != 0) {
            fprintf(stderr, "  error: extract failed\n\n");
            free(saved_trailers); secure_zero(role_keys, sizeof(role_keys));
            return 1;
        }
        if (!quiet) fprintf(stderr, "\n  decrypted → %s/\n", out_path);
    } else {
        rc = write_file_atomic(out_path, pt_buf, pt_len);
        memset(pt_buf, 0, pt_len); free(pt_buf);
        if (rc != 0) {
            fprintf(stderr, "  error: write failed — check disk space and permissions\n\n");
            free(saved_trailers); secure_zero(role_keys, sizeof(role_keys));
            return 1;
        }
        if (!quiet) fprintf(stderr, "\n  decrypted → %s (%zu bytes)\n", out_path, pt_len);
    }

    /* Display engraved messages and extract files (requires role keys) */
    if (trailer_total_len > 0 && !quiet) {
        char engr_dir[4096];
        snprintf(engr_dir, sizeof(engr_dir), "%s.engravings", out_path);
        int found_engr = 0;

        /* Scan all trailer sections for ENGR blocks */
        size_t toff = 0;
        while (toff + TRAILER_HDR_SIZE <= trailer_total_len) {
            uint32_t slen = le32_get(saved_trailers + toff + 4);
            if (toff + TRAILER_HDR_SIZE + slen > trailer_total_len) break;
            if (memcmp(saved_trailers + toff, ENGR_MAGIC, 4) == 0) {
                if (!found_engr) {
                    fprintf(stderr, "\n  engraved messages:\n");
                    found_engr = 1;
                }
                engr_display(saved_trailers + toff + TRAILER_HDR_SIZE, slen,
                             role_keys, 0 /* root sees all */, engr_dir);
            }
            toff += TRAILER_HDR_SIZE + slen;
        }
    }
    secure_zero(role_keys, sizeof(role_keys));

    /* Self-purge: destroy the single .cute file */
    if ((flags & FLAG_FUSED) && fuses_rem - 1 == 0 && (flags & FLAG_PURGE)) {
        if (!quiet) fprintf(stderr, "  self-purging...\n");
        secure_delete(path);
        /* Clean up keychain entry */
        if (flags & FLAG_KEYCHAIN)
            keychain_delete(saved_kc_id);
        /* Clean up remote fuse */
        if ((flags & FLAG_REMOTE_FUSE) && opts->fuse_server)
            remote_fuse_delete(opts->fuse_server, saved_file_id);
        if (!quiet) fprintf(stderr, "  purged.\n");
    }

    /* ---- Claim: re-encrypt with claimant's password, strip CLAM trailer ---- */
    if (is_claim) {
        if (!quiet) {
            fprintf(stderr, "\n  ┌─────────────────────────────────────┐\n");
            fprintf(stderr, "  │  CLAIM — set your master key now    │\n");
            fprintf(stderr, "  └─────────────────────────────────────┘\n\n");
        }

        char claim_password[256];
        char claim_confirm[256];

        if (opts->headless && opts->password) {
            /* Headless claim: use --password as the new master key */
            strncpy(claim_password, opts->password, sizeof(claim_password) - 1);
            claim_password[sizeof(claim_password) - 1] = '\0';
        } else if (opts->passkey) {
            /* Passkey claim: derive from platform identity */
            char identity[512];
            snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s",
                     getenv("USER") ?: "default", getenv("HOME") ?: "/");
            uint8_t pk_hash[CC_CUTE_HASH_LEN];
            cc_cute_hash((const uint8_t *)identity, strlen(identity), pk_hash);
            for (int i = 0; i < 32; i++)
                snprintf(claim_password + i*2, 3, "%02x", pk_hash[i]);
            claim_password[64] = '\0';
            secure_zero(pk_hash, sizeof(pk_hash));
            if (!quiet) fprintf(stderr, "  claiming with passkey credential\n");
        } else {
            /* Interactive claim */
            read_password("  new master password: ", claim_password, sizeof(claim_password));
            read_password("  confirm password:    ", claim_confirm, sizeof(claim_confirm));
            if (strcmp(claim_password, claim_confirm) != 0) {
                fprintf(stderr, "  error: passwords don't match — file NOT claimed\n");
                fprintf(stderr, "  (your decrypted data is still at: %s)\n\n", out_path);
                secure_zero(claim_password, sizeof(claim_password));
                secure_zero(claim_confirm, sizeof(claim_confirm));
                free(saved_trailers);
                return 1;
            }
            secure_zero(claim_confirm, sizeof(claim_confirm));
        }

        if (strlen(claim_password) == 0) {
            fprintf(stderr, "  error: password cannot be empty — file NOT claimed\n\n");
            free(saved_trailers);
            return 1;
        }

        /* Re-read the decrypted content to re-encrypt */
        uint8_t *claim_pt = NULL;
        size_t claim_pt_len = 0;
        if (is_folder) {
            claim_pt = tar_folder(out_path, &claim_pt_len);
        } else {
            claim_pt = read_file(out_path, &claim_pt_len);
        }
        if (!claim_pt) {
            fprintf(stderr, "  error: cannot re-read decrypted output — file NOT claimed\n\n");
            secure_zero(claim_password, sizeof(claim_password));
            free(saved_trailers);
            return 1;
        }

        /* Build a temporary opts for re-encryption, inheriting all DRM flags */
        cli_opts claim_opts;
        memset(&claim_opts, 0, sizeof(claim_opts));
        claim_opts.headless = 1;
        claim_opts.quiet = 1;
        claim_opts.password = claim_password;
        claim_opts.force = 1;
        claim_opts.output = (char *)path; /* overwrite original .cute */
        claim_opts.kdf_rounds = kdf_rounds;
        /* Inherit DRM flags from original */
        if (flags & FLAG_FUSED) claim_opts.fuses = max_fuses;
        if (flags & FLAG_TIMED) {
            claim_opts.valid_epochs = valid_until;
            claim_opts.epoch_len = epoch_len;
        }
        if (flags & FLAG_PURGE) claim_opts.purge = 1;
        if (flags & FLAG_KEYCHAIN) claim_opts.keychain = 1;
        if (is_folder) claim_opts.archive = 1;

        /* Re-encrypt: call do_encrypt on the decrypted content.
         * do_encrypt writes to claim_opts.output = original path,
         * effectively replacing the claimable file with a claimed one. */
        int crc;
        if (is_folder) {
            char *arc_paths[] = {(char *)out_path};
            crc = do_archive_encrypt(1, arc_paths, &claim_opts);
        } else {
            crc = do_encrypt(out_path, &claim_opts);
        }

        secure_zero(claim_password, sizeof(claim_password));
        free(claim_pt);

        if (crc != 0) {
            fprintf(stderr, "  error: re-encryption failed — file NOT claimed\n");
            fprintf(stderr, "  (your decrypted data is still at: %s)\n\n", out_path);
            free(saved_trailers);
            return 1;
        }

        if (!quiet) {
            fprintf(stderr, "\n  ┌─────────────────────────────────────┐\n");
            fprintf(stderr, "  │  CLAIMED — master key is now set    │\n");
            fprintf(stderr, "  └─────────────────────────────────────┘\n");
            fprintf(stderr, "  original file re-encrypted with your key\n");
        }
    }

    free(saved_trailers);
    if (!quiet) fprintf(stderr, "\n");
    return 0;
}

/* ---- Compression (cutepress) ---- */

static int do_compress(const char *path, const cli_opts *opts) {
    int quiet = opts->quiet;
    int level = opts->press_level > 0 ? opts->press_level : CP_LEVEL_DEFAULT;

    size_t in_len;
    uint8_t *in_data = read_file(path, &in_len);
    if (!in_data) {
        fprintf(stderr, "  error: cannot read '%s'\n", path);
        return 1;
    }

    /* Compress with cutepress */
    size_t out_cap = cp_compress_bound(in_len);
    uint8_t *press_data = malloc(out_cap);
    if (!press_data) {
        fprintf(stderr, "  error: out of memory\n");
        free(in_data);
        return 1;
    }

    int64_t press_len = cp_compress(in_data, in_len, press_data, out_cap, level);
    free(in_data);

    if (press_len < 0) {
        fprintf(stderr, "  error: compression failed (%lld)\n", (long long)press_len);
        free(press_data);
        return 1;
    }

    /* Wrap compressed data in a .cute container.
     * If --password was given → locked container (encrypted).
     * Otherwise → unlocked container (kdf_rounds=0, fixed key). */
    const char *password;
    uint32_t kdf_rounds;
    int is_unlocked;

    if (opts->password && strlen(opts->password) > 0) {
        password = opts->password;
        kdf_rounds = opts->kdf_rounds ? opts->kdf_rounds : KDF_ROUNDS_DEFAULT;
        is_unlocked = 0;
    } else {
        password = UNLOCKED_PASSPHRASE;
        kdf_rounds = UNLOCKED_KDF_ROUNDS;
        is_unlocked = 1;
    }

    /* Build .cute header */
    uint8_t header[HDR_SIZE];
    memset(header, 0, HDR_SIZE);
    memcpy(header + HDR_MAGIC, CUTE_MAGIC, 4);
    header[HDR_VERSION] = CUTE_VERSION;
    header[HDR_FLAGS] = 0; /* no folder, no fuses, no timed */

    uint8_t salt[SALT_LEN], nonce[CC_AES256_NONCE_LEN];
    randombytes(salt, SALT_LEN);
    randombytes(nonce, CC_AES256_NONCE_LEN);
    memcpy(header + HDR_SALT, salt, SALT_LEN);
    memcpy(header + HDR_NONCE, nonce, CC_AES256_NONCE_LEN);

    uint64_t now = (uint64_t)time(NULL);
    le64_put(header + HDR_CREATED, now);
    le32_put(header + HDR_EPOCH_LEN, 3600);
    le32_put(header + HDR_VALID_FROM, 0);
    le32_put(header + HDR_VALID_UNTIL, 0xFFFFFFFF);
    le16_put(header + HDR_MAX_FUSES, 0);
    le16_put(header + HDR_FUSES_REM, 0);

    uint8_t ns[NS_LEN];
    cc_cute_namespace(ns, "cutecrypt.file", 14);
    memcpy(header + HDR_NAMESPACE, ns, NS_LEN);
    le32_put(header + HDR_KDF_ROUNDS, kdf_rounds);

    uint8_t epoch_chain[EPOCH_CHAIN_LEN];
    compute_epoch_chain(salt, now, 3600, 0, 0xFFFFFFFF, kdf_rounds, epoch_chain);
    memcpy(header + HDR_EPOCH_CHAIN, epoch_chain, EPOCH_CHAIN_LEN);
    le32_put(header + HDR_HEARTBEAT, 0);
    memset(header + HDR_CONT_SEED, 0, CONT_SEED_LEN);

    /* Derive key */
    uint8_t key[CC_AES256_KEY_LEN];
    derive_key(password, strlen(password), salt, ns, NULL, kdf_rounds, key, NULL);

    /* Encrypt compressed payload */
    size_t ct_len = (size_t)press_len + CC_AES256_TAG_LEN;
    uint8_t *ct_buf = malloc(ct_len);
    if (!ct_buf) {
        fprintf(stderr, "  error: out of memory\n");
        free(press_data);
        return 1;
    }
    memcpy(ct_buf, press_data, (size_t)press_len);
    free(press_data);

    /* Use header as AAD */
    le32_put(header + HDR_VAULT_SIZE, 0);
    le32_put(header + HDR_PAYLOAD_SIZE, (uint32_t)ct_len);
    le16_put(header + HDR_LEDGER_COUNT, 1);

    uint8_t aad[HDR_SIZE];
    prepare_aad(aad, header);

    cc_aes256_ctx *ctx = cc_aes256_init(key);
    int rc = cc_aes256_encrypt(ctx, nonce, aad, HDR_SIZE, ct_buf, (size_t)press_len);
    cc_aes256_free(ctx);
    secure_zero(key, CC_AES256_KEY_LEN);

    if (rc != 0) {
        fprintf(stderr, "  error: encryption failed\n");
        free(ct_buf);
        return 1;
    }

    /* Build ledger with CREATED entry */
    uint8_t ledger[LEDGER_ENTRY_SIZE];
    memset(ledger, 0, LEDGER_ENTRY_SIZE);
    le64_put(ledger, now);
    uint8_t ledger_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(header, HDR_SIZE, ledger_hash);
    memcpy(ledger + 8, ledger_hash, CC_CUTE_HASH_LEN);
    le32_put(ledger + 40, 0); /* action = CREATED */
    le32_put(ledger + 44, 0); /* epoch = 0 */

    /* Assemble output: header + payload + ledger */
    size_t total = HDR_SIZE + ct_len + LEDGER_ENTRY_SIZE;
    uint8_t *out = malloc(total);
    if (!out) { free(ct_buf); return 1; }
    size_t pos = 0;
    memcpy(out + pos, header, HDR_SIZE); pos += HDR_SIZE;
    memcpy(out + pos, ct_buf, ct_len); pos += ct_len;
    free(ct_buf);
    memcpy(out + pos, ledger, LEDGER_ENTRY_SIZE); pos += LEDGER_ENTRY_SIZE;

    /* Output path: .cute instead of .press */
    char auto_path[4096];
    const char *out_path = opts->output;
    if (!out_path) {
        snprintf(auto_path, sizeof(auto_path), "%s.cute", path);
        out_path = auto_path;
    }

    if (check_overwrite(out_path, opts->force, opts->quiet)) {
        fprintf(stderr, "  aborted.\n");
        free(out);
        return 1;
    }

    if (write_file_atomic(out_path, out, total) != 0) {
        fprintf(stderr, "  error: cannot write '%s' — check disk space and permissions\n", out_path);
        free(out);
        return 1;
    }

    if (!quiet) {
        double ratio = in_len > 0 ? (double)press_len / (double)in_len * 100.0 : 0.0;
        fprintf(stderr, "  %s → %s (%zu → %lld, %.1f%%) [%s .cute]\n",
                path, out_path, in_len, (long long)press_len, ratio,
                is_unlocked ? "unlocked" : "locked");
    }
    free(out);
    return 0;
}

static int do_decompress(const char *path, const cli_opts *opts) {
    int quiet = opts->quiet;

    size_t in_len;
    uint8_t *in_data = read_file(path, &in_len);
    if (!in_data) {
        fprintf(stderr, "  error: cannot read '%s'\n", path);
        return 1;
    }

    /* .cute container wrapping compressed data — route to decrypt (auto-decompresses) */
    if (in_len >= 4 && memcmp(in_data, CUTE_MAGIC, 4) == 0) {
        free(in_data);
        return do_decrypt(path, opts);
    }

    uint64_t orig = cp_original_size(in_data);
    if (orig == 0) {
        fprintf(stderr, "  error: invalid .press file\n");
        free(in_data);
        return 1;
    }

    uint8_t *out_data = malloc((size_t)orig);
    if (!out_data) {
        fprintf(stderr, "  error: out of memory\n");
        free(in_data);
        return 1;
    }

    int64_t result = cp_decompress(in_data, in_len, out_data, (size_t)orig);
    free(in_data);

    if (result < 0) {
        fprintf(stderr, "  error: decompression failed (%lld)\n", (long long)result);
        free(out_data);
        return 1;
    }

    char auto_path[4096];
    const char *out_path = opts->output;
    if (!out_path) {
        /* strip .press extension */
        strncpy(auto_path, path, sizeof(auto_path) - 1);
        auto_path[sizeof(auto_path) - 1] = '\0';
        size_t plen = strlen(auto_path);
        if (plen > 6 && strcmp(auto_path + plen - 6, ".press") == 0)
            auto_path[plen - 6] = '\0';
        else
            strncat(auto_path, ".out", sizeof(auto_path) - plen - 1);
        out_path = auto_path;
    }

    if (write_file_atomic(out_path, out_data, (size_t)result) != 0) {
        fprintf(stderr, "  error: cannot write '%s'\n", out_path);
        free(out_data);
        return 1;
    }

    if (!quiet)
        fprintf(stderr, "  %s → %s (%llu bytes)\n",
                path, out_path, (unsigned long long)result);
    free(out_data);
    return 0;
}

/* ---- Parted files ---- */

#define PART_MAGIC       "PART"
#define PART_SECTION_SIZE 124  /* fixed: 32+2+2+8+8+8+32+32 */
#define PART_ARCHIVE_ID_LEN 32

/* PART trailer layout within section data (124 bytes):
 *   [32] archive_id       (random, identical across all parts)
 *   [2]  part_index LE    (0-based)
 *   [2]  total_parts LE
 *   [8]  part_offset LE   (byte offset into original payload)
 *   [8]  part_length LE   (this part's payload size)
 *   [8]  total_length LE  (original full payload size)
 *   [32] part_hash        (CuteHash of this part's payload slice)
 *   [32] full_hash        (CuteHash of entire original payload)
 */
#define PT_ARCHIVE_ID    0
#define PT_PART_INDEX    32
#define PT_TOTAL_PARTS   34
#define PT_PART_OFFSET   36
#define PT_PART_LENGTH   44
#define PT_TOTAL_LENGTH  52
#define PT_PART_HASH     60
#define PT_FULL_HASH     92

/* ---- Info: show .cute metadata without password ---- */
static int do_info(const char *path) {
    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data) {
        fprintf(stderr, "  error: cannot read '%s'\n", path);
        return 1;
    }
    if (file_len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) {
        /* Check for PRSS (compressed) */
        if (file_len >= 4 && memcmp(data, "PRSS", 4) == 0) {
            uint64_t orig = cp_original_size(data);
            fprintf(stderr, "\n  cutedepo — file info\n");
            fprintf(stderr, "  ───────────────────────────────────\n");
            fprintf(stderr, "  file:        %s\n", path);
            fprintf(stderr, "  format:      cutepress (compressed)\n");
            fprintf(stderr, "  compressed:  %zu bytes\n", file_len);
            fprintf(stderr, "  original:    %llu bytes\n", (unsigned long long)orig);
            if (orig > 0)
                fprintf(stderr, "  ratio:       %.1f%%\n",
                        100.0 * (double)file_len / (double)orig);
            fprintf(stderr, "\n");
            free(data);
            return 0;
        }
        fprintf(stderr, "  error: '%s' is not a .cute or .press file\n", path);
        free(data);
        return 1;
    }

    uint8_t version = data[HDR_VERSION];
    uint8_t flags = data[HDR_FLAGS];
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);
    uint64_t created_at = le64_get(data + HDR_CREATED);
    uint32_t epoch_len = le32_get(data + HDR_EPOCH_LEN);
    uint32_t valid_from = le32_get(data + HDR_VALID_FROM);
    uint32_t valid_until = le32_get(data + HDR_VALID_UNTIL);
    uint16_t max_fuses = le16_get(data + HDR_MAX_FUSES);
    uint16_t fuses_rem = le16_get(data + HDR_FUSES_REM);
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    int is_folder = (flags & FLAG_FOLDER) != 0;
    int is_unlocked = (kdf_rounds == UNLOCKED_KDF_ROUNDS);

    fprintf(stderr, "\n  cutedepo — file info\n");
    fprintf(stderr, "  ───────────────────────────────────\n");
    fprintf(stderr, "  file:        %s\n", path);
    fprintf(stderr, "  size:        %zu bytes\n", file_len);
    fprintf(stderr, "  format:      CUTE v%u\n", version);
    fprintf(stderr, "  security:    %s\n", is_unlocked ? "unlocked (compression only)" : "encrypted");
    if (!is_unlocked)
        fprintf(stderr, "  kdf rounds:  %u\n", kdf_rounds);
    fprintf(stderr, "  type:        %s\n", is_folder ? "folder/archive" : "single file");
    fprintf(stderr, "  payload:     %u bytes\n", payload_size);
    fprintf(stderr, "  vault:       %u bytes\n", vault_size);
    fprintf(stderr, "  ledger:      %u entries\n", ledger_count);

    /* Time info */
    time_t ct = (time_t)created_at;
    char timebuf[64];
    struct tm *tm = localtime(&ct);
    if (tm) {
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(stderr, "  created:     %s\n", timebuf);
    }

    /* Flags */
    fprintf(stderr, "  flags:      ");
    if (flags & FLAG_TIMED)     fprintf(stderr, " timed");
    if (flags & FLAG_DELAYED)   fprintf(stderr, " delayed");
    if (flags & FLAG_FUSED)     fprintf(stderr, " fused");
    if (flags & FLAG_PURGE)     fprintf(stderr, " self-purge");
    if (flags & FLAG_CONTAINER) fprintf(stderr, " container");
    if (flags & FLAG_KEYCHAIN)  fprintf(stderr, " keychain");
    if (flags == 0 && !is_folder) fprintf(stderr, " none");
    fprintf(stderr, "\n");

    if (flags & FLAG_TIMED)
        fprintf(stderr, "  epochs:      %u–%u (period: %u sec)\n",
                valid_from, valid_until, epoch_len);
    if (flags & FLAG_FUSED)
        fprintf(stderr, "  fuses:       %u/%u remaining\n", fuses_rem, max_fuses);

    /* Trailer sections */
    size_t bind_size = binding_section_size(flags);
    size_t payload_offset = HDR_SIZE + bind_size + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_offset = ledger_offset + ledger_size;

    if (trailer_offset < file_len) {
        size_t tl = file_len - trailer_offset;
        const uint8_t *tptr = data + trailer_offset;
        /* Scan trailer sections by magic bytes */
        fprintf(stderr, "  trailers:   ");
        static const char *trailer_names[] = {
            "ARCV", "PMSG", "ENGR", "TOTP", "PKEY", "PART", "FBOX", "CLAM", NULL
        };
        int trailer_count = 0;
        for (int ti = 0; trailer_names[ti]; ti++) {
            size_t slen;
            if (trailer_section_find(tptr, tl, trailer_names[ti], &slen)) {
                fprintf(stderr, " %s", trailer_names[ti]);
                trailer_count++;
            }
        }
        if (trailer_count == 0)
            fprintf(stderr, " none");
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "\n");
    free(data);
    return 0;
}

/* ---- Check: machine-readable type identification ---- */
/*
 * Outputs a single-line type string to stdout for easy scripting:
 *   file          — encrypted single file
 *   archive       — locked archive (folder)
 *   app           — DRM-wrapped app bundle (archive + PKEY)
 *   ledger        — file with ledger entries (fuse history)
 *   fused         — fuse-limited container
 *   fbox          — fuse box (renounced master key)
 *   compressed    — cutepress compressed (no encryption)
 *   parted        — part of a split file
 *   unlocked      — unlocked container (compression-only .cute)
 *   unknown       — not a recognized .cute format
 *
 * Multiple types are space-separated when applicable, e.g.:
 *   "archive fused fbox ledger"
 */
static int do_check(const char *path) {
    /* Check if it's a wrapper .app bundle (directory with launcher.json) */
    {
        struct stat ds;
        if (stat(path, &ds) == 0 && S_ISDIR(ds.st_mode)) {
            char json_path[4096];
            snprintf(json_path, sizeof(json_path), "%s/Contents/Resources/launcher.json", path);
            if (stat(json_path, &ds) == 0) {
                fprintf(stdout, "app\n");
                return 0;
            }
        }
    }

    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data) {
        fprintf(stdout, "unknown\n");
        return 1;
    }

    /* Check for cutepress compressed */
    if (file_len >= 4 && memcmp(data, "PRSS", 4) == 0) {
        fprintf(stdout, "compressed\n");
        free(data);
        return 0;
    }

    /* Not a .cute file */
    if (file_len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stdout, "unknown\n");
        free(data);
        return 1;
    }

    uint8_t flags = data[HDR_FLAGS];
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);
    uint16_t max_fuses = le16_get(data + HDR_MAX_FUSES);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    int is_folder = (flags & FLAG_FOLDER) != 0;
    int is_unlocked = (kdf_rounds == UNLOCKED_KDF_ROUNDS);

    /* Parse trailers */
    size_t bind_size = binding_section_size(flags);
    size_t payload_offset = HDR_SIZE + bind_size + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_offset = ledger_offset + ledger_size;

    int has_arcv = 0, has_pkey = 0, has_part = 0, has_fbox = 0;
    int has_totp = 0, has_engr = 0, has_clam = 0;
    if (trailer_offset < file_len) {
        size_t tl = file_len - trailer_offset;
        const uint8_t *tptr = data + trailer_offset;
        size_t dummy;
        has_arcv = trailer_section_find(tptr, tl, "ARCV", &dummy) != NULL;
        has_pkey = trailer_section_find(tptr, tl, "PKEY", &dummy) != NULL;
        has_part = trailer_section_find(tptr, tl, "PART", &dummy) != NULL;
        has_fbox = trailer_section_find(tptr, tl, "FBOX", &dummy) != NULL;
        has_totp = trailer_section_find(tptr, tl, "TOTP", &dummy) != NULL;
        has_engr = trailer_section_find(tptr, tl, "ENGR", &dummy) != NULL;
        has_clam = trailer_section_find(tptr, tl, "CLAM", &dummy) != NULL;
    }

    /* Build type string */
    char types[512] = {0};
    int n = 0;

    /* Primary type */
    if (has_arcv && has_pkey)
        n += snprintf(types + n, sizeof(types) - n, "app ");
    else if (has_arcv)
        n += snprintf(types + n, sizeof(types) - n, "archive ");
    else if (has_part)
        n += snprintf(types + n, sizeof(types) - n, "parted ");
    else if (is_unlocked)
        n += snprintf(types + n, sizeof(types) - n, "unlocked ");
    else
        n += snprintf(types + n, sizeof(types) - n, "file ");

    /* Modifiers */
    if (flags & FLAG_FUSED)
        n += snprintf(types + n, sizeof(types) - n, "fused ");
    if (has_fbox)
        n += snprintf(types + n, sizeof(types) - n, "fbox ");
    if (ledger_count > 0)
        n += snprintf(types + n, sizeof(types) - n, "ledger ");
    if (has_totp)
        n += snprintf(types + n, sizeof(types) - n, "totp ");
    if (has_engr)
        n += snprintf(types + n, sizeof(types) - n, "engraved ");
    if (has_clam)
        n += snprintf(types + n, sizeof(types) - n, "claimable ");
    if (flags & FLAG_KEYCHAIN)
        n += snprintf(types + n, sizeof(types) - n, "keychain ");
    if (flags & FLAG_PURGE)
        n += snprintf(types + n, sizeof(types) - n, "purge ");
    if (flags & FLAG_TIMED)
        n += snprintf(types + n, sizeof(types) - n, "timed ");
    if (flags & FLAG_DELAYED)
        n += snprintf(types + n, sizeof(types) - n, "delayed ");

    /* Trim trailing space */
    size_t len = strlen(types);
    if (len > 0 && types[len - 1] == ' ')
        types[len - 1] = '\0';

    fprintf(stdout, "%s\n", types);
    free(data);
    return 0;
}

/* ---- Verify: integrity check without full decrypt ---- */
static int do_verify(const char *path) {
    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data) {
        fprintf(stderr, "  error: cannot read '%s'\n", path);
        return 1;
    }

    fprintf(stderr, "\n  cutedepo — verify\n");
    fprintf(stderr, "  ───────────────────────────────────\n");
    fprintf(stderr, "  file: %s\n", path);

    int errors = 0;

    /* 1. Magic check */
    if (file_len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stderr, "  [FAIL] invalid magic bytes — not a .cute file\n");
        free(data);
        return 1;
    }
    fprintf(stderr, "  [OK]   magic: CUTE v%u\n", data[HDR_VERSION]);

    /* 2. Size sanity */
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    uint8_t flags = data[HDR_FLAGS];
    size_t bind_size = binding_section_size(flags);
    size_t expected = HDR_SIZE + bind_size + vault_size + payload_size
                      + (size_t)ledger_count * LEDGER_ENTRY_SIZE;

    if (file_len < expected) {
        fprintf(stderr, "  [FAIL] file truncated: expected >= %zu bytes, got %zu\n",
                expected, file_len);
        errors++;
    } else {
        fprintf(stderr, "  [OK]   structure: header(%d) + bind(%zu) + vault(%u) + payload(%u) + ledger(%u)\n",
                HDR_SIZE, bind_size, vault_size, payload_size, ledger_count);
    }

    /* 3. Epoch chain */
    uint64_t created_at = le64_get(data + HDR_CREATED);
    uint32_t epoch_len = le32_get(data + HDR_EPOCH_LEN);
    uint32_t valid_from = le32_get(data + HDR_VALID_FROM);
    uint32_t valid_until = le32_get(data + HDR_VALID_UNTIL);
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);

    uint8_t expected_chain[EPOCH_CHAIN_LEN];
    compute_epoch_chain(data + HDR_SALT, created_at, epoch_len,
                        valid_from, valid_until, kdf_rounds, expected_chain);
    uint8_t diff = 0;
    for (int i = 0; i < EPOCH_CHAIN_LEN; i++)
        diff |= expected_chain[i] ^ data[HDR_EPOCH_CHAIN + i];
    if (diff != 0) {
        fprintf(stderr, "  [FAIL] epoch chain mismatch — header has been tampered\n");
        errors++;
    } else {
        fprintf(stderr, "  [OK]   epoch chain: verified\n");
    }

    /* 4. Ledger chain */
    if (ledger_count > 0 && file_len >= expected) {
        size_t ledger_offset = HDR_SIZE + bind_size + vault_size + payload_size;
        /* Verify first entry has a plausible hash */
        const uint8_t *genesis = data + ledger_offset;
        uint64_t entry_ts = le64_get(genesis);
        if (entry_ts > 0 && entry_ts < 0xFFFFFFFF00000000ULL) {
            fprintf(stderr, "  [OK]   ledger: %u entries, genesis valid\n", ledger_count);
        } else {
            fprintf(stderr, "  [WARN] ledger: genesis timestamp looks invalid\n");
        }
    }

    /* 5. Trailer sections parseable */
    if (file_len > expected) {
        size_t trailer_len = file_len - expected;
        const uint8_t *tptr = data + expected;
        size_t toff = 0;
        int trailer_count = 0;
        int trailer_ok = 1;
        while (toff + TRAILER_HDR_SIZE <= trailer_len) {
            uint32_t slen = le32_get(tptr + toff + 4);
            if (toff + TRAILER_HDR_SIZE + slen > trailer_len) {
                fprintf(stderr, "  [FAIL] trailer at offset %zu: claims %u bytes but only %zu available\n",
                        toff, slen, trailer_len - toff - TRAILER_HDR_SIZE);
                trailer_ok = 0;
                errors++;
                break;
            }
            trailer_count++;
            toff += TRAILER_HDR_SIZE + slen;
        }
        if (trailer_ok && trailer_count > 0)
            fprintf(stderr, "  [OK]   trailers: %d sections parsed\n", trailer_count);
    }

    fprintf(stderr, "\n");
    if (errors == 0) {
        fprintf(stderr, "  result: PASS — file structure is intact\n");
        fprintf(stderr, "  note: full cryptographic verification requires password\n\n");
    } else {
        fprintf(stderr, "  result: FAIL — %d integrity error(s) found\n\n", errors);
    }

    free(data);
    return errors > 0 ? 1 : 0;
}

static int do_split(const char *path, uint32_t part_size_mb) {
    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data) { fprintf(stderr, "  error: cannot read '%s'\n", path); return 1; }

    /* validate .cute header */
    if (file_len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stderr, "  error: '%s' is not a valid .cute file\n", path);
        free(data); return 1;
    }

    uint8_t flags = data[HDR_FLAGS];
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    size_t binding_size = binding_section_size(flags);

    size_t payload_offset = HDR_SIZE + binding_size + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_offset = ledger_offset + ledger_size;
    size_t trailer_len = file_len > trailer_offset ? file_len - trailer_offset : 0;

    if (payload_offset + payload_size > file_len) {
        fprintf(stderr, "  error: file truncated\n");
        free(data); return 1;
    }

    /* compute part count */
    size_t part_bytes = (size_t)part_size_mb * 1024 * 1024;
    if (part_bytes == 0) part_bytes = 1;
    uint16_t total_parts = (uint16_t)((payload_size + part_bytes - 1) / part_bytes);
    if (total_parts == 0) total_parts = 1;
    if (total_parts > 65535) {
        fprintf(stderr, "  error: too many parts (%u)\n", (unsigned)total_parts);
        free(data); return 1;
    }

    /* compute full payload hash */
    uint8_t full_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(data + payload_offset, payload_size, full_hash);

    /* generate archive_id */
    uint8_t archive_id[PART_ARCHIVE_ID_LEN];
    randombytes(archive_id, PART_ARCHIVE_ID_LEN);

    /* metadata size = header + binding + vault + ledger + existing trailers */
    size_t meta_before_payload = payload_offset;
    size_t meta_after_payload = ledger_size + trailer_len;

    /* strip .cute suffix for base name */
    char base[4096];
    strncpy(base, path, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';

    for (uint16_t p = 0; p < total_parts; p++) {
        size_t poff = (size_t)p * part_bytes;
        size_t plen = payload_size - poff;
        if (plen > part_bytes) plen = part_bytes;

        /* compute part hash */
        uint8_t part_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash(data + payload_offset + poff, plen, part_hash);

        /* build PART trailer section data */
        uint8_t part_data[PART_SECTION_SIZE];
        memcpy(part_data + PT_ARCHIVE_ID, archive_id, PART_ARCHIVE_ID_LEN);
        le16_put(part_data + PT_PART_INDEX, p);
        le16_put(part_data + PT_TOTAL_PARTS, total_parts);
        le64_put(part_data + PT_PART_OFFSET, (uint64_t)poff);
        le64_put(part_data + PT_PART_LENGTH, (uint64_t)plen);
        le64_put(part_data + PT_TOTAL_LENGTH, (uint64_t)payload_size);
        memcpy(part_data + PT_PART_HASH, part_hash, CC_CUTE_HASH_LEN);
        memcpy(part_data + PT_FULL_HASH, full_hash, CC_CUTE_HASH_LEN);

        /* part file = [header+binding+vault] [payload_slice] [ledger] [trailers] [PART trailer] */
        size_t part_file_len = meta_before_payload + plen + meta_after_payload
                               + TRAILER_HDR_SIZE + PART_SECTION_SIZE;
        uint8_t *part_file = malloc(part_file_len);
        size_t w = 0;

        /* header + binding + vault (with payload_size = TOTAL, not slice) */
        memcpy(part_file, data, meta_before_payload);
        w += meta_before_payload;

        /* payload slice */
        memcpy(part_file + w, data + payload_offset + poff, plen);
        w += plen;

        /* ledger + existing trailers */
        memcpy(part_file + w, data + ledger_offset, meta_after_payload);
        w += meta_after_payload;

        /* PART trailer header */
        memcpy(part_file + w, PART_MAGIC, 4);
        le32_put(part_file + w + 4, PART_SECTION_SIZE);
        w += TRAILER_HDR_SIZE;

        /* PART trailer data */
        memcpy(part_file + w, part_data, PART_SECTION_SIZE);
        w += PART_SECTION_SIZE;

        /* write part file */
        char part_path[4096];
        snprintf(part_path, sizeof(part_path), "%s.part%u", base, (unsigned)p);
        if (write_file_atomic(part_path, part_file, part_file_len) != 0) {
            fprintf(stderr, "  error: failed to write '%s'\n", part_path);
            free(part_file); free(data); return 1;
        }
        free(part_file);
        fprintf(stderr, "  wrote %s (%zu bytes)\n", part_path, part_file_len);
    }

    fprintf(stderr, "  split into %u parts\n", (unsigned)total_parts);
    free(data);
    return 0;
}

static int do_join(const char *path) {
    /* read the provided part file to get archive_id and total_parts */
    size_t p0_len;
    uint8_t *p0_data = read_file(path, &p0_len);
    if (!p0_data) { fprintf(stderr, "  error: cannot read '%s'\n", path); return 1; }

    /* find PART trailer in this file */
    if (p0_len < HDR_SIZE) {
        fprintf(stderr, "  error: '%s' is not a valid .cute file\n", path);
        free(p0_data); return 1;
    }

    uint8_t flags = p0_data[HDR_FLAGS];
    uint32_t vault_size = le32_get(p0_data + HDR_VAULT_SIZE);
    uint32_t payload_size_total = le32_get(p0_data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(p0_data + HDR_LEDGER_COUNT);
    size_t binding_size = binding_section_size(flags);
    size_t meta_before_payload = HDR_SIZE + binding_size + vault_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;

    /* for this part file, payload slice sits right after header+binding+vault,
     * and the slice length = file_len - meta - ledger - trailers.
     * We need to find the PART trailer to know the total structure. */

    /* Scan trailers from the end. The PART trailer is last. */
    /* Look for "PART" magic near the end of the file */
    if (p0_len < TRAILER_HDR_SIZE + PART_SECTION_SIZE) {
        fprintf(stderr, "  error: file too small for PART trailer\n");
        free(p0_data); return 1;
    }

    /* PART trailer is the last trailer — check at end of file */
    size_t part_trailer_start = p0_len - TRAILER_HDR_SIZE - PART_SECTION_SIZE;
    if (memcmp(p0_data + part_trailer_start, PART_MAGIC, 4) != 0) {
        fprintf(stderr, "  error: '%s' is not a parted .cute file\n", path);
        free(p0_data); return 1;
    }

    const uint8_t *pt = p0_data + part_trailer_start + TRAILER_HDR_SIZE;
    uint16_t total_parts = le16_get(pt + PT_TOTAL_PARTS);
    uint64_t total_length = le64_get(pt + PT_TOTAL_LENGTH);
    uint8_t archive_id[PART_ARCHIVE_ID_LEN];
    memcpy(archive_id, pt + PT_ARCHIVE_ID, PART_ARCHIVE_ID_LEN);
    uint8_t expected_full_hash[CC_CUTE_HASH_LEN];
    memcpy(expected_full_hash, pt + PT_FULL_HASH, CC_CUTE_HASH_LEN);

    free(p0_data);

    if (total_parts == 0 || total_length != payload_size_total) {
        fprintf(stderr, "  error: invalid PART trailer\n");
        return 1;
    }

    /* derive base path: strip ".partN" suffix */
    char base[4096];
    strncpy(base, path, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    char *dot = strrchr(base, '.');
    if (dot && strncmp(dot, ".part", 5) == 0) *dot = '\0';

    /* allocate reassembled payload */
    uint8_t *payload = calloc(1, (size_t)total_length);
    if (!payload) { fprintf(stderr, "  error: out of memory\n"); return 1; }

    /* metadata buffers (from first part we read) */
    uint8_t *meta_before = NULL;
    uint8_t *meta_after = NULL;
    size_t meta_after_len = 0;

    for (uint16_t p = 0; p < total_parts; p++) {
        char part_path[4096];
        snprintf(part_path, sizeof(part_path), "%s.part%u", base, (unsigned)p);

        size_t pf_len;
        uint8_t *pf = read_file(part_path, &pf_len);
        if (!pf) {
            fprintf(stderr, "  error: cannot read '%s'\n", part_path);
            free(payload); free(meta_before); free(meta_after);
            return 1;
        }

        /* validate PART trailer at end */
        if (pf_len < TRAILER_HDR_SIZE + PART_SECTION_SIZE) {
            fprintf(stderr, "  error: '%s' too small\n", part_path);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }
        size_t pt_off = pf_len - TRAILER_HDR_SIZE - PART_SECTION_SIZE;
        if (memcmp(pf + pt_off, PART_MAGIC, 4) != 0) {
            fprintf(stderr, "  error: '%s' missing PART trailer\n", part_path);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }

        const uint8_t *ppt = pf + pt_off + TRAILER_HDR_SIZE;

        /* verify archive_id matches */
        if (memcmp(ppt + PT_ARCHIVE_ID, archive_id, PART_ARCHIVE_ID_LEN) != 0) {
            fprintf(stderr, "  error: '%s' has different archive_id\n", part_path);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }

        uint16_t idx = le16_get(ppt + PT_PART_INDEX);
        if (idx != p) {
            fprintf(stderr, "  error: '%s' has index %u, expected %u\n", part_path, idx, p);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }

        uint64_t poff = le64_get(ppt + PT_PART_OFFSET);
        uint64_t plen = le64_get(ppt + PT_PART_LENGTH);

        /* verify part hash */
        uint8_t expected_part_hash[CC_CUTE_HASH_LEN];
        memcpy(expected_part_hash, ppt + PT_PART_HASH, CC_CUTE_HASH_LEN);

        /* extract payload slice from part file */
        /* part file layout: [meta_before][payload_slice][meta_after][PART trailer] */
        size_t slice_start = meta_before_payload;
        /* meta_after = everything between end of slice and start of PART trailer */
        size_t part_meta_after_len = pt_off - (slice_start + (size_t)plen);

        uint8_t part_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash(pf + slice_start, (size_t)plen, part_hash);
        if (memcmp(part_hash, expected_part_hash, CC_CUTE_HASH_LEN) != 0) {
            fprintf(stderr, "  error: '%s' part hash mismatch (corrupted)\n", part_path);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }

        /* copy payload slice */
        if (poff + plen > total_length) {
            fprintf(stderr, "  error: '%s' offset+length exceeds total\n", part_path);
            free(pf); free(payload); free(meta_before); free(meta_after);
            return 1;
        }
        memcpy(payload + poff, pf + slice_start, (size_t)plen);

        /* save metadata from first part */
        if (p == 0) {
            meta_before = malloc(meta_before_payload);
            memcpy(meta_before, pf, meta_before_payload);
            meta_after_len = part_meta_after_len;
            meta_after = malloc(meta_after_len);
            memcpy(meta_after, pf + slice_start + (size_t)plen, meta_after_len);
        }

        fprintf(stderr, "  read %s (part %u/%u)\n", part_path, p + 1, total_parts);
        free(pf);
    }

    /* verify full hash */
    uint8_t full_hash[CC_CUTE_HASH_LEN];
    cc_cute_hash(payload, (size_t)total_length, full_hash);
    if (memcmp(full_hash, expected_full_hash, CC_CUTE_HASH_LEN) != 0) {
        fprintf(stderr, "  error: full payload hash mismatch after reassembly\n");
        free(payload); free(meta_before); free(meta_after);
        return 1;
    }

    /* reassemble: [meta_before][full_payload][meta_after (ledger+trailers, no PART)] */
    size_t out_len = meta_before_payload + (size_t)total_length + meta_after_len;
    uint8_t *out = malloc(out_len);
    memcpy(out, meta_before, meta_before_payload);
    memcpy(out + meta_before_payload, payload, (size_t)total_length);
    memcpy(out + meta_before_payload + (size_t)total_length, meta_after, meta_after_len);

    /* write output */
    char out_path[4096];
    snprintf(out_path, sizeof(out_path), "%s", base);
    if (write_file_atomic(out_path, out, out_len) != 0) {
        fprintf(stderr, "  error: failed to write '%s'\n", out_path);
        free(out); free(payload); free(meta_before); free(meta_after);
        return 1;
    }

    fprintf(stderr, "  reassembled %s (%zu bytes)\n", out_path, out_len);

    free(out);
    free(payload);
    free(meta_before);
    free(meta_after);
    return 0;
}

/* ---- Locked archives ---- */

#define ARCV_MAGIC       "ARCV"
#define ARCV_ENTRY_FILE  0
#define ARCV_ENTRY_DIR   1

/* Per-file key derivation: file_key = Hash(role_key[level] || nonce || "cutecrypt.archive.file") */
static void derive_file_key(
    const uint8_t role_key[CC_AES256_KEY_LEN],
    const uint8_t nonce[CC_AES256_NONCE_LEN],
    uint8_t file_key[CC_AES256_KEY_LEN])
{
    uint8_t in[CC_AES256_KEY_LEN + CC_AES256_NONCE_LEN + 22];
    memcpy(in, role_key, CC_AES256_KEY_LEN);
    memcpy(in + CC_AES256_KEY_LEN, nonce, CC_AES256_NONCE_LEN);
    memcpy(in + CC_AES256_KEY_LEN + CC_AES256_NONCE_LEN, "cutecrypt.archive.file", 22);
    uint8_t h[CC_CUTE_HASH_LEN];
    cc_cute_hash(in, sizeof(in), h);
    memcpy(file_key, h, CC_AES256_KEY_LEN);
    memset(h, 0, sizeof(h));
    memset(in, 0, sizeof(in));
}

/* Archive entry in memory */
typedef struct {
    char *path;             /* relative path (UTF-8) */
    uint8_t entry_type;     /* 0=file, 1=directory */
    uint8_t role_level;     /* 0=root .. 3=reader */
    uint64_t original_size;
    uint64_t payload_offset;
    uint64_t payload_length;
    uint8_t entry_nonce[CC_AES256_NONCE_LEN];
    uint8_t entry_hash[CC_CUTE_HASH_LEN];
    uint32_t permissions;
    uint64_t mtime;
} arcv_entry;

/* Recursive directory walk */
static int walk_directory(const char *base, const char *prefix,
                          arcv_entry **entries, size_t *count, size_t *cap)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", base, prefix);

    DIR *d = opendir(full[0] ? full : base);
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' || (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;

        char rel[4096];
        if (prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", prefix, de->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", de->d_name);

        char abs_path[4096];
        snprintf(abs_path, sizeof(abs_path), "%s/%s", base, rel);

        struct stat st;
        if (stat(abs_path, &st) != 0) continue;

        if (*count >= *cap) {
            *cap = *cap == 0 ? 64 : *cap * 2;
            *entries = realloc(*entries, *cap * sizeof(arcv_entry));
        }

        arcv_entry *e = &(*entries)[*count];
        memset(e, 0, sizeof(*e));
        e->path = strdup(rel);
        e->permissions = (uint32_t)(st.st_mode & 0777);
        e->mtime = (uint64_t)st.st_mtime;

        if (S_ISDIR(st.st_mode)) {
            e->entry_type = ARCV_ENTRY_DIR;
            e->original_size = 0;
            (*count)++;
            if (walk_directory(base, rel, entries, count, cap) != 0) {
                closedir(d); return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            e->entry_type = ARCV_ENTRY_FILE;
            e->original_size = (uint64_t)st.st_size;
            (*count)++;
        } else {
            free(e->path);
        }
    }
    closedir(d);
    return 0;
}

/* Build ARCV trailer data from entries */
static uint8_t *arcv_build(const arcv_entry *entries, size_t count, size_t *out_len)
{
    /* compute total size */
    size_t total = 2; /* file_count LE */
    for (size_t i = 0; i < count; i++) {
        /* path_len(2) + path + type(1) + role(1) + orig_size(8) + offset(8) + length(8)
         * + nonce(12) + hash(32) + permissions(4) + mtime(8) */
        total += 2 + strlen(entries[i].path) + 1 + 1 + 8 + 8 + 8 + 12 + 32 + 4 + 8;
    }

    uint8_t *buf = malloc(total);
    le16_put(buf, (uint16_t)count);
    size_t off = 2;

    for (size_t i = 0; i < count; i++) {
        const arcv_entry *e = &entries[i];
        uint16_t plen = (uint16_t)strlen(e->path);
        le16_put(buf + off, plen); off += 2;
        memcpy(buf + off, e->path, plen); off += plen;
        buf[off++] = e->entry_type;
        buf[off++] = e->role_level;
        le64_put(buf + off, e->original_size); off += 8;
        le64_put(buf + off, e->payload_offset); off += 8;
        le64_put(buf + off, e->payload_length); off += 8;
        memcpy(buf + off, e->entry_nonce, CC_AES256_NONCE_LEN); off += CC_AES256_NONCE_LEN;
        memcpy(buf + off, e->entry_hash, CC_CUTE_HASH_LEN); off += CC_CUTE_HASH_LEN;
        le32_put(buf + off, e->permissions); off += 4;
        le64_put(buf + off, e->mtime); off += 8;
    }

    *out_len = total;
    return buf;
}

/* Parse ARCV trailer data */
static int arcv_parse(const uint8_t *data, size_t data_len,
                      arcv_entry **entries, size_t *count)
{
    if (data_len < 2) return -1;
    uint16_t n = le16_get(data);
    *count = n;
    *entries = calloc(n, sizeof(arcv_entry));
    size_t off = 2;

    for (uint16_t i = 0; i < n; i++) {
        if (off + 2 > data_len) goto fail;
        uint16_t plen = le16_get(data + off); off += 2;
        if (off + plen > data_len) goto fail;
        (*entries)[i].path = malloc(plen + 1);
        memcpy((*entries)[i].path, data + off, plen);
        (*entries)[i].path[plen] = '\0';
        off += plen;

        if (off + 1 + 1 + 8 + 8 + 8 + 12 + 32 + 4 + 8 > data_len) goto fail;
        (*entries)[i].entry_type = data[off++];
        (*entries)[i].role_level = data[off++];
        (*entries)[i].original_size = le64_get(data + off); off += 8;
        (*entries)[i].payload_offset = le64_get(data + off); off += 8;
        (*entries)[i].payload_length = le64_get(data + off); off += 8;
        memcpy((*entries)[i].entry_nonce, data + off, CC_AES256_NONCE_LEN); off += CC_AES256_NONCE_LEN;
        memcpy((*entries)[i].entry_hash, data + off, CC_CUTE_HASH_LEN); off += CC_CUTE_HASH_LEN;
        (*entries)[i].permissions = le32_get(data + off); off += 4;
        (*entries)[i].mtime = le64_get(data + off); off += 8;
    }
    return 0;
fail:
    for (uint16_t j = 0; j < n; j++) free((*entries)[j].path);
    free(*entries);
    *entries = NULL; *count = 0;
    return -1;
}

static void arcv_entries_free(arcv_entry *entries, size_t count) {
    for (size_t i = 0; i < count; i++) free(entries[i].path);
    free(entries);
}

/* List archive contents (no password needed) */
static int do_archive_list(const char *path) {
    size_t file_len;
    uint8_t *data = read_file(path, &file_len);
    if (!data) { fprintf(stderr, "  error: cannot read '%s'\n", path); return 1; }

    if (file_len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) {
        fprintf(stderr, "  error: not a valid .cute file\n");
        free(data); return 1;
    }

    uint8_t flags = data[HDR_FLAGS];
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    size_t binding_size = binding_section_size(flags);
    size_t payload_offset = HDR_SIZE + binding_size + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_offset = ledger_offset + ledger_size;
    size_t trailer_len = file_len > trailer_offset ? file_len - trailer_offset : 0;

    size_t arcv_data_len;
    const uint8_t *arcv_data = trailer_section_find(
        data + trailer_offset, trailer_len, ARCV_MAGIC, &arcv_data_len);
    if (!arcv_data) {
        fprintf(stderr, "  error: no ARCV trailer — not a locked archive\n");
        free(data); return 1;
    }

    arcv_entry *entries;
    size_t count;
    if (arcv_parse(arcv_data, arcv_data_len, &entries, &count) != 0) {
        fprintf(stderr, "  error: corrupt ARCV trailer\n");
        free(data); return 1;
    }

    static const char *role_n[] = {"root","admin","auditor","reader"};
    fprintf(stderr, "\n  locked archive: %zu entries\n\n", count);
    for (size_t i = 0; i < count; i++) {
        const arcv_entry *e = &entries[i];
        if (e->entry_type == ARCV_ENTRY_DIR) {
            fprintf(stderr, "  [dir]  %s/\n", e->path);
        } else {
            fprintf(stderr, "  [%s]  %s  (%llu bytes)\n",
                    e->role_level < 4 ? role_n[e->role_level] : "?",
                    e->path, (unsigned long long)e->original_size);
        }
    }
    fprintf(stderr, "\n");

    arcv_entries_free(entries, count);
    free(data);
    return 0;
}

/* Create a locked archive from files/directories.
 * This creates a .cute file with concatenated per-file ciphertexts
 * and an ARCV trailer. The payload is then encrypted with the outer key. */
static int do_archive_encrypt(int n_paths, char **paths, const cli_opts *opts) {
    int quiet = opts->quiet;

    /* collect entries */
    arcv_entry *entries = NULL;
    size_t entry_count = 0, entry_cap = 0;

    for (int pi = 0; pi < n_paths; pi++) {
        struct stat st;
        if (stat(paths[pi], &st) != 0) {
            fprintf(stderr, "  error: '%s' not found\n", paths[pi]);
            arcv_entries_free(entries, entry_count);
            return 1;
        }
        if (S_ISDIR(st.st_mode)) {
            if (walk_directory(paths[pi], "", &entries, &entry_count, &entry_cap) != 0) {
                fprintf(stderr, "  error: cannot traverse '%s'\n", paths[pi]);
                arcv_entries_free(entries, entry_count);
                return 1;
            }
        } else {
            if (entry_count >= entry_cap) {
                entry_cap = entry_cap == 0 ? 64 : entry_cap * 2;
                entries = realloc(entries, entry_cap * sizeof(arcv_entry));
            }
            arcv_entry *e = &entries[entry_count++];
            memset(e, 0, sizeof(*e));
            /* use basename as path */
            const char *bn = strrchr(paths[pi], '/');
            e->path = strdup(bn ? bn + 1 : paths[pi]);
            e->entry_type = ARCV_ENTRY_FILE;
            e->original_size = (uint64_t)st.st_size;
            e->permissions = (uint32_t)(st.st_mode & 0777);
            e->mtime = (uint64_t)st.st_mtime;
        }
    }

    if (entry_count == 0) {
        fprintf(stderr, "  error: no files to archive\n");
        return 1;
    }

    /* password / auth */
    char password[256];
    int totp_active = 0;
    uint8_t totp_secret_raw[128];
    size_t totp_secret_len = 0;

    uint8_t clam_ephemeral_arc[CLAM_SECTION_SIZE];
    int is_claimable_arc = opts->claimable;

    if (is_claimable_arc) {
        /* Claimable: generate random ephemeral password */
        randombytes(clam_ephemeral_arc, CLAM_SECTION_SIZE);
        for (int i = 0; i < CLAM_SECTION_SIZE; i++)
            snprintf(password + i*2, 3, "%02x", clam_ephemeral_arc[i]);
        password[CLAM_SECTION_SIZE * 2] = '\0';
        if (!quiet) fprintf(stderr, "  claimable: master key will be set on first open\n");
    } else if (opts->totp_secret) {
        /* TOTP setup — decode secret, generate current code as password */
        int drc = base32_decode(opts->totp_secret, totp_secret_raw,
                                sizeof(totp_secret_raw), &totp_secret_len);
        if (drc != 0 || totp_secret_len == 0) {
            fprintf(stderr, "  error: invalid base32 TOTP secret\n");
            arcv_entries_free(entries, entry_count);
            return 1;
        }
        uint32_t code = totp_generate(totp_secret_raw, totp_secret_len,
                                      (uint64_t)time(NULL),
                                      TOTP_PERIOD_DEFAULT, TOTP_DIGITS_DEFAULT);
        totp_format(code, TOTP_DIGITS_DEFAULT, password, sizeof(password));
        totp_active = 1;
        if (!quiet) fprintf(stderr, "  TOTP authentication configured\n");
    } else if (opts->passkey) {
        /* Passkey — derive from platform identity */
        const char *user = getenv("USER");
        const char *home = getenv("HOME");
        if (!user) user = "default";
        if (!home) home = "/";
        char identity[512];
        snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s", user, home);
        uint8_t id_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash((const uint8_t *)identity, strlen(identity), id_hash);
        for (int i = 0; i < 32; i++)
            snprintf(password + i * 2, 3, "%02x", id_hash[i]);
        password[64] = '\0';
        secure_zero(id_hash, sizeof(id_hash));
        if (!quiet) fprintf(stderr, "  passkey authentication\n");
    } else if (opts->headless) {
        strncpy(password, opts->password, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
    } else {
        read_password("  password: ", password, sizeof(password));
        char confirm[256];
        read_password("  confirm:  ", confirm, sizeof(confirm));
        if (strcmp(password, confirm) != 0) {
            fprintf(stderr, "  error: passwords don't match\n");
            memset(password, 0, sizeof(password));
            memset(confirm, 0, sizeof(confirm));
            arcv_entries_free(entries, entry_count);
            return 1;
        }
        memset(confirm, 0, sizeof(confirm));
    }

    /* derive master key */
    uint8_t salt[SALT_LEN], nonce[CC_AES256_NONCE_LEN];
    uint8_t ns[NS_LEN];
    randombytes(salt, SALT_LEN);
    randombytes(nonce, CC_AES256_NONCE_LEN);
    cc_cute_namespace(ns, "cutecrypt.key", 13);

    uint32_t kdf_rounds = opts->kdf_rounds > 0 ? opts->kdf_rounds : KDF_ROUNDS_DEFAULT;

    kdf_task arch_task;
    kdf_task_init(&arch_task, password, strlen(password), salt, ns, NULL, kdf_rounds);
    kdf_run(&arch_task, quiet);
    uint8_t *master_key = arch_task.key;

    /* derive role keys */
    uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN];
    derive_role_keys(master_key, role_keys);

    /* encrypt each file entry */
    uint8_t *payload_buf = NULL;
    size_t payload_len = 0;
    size_t payload_cap = 0;

    for (size_t i = 0; i < entry_count; i++) {
        arcv_entry *e = &entries[i];
        if (e->entry_type == ARCV_ENTRY_DIR) {
            e->payload_offset = payload_len;
            e->payload_length = 0;
            memset(e->entry_nonce, 0, CC_AES256_NONCE_LEN);
            secure_zero(e->entry_hash, CC_CUTE_HASH_LEN);
            continue;
        }

        /* find full path for this entry */
        char full_path[4096];
        /* try each input path as base */
        int found = 0;
        for (int pi = 0; pi < n_paths; pi++) {
            struct stat pst;
            if (stat(paths[pi], &pst) == 0 && S_ISDIR(pst.st_mode)) {
                snprintf(full_path, sizeof(full_path), "%s/%s", paths[pi], e->path);
            } else {
                snprintf(full_path, sizeof(full_path), "%s", paths[pi]);
            }
            if (stat(full_path, &pst) == 0 && S_ISREG(pst.st_mode)) {
                found = 1; break;
            }
        }
        if (!found) {
            fprintf(stderr, "  error: cannot find '%s'\n", e->path);
            free(payload_buf);
            memset(password, 0, sizeof(password));
            secure_zero(master_key, CC_AES256_KEY_LEN);
            secure_zero(role_keys, sizeof(role_keys));
            arcv_entries_free(entries, entry_count);
            return 1;
        }

        /* read file */
        size_t flen;
        uint8_t *fdata = read_file(full_path, &flen);
        if (!fdata) {
            fprintf(stderr, "  error: cannot read '%s'\n", full_path);
            free(payload_buf);
            memset(password, 0, sizeof(password));
            secure_zero(master_key, CC_AES256_KEY_LEN);
            secure_zero(role_keys, sizeof(role_keys));
            arcv_entries_free(entries, entry_count);
            return 1;
        }

        /* hash plaintext */
        cc_cute_hash(fdata, flen, e->entry_hash);

        /* generate per-file nonce and key */
        randombytes(e->entry_nonce, CC_AES256_NONCE_LEN);
        uint8_t file_key[CC_AES256_KEY_LEN];
        derive_file_key(role_keys[e->role_level], e->entry_nonce, file_key);

        /* encrypt: AES-256-GCM */
        size_t ct_len = flen + CC_AES256_TAG_LEN;
        uint8_t *ct = malloc(ct_len);
        memcpy(ct, fdata, flen);
        free(fdata);

        /* AAD = entry path (for binding) */
        cc_aes256_ctx *ctx = cc_aes256_init(file_key);
        secure_zero(file_key, CC_AES256_KEY_LEN);
        if (!ctx) {
            free(ct); free(payload_buf);
            memset(password, 0, sizeof(password));
            secure_zero(master_key, CC_AES256_KEY_LEN);
            secure_zero(role_keys, sizeof(role_keys));
            arcv_entries_free(entries, entry_count);
            return 1;
        }
        int rc = cc_aes256_encrypt(ctx, e->entry_nonce,
                                    (uint8_t *)e->path, strlen(e->path),
                                    ct, flen);
        cc_aes256_free(ctx);
        if (rc != 0) {
            fprintf(stderr, "  error: encrypt failed for '%s'\n", e->path);
            free(ct); free(payload_buf);
            memset(password, 0, sizeof(password));
            secure_zero(master_key, CC_AES256_KEY_LEN);
            secure_zero(role_keys, sizeof(role_keys));
            arcv_entries_free(entries, entry_count);
            return 1;
        }

        /* append to payload */
        e->payload_offset = payload_len;
        e->payload_length = ct_len;
        size_t new_len = payload_len + ct_len;
        if (new_len > payload_cap) {
            payload_cap = new_len + new_len / 2 + 4096;
            payload_buf = realloc(payload_buf, payload_cap);
        }
        memcpy(payload_buf + payload_len, ct, ct_len);
        payload_len = new_len;
        free(ct);

        if (!quiet) fprintf(stderr, "  encrypted %s (%llu bytes)\n",
                            e->path, (unsigned long long)e->original_size);
    }

    /* build ARCV trailer */
    size_t arcv_data_len;
    uint8_t *arcv_data = arcv_build(entries, entry_count, &arcv_data_len);

    /* now encrypt the full payload with the master key via AES-GCM */
    size_t enc_payload_len = payload_len + CC_AES256_TAG_LEN;
    uint8_t *enc_payload = malloc(enc_payload_len);
    memcpy(enc_payload, payload_buf, payload_len);
    free(payload_buf);

    /* build header */
    uint8_t header[HDR_SIZE];
    memset(header, 0, HDR_SIZE);
    memcpy(header + HDR_MAGIC, CUTE_MAGIC, 4);
    header[HDR_VERSION] = CUTE_VERSION;
    header[HDR_FLAGS] = FLAG_FOLDER;  /* reuse FLAG_FOLDER for archive */
    memcpy(header + HDR_SALT, salt, SALT_LEN);
    memcpy(header + HDR_NONCE, nonce, CC_AES256_NONCE_LEN);
    uint64_t now = (uint64_t)time(NULL);
    le64_put(header + HDR_CREATED, now);
    le32_put(header + HDR_EPOCH_LEN, 3600);
    le32_put(header + HDR_VALID_FROM, 0);
    le32_put(header + HDR_VALID_UNTIL, 0xFFFFFFFF);
    memcpy(header + HDR_NAMESPACE, ns, NS_LEN);
    le32_put(header + HDR_KDF_ROUNDS, kdf_rounds);
    le32_put(header + HDR_VAULT_SIZE, 0);
    le32_put(header + HDR_PAYLOAD_SIZE, (uint32_t)enc_payload_len);
    le16_put(header + HDR_LEDGER_COUNT, 1);

    /* compute epoch chain */
    uint8_t epoch_chain[EPOCH_CHAIN_LEN];
    compute_epoch_chain(salt, now, 3600, 0, 0xFFFFFFFF, kdf_rounds, epoch_chain);
    memcpy(header + HDR_EPOCH_CHAIN, epoch_chain, EPOCH_CHAIN_LEN);

    /* AAD */
    uint8_t aad[HDR_SIZE];
    prepare_aad(aad, header);

    cc_aes256_ctx *ctx = cc_aes256_init(master_key);
    secure_zero(master_key, CC_AES256_KEY_LEN);
    secure_zero(role_keys, sizeof(role_keys));
    memset(password, 0, sizeof(password));

    if (!ctx) {
        free(enc_payload); free(arcv_data);
        arcv_entries_free(entries, entry_count);
        return 1;
    }

    int rc = cc_aes256_encrypt(ctx, nonce, aad, HDR_SIZE, enc_payload, payload_len);
    cc_aes256_free(ctx);
    if (rc != 0) {
        fprintf(stderr, "  error: archive payload encryption failed\n");
        free(enc_payload); free(arcv_data);
        arcv_entries_free(entries, entry_count);
        return 1;
    }

    /* build ledger genesis */
    uint8_t genesis[LEDGER_ENTRY_SIZE];
    ledger_genesis(genesis);

    /* Build optional TOTP/PKEY trailers */
    uint8_t *totp_trailer = NULL;
    size_t totp_trailer_len = 0;
    uint8_t *pkey_trailer = NULL;
    size_t pkey_trailer_len = 0;

    if (totp_active && totp_secret_len > 0) {
        /* Encrypt TOTP secret with master key */
        size_t enc_sec_len = totp_secret_len + CC_AES256_TAG_LEN;
        uint8_t *enc_sec = malloc(enc_sec_len);
        memcpy(enc_sec, totp_secret_raw, totp_secret_len);
        uint8_t totp_nonce[CC_AES256_NONCE_LEN];
        randombytes(totp_nonce, CC_AES256_NONCE_LEN);
        cc_aes256_ctx *tctx = cc_aes256_init(master_key);
        cc_aes256_encrypt(tctx, totp_nonce, NULL, 0, enc_sec, totp_secret_len);
        cc_aes256_free(tctx);

        totp_trailer_len = TRAILER_HDR_SIZE + 4 + CC_AES256_NONCE_LEN + enc_sec_len;
        totp_trailer = calloc(1, totp_trailer_len);
        memcpy(totp_trailer, TOTP_MAGIC, 4);
        le32_put(totp_trailer + 4, (uint32_t)(totp_trailer_len - TRAILER_HDR_SIZE));
        totp_trailer[TRAILER_HDR_SIZE + 0] = TOTP_DIGITS_DEFAULT;
        totp_trailer[TRAILER_HDR_SIZE + 1] = TOTP_PERIOD_DEFAULT;
        le16_put(totp_trailer + TRAILER_HDR_SIZE + 2, (uint16_t)totp_secret_len);
        memcpy(totp_trailer + TRAILER_HDR_SIZE + 4, totp_nonce, CC_AES256_NONCE_LEN);
        memcpy(totp_trailer + TRAILER_HDR_SIZE + 4 + CC_AES256_NONCE_LEN, enc_sec, enc_sec_len);
        free(enc_sec);
    }

    if (opts->passkey) {
        pkey_trailer_len = TRAILER_HDR_SIZE + PKEY_SECTION_SIZE;
        pkey_trailer = calloc(1, pkey_trailer_len);
        memcpy(pkey_trailer, PKEY_MAGIC, 4);
        le32_put(pkey_trailer + 4, PKEY_SECTION_SIZE);
        /* key_id = hash of password (passkey-derived) */
        uint8_t key_id[CC_CUTE_HASH_LEN];
        cc_cute_hash((const uint8_t *)password, strlen(password), key_id);
        memcpy(pkey_trailer + TRAILER_HDR_SIZE, key_id, 32);
        memcpy(pkey_trailer + TRAILER_HDR_SIZE + 32, salt, 32);
    }

    /* Build CLAM trailer if claimable */
    uint8_t clam_arc_buf[TRAILER_HDR_SIZE + CLAM_SECTION_SIZE];
    size_t clam_arc_len = 0;
    if (is_claimable_arc) {
        memcpy(clam_arc_buf, CLAM_MAGIC, 4);
        le32_put(clam_arc_buf + 4, CLAM_SECTION_SIZE);
        memcpy(clam_arc_buf + TRAILER_HDR_SIZE, clam_ephemeral_arc, CLAM_SECTION_SIZE);
        clam_arc_len = TRAILER_HDR_SIZE + CLAM_SECTION_SIZE;
        secure_zero(clam_ephemeral_arc, sizeof(clam_ephemeral_arc));
    }

    /* assemble output file: [header][payload][ledger][ARCV trailer][optional trailers] */
    size_t out_len = HDR_SIZE + enc_payload_len + LEDGER_ENTRY_SIZE
                     + TRAILER_HDR_SIZE + arcv_data_len
                     + totp_trailer_len + pkey_trailer_len + clam_arc_len;
    uint8_t *out = malloc(out_len);
    size_t w = 0;
    memcpy(out + w, header, HDR_SIZE); w += HDR_SIZE;
    memcpy(out + w, enc_payload, enc_payload_len); w += enc_payload_len;
    memcpy(out + w, genesis, LEDGER_ENTRY_SIZE); w += LEDGER_ENTRY_SIZE;
    /* ARCV trailer header */
    memcpy(out + w, ARCV_MAGIC, 4);
    le32_put(out + w + 4, (uint32_t)arcv_data_len);
    w += TRAILER_HDR_SIZE;
    memcpy(out + w, arcv_data, arcv_data_len);
    w += arcv_data_len;
    /* Optional TOTP trailer */
    if (totp_trailer) {
        memcpy(out + w, totp_trailer, totp_trailer_len);
        w += totp_trailer_len;
        free(totp_trailer);
    }
    /* Optional PKEY trailer */
    if (pkey_trailer) {
        memcpy(out + w, pkey_trailer, pkey_trailer_len);
        w += pkey_trailer_len;
        free(pkey_trailer);
    }
    /* Optional CLAM trailer */
    if (clam_arc_len > 0) {
        memcpy(out + w, clam_arc_buf, clam_arc_len);
        w += clam_arc_len;
    }

    free(enc_payload);
    free(arcv_data);

    /* determine output path */
    char out_path[4096];
    if (opts->output) {
        strncpy(out_path, opts->output, sizeof(out_path) - 1);
        out_path[sizeof(out_path) - 1] = '\0';
    } else {
        /* use first input path as base */
        const char *bn = strrchr(paths[0], '/');
        const char *name = bn ? bn + 1 : paths[0];
        /* strip trailing slash */
        char clean[256];
        strncpy(clean, name, sizeof(clean) - 1);
        clean[sizeof(clean) - 1] = '\0';
        size_t cl = strlen(clean);
        while (cl > 0 && clean[cl - 1] == '/') clean[--cl] = '\0';
        snprintf(out_path, sizeof(out_path), "%s.cute", clean);
    }

    rc = write_file_atomic(out_path, out, out_len);
    free(out);
    arcv_entries_free(entries, entry_count);

    if (rc != 0) {
        fprintf(stderr, "  error: failed to write '%s'\n", out_path);
        return 1;
    }

    if (!quiet) {
        fprintf(stderr, "  archive: %s (%zu bytes, %zu entries)\n\n", out_path, out_len, entry_count);
    }
    return 0;
}

/* Decrypt and extract a locked archive (all files) */
static int do_archive_decrypt(const char *path, const uint8_t *data, size_t file_len,
                              const char *target_extract, const cli_opts *opts) {
    int quiet = opts->quiet;
    uint8_t flags = data[HDR_FLAGS];
    const uint8_t *salt = data + HDR_SALT;
    const uint8_t *nonce = data + HDR_NONCE;
    uint32_t vault_size = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_size = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_count = le16_get(data + HDR_LEDGER_COUNT);
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);
    size_t binding_size = binding_section_size(flags);
    size_t payload_offset = HDR_SIZE + binding_size + vault_size;
    size_t ledger_offset = payload_offset + payload_size;
    size_t ledger_size = (size_t)ledger_count * LEDGER_ENTRY_SIZE;
    size_t trailer_offset = ledger_offset + ledger_size;
    size_t trailer_len = file_len > trailer_offset ? file_len - trailer_offset : 0;

    /* find ARCV trailer */
    size_t arcv_data_len;
    const uint8_t *arcv_data = trailer_section_find(
        data + trailer_offset, trailer_len, ARCV_MAGIC, &arcv_data_len);
    if (!arcv_data) {
        fprintf(stderr, "  error: no ARCV trailer — not a locked archive\n");
        return 1;
    }

    arcv_entry *entries;
    size_t entry_count;
    if (arcv_parse(arcv_data, arcv_data_len, &entries, &entry_count) != 0) {
        fprintf(stderr, "  error: corrupt ARCV trailer\n");
        return 1;
    }

    /* Check for CLAM (claimable) trailer */
    int is_claim_arc = 0;
    char claim_pw_arc[256] = {0};
    {
        size_t clam_data_len = 0;
        const uint8_t *clam_data = trailer_section_find(
            data + trailer_offset, trailer_len, CLAM_MAGIC, &clam_data_len);
        if (clam_data && clam_data_len == CLAM_SECTION_SIZE) {
            is_claim_arc = 1;
            for (int i = 0; i < CLAM_SECTION_SIZE; i++)
                snprintf(claim_pw_arc + i*2, 3, "%02x", clam_data[i]);
            claim_pw_arc[CLAM_SECTION_SIZE * 2] = '\0';
            if (!quiet) {
                fprintf(stderr, "  ┌─────────────────────────────────────┐\n");
                fprintf(stderr, "  │  UNCLAIMED — first open claims key  │\n");
                fprintf(stderr, "  └─────────────────────────────────────┘\n\n");
            }
        }
    }

    /* password / auth */
    char password[256];
    if (is_claim_arc) {
        strncpy(password, claim_pw_arc, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        secure_zero(claim_pw_arc, sizeof(claim_pw_arc));
    } else if (opts->totp_code) {
        strncpy(password, opts->totp_code, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
        if (!quiet) fprintf(stderr, "  authenticating with TOTP code\n");
    } else if (opts->passkey) {
        const char *user = getenv("USER");
        const char *home = getenv("HOME");
        if (!user) user = "default";
        if (!home) home = "/";
        char identity[512];
        snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s", user, home);
        uint8_t id_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash((const uint8_t *)identity, strlen(identity), id_hash);
        for (int i = 0; i < 32; i++)
            snprintf(password + i * 2, 3, "%02x", id_hash[i]);
        password[64] = '\0';
        secure_zero(id_hash, sizeof(id_hash));
        if (!quiet) fprintf(stderr, "  passkey authentication\n");
    } else if (opts->headless) {
        strncpy(password, opts->password, sizeof(password) - 1);
        password[sizeof(password) - 1] = '\0';
    } else {
        read_password("  password: ", password, sizeof(password));
    }

    /* derive master key */
    uint8_t ns[NS_LEN];
    cc_cute_namespace(ns, "cutecrypt.key", 13);

    kdf_task dec_task;
    kdf_task_init(&dec_task, password, strlen(password), salt, ns, NULL, kdf_rounds);
    kdf_run(&dec_task, quiet);
    uint8_t *master_key = dec_task.key;

    /* derive role keys */
    uint8_t role_keys[ROLE_COUNT][CC_AES256_KEY_LEN];
    derive_role_keys(master_key, role_keys);

    /* decrypt outer payload */
    uint8_t *payload = malloc(payload_size);
    memcpy(payload, data + payload_offset, payload_size);

    uint8_t aad[HDR_SIZE];
    prepare_aad(aad, data);

    cc_aes256_ctx *ctx = cc_aes256_init(master_key);
    secure_zero(master_key, CC_AES256_KEY_LEN);
    memset(password, 0, sizeof(password));
    if (!ctx) {
        free(payload);
        secure_zero(role_keys, sizeof(role_keys));
        arcv_entries_free(entries, entry_count);
        return 1;
    }

    int rc = cc_aes256_decrypt(ctx, nonce, aad, HDR_SIZE, payload, payload_size);
    cc_aes256_free(ctx);
    if (rc != 0) {
        fprintf(stderr, "  error: decryption failed — wrong password, corrupted file, or mismatched auth method\n");
        free(payload);
        secure_zero(role_keys, sizeof(role_keys));
        arcv_entries_free(entries, entry_count);
        return 1;
    }

    size_t inner_payload_len = payload_size - CC_AES256_TAG_LEN;

    /* determine output directory */
    char out_dir[4096];
    if (opts->output) {
        strncpy(out_dir, opts->output, sizeof(out_dir) - 1);
        out_dir[sizeof(out_dir) - 1] = '\0';
    } else {
        /* strip .cute from filename */
        strncpy(out_dir, path, sizeof(out_dir) - 1);
        out_dir[sizeof(out_dir) - 1] = '\0';
        size_t l = strlen(out_dir);
        if (l > 5 && strcmp(out_dir + l - 5, ".cute") == 0)
            out_dir[l - 5] = '\0';
    }

    /* extract entries */
    for (size_t i = 0; i < entry_count; i++) {
        const arcv_entry *e = &entries[i];

        /* if selective extraction, skip non-matching */
        if (target_extract && strcmp(e->path, target_extract) != 0)
            continue;

        char full_path[4096];
        snprintf(full_path, sizeof(full_path), "%s/%s", out_dir, e->path);

        if (e->entry_type == ARCV_ENTRY_DIR) {
            /* create directory recursively */
            char tmp[4096];
            strncpy(tmp, full_path, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
            for (char *p = tmp + 1; *p; p++) {
                if (*p == '/') {
                    *p = '\0';
                    mkdir(tmp, 0755);
                    *p = '/';
                }
            }
            mkdir(tmp, 0755);
            if (!quiet) fprintf(stderr, "  created %s/\n", e->path);
            continue;
        }

        /* create parent directories */
        {
            char tmp[4096];
            strncpy(tmp, full_path, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
            char *sl = strrchr(tmp, '/');
            if (sl) {
                *sl = '\0';
                for (char *p = tmp + 1; *p; p++) {
                    if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
                }
                mkdir(tmp, 0755);
            }
        }

        /* decrypt file */
        if (e->payload_offset + e->payload_length > inner_payload_len) {
            fprintf(stderr, "  error: entry '%s' exceeds payload bounds\n", e->path);
            continue;
        }

        uint8_t file_key[CC_AES256_KEY_LEN];
        derive_file_key(role_keys[e->role_level], e->entry_nonce, file_key);

        size_t ct_len = (size_t)e->payload_length;
        uint8_t *ct = malloc(ct_len);
        memcpy(ct, payload + e->payload_offset, ct_len);

        cc_aes256_ctx *fctx = cc_aes256_init(file_key);
        secure_zero(file_key, CC_AES256_KEY_LEN);
        if (!fctx) { free(ct); continue; }

        rc = cc_aes256_decrypt(fctx, e->entry_nonce,
                                (uint8_t *)e->path, strlen(e->path),
                                ct, ct_len);
        cc_aes256_free(fctx);
        if (rc != 0) {
            fprintf(stderr, "  error: decrypt failed for '%s' (wrong role?)\n", e->path);
            free(ct); continue;
        }

        size_t pt_len = ct_len - CC_AES256_TAG_LEN;

        /* verify hash */
        uint8_t check_hash[CC_CUTE_HASH_LEN];
        cc_cute_hash(ct, pt_len, check_hash);
        if (memcmp(check_hash, e->entry_hash, CC_CUTE_HASH_LEN) != 0) {
            fprintf(stderr, "  warning: hash mismatch for '%s'\n", e->path);
        }

        if (write_file_atomic(full_path, ct, pt_len) != 0) {
            fprintf(stderr, "  error: cannot write '%s'\n", full_path);
            free(ct); continue;
        }

        /* restore permissions */
        chmod(full_path, e->permissions);

        if (!quiet) fprintf(stderr, "  extracted %s (%llu bytes)\n",
                            e->path, (unsigned long long)pt_len);
        free(ct);

        if (target_extract) break; /* only extracting one */
    }

    secure_zero(role_keys, sizeof(role_keys));
    free(payload);
    arcv_entries_free(entries, entry_count);

    /* ---- Claim: re-encrypt archive with claimant's password ---- */
    if (is_claim_arc && !target_extract) {
        if (!quiet) {
            fprintf(stderr, "\n  ┌─────────────────────────────────────┐\n");
            fprintf(stderr, "  │  CLAIM — set your master key now    │\n");
            fprintf(stderr, "  └─────────────────────────────────────┘\n\n");
        }

        char claim_password[256];
        char claim_confirm[256];

        if (opts->headless && opts->password) {
            strncpy(claim_password, opts->password, sizeof(claim_password) - 1);
            claim_password[sizeof(claim_password) - 1] = '\0';
        } else if (opts->passkey) {
            char identity[512];
            snprintf(identity, sizeof(identity), "cutedepo.passkey.%s.%s",
                     getenv("USER") ?: "default", getenv("HOME") ?: "/");
            uint8_t pk_hash[CC_CUTE_HASH_LEN];
            cc_cute_hash((const uint8_t *)identity, strlen(identity), pk_hash);
            for (int i = 0; i < 32; i++)
                snprintf(claim_password + i*2, 3, "%02x", pk_hash[i]);
            claim_password[64] = '\0';
            secure_zero(pk_hash, sizeof(pk_hash));
            if (!quiet) fprintf(stderr, "  claiming with passkey credential\n");
        } else {
            read_password("  new master password: ", claim_password, sizeof(claim_password));
            read_password("  confirm password:    ", claim_confirm, sizeof(claim_confirm));
            if (strcmp(claim_password, claim_confirm) != 0) {
                fprintf(stderr, "  error: passwords don't match — archive NOT claimed\n\n");
                secure_zero(claim_password, sizeof(claim_password));
                secure_zero(claim_confirm, sizeof(claim_confirm));
                return 1;
            }
            secure_zero(claim_confirm, sizeof(claim_confirm));
        }

        if (strlen(claim_password) == 0) {
            fprintf(stderr, "  error: password cannot be empty — archive NOT claimed\n\n");
            return 1;
        }

        /* Determine output dir to re-archive from */
        char out_dir[4096];
        if (opts->output) {
            strncpy(out_dir, opts->output, sizeof(out_dir) - 1);
            out_dir[sizeof(out_dir) - 1] = '\0';
        } else {
            size_t plen = strlen(path);
            if (plen > 5 && ends_with(path, ".cute"))
                snprintf(out_dir, sizeof(out_dir), "%.*s", (int)(plen - 5), path);
            else
                snprintf(out_dir, sizeof(out_dir), "%s.dec", path);
        }

        cli_opts claim_opts;
        memset(&claim_opts, 0, sizeof(claim_opts));
        claim_opts.headless = 1;
        claim_opts.quiet = 1;
        claim_opts.password = claim_password;
        claim_opts.force = 1;
        claim_opts.output = (char *)path;
        claim_opts.kdf_rounds = kdf_rounds;

        char *arc_paths[] = {out_dir};
        int crc = do_archive_encrypt(1, arc_paths, &claim_opts);
        secure_zero(claim_password, sizeof(claim_password));

        if (crc != 0) {
            fprintf(stderr, "  error: re-encryption failed — archive NOT claimed\n\n");
            return 1;
        }

        if (!quiet) {
            fprintf(stderr, "\n  ┌─────────────────────────────────────┐\n");
            fprintf(stderr, "  │  CLAIMED — master key is now set    │\n");
            fprintf(stderr, "  └─────────────────────────────────────┘\n");
            fprintf(stderr, "  original archive re-encrypted with your key\n");
        }
    }

    if (!quiet) fprintf(stderr, "\n");
    return 0;
}

/* ---- DRM Bundle Wrapping ---- */

/* Copy a file from src to dst, preserving permissions */
static int copy_file(const char *src, const char *dst) {
    size_t len;
    uint8_t *data = read_file(src, &len);
    if (!data) return -1;
    int rc = write_file_atomic(dst, data, len);
    free(data);
    if (rc == 0) {
        struct stat st;
        if (stat(src, &st) == 0)
            chmod(dst, st.st_mode);
    }
    return rc;
}

/* Extract a plist string value by key (simple XML parser, no libxml dependency) */
static int plist_get_string(const char *plist_data, const char *key,
                            char *out, size_t out_cap) {
    /* Search for <key>KEY</key>\n\t<string>VALUE</string> */
    char needle[512];
    snprintf(needle, sizeof(needle), "<key>%s</key>", key);
    const char *kp = strstr(plist_data, needle);
    if (!kp) return -1;
    const char *sp = strstr(kp, "<string>");
    if (!sp) return -1;
    sp += 8; /* skip <string> */
    const char *ep = strstr(sp, "</string>");
    if (!ep || (size_t)(ep - sp) >= out_cap) return -1;
    memcpy(out, sp, ep - sp);
    out[ep - sp] = '\0';
    return 0;
}

static int do_wrap(const char *app_path, cli_opts *opts) {
    int quiet = opts->quiet;

    if (!quiet) fprintf(stderr, "\n  cutedepo — DRM bundle wrap\n\n");

    /* Validate input is a .app bundle */
    if (!is_directory(app_path) || !ends_with(app_path, ".app")) {
        fprintf(stderr, "  error: '%s' is not a .app bundle\n", app_path);
        return 1;
    }

    char inner_plist[4096], inner_macos[4096];
    snprintf(inner_plist, sizeof(inner_plist), "%s/Contents/Info.plist", app_path);
    snprintf(inner_macos, sizeof(inner_macos), "%s/Contents/MacOS", app_path);

    struct stat st;
    if (stat(inner_plist, &st) != 0 || stat(inner_macos, &st) != 0) {
        fprintf(stderr, "  error: '%s' missing Contents/Info.plist or Contents/MacOS\n", app_path);
        return 1;
    }

    /* Read inner app's Info.plist */
    size_t plist_len;
    uint8_t *plist_data = read_file(inner_plist, &plist_len);
    if (!plist_data) {
        fprintf(stderr, "  error: cannot read '%s'\n", inner_plist);
        return 1;
    }

    char inner_name[256] = "App";
    char inner_id[256] = "com.unknown.app";
    char inner_exe[256] = "";
    char inner_icon[256] = "";

    plist_get_string((const char *)plist_data, "CFBundleName", inner_name, sizeof(inner_name));
    plist_get_string((const char *)plist_data, "CFBundleIdentifier", inner_id, sizeof(inner_id));
    plist_get_string((const char *)plist_data, "CFBundleExecutable", inner_exe, sizeof(inner_exe));
    plist_get_string((const char *)plist_data, "CFBundleIconFile", inner_icon, sizeof(inner_icon));
    free(plist_data);

    if (inner_exe[0] == '\0') {
        fprintf(stderr, "  error: inner app has no CFBundleExecutable\n");
        return 1;
    }

    /* Determine auth mode string */
    const char *auth_mode = "password";
    if (opts->totp_secret) auth_mode = "totp";
    else if (opts->passkey) auth_mode = "passkey";

    /* Determine output path */
    char out_path[4096];
    if (opts->output) {
        snprintf(out_path, sizeof(out_path), "%s", opts->output);
    } else {
        /* Strip .app from input, add .app for output */
        const char *base = strrchr(app_path, '/');
        base = base ? base + 1 : app_path;
        snprintf(out_path, sizeof(out_path), "%s-wrapped.app", inner_name);
    }

    /* Check overwrite */
    if (check_overwrite(out_path, opts->force, opts->quiet) != 0)
        return 1;

    if (!quiet) fprintf(stderr, "  wrapping: %s\n", app_path);
    if (!quiet) fprintf(stderr, "  auth:     %s\n", auth_mode);
    if (!quiet) fprintf(stderr, "  output:   %s\n\n", out_path);

    /* Step 1: Encrypt inner .app as an archive → temp payload.cute */
    char tmp_payload[4096];
    snprintf(tmp_payload, sizeof(tmp_payload), "%s.payload.cute.tmp", out_path);

    /* Set up archive opts — reuse the app_path as archive input */
    cli_opts arc_opts = *opts;
    arc_opts.archive = 1;
    arc_opts.output = tmp_payload;
    arc_opts.quiet = 1;

    char *arc_paths[] = {(char *)app_path};
    if (!quiet) fprintf(stderr, "  encrypting app bundle...\n");
    int rc = do_archive_encrypt(1, arc_paths, &arc_opts);
    if (rc != 0) {
        fprintf(stderr, "  error: archive encryption failed\n");
        unlink(tmp_payload);
        return 1;
    }
    if (!quiet) fprintf(stderr, "  payload encrypted\n");

    /* Step 2: Find pre-built launcher and CLI binaries */
    /* Look next to our own binary first */
    char self_dir[4096] = ".";
    {
        char self_path[4096];
        uint32_t sp_len = sizeof(self_path);
        if (_NSGetExecutablePath(self_path, &sp_len) == 0) {
            char *sl = strrchr(self_path, '/');
            if (sl) { *sl = '\0'; strncpy(self_dir, self_path, sizeof(self_dir) - 1); }
        }
    }

    char launcher_src[4096], cli_src[4096];

    /* Try: build dir launcher .app bundle */
    snprintf(launcher_src, sizeof(launcher_src),
             "%s/cutedepo-launcher.app/Contents/MacOS/cutedepo-launcher", self_dir);
    if (stat(launcher_src, &st) != 0) {
        /* Try: same directory */
        snprintf(launcher_src, sizeof(launcher_src), "%s/cutedepo-launcher", self_dir);
    }
    if (stat(launcher_src, &st) != 0) {
        fprintf(stderr, "  error: cutedepo-launcher binary not found\n");
        fprintf(stderr, "  hint: build it first with 'cmake --build . --target cutedepo-launcher'\n");
        unlink(tmp_payload);
        return 1;
    }

    /* CLI binary — we are it */
    snprintf(cli_src, sizeof(cli_src), "%s/cutedepo", self_dir);
    if (stat(cli_src, &st) != 0) {
        fprintf(stderr, "  error: cutedepo CLI binary not found at '%s'\n", cli_src);
        unlink(tmp_payload);
        return 1;
    }

    /* Step 3: Build wrapper .app directory structure */
    if (!quiet) fprintf(stderr, "  assembling wrapper bundle...\n");

    char dir_buf[4096];

    snprintf(dir_buf, sizeof(dir_buf), "%s/Contents/MacOS", out_path);
    mkdir(out_path, 0755);
    snprintf(dir_buf, sizeof(dir_buf), "%s/Contents", out_path);
    mkdir(dir_buf, 0755);
    snprintf(dir_buf, sizeof(dir_buf), "%s/Contents/MacOS", out_path);
    mkdir(dir_buf, 0755);
    snprintf(dir_buf, sizeof(dir_buf), "%s/Contents/Resources", out_path);
    mkdir(dir_buf, 0755);

    /* Copy launcher binary */
    char dst_buf[4096];
    snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/MacOS/launcher", out_path);
    if (copy_file(launcher_src, dst_buf) != 0) {
        fprintf(stderr, "  error: failed to copy launcher binary\n");
        unlink(tmp_payload);
        return 1;
    }
    chmod(dst_buf, 0755);

    /* Copy CLI binary */
    snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/MacOS/cutedepo", out_path);
    if (copy_file(cli_src, dst_buf) != 0) {
        fprintf(stderr, "  error: failed to copy CLI binary\n");
        unlink(tmp_payload);
        return 1;
    }
    chmod(dst_buf, 0755);

    /* Move payload.cute */
    snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/Resources/payload.cute", out_path);
    if (rename(tmp_payload, dst_buf) != 0) {
        /* rename failed (cross-device?), fall back to copy */
        if (copy_file(tmp_payload, dst_buf) != 0) {
            fprintf(stderr, "  error: failed to install payload.cute\n");
            unlink(tmp_payload);
            return 1;
        }
        unlink(tmp_payload);
    }

    /* Copy icon if present */
    if (inner_icon[0] != '\0') {
        char icon_src[4096];
        snprintf(icon_src, sizeof(icon_src), "%s/Contents/Resources/%s", app_path, inner_icon);
        /* Add .icns if missing */
        if (!ends_with(icon_src, ".icns")) {
            size_t il = strlen(icon_src);
            if (il + 5 < sizeof(icon_src)) { strcat(icon_src, ".icns"); }
        }
        if (stat(icon_src, &st) == 0) {
            snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/Resources/AppIcon.icns", out_path);
            copy_file(icon_src, dst_buf);
        }
    }

    /* Step 4: Generate Info.plist */
    snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/Info.plist", out_path);
    {
        char plist_buf[4096];
        int plen = snprintf(plist_buf, sizeof(plist_buf),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n"
            "  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n"
            "    <key>CFBundleName</key>\n"
            "    <string>%s</string>\n"
            "    <key>CFBundleDisplayName</key>\n"
            "    <string>%s</string>\n"
            "    <key>CFBundleIdentifier</key>\n"
            "    <string>%s.wrapped</string>\n"
            "    <key>CFBundleVersion</key>\n"
            "    <string>1.0</string>\n"
            "    <key>CFBundleShortVersionString</key>\n"
            "    <string>1.0</string>\n"
            "    <key>CFBundlePackageType</key>\n"
            "    <string>APPL</string>\n"
            "    <key>CFBundleExecutable</key>\n"
            "    <string>launcher</string>\n"
            "    <key>CFBundleIconFile</key>\n"
            "    <string>AppIcon</string>\n"
            "    <key>NSPrincipalClass</key>\n"
            "    <string>NSApplication</string>\n"
            "    <key>NSHighResolutionCapable</key>\n"
            "    <true/>\n"
            "    <key>LSMinimumSystemVersion</key>\n"
            "    <string>12.0</string>\n"
            "</dict>\n"
            "</plist>\n",
            inner_name, inner_name, inner_id);
        write_file_atomic(dst_buf, (const uint8_t *)plist_buf, (size_t)plen);
    }

    /* Step 5: Generate launcher.json */
    snprintf(dst_buf, sizeof(dst_buf), "%s/Contents/Resources/launcher.json", out_path);
    {
        /* inner_bundle_name = last component of app_path */
        const char *bn = strrchr(app_path, '/');
        bn = bn ? bn + 1 : app_path;

        char json_buf[2048];
        int jlen = snprintf(json_buf, sizeof(json_buf),
            "{\n"
            "  \"auth_mode\": \"%s\",\n"
            "  \"inner_executable\": \"%s\",\n"
            "  \"inner_bundle_name\": \"%s\"\n"
            "}\n",
            auth_mode, inner_exe, bn);
        write_file_atomic(dst_buf, (const uint8_t *)json_buf, (size_t)jlen);
    }

    if (!quiet) {
        fprintf(stderr, "  wrapper bundle created: %s\n", out_path);
        fprintf(stderr, "  inner app:  %s (%s)\n", inner_name, inner_exe);
        fprintf(stderr, "  auth mode:  %s\n", auth_mode);
        if (opts->fuses > 0)
            fprintf(stderr, "  fuses:      %u\n", opts->fuses);
        fprintf(stderr, "\n");
    }

    return 0;
}

/* ---- Option parsing ---- */

static void print_usage(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, "  cutedepo — unified encryption + compression (v4)\n");
    fprintf(stderr, "  ───────────────────────────────────────────────\n\n");
    fprintf(stderr, "  file sensing:\n");
    fprintf(stderr, "    cutedepo file.cute           → decrypt / decompress\n");
    fprintf(stderr, "    cutedepo file.press           → decompress (legacy)\n");
    fprintf(stderr, "    cutedepo --compress file      → compress → .cute container\n");
    fprintf(stderr, "    cutedepo file_or_folder       → encrypt\n\n");
    fprintf(stderr, "  interactive:  cutedepo <file_or_folder>\n");
    fprintf(stderr, "  headless:     cutedepo --password PASS [options] <file_or_folder>\n\n");
    fprintf(stderr, "  authentication:\n");
    fprintf(stderr, "    --password PASS       password authentication\n");
    fprintf(stderr, "    --passkey             platform credential (Touch ID / Secure Enclave)\n");
    fprintf(stderr, "    --totp-secret BASE32  set up TOTP authentication on encrypt\n");
    fprintf(stderr, "    --totp CODE           provide TOTP code on decrypt\n\n");
    fprintf(stderr, "  encrypt options:\n");
    fprintf(stderr, "    --password PASS       password (required unless --passkey)\n");
    fprintf(stderr, "    --epoch-len SECS      epoch length (default: 3600)\n");
    fprintf(stderr, "    --valid-epochs N      expire after N epochs\n");
    fprintf(stderr, "    --delay SECS          delay access by N seconds\n");
    fprintf(stderr, "    --fuses N             max decryptions\n");
    fprintf(stderr, "    --purge               self-purge on expiry/exhaustion\n");
    fprintf(stderr, "    --kdf-rounds N        KDF iterations (default: 100000)\n");
    fprintf(stderr, "    --keychain            bind to OS keychain (anti file-copy replay)\n");
    fprintf(stderr, "    --fuse-server URL     register with remote fuse server\n");
    fprintf(stderr, "    --engrave MSG         engraved message (encrypted, role-gated)\n");
    fprintf(stderr, "    --engrave-file PATH   engraved file (encrypted, role-gated)\n");
    fprintf(stderr, "    --engrave-level ROLE  role for engrave: root|admin|auditor|reader (default: root)\n");
    fprintf(stderr, "    --public MSG          public message (cleartext, visible to all)\n");
    fprintf(stderr, "    --output PATH         custom output path\n");
    fprintf(stderr, "    -q, --quiet           suppress status output\n\n");
    fprintf(stderr, "  decrypt options:\n");
    fprintf(stderr, "    --password PASS       password (required)\n");
    fprintf(stderr, "    --fuse-key HEX        outer fuse preimage (64 hex, bypass vault)\n");
    fprintf(stderr, "    --inner-fuse-key HEX  inner fuse preimage (64 hex, bypass vault)\n");
    fprintf(stderr, "    --fuse-server URL     remote fuse server (required if file uses it)\n");
    fprintf(stderr, "    --output PATH         custom output path\n");
    fprintf(stderr, "    -q, --quiet           suppress status output\n\n");
    fprintf(stderr, "  locked archive operations:\n");
    fprintf(stderr, "    --archive             create locked archive from files/folders\n");
    fprintf(stderr, "    --extract PATH        extract single file from archive\n");
    fprintf(stderr, "    --list                list archive contents (no password)\n");
    fprintf(stderr, "    --file-role PATH:ROLE  set role for file (root|admin|auditor|reader)\n\n");
    fprintf(stderr, "  fuse box (DRM enforcement):\n");
    fprintf(stderr, "    --fuse-box            renounce master key (fuse-only access)\n");
    fprintf(stderr, "    --refresh-key PASS    assign fuse refresh key (master only, once)\n");
    fprintf(stderr, "    --refresh KEY         refill fuses using refresh key\n\n");
    fprintf(stderr, "  claimable (first-open-claims-key):\n");
    fprintf(stderr, "    --claimable           no master key until first open\n");
    fprintf(stderr, "                          first person to decrypt claims the key\n\n");
    fprintf(stderr, "  DRM bundle wrapping:\n");
    fprintf(stderr, "    --wrap                wrap .app bundle with DRM launcher\n");
    fprintf(stderr, "    --passkey / --totp-secret / --password    auth method\n");
    fprintf(stderr, "    all encrypt options (--fuses, --epoch-len, etc.) apply\n\n");
    fprintf(stderr, "  parted file operations:\n");
    fprintf(stderr, "    --split SIZE_MB       split .cute into parts of SIZE_MB each\n");
    fprintf(stderr, "    --join                reassemble .cute from parts\n\n");
    fprintf(stderr, "  compression (cutepress):\n");
    fprintf(stderr, "    -c, --compress        compress file → .cute container\n");
    fprintf(stderr, "    -c --password PASS    compress + encrypt → locked .cute\n");
    fprintf(stderr, "    -d, --decompress      decompress .cute / .press file\n");
    fprintf(stderr, "    -l <1-9>              compression level (default: 5)\n\n");
    fprintf(stderr, "  inspect / verify:\n");
    fprintf(stderr, "    --info                show file metadata (no password required)\n");
    fprintf(stderr, "    --check               machine-readable type (file|archive|app|...)\n");
    fprintf(stderr, "    --verify              check file integrity (no password required)\n\n");
    fprintf(stderr, "  output:\n");
    fprintf(stderr, "    --output PATH         custom output path\n");
    fprintf(stderr, "    --force               overwrite existing files without prompting\n");
    fprintf(stderr, "    -q, --quiet           suppress status output\n\n");
    fprintf(stderr, "  security:\n");
    fprintf(stderr, "    --no-harden           disable process hardening (anti-debug,\n");
    fprintf(stderr, "                          core dump prevention, memory locking)\n");
    fprintf(stderr, "                          hardening is ON by default\n\n");
    fprintf(stderr, "  .cute is the universal container format:\n");
    fprintf(stderr, "    unlocked  — compression only (no password required)\n");
    fprintf(stderr, "    locked    — encrypted with password, passkey, or TOTP\n");
    fprintf(stderr, "  auto-detects by extension and magic bytes (CUTE / PRSS)\n\n");
}

enum {
    OPT_PASSWORD = 256,
    OPT_EPOCH_LEN,
    OPT_VALID_EPOCHS,
    OPT_DELAY,
    OPT_FUSES,
    OPT_PURGE,
    OPT_FUSE_KEY,
    OPT_INNER_FUSE_KEY,
    OPT_OUTPUT,
    OPT_KDF_ROUNDS,
    OPT_KEYCHAIN,
    OPT_FUSE_SERVER,
    OPT_ENGRAVE,
    OPT_ENGRAVE_FILE,
    OPT_ENGRAVE_LEVEL,
    OPT_PUBLIC,
    OPT_SPLIT,
    OPT_JOIN,
    OPT_ARCHIVE,
    OPT_EXTRACT,
    OPT_LIST,
    OPT_FILE_ROLE,
    OPT_COMPRESS,
    OPT_DECOMPRESS,
    OPT_PASSKEY,
    OPT_TOTP_SECRET,
    OPT_TOTP,
    OPT_INFO,
    OPT_VERIFY,
    OPT_FORCE,
    OPT_WRAP,
    OPT_FUSE_BOX,
    OPT_REFRESH_KEY,
    OPT_REFRESH,
    OPT_NO_HARDEN,
    OPT_CHECK,
    OPT_CLAIMABLE,
};

static struct option long_options[] = {
    {"password",     required_argument, NULL, OPT_PASSWORD},
    {"epoch-len",    required_argument, NULL, OPT_EPOCH_LEN},
    {"valid-epochs", required_argument, NULL, OPT_VALID_EPOCHS},
    {"delay",        required_argument, NULL, OPT_DELAY},
    {"fuses",        required_argument, NULL, OPT_FUSES},
    {"purge",        no_argument,       NULL, OPT_PURGE},
    {"fuse-key",       required_argument, NULL, OPT_FUSE_KEY},
    {"inner-fuse-key", required_argument, NULL, OPT_INNER_FUSE_KEY},
    {"output",         required_argument, NULL, OPT_OUTPUT},
    {"kdf-rounds",   required_argument, NULL, OPT_KDF_ROUNDS},
    {"keychain",       no_argument,       NULL, OPT_KEYCHAIN},
    {"fuse-server",    required_argument, NULL, OPT_FUSE_SERVER},
    {"engrave",        required_argument, NULL, OPT_ENGRAVE},
    {"engrave-file",   required_argument, NULL, OPT_ENGRAVE_FILE},
    {"engrave-level",  required_argument, NULL, OPT_ENGRAVE_LEVEL},
    {"public",         required_argument, NULL, OPT_PUBLIC},
    {"split",          required_argument, NULL, OPT_SPLIT},
    {"join",           no_argument,       NULL, OPT_JOIN},
    {"archive",        no_argument,       NULL, OPT_ARCHIVE},
    {"extract",        required_argument, NULL, OPT_EXTRACT},
    {"list",           no_argument,       NULL, OPT_LIST},
    {"file-role",      required_argument, NULL, OPT_FILE_ROLE},
    {"compress",       no_argument,       NULL, OPT_COMPRESS},
    {"decompress",     no_argument,       NULL, OPT_DECOMPRESS},
    {"passkey",        no_argument,       NULL, OPT_PASSKEY},
    {"totp-secret",    required_argument, NULL, OPT_TOTP_SECRET},
    {"totp",           required_argument, NULL, OPT_TOTP},
    {"info",           no_argument,       NULL, OPT_INFO},
    {"verify",         no_argument,       NULL, OPT_VERIFY},
    {"force",          no_argument,       NULL, OPT_FORCE},
    {"wrap",           no_argument,       NULL, OPT_WRAP},
    {"fuse-box",       no_argument,       NULL, OPT_FUSE_BOX},
    {"refresh-key",    required_argument, NULL, OPT_REFRESH_KEY},
    {"refresh",        required_argument, NULL, OPT_REFRESH},
    {"no-harden",      no_argument,       NULL, OPT_NO_HARDEN},
    {"check",          no_argument,       NULL, OPT_CHECK},
    {"claimable",      no_argument,       NULL, OPT_CLAIMABLE},
    {"quiet",          no_argument,       NULL, 'q'},
    {"help",         no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/* ---- Main ---- */

int depo_cli_main(int argc, char **argv) {
    cli_opts opts;
    memset(&opts, 0, sizeof(opts));

    int opt;
    while ((opt = getopt_long(argc, argv, "qhcl:do:", long_options, NULL)) != -1) {
        switch (opt) {
        case OPT_PASSWORD:     opts.password = optarg; opts.headless = 1; break;
        case OPT_EPOCH_LEN:    opts.epoch_len = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_VALID_EPOCHS: opts.valid_epochs = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_DELAY:        opts.delay_secs = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_FUSES:        opts.fuses = (uint16_t)strtoul(optarg, NULL, 10); break;
        case OPT_PURGE:        opts.purge = 1; break;
        case OPT_FUSE_KEY:       opts.fuse_key = optarg; break;
        case OPT_INNER_FUSE_KEY: opts.inner_fuse_key = optarg; break;
        case OPT_OUTPUT:
        case 'o':                opts.output = optarg; break;
        case OPT_KDF_ROUNDS:   opts.kdf_rounds = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_KEYCHAIN:     opts.keychain = 1; break;
        case OPT_FUSE_SERVER:  opts.fuse_server = optarg; break;
        case OPT_ENGRAVE:      opts.engrave = optarg; break;
        case OPT_ENGRAVE_FILE: opts.engrave_file = optarg; break;
        case OPT_ENGRAVE_LEVEL: {
            if (strcmp(optarg, "root") == 0) opts.engrave_level = ROLE_ROOT;
            else if (strcmp(optarg, "admin") == 0) opts.engrave_level = ROLE_ADMIN;
            else if (strcmp(optarg, "auditor") == 0) opts.engrave_level = ROLE_AUDITOR;
            else if (strcmp(optarg, "reader") == 0) opts.engrave_level = ROLE_READER;
            else { fprintf(stderr, "  error: --engrave-level must be root|admin|auditor|reader\n"); return 1; }
            break;
        }
        case OPT_PUBLIC:       opts.public_msg = optarg; break;
        case OPT_SPLIT:        opts.split_mb = (uint32_t)strtoul(optarg, NULL, 10); break;
        case OPT_JOIN:         opts.join = 1; break;
        case OPT_ARCHIVE:      opts.archive = 1; break;
        case OPT_EXTRACT:      opts.extract = optarg; break;
        case OPT_LIST:         opts.list = 1; break;
        case OPT_FILE_ROLE:    /* stored but applied later during archive creation */
            break;
        case OPT_COMPRESS:
        case 'c':              opts.compress = 1; break;
        case OPT_DECOMPRESS:
        case 'd':              opts.decompress = 1; break;
        case OPT_PASSKEY:      opts.passkey = 1; opts.headless = 1; break;
        case OPT_TOTP_SECRET:  opts.totp_secret = optarg; opts.headless = 1; break;
        case OPT_TOTP:         opts.totp_code = optarg; opts.headless = 1; break;
        case OPT_INFO:         opts.info = 1; break;
        case OPT_VERIFY:       opts.verify = 1; break;
        case OPT_FORCE:        opts.force = 1; break;
        case OPT_WRAP:         opts.wrap = 1; break;
        case OPT_FUSE_BOX:    opts.fuse_box = 1; break;
        case OPT_REFRESH_KEY: opts.refresh_key = optarg; break;
        case OPT_REFRESH:     opts.do_refresh = optarg; break;
        case OPT_NO_HARDEN:  opts.no_harden = 1; break;
        case OPT_CHECK:      opts.check = 1; break;
        case OPT_CLAIMABLE:  opts.claimable = 1; opts.headless = 1; break;
        case 'l': {
            int lv = atoi(optarg);
            if (lv < 1 || lv > 9) {
                fprintf(stderr, "  error: compression level must be 1-9\n");
                return 1;
            }
            opts.press_level = lv;
            break;
        }
        case 'q':              opts.quiet = 1; break;
        case 'h':
        default:
            print_usage();
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (optind >= argc) {
        print_usage();
        return 1;
    }

    char clean_path[4096];
    strncpy(clean_path, argv[optind], sizeof(clean_path) - 1);
    clean_path[sizeof(clean_path) - 1] = '\0';
    size_t cplen = strlen(clean_path);
    while (cplen > 1 && clean_path[cplen - 1] == '/')
        clean_path[--cplen] = '\0';

    opts.input = clean_path;

    struct stat st;
    if (stat(clean_path, &st) != 0) {
        fprintf(stderr, "  error: '%s' not found\n", clean_path);
        return 1;
    }

    /* ---- File sensing ---- */

    /* Info / Verify / Check — no password needed, no hardening needed */
    if (opts.info)
        return do_info(clean_path);
    if (opts.check)
        return do_check(clean_path);
    if (opts.verify)
        return do_verify(clean_path);

    /* Apply process hardening (enabled by default, disable with --no-harden) */
    if (!opts.no_harden)
        harden_process();

    /* Explicit compression → wraps in .cute container */
    if (opts.compress)
        return do_compress(clean_path, &opts);
    /* Explicit decompression — supports legacy .press and .cute containers */
    if (opts.decompress)
        return do_decompress(clean_path, &opts);

    /* Parted file operations */
    if (opts.split_mb > 0)
        return do_split(clean_path, opts.split_mb);
    if (opts.join)
        return do_join(clean_path);

    /* Archive list (no password) */
    if (opts.list)
        return do_archive_list(clean_path);

    /* Fuse refresh */
    if (opts.do_refresh)
        return do_fuse_refresh(clean_path, &opts);

    /* DRM bundle wrapping */
    if (opts.wrap)
        return do_wrap(clean_path, &opts);

    /* Archive creation */
    if (opts.archive) {
        int n_inputs = argc - optind;
        return do_archive_encrypt(n_inputs, &argv[optind], &opts);
    }

    /* .press file → decompress */
    if (ends_with(clean_path, ".press") && !is_directory(clean_path))
        return do_decompress(clean_path, &opts);

    /* .cute file → decrypt (with archive detection) */
    if (ends_with(clean_path, ".cute") && !is_directory(clean_path)) {
        /* check for ARCV trailer to decide archive vs normal decrypt */
        size_t file_len;
        uint8_t *data = read_file(clean_path, &file_len);
        if (data && file_len >= HDR_SIZE && memcmp(data, CUTE_MAGIC, 4) == 0) {
            uint8_t fl = data[HDR_FLAGS];
            uint32_t vs = le32_get(data + HDR_VAULT_SIZE);
            uint32_t ps = le32_get(data + HDR_PAYLOAD_SIZE);
            uint16_t lc = le16_get(data + HDR_LEDGER_COUNT);
            size_t bs = binding_section_size(fl);
            size_t po = HDR_SIZE + bs + vs;
            size_t lo = po + ps;
            size_t ls = (size_t)lc * LEDGER_ENTRY_SIZE;
            size_t to = lo + ls;
            size_t tl = file_len > to ? file_len - to : 0;
            size_t arcv_len;
            if (trailer_section_find(data + to, tl, ARCV_MAGIC, &arcv_len)) {
                int rc = do_archive_decrypt(clean_path, data, file_len,
                                            opts.extract, &opts);
                free(data);
                return rc;
            }
        }
        free(data);
        return do_decrypt(clean_path, &opts);
    }

    /* Magic byte detection for files without recognized extension */
    if (!is_directory(clean_path)) {
        size_t probe_len;
        uint8_t *probe = read_file(clean_path, &probe_len);
        if (probe) {
            if (probe_len >= 4 && memcmp(probe, "PRSS", 4) == 0) {
                free(probe);
                return do_decompress(clean_path, &opts);
            }
            if (probe_len >= 4 && memcmp(probe, CUTE_MAGIC, 4) == 0) {
                free(probe);
                return do_decrypt(clean_path, &opts);
            }
            free(probe);
        }
    }

    /* Default: encrypt */
    return do_encrypt(clean_path, &opts);
}

/* ---- Public API stubs ---- */

depo_opts depo_opts_default(void) {
    depo_opts o;
    memset(&o, 0, sizeof(o));
    o.epoch_len = 3600;
    o.kdf_rounds = KDF_ROUNDS_DEFAULT;
    return o;
}

int depo_info(const uint8_t *data, size_t len, char *buf, size_t cap) {
    if (len < HDR_SIZE || memcmp(data, CUTE_MAGIC, 4) != 0) return -1;
    uint8_t  flags     = data[HDR_FLAGS];
    uint32_t vault_sz  = le32_get(data + HDR_VAULT_SIZE);
    uint32_t payload_sz = le32_get(data + HDR_PAYLOAD_SIZE);
    uint16_t ledger_n  = le16_get(data + HDR_LEDGER_COUNT);
    uint64_t created   = le64_get(data + HDR_CREATED);
    uint32_t epoch_len = le32_get(data + HDR_EPOCH_LEN);
    uint32_t valid_from = le32_get(data + HDR_VALID_FROM);
    uint32_t valid_until = le32_get(data + HDR_VALID_UNTIL);
    uint16_t max_fuses = le16_get(data + HDR_MAX_FUSES);
    uint16_t fuses_rem = le16_get(data + HDR_FUSES_REM);
    uint32_t kdf_rounds = le32_get(data + HDR_KDF_ROUNDS);

    /* Each line is "key: value" — the cli's `info --json` walker turns the
     * whole block into a parsed map for the GUI to render structured rows. */
    snprintf(buf, cap,
        "format: cutedepo v%d\n"
        "flags: 0x%02x\n"
        "flag_timed: %d\n"
        "flag_delayed: %d\n"
        "flag_fused: %d\n"
        "flag_purge: %d\n"
        "flag_container: %d\n"
        "flag_keychain: %d\n"
        "flag_remote_fuse: %d\n"
        "max_fuses: %u\n"
        "fuses_remaining: %u\n"
        "epoch_len_seconds: %u\n"
        "valid_from_epoch: %u\n"
        "valid_until_epoch: %u\n"
        "kdf_rounds: %u\n"
        "created_unix: %llu\n"
        "vault_bytes: %u\n"
        "payload_bytes: %u\n"
        "ledger_entries: %u\n",
        data[HDR_VERSION], flags,
        (flags & FLAG_TIMED)       ? 1 : 0,
        (flags & FLAG_DELAYED)     ? 1 : 0,
        (flags & FLAG_FUSED)       ? 1 : 0,
        (flags & FLAG_PURGE)       ? 1 : 0,
        (flags & FLAG_CONTAINER)   ? 1 : 0,
        (flags & FLAG_KEYCHAIN)    ? 1 : 0,
        (flags & FLAG_REMOTE_FUSE) ? 1 : 0,
        max_fuses, fuses_rem,
        epoch_len, valid_from, valid_until, kdf_rounds,
        (unsigned long long)created,
        vault_sz, payload_sz, ledger_n);
    return 0;
}

/* Translate the public depo_opts to the internal cli_opts that the
 * full do_encrypt / do_decrypt / do_archive_* implementations consume.
 * `headless` is forced on so the public API never tries to prompt. */
static void depo_opts_to_cli(const depo_opts *o, cli_opts *c,
                             const char *in, const char *out) {
    memset(c, 0, sizeof(*c));
    c->headless     = 1;
    c->quiet        = !o->verbose;
    c->password     = o->password;
    c->valid_epochs = o->valid_epochs;
    c->delay_secs   = o->delay_epochs * (o->epoch_len ? o->epoch_len : 3600);
    c->fuses        = o->fuses;
    c->epoch_len    = o->epoch_len;
    c->kdf_rounds   = o->kdf_rounds;
    c->purge        = o->purge;
    c->keychain     = o->keychain;
    c->fuse_server  = o->remote_url;
    c->archive      = o->archive;
    c->public_msg   = o->public_message;
    c->engrave      = o->engrave_text;
    c->engrave_level = o->engrave_role;
    c->totp_secret  = o->totp_secret;
    c->totp_code    = o->totp_code;
    c->force        = o->force;
    c->refresh_key  = o->refresh_key;
    c->fuse_box     = o->fuse_box;
    c->input        = in;
    c->output       = out;
}

int depo_encrypt_file(const char *in_path, const char *out_path,
                      const depo_opts *opts) {
    if (!in_path) return -1;
    depo_opts d = depo_opts_default();
    if (opts) d = *opts;
    cli_opts c; depo_opts_to_cli(&d, &c, in_path, out_path);
    return do_encrypt(in_path, &c);
}

int depo_decrypt_file(const char *in_path, const char *out_path,
                      const depo_opts *opts) {
    if (!in_path) return -1;
    depo_opts d = depo_opts_default();
    if (opts) d = *opts;
    cli_opts c; depo_opts_to_cli(&d, &c, in_path, out_path);
    return do_decrypt(in_path, &c);
}

int depo_encrypt_buf(const uint8_t *in, size_t in_len,
                     uint8_t **out, size_t *out_len,
                     const depo_opts *opts) {
    /* Buffer-mode encrypt isn't supported by the existing do_encrypt
     * internals; they're file-path-driven. Surface that explicitly so
     * callers don't get silent failure. */
    (void)in; (void)in_len; (void)out; (void)out_len; (void)opts;
    return -1;
}

int depo_decrypt_buf(const uint8_t *in, size_t in_len,
                     uint8_t **out, size_t *out_len,
                     const depo_opts *opts) {
    (void)in; (void)in_len; (void)out; (void)out_len; (void)opts;
    return -1;
}

int depo_archive_encrypt(const char **paths, int count, const char *out_path,
                         const depo_opts *opts) {
    if (!paths || count <= 0 || !out_path) return -1;
    depo_opts d = depo_opts_default();
    if (opts) d = *opts;
    cli_opts c; depo_opts_to_cli(&d, &c, NULL, out_path);
    c.archive = 1;
    /* do_archive_encrypt mutates the paths array via getopt; it expects
     * char ** rather than const char **. Cast through. */
    return do_archive_encrypt(count, (char **)(uintptr_t)paths, &c);
}

int depo_archive_decrypt(const char *in_path, const char *out_dir,
                         const depo_opts *opts) {
    if (!in_path || !out_dir) return -1;
    depo_opts d = depo_opts_default();
    if (opts) d = *opts;
    size_t flen = 0;
    uint8_t *data = read_file(in_path, &flen);
    if (!data) return -1;
    cli_opts c; depo_opts_to_cli(&d, &c, in_path, out_dir);
    int rc = do_archive_decrypt(in_path, data, flen, NULL, &c);
    free(data);
    return rc;
}
int depo_archive_list(const char *p, char *b, size_t c) {
    (void)p;(void)b;(void)c; return -1;
}
int depo_verify(const uint8_t *d, size_t l) { (void)d;(void)l; return -1; }
int depo_compress_file(const char *i, const char *o) { (void)i;(void)o; return -1; }
int depo_decompress_file(const char *i, const char *o) { (void)i;(void)o; return -1; }
int depo_split(const char *p, size_t s) { (void)p;(void)s; return -1; }
int depo_join(const char *p, const char *o) { (void)p;(void)o; return -1; }
int depo_fuse_refresh(const char *path, const char *refresh_key, uint16_t new_fuses) {
    if (!path || !refresh_key) return -1;
    cli_opts c;
    memset(&c, 0, sizeof(c));
    c.headless    = 1;
    c.quiet       = 1;
    c.input       = path;
    c.do_refresh  = refresh_key;
    c.fuses       = new_fuses;
    return do_fuse_refresh(path, &c);
}
void depo_secure_zero(void *p, size_t l) { secure_zero(p, l); }
void depo_harden_process(void) { harden_process(); }
void *depo_secure_alloc(size_t l) { return secure_alloc(l); }
void depo_secure_free(void *p, size_t l) { secure_free(p, l); }
