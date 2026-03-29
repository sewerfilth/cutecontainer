/*
 * volume.h — Game asset volume backed by .cute containers
 *
 * A volume is a single .cute file containing many assets, each
 * individually addressable by path. The WAL rail serves as the
 * table of contents — mounting a volume reads only the WAL,
 * never the payload. Individual assets are decompressed on demand.
 *
 * ── Architecture ──
 *
 * On disk:
 *   [64]        container header (CC_TYPE_RAW, layers=none)
 *   [meta]      volume manifest (serialized cc_vol_manifest)
 *   [payload]:
 *     [asset 0 data]
 *     [asset 1 data]
 *     ...
 *     [asset N data]
 *   [WAL trailer]  ← mount reads only this
 *
 * The manifest maps paths → offsets within the payload section.
 * Each asset can be individually compressed (press) or left raw.
 * The WAL summary tells you the asset count and total size
 * without parsing the manifest.
 *
 * ── Usage ──
 *
 *   cc_volume *vol = cc_vol_mount("game.cute");
 *   int count = cc_vol_asset_count(vol);
 *
 *   // list all assets (reads manifest, not payload)
 *   for (int i = 0; i < count; i++)
 *       printf("%s\n", cc_vol_asset_path(vol, i));
 *
 *   // load one asset (decompresses on demand)
 *   size_t len;
 *   void *tex = cc_vol_load(vol, "textures/brick.cute", &len);
 *   // use tex...
 *   cc_vol_free(tex);
 *
 *   cc_vol_unmount(vol);
 *
 * ── Build ──
 *
 *   cc_vol_builder *b = cc_vol_builder_create("game.cute");
 *   cc_vol_builder_add_file(b, "textures/brick.png", CC_VOL_COMPRESS);
 *   cc_vol_builder_add_file(b, "shaders/main.spv", CC_VOL_RAW);
 *   cc_vol_builder_add_buf(b, "config.json", data, len, CC_VOL_RAW);
 *   cc_vol_builder_finish(b);  // writes the .cute volume
 */

#ifndef CUTECONTAINER_VOLUME_H
#define CUTECONTAINER_VOLUME_H

#include "container.h"
#include "wal.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Asset flags ── */

#define CC_VOL_RAW         0x00   /* stored uncompressed */
#define CC_VOL_COMPRESS    0x01   /* compressed with press */
#define CC_VOL_ENCRYPT     0x02   /* encrypted with crypt (per-asset) */
#define CC_VOL_PRELOAD     0x04   /* hint: load at mount time */
#define CC_VOL_STREAM      0x08   /* hint: this is streaming data */

/* ── Asset entry (in manifest) ── */

typedef struct {
    char        path[256];       /* asset path (e.g., "textures/brick.png") */
    uint64_t    offset;          /* byte offset within payload section */
    uint64_t    stored_size;     /* size on disk (after compression) */
    uint64_t    original_size;   /* size after decompression */
    uint32_t    flags;           /* CC_VOL_* */
    uint16_t    wrap_type;       /* cc_wrap_type of this asset (0 = unknown) */
    uint16_t    group;           /* user-defined group index (LOD, level, etc.) */
    uint8_t     hash[32];        /* SHA3-256 of original data */
} cc_vol_entry;

/* ── Volume (read-only, mounted) ── */

typedef struct cc_volume cc_volume;

/* Mount a volume from a .cute file. Reads only the WAL + manifest.
 * No asset payload is touched until cc_vol_load(). */
cc_volume *cc_vol_mount(const char *path);

/* Mount from an in-memory buffer. */
cc_volume *cc_vol_mount_mem(const uint8_t *data, size_t len);

/* Unmount and free. */
void cc_vol_unmount(cc_volume *vol);

/* ── Query (fast — reads manifest only, no decompression) ── */

/* Total number of assets. */
int cc_vol_asset_count(const cc_volume *vol);

/* Asset path by index. */
const char *cc_vol_asset_path(const cc_volume *vol, int index);

/* Full entry by index. */
const cc_vol_entry *cc_vol_asset_entry(const cc_volume *vol, int index);

/* Find asset by path. Returns index or -1. */
int cc_vol_find(const cc_volume *vol, const char *path);

/* Find all assets in a group. Returns count, writes indices to out[]. */
int cc_vol_find_group(const cc_volume *vol, uint16_t group,
                      int *out, int max);

/* Find all assets matching a prefix (e.g., "textures/"). */
int cc_vol_find_prefix(const cc_volume *vol, const char *prefix,
                       int *out, int max);

/* Find all assets of a given wrap type. */
int cc_vol_find_type(const cc_volume *vol, uint16_t wrap_type,
                     int *out, int max);

/* Total stored size (compressed, on disk). */
uint64_t cc_vol_total_stored(const cc_volume *vol);

/* Total original size (uncompressed). */
uint64_t cc_vol_total_original(const cc_volume *vol);

/* ── Load (decompresses / decrypts on demand) ── */

/* Load asset by path. Allocates buffer — caller frees with cc_vol_free().
 * Returns NULL on not found or error. */
void *cc_vol_load(cc_volume *vol, const char *path, size_t *out_len);

/* Load asset by index (faster — skips path lookup). */
void *cc_vol_load_index(cc_volume *vol, int index, size_t *out_len);

/* Load into a caller-provided buffer (no allocation).
 * buf must be at least entry->original_size bytes.
 * Returns 0 on success. */
int cc_vol_load_into(cc_volume *vol, int index, void *buf, size_t buf_len);

/* Free a buffer returned by cc_vol_load(). */
void cc_vol_free(void *buf);

/* ── Builder (create a volume) ── */

typedef struct cc_vol_builder cc_vol_builder;

/* Create a builder that will write to the given path. */
cc_vol_builder *cc_vol_builder_create(const char *out_path);

/* Add a file from disk. Reads and optionally compresses it. */
int cc_vol_builder_add_file(cc_vol_builder *b, const char *asset_path,
                            const char *disk_path, uint32_t flags);

/* Add from a memory buffer. */
int cc_vol_builder_add_buf(cc_vol_builder *b, const char *asset_path,
                           const void *data, size_t len, uint32_t flags);

/* Set wrap type for the most recently added asset. */
void cc_vol_builder_set_wrap(cc_vol_builder *b, uint16_t wrap_type);

/* Set group for the most recently added asset. */
void cc_vol_builder_set_group(cc_vol_builder *b, uint16_t group);

/* Finalize: writes the .cute volume with manifest + WAL. */
int cc_vol_builder_finish(cc_vol_builder *b);

/* Destroy builder (calls finish if not already done). */
void cc_vol_builder_destroy(cc_vol_builder *b);

/* ══════════════════════════════════════════════════════════════
 * Overlay filesystem — writable public dir for user data
 *
 * The volume itself is read-only (master-signed). But when
 * mounted for execution, a writable overlay directory is
 * created alongside it. The overlay works like a union mount:
 *
 *   Read layer:   game.cute (immutable volume)
 *   Write layer:  <user_data>/<bundle_id>/  (writable)
 *   Merged view:  write layer overrides read layer by path
 *
 * When an app reads "config.json", the volume checks the
 * overlay first. If the user has saved a modified config,
 * that version is returned. Otherwise, the original from
 * the volume is returned.
 *
 * When an app writes "saves/slot1.sav", it goes to the
 * overlay — the volume is never modified.
 *
 * Standard overlay paths:
 *   saves/        — save games
 *   config/       — user settings overrides
 *   mods/         — user-installed mod content
 *   cache/        — runtime cache (can be deleted)
 *   logs/         — app logs
 *
 * On macOS: ~/Library/Application Support/<bundle_id>/
 * On Linux: ~/.local/share/<bundle_id>/
 * On Windows: %APPDATA%/<bundle_id>/
 * ══════════════════════════════════════════════════════════════ */

/* Get the overlay (user data) directory for this volume.
 * Creates the directory if it doesn't exist.
 * Returns the path, or NULL if no exec manifest / bundle_id. */
const char *cc_vol_overlay_path(cc_volume *vol);

/* Load an asset with overlay priority:
 * 1. Check overlay dir for <path> — return if exists
 * 2. Fall back to volume — decompress and return
 * Returns NULL if not found in either layer. */
void *cc_vol_load_overlay(cc_volume *vol, const char *path, size_t *out_len);

/* Write data to the overlay dir (saves, config, etc.).
 * Creates parent directories as needed. */
int cc_vol_write_overlay(cc_volume *vol, const char *path,
                         const void *data, size_t len);

/* Delete a file from the overlay (revert to volume original). */
int cc_vol_delete_overlay(cc_volume *vol, const char *path);

/* List files in an overlay subdirectory (e.g., "saves/").
 * Writes paths to out[], returns count. */
int cc_vol_list_overlay(cc_volume *vol, const char *subdir,
                        char out[][256], int max);

/* Check if an overlay file exists (without loading it). */
int cc_vol_overlay_exists(cc_volume *vol, const char *path);

/* Get total size of all overlay data (user data size). */
uint64_t cc_vol_overlay_size(cc_volume *vol);

/* ══════════════════════════════════════════════════════════════
 * Executable volume — the volume as an app bundle / launcher
 *
 * The master (creator) declares entry points per platform.
 * When a user "runs" the volume, it extracts the matching
 * entry point to a temp sandbox and executes it. The entry
 * point can be a native binary, a script, or an inline
 * command that references other assets in the volume.
 *
 * ── Platform entry points ──
 *
 * The creator can set one entry per platform:
 *   "bin/game.exe"          — Windows native
 *   "bin/game"              — Linux native
 *   "bin/game.app"          — macOS native
 *   "scripts/main.lua"      — Lua script (interpreter detected)
 *   "scripts/main.py"       — Python script
 *   "scripts/main.sh"       — shell script
 *   "!inline lua"           — inline Lua source stored in the volume
 *
 * The volume also supports:
 *   - Arguments: passed to the entry point
 *   - Environment: volume path injected as $CUTE_VOLUME
 *   - Working dir: extracted assets in a temp sandbox
 *   - Dependencies: assets marked CC_VOL_PRELOAD extracted before exec
 *   - Return code: captured from the child process
 *
 * ── Security ──
 *
 * Entry points are controlled exclusively by the master. The
 * exec manifest is part of the signed volume — you can't
 * inject an entry point into someone else's volume without
 * invalidating the content hash in the WAL.
 *
 * ══════════════════════════════════════════════════════════════ */

/* ── Platform IDs ── */

typedef enum {
    CC_PLAT_ANY      = 0x00,   /* platform-independent (scripts) */
    CC_PLAT_MACOS    = 0x01,
    CC_PLAT_LINUX    = 0x02,
    CC_PLAT_WINDOWS  = 0x03,
    CC_PLAT_IOS      = 0x04,
    CC_PLAT_ANDROID  = 0x05,
    CC_PLAT_WASM     = 0x06,
} cc_platform;

/* ── Interpreter hints (for script entry points) ── */

typedef enum {
    CC_INTERP_NONE   = 0x00,   /* native binary, no interpreter */
    CC_INTERP_SHELL  = 0x01,   /* /bin/sh (or cmd.exe on Windows) */
    CC_INTERP_LUA    = 0x02,   /* lua / luajit */
    CC_INTERP_PYTHON = 0x03,   /* python3 */
    CC_INTERP_NODE   = 0x04,   /* node */
    CC_INTERP_WASM   = 0x05,   /* wasmtime / wasmer */
    CC_INTERP_RUBY   = 0x06,
    CC_INTERP_PERL   = 0x07,
    CC_INTERP_JAVA   = 0x08,   /* java -jar */
    CC_INTERP_DOTNET = 0x09,   /* dotnet */
    CC_INTERP_CUSTOM = 0xFF,   /* interpreter path in custom_interp */
} cc_interpreter;

/* ── Entry point descriptor ── */

#define CC_EXEC_MAX_ARGS     16
#define CC_EXEC_MAX_ENTRIES  8

typedef struct {
    cc_platform     platform;
    cc_interpreter  interpreter;
    char            asset_path[256];    /* path within the volume */
    char            custom_interp[128]; /* for CC_INTERP_CUSTOM */
    char            args[512];          /* space-separated arguments */
    char            display_name[64];   /* human-readable name (window title, etc.) */
    char            version[32];        /* app version string */
    uint32_t        flags;
} cc_exec_entry;

/* Exec flags */
#define CC_EXEC_SANDBOX      0x01   /* extract to temp dir (default) */
#define CC_EXEC_INPLACE      0x02   /* run directly from volume (mmap) */
#define CC_EXEC_CONSOLE      0x04   /* needs a terminal / console */
#define CC_EXEC_GUI          0x08   /* GUI app (no console) */
#define CC_EXEC_PRELOAD_ALL  0x10   /* extract all assets before exec */
#define CC_EXEC_CLEANUP      0x20   /* delete sandbox after exit */

/* ── Exec manifest (stored in volume metadata) ── */

typedef struct {
    uint32_t        entry_count;
    cc_exec_entry   entries[CC_EXEC_MAX_ENTRIES];
    char            author[128];        /* creator / publisher name */
    char            bundle_id[128];     /* reverse-domain ID (com.cuteheart.mygame) */
    uint8_t         icon_hash[32];      /* SHA3 of icon asset (for OS integration) */
    char            icon_path[256];     /* path to icon asset in volume */
} cc_exec_manifest;

/* ── Runtime: execute the volume ── */

/* Get the exec manifest from a mounted volume (NULL if not executable). */
const cc_exec_manifest *cc_vol_exec_manifest(const cc_volume *vol);

/* Find the entry point for the current platform.
 * Tries exact platform match first, then CC_PLAT_ANY fallback. */
const cc_exec_entry *cc_vol_exec_entry_for_platform(const cc_volume *vol);

/* Check if the current system has the required interpreter. */
int cc_vol_exec_can_run(const cc_exec_entry *entry);

/* Execute the volume's entry point for the current platform.
 *
 * 1. Creates a temp sandbox directory
 * 2. Extracts the entry point asset (+ PRELOAD assets)
 * 3. Sets $CUTE_VOLUME to the volume file path
 * 4. Sets $CUTE_SANDBOX to the sandbox directory
 * 5. Launches the process (native or via interpreter)
 * 6. Returns the child's exit code (or -1 on failure)
 *
 * If CC_EXEC_CLEANUP is set, the sandbox is deleted after exit. */
int cc_vol_exec(cc_volume *vol);

/* Execute with custom arguments (appended after manifest args). */
int cc_vol_exec_args(cc_volume *vol, const char **argv, int argc);

/* ── Builder: set exec manifest ── */

/* Set the volume as executable with the given manifest. */
void cc_vol_builder_set_exec(cc_vol_builder *b, const cc_exec_manifest *manifest);

/* Convenience: add an entry point for a platform. */
void cc_vol_builder_add_entry_point(cc_vol_builder *b,
                                     cc_platform platform,
                                     cc_interpreter interpreter,
                                     const char *asset_path,
                                     const char *args,
                                     uint32_t flags);

/* Set bundle metadata. */
void cc_vol_builder_set_bundle(cc_vol_builder *b,
                                const char *author,
                                const char *bundle_id,
                                const char *display_name,
                                const char *version);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_VOLUME_H */
