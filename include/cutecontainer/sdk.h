/*
 * sdk.h — cutecontainer module SDK
 *
 * Standard interface for codec modules. Modules can be:
 *   1. Built-in (statically linked, registered at startup)
 *   2. Dynamic (loaded from .dylib/.so/.dll at runtime)
 *
 * Each module handles one content type (press, crypt, film, etc.)
 * and exposes encode/decode/probe/info through function pointers.
 *
 * Dynamic modules export a single entry point:
 *   const cc_module *cc_module_init(void);
 *
 * The core scans a modules directory at startup and loads any
 * shared libraries it finds, calling cc_module_init() on each.
 */

#ifndef CUTECONTAINER_SDK_H
#define CUTECONTAINER_SDK_H

#include "container.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CC_SDK_VERSION      1
#define CC_MAX_MODULES      32

/* ---- Module capabilities (bitmask) ---- */

#define CC_CAP_ENCODE       0x0001  /* can encode */
#define CC_CAP_DECODE       0x0002  /* can decode */
#define CC_CAP_STREAM       0x0004  /* supports streaming I/O */
#define CC_CAP_GPU           0x0008  /* has GPU acceleration */
#define CC_CAP_ASM           0x0010  /* has per-arch ASM hot paths */
#define CC_CAP_HARDWARE      0x0020  /* uses hardware encoder/decoder */

/* ---- Module options (key-value pairs for configuration) ---- */

typedef struct {
    const char *key;
    const char *value;
} cc_opt;

/* ---- Module descriptor ---- */

typedef struct cc_module {
    /* identity */
    const char     *name;           /* e.g. "press", "crypt", "film" */
    const char     *description;    /* human-readable, one line */
    cc_content_type type;           /* CC_TYPE_PRESS, etc. */
    uint32_t        sdk_version;    /* CC_SDK_VERSION this module was built against */
    uint32_t        caps;           /* CC_CAP_* bitmask */

    /* probe: can this module handle this data?
     * Returns 1 if yes, 0 if no. Called with at least the first 64 bytes. */
    int (*probe)(const uint8_t *header, size_t len);

    /* encode: transform input → output.
     * opts: NULL-terminated array of key-value options (NULL if none).
     * Allocates *out — caller frees with module->free_buf().
     * Returns 0 on success, negative on error. */
    int (*encode)(const uint8_t *in, size_t in_len,
                  uint8_t **out, size_t *out_len,
                  const cc_opt *opts);

    /* decode: reverse of encode.
     * Allocates *out — caller frees with module->free_buf(). */
    int (*decode)(const uint8_t *in, size_t in_len,
                  uint8_t **out, size_t *out_len);

    /* info: describe the contents of encoded data (human-readable).
     * Writes a null-terminated string to buf. Returns 0 or negative. */
    int (*info)(const uint8_t *data, size_t len, char *buf, size_t cap);

    /* free a buffer allocated by encode/decode. */
    void (*free_buf)(void *buf);

} cc_module;

/* ---- Module registry ---- */

/* Register a module. Built-in modules call this at startup.
 * Dynamic modules are registered automatically when loaded. */
int cc_register_module(const cc_module *mod);

/* Find a module by content type. Returns NULL if not found. */
const cc_module *cc_find_module(cc_content_type type);

/* Find a module that can handle this data (probes all registered modules). */
const cc_module *cc_probe_module(const uint8_t *data, size_t len);

/* Iterate all registered modules. Returns count. */
int cc_list_modules(const cc_module **out, int max);

/* ---- Dynamic module loader ---- */

/* Load all .dylib/.so modules from a directory.
 * Each must export: const cc_module *cc_module_init(void);
 * Returns number of modules loaded. */
int cc_load_modules(const char *dir);

/* Load a single dynamic module. Returns 0 on success. */
int cc_load_module(const char *path);

/* ---- Init / shutdown ---- */

/* Initialize the SDK and register all built-in modules. */
void cc_sdk_init(void);

/* Convenience: init + load dynamic modules from default paths. */
void cc_sdk_init_full(void);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_SDK_H */
