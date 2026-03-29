/*
 * sdk.c — module registry, dynamic loader, and built-in module init
 */

#include "cutecontainer/sdk.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

/* ---- Module registry ---- */

static const cc_module *g_modules[CC_MAX_MODULES];
static int g_module_count = 0;

int cc_register_module(const cc_module *mod)
{
    if (!mod || g_module_count >= CC_MAX_MODULES) return -1;
    if (mod->sdk_version != CC_SDK_VERSION) return -1;

    /* prevent duplicate registration */
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i]->type == mod->type) return 0;

    g_modules[g_module_count++] = mod;
    return 0;
}

const cc_module *cc_find_module(cc_content_type type)
{
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i]->type == type) return g_modules[i];
    return NULL;
}

const cc_module *cc_probe_module(const uint8_t *data, size_t len)
{
    if (!data || len < 4) return NULL;

    /* fast path: check container detection first */
    cc_content_type detected = cc_container_detect(data, len);
    if (detected != CC_TYPE_UNKNOWN) {
        const cc_module *m = cc_find_module(detected);
        if (m) return m;
    }

    /* slow path: ask each module */
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i]->probe && g_modules[i]->probe(data, len))
            return g_modules[i];

    return NULL;
}

int cc_list_modules(const cc_module **out, int max)
{
    int n = g_module_count < max ? g_module_count : max;
    for (int i = 0; i < n; i++) out[i] = g_modules[i];
    return n;
}

/* ---- Dynamic module loader ---- */

typedef const cc_module *(*cc_module_init_fn)(void);

int cc_load_module(const char *path)
{
#ifndef _WIN32
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) return -1;

    cc_module_init_fn init = (cc_module_init_fn)dlsym(handle, "cc_module_init");
    if (!init) { dlclose(handle); return -1; }

    const cc_module *mod = init();
    if (!mod) { dlclose(handle); return -1; }

    return cc_register_module(mod);
#else
    HMODULE handle = LoadLibraryA(path);
    if (!handle) return -1;

    cc_module_init_fn init = (cc_module_init_fn)GetProcAddress(handle, "cc_module_init");
    if (!init) { FreeLibrary(handle); return -1; }

    const cc_module *mod = init();
    if (!mod) { FreeLibrary(handle); return -1; }

    return cc_register_module(mod);
#endif
}

int cc_load_modules(const char *dir)
{
    int loaded = 0;

#ifndef _WIN32
    DIR *d = opendir(dir);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);

        /* check for .dylib or .so */
        int is_dylib = (nlen > 6 && strcmp(name + nlen - 6, ".dylib") == 0);
        int is_so    = (nlen > 3 && strcmp(name + nlen - 3, ".so") == 0);
        if (!is_dylib && !is_so) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, name);

        if (cc_load_module(path) == 0) loaded++;
    }

    closedir(d);
#else
    WIN32_FIND_DATAA fd;
    char pattern[1024];
    snprintf(pattern, sizeof(pattern), "%s\\*.dll", dir);

    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    do {
        char path[1024];
        snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
        if (cc_load_module(path) == 0) loaded++;
    } while (FindNextFileA(h, &fd));

    FindClose(h);
#endif

    return loaded;
}

/* ---- Built-in module declarations ---- */

extern const cc_module cc_builtin_press;
extern const cc_module cc_builtin_crypt;
extern const cc_module cc_builtin_film;
extern const cc_module cc_builtin_depo;

/* ---- Init ---- */

void cc_sdk_init(void)
{
    g_module_count = 0;
    cc_register_module(&cc_builtin_press);
    cc_register_module(&cc_builtin_crypt);
    cc_register_module(&cc_builtin_film);
    cc_register_module(&cc_builtin_depo);
}

void cc_sdk_init_full(void)
{
    cc_sdk_init();

    /* load dynamic modules from default paths */
    const char *home = getenv("HOME");
    if (home) {
        char path[1024];
        snprintf(path, sizeof(path), "%s/.cutecontainer/modules", home);
        cc_load_modules(path);
    }

    cc_load_modules("/usr/local/lib/cutecontainer/modules");

#ifdef __APPLE__
    cc_load_modules("/Library/Application Support/cutecontainer/modules");
#endif
}
