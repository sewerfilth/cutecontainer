/*
 * cutecontainer CLI — unified command-line tool
 *
 * Routes operations through the module SDK. Auto-detects file types
 * and dispatches to the right codec module.
 *
 * Usage:
 *   cutecontainer compress [-l level] <file>
 *   cutecontainer decompress <file.cute>
 *   cutecontainer encrypt [-p password] <file>
 *   cutecontainer decrypt [-p password] <file.cute>
 *   cutecontainer spectral -m <128|256|512> -w <W> -h <H> <in.raw> <out.cute>
 *   cutecontainer info <file>
 *   cutecontainer modules
 *   cutecontainer <file>              (auto-detect and process)
 *
 * Depo commands (encrypted containers):
 *   cutecontainer lock [-p pw] [--fuses N] [--timed N] <file>
 *   cutecontainer unlock [-p pw] <file.cute>
 *   cutecontainer archive [-p pw] <files...> -o <out.cute>
 */

#include "cutecontainer/sdk.h"
#include "cutecontainer/container.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt.h"
#include "cutecontainer/film.h"
#include "cutecontainer/depo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Helpers ---- */

static uint8_t *read_file(const char *path, size_t *len)
{
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
    *len = (size_t)sz;
    return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wr = fwrite(data, 1, len, f);
    fclose(f);
    return (wr == len) ? 0 : -1;
}

static void make_output_path(char *out, size_t cap, const char *in, const char *ext)
{
    snprintf(out, cap, "%s%s", in, ext);
}

/* ---- Commands ---- */

static void usage(void)
{
    fprintf(stderr,
        "cutecontainer — unified .cute toolchain\n\n"
        "Usage:\n"
        "  cutecontainer compress [-l 1-9] <file>          compress via press module\n"
        "  cutecontainer decompress <file>                  decompress\n"
        "  cutecontainer lock <file>                        encrypt with password\n"
        "  cutecontainer unlock <file.cute>                 decrypt with password\n"
        "  cutecontainer info <file>                        show file info\n"
        "  cutecontainer modules                            list loaded modules\n"
        "  cutecontainer <file>                             auto-detect and process\n"
    );
}

static int cmd_modules(void)
{
    const cc_module *mods[CC_MAX_MODULES];
    int n = cc_list_modules(mods, CC_MAX_MODULES);
    printf("loaded modules (%d):\n", n);
    for (int i = 0; i < n; i++) {
        printf("  %-8s  type=%d  caps=0x%04x  %s\n",
            mods[i]->name, mods[i]->type, mods[i]->caps, mods[i]->description);
    }
    return 0;
}

static int cmd_info(const char *path)
{
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "error: cannot read %s\n", path); return 1; }

    cc_content_type type = cc_container_detect(data, len);
    printf("type:   %s\n", cc_content_type_name(type));

    /* unified v5 container — show container-level info */
    if (len >= 6 && memcmp(data, "CUTE", 4) == 0 && data[4] >= 0x05) {
        uint16_t layers = data[6] | (data[7] << 8);
        printf("format: unified container v%d\n", data[4]);
        printf("layers: %s%s%s\n",
            (layers & CC_LAYER_COMPRESSED) ? "compressed " : "",
            (layers & CC_LAYER_ENCRYPTED) ? "encrypted " : "",
            layers == 0 ? "none" : "");
        printf("size:   %zu bytes\n", len);
    }

    /* try module-level info for legacy or typed content */
    const cc_module *mod = cc_probe_module(data, len);
    if (mod && mod->info) {
        char info[2048] = {0};
        mod->info(data, len, info, sizeof(info));
        printf("module: %s\n%s", mod->name, info);
    }

    free(data);
    return 0;
}

static int cmd_compress(const char *path, int level)
{
    size_t in_len = 0;
    uint8_t *in = read_file(path, &in_len);
    if (!in) { fprintf(stderr, "error: cannot read %s\n", path); return 1; }

    /* wrap in container with press layer */
    cc_container *c = cc_container_create(CC_TYPE_RAW);
    cc_container_set_payload(c, in, in_len);
    cc_container_set_layers(c, CC_LAYER_COMPRESSED);
    cc_container_set_compression_level(c, level);

    uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = cc_container_write(c, &out, &out_len);
    cc_container_destroy(c);
    free(in);

    if (rc != CC_OK) { fprintf(stderr, "error: compress failed (%d)\n", rc); return 1; }

    char out_path[1024];
    make_output_path(out_path, sizeof(out_path), path, ".cute");
    if (write_file(out_path, out, out_len) != 0) {
        fprintf(stderr, "error: cannot write %s\n", out_path);
        free(out);
        return 1;
    }

    printf("%s → %s (%.1f%% ratio)\n", path, out_path,
        (double)out_len / (double)in_len * 100.0);
    free(out);
    return 0;
}

static int cmd_decompress(const char *path)
{
    size_t in_len = 0;
    uint8_t *in = read_file(path, &in_len);
    if (!in) { fprintf(stderr, "error: cannot read %s\n", path); return 1; }

    cc_container *c = cc_container_open(in, in_len);
    free(in);
    if (!c) { fprintf(stderr, "error: cannot open container\n"); return 1; }

    size_t payload_len = 0;
    const uint8_t *payload = cc_container_payload(c, &payload_len);

    /* strip .cute extension for output */
    char out_path[1024];
    strncpy(out_path, path, sizeof(out_path) - 1);
    size_t plen = strlen(out_path);
    if (plen > 5 && strcmp(out_path + plen - 5, ".cute") == 0)
        out_path[plen - 5] = '\0';
    else
        make_output_path(out_path, sizeof(out_path), path, ".out");

    if (write_file(out_path, payload, payload_len) != 0) {
        fprintf(stderr, "error: cannot write %s\n", out_path);
        cc_container_destroy(c);
        return 1;
    }

    printf("%s → %s (%zu bytes)\n", path, out_path, payload_len);
    cc_container_destroy(c);
    return 0;
}

static int cmd_auto(const char *path)
{
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data) { fprintf(stderr, "error: cannot read %s\n", path); return 1; }

    cc_content_type type = cc_container_detect(data, len);
    free(data);

    switch (type) {
    case CC_TYPE_RAW:
    case CC_TYPE_PRESS:
    case CC_TYPE_FILM:
    case CC_TYPE_CRYPT:
    case CC_TYPE_DEPO:
        return cmd_decompress(path);
    default:
        /* unknown format — compress it */
        return cmd_compress(path, CP_LEVEL_DEFAULT);
    }
}

/* ---- Depo: lock (encrypt) ---- */

static int cmd_lock(int argc, char **argv)
{
    const char *password = NULL;
    const char *file = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc)
            password = argv[++i];
        else if (!file)
            file = argv[i];
    }

    if (!file) { fprintf(stderr, "error: lock requires a file\n"); return 1; }
    if (!password) {
        fprintf(stderr, "password: ");
        static char pw[256];
        if (!fgets(pw, sizeof(pw), stdin)) return 1;
        pw[strcspn(pw, "\n")] = 0;
        password = pw;
    }

    depo_opts opts = depo_opts_default();
    opts.password = password;
    opts.headless = 1;

    char out_path[1024];
    make_output_path(out_path, sizeof(out_path), file, ".cute");

    int rc = depo_encrypt_file(file, out_path, &opts);
    if (rc != 0) { fprintf(stderr, "error: lock failed (%d)\n", rc); return 1; }

    printf("locked %s → %s\n", file, out_path);
    return 0;
}

/* ---- Depo: unlock (decrypt) ---- */

static int cmd_unlock(int argc, char **argv)
{
    const char *password = NULL;
    const char *file = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc)
            password = argv[++i];
        else if (!file)
            file = argv[i];
    }

    if (!file) { fprintf(stderr, "error: unlock requires a file\n"); return 1; }
    if (!password) {
        fprintf(stderr, "password: ");
        static char pw[256];
        if (!fgets(pw, sizeof(pw), stdin)) return 1;
        pw[strcspn(pw, "\n")] = 0;
        password = pw;
    }

    depo_opts opts = depo_opts_default();
    opts.password = password;
    opts.headless = 1;

    char out_path[1024];
    strncpy(out_path, file, sizeof(out_path) - 1);
    size_t plen = strlen(out_path);
    if (plen > 5 && strcmp(out_path + plen - 5, ".cute") == 0)
        out_path[plen - 5] = '\0';
    else
        make_output_path(out_path, sizeof(out_path), file, ".unlocked");

    int rc = depo_decrypt_file(file, out_path, &opts);
    if (rc != 0) { fprintf(stderr, "error: unlock failed (%d)\n", rc); return 1; }

    printf("unlocked %s → %s\n", file, out_path);
    return 0;
}

/* ---- Main ---- */

int main(int argc, char **argv)
{
    cc_sdk_init_full();

    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "modules") == 0)
        return cmd_modules();

    if (strcmp(cmd, "info") == 0 && argc >= 3)
        return cmd_info(argv[2]);

    if (strcmp(cmd, "compress") == 0 && argc >= 3) {
        int level = CP_LEVEL_DEFAULT;
        int file_idx = 2;
        if (argc >= 4 && strcmp(argv[2], "-l") == 0) {
            level = atoi(argv[3]);
            file_idx = 4;
        }
        if (file_idx >= argc) { usage(); return 1; }
        return cmd_compress(argv[file_idx], level);
    }

    if (strcmp(cmd, "decompress") == 0 && argc >= 3)
        return cmd_decompress(argv[2]);

    if (strcmp(cmd, "lock") == 0)
        return cmd_lock(argc - 2, argv + 2);

    if (strcmp(cmd, "unlock") == 0)
        return cmd_unlock(argc - 2, argv + 2);

    /* auto-detect: just a file path */
    return cmd_auto(argv[1]);
}
