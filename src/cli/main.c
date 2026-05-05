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
#include "cutecontainer/archive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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
        "\n"
        "Multi-format archive (zip/tar/tar.gz/tar.bz2/tar.xz/7z/rar/cute):\n"
        "  cutecontainer archive detect  <path>             print detected format\n"
        "  cutecontainer archive list    <path>             JSON listing of entries\n"
        "  cutecontainer archive extract <path> -o <dest> [-i <i>]\n"
        "  cutecontainer archive create  [-f <fmt>] <out> <files...>\n"
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

/* ---- Archive (multi-format reader/writer over archive.h) ---- */

static int ends_with_ci(const char *s, const char *suffix)
{
    size_t sl = strlen(s), tl = strlen(suffix);
    if (tl > sl) return 0;
    return strcasecmp(s + sl - tl, suffix) == 0;
}

static cc_archive_format format_from_path(const char *path)
{
    if (ends_with_ci(path, ".cute"))    return CC_ARCHIVE_CUTE;
    if (ends_with_ci(path, ".zip"))     return CC_ARCHIVE_ZIP;
    if (ends_with_ci(path, ".tar.gz"))  return CC_ARCHIVE_TAR_GZ;
    if (ends_with_ci(path, ".tgz"))     return CC_ARCHIVE_TAR_GZ;
    if (ends_with_ci(path, ".tar.bz2")) return CC_ARCHIVE_TAR_BZ2;
    if (ends_with_ci(path, ".tbz2"))    return CC_ARCHIVE_TAR_BZ2;
    if (ends_with_ci(path, ".tar.xz"))  return CC_ARCHIVE_TAR_XZ;
    if (ends_with_ci(path, ".txz"))     return CC_ARCHIVE_TAR_XZ;
    if (ends_with_ci(path, ".tar"))     return CC_ARCHIVE_TAR;
    if (ends_with_ci(path, ".7z"))      return CC_ARCHIVE_SEVEN_Z;
    if (ends_with_ci(path, ".rar"))     return CC_ARCHIVE_RAR;
    return CC_ARCHIVE_UNKNOWN;
}

static cc_archive_format format_from_name(const char *name)
{
    if (!strcasecmp(name, "cute"))    return CC_ARCHIVE_CUTE;
    if (!strcasecmp(name, "zip"))     return CC_ARCHIVE_ZIP;
    if (!strcasecmp(name, "tar"))     return CC_ARCHIVE_TAR;
    if (!strcasecmp(name, "tar.gz"))  return CC_ARCHIVE_TAR_GZ;
    if (!strcasecmp(name, "tgz"))     return CC_ARCHIVE_TAR_GZ;
    if (!strcasecmp(name, "tar.bz2")) return CC_ARCHIVE_TAR_BZ2;
    if (!strcasecmp(name, "tar.xz"))  return CC_ARCHIVE_TAR_XZ;
    if (!strcasecmp(name, "7z"))      return CC_ARCHIVE_SEVEN_Z;
    if (!strcasecmp(name, "rar"))     return CC_ARCHIVE_RAR;
    return CC_ARCHIVE_UNKNOWN;
}

static void json_print_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\b': fputs("\\b", f);  break;
        case '\f': fputs("\\f", f);  break;
        case '\n': fputs("\\n", f);  break;
        case '\r': fputs("\\r", f);  break;
        case '\t': fputs("\\t", f);  break;
        default:
            if (*p < 0x20) fprintf(f, "\\u%04x", *p);
            else fputc(*p, f);
        }
    }
    fputc('"', f);
}

static int cmd_archive_detect(const char *path)
{
    cc_archive_format fmt = cc_archive_detect_path(path);
    if (fmt == CC_ARCHIVE_UNKNOWN) {
        printf("unknown\n");
        return 1;
    }
    printf("%s\n", cc_archive_format_name(fmt));
    return 0;
}

static int cmd_archive_list(const char *path)
{
    cc_archive *a = cc_archive_open(path);
    if (!a) {
        fprintf(stderr, "error: cannot open archive %s\n", path);
        return 1;
    }
    int count = cc_archive_count(a);
    printf("{\"format\":");
    json_print_string(stdout, cc_archive_format_name(cc_archive_format_of(a)));
    printf(",\"count\":%d,\"entries\":[", count);
    for (int i = 0; i < count; i++) {
        const cc_archive_entry *e = cc_archive_entry_at(a, i);
        if (!e) continue;
        if (i > 0) fputc(',', stdout);
        printf("{\"path\":");
        json_print_string(stdout, e->path);
        printf(",\"size\":%llu,\"compressed_size\":%llu,\"mtime\":%llu,"
               "\"is_dir\":%s,\"is_encrypted\":%s,\"is_symlink\":%s}",
            (unsigned long long)e->size,
            (unsigned long long)e->compressed_size,
            (unsigned long long)e->mtime,
            e->is_dir ? "true" : "false",
            e->is_encrypted ? "true" : "false",
            e->is_symlink ? "true" : "false");
    }
    printf("]}\n");
    cc_archive_close(a);
    return 0;
}

static int cmd_archive_extract(int argc, char **argv)
{
    /* archive extract <path> -o <dest> [-i <index>] */
    const char *src = NULL, *dest = NULL;
    int index = -1;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) dest = argv[++i];
        else if (!strcmp(argv[i], "-i") && i + 1 < argc) index = atoi(argv[++i]);
        else if (!src) src = argv[i];
    }
    if (!src || !dest) {
        fprintf(stderr, "usage: archive extract <path> -o <dest> [-i <index>]\n");
        return 1;
    }
    cc_archive *a = cc_archive_open(src);
    if (!a) {
        fprintf(stderr, "error: cannot open archive %s\n", src);
        return 1;
    }
    int rc;
    if (index >= 0) {
        rc = cc_archive_extract_to(a, index, dest);
        if (rc == 0) printf("extracted entry %d → %s\n", index, dest);
    } else {
        rc = cc_archive_extract_all(a, dest);
        if (rc == 0) printf("extracted %d entries → %s\n", cc_archive_count(a), dest);
    }
    cc_archive_close(a);
    if (rc != 0) {
        fprintf(stderr, "error: extract failed (%d)\n", rc);
        return 1;
    }
    return 0;
}

static int cmd_archive_create(int argc, char **argv)
{
    /* archive create [-f <fmt>] <out> <files...>
     * Format defaults to whatever the output extension implies. */
    cc_archive_format fmt = CC_ARCHIVE_UNKNOWN;
    const char *out = NULL;
    int first_input = -1;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            fmt = format_from_name(argv[++i]);
            if (fmt == CC_ARCHIVE_UNKNOWN) {
                fprintf(stderr, "error: unknown format '%s'\n", argv[i]);
                return 1;
            }
        } else if (!out) {
            out = argv[i];
        } else {
            first_input = i;
            break;
        }
    }
    if (!out || first_input < 0) {
        fprintf(stderr, "usage: archive create [-f <fmt>] <out> <files...>\n");
        return 1;
    }
    if (fmt == CC_ARCHIVE_UNKNOWN) fmt = format_from_path(out);
    if (fmt == CC_ARCHIVE_UNKNOWN) fmt = CC_ARCHIVE_CUTE; /* sensible default */

    cc_archive_writer *w = cc_archive_create(out, fmt);
    if (!w) {
        fprintf(stderr,
            "error: archive create not yet implemented in libcutecontainer\n"
            "       (cc_archive_create / depo_archive_encrypt are stubs).\n"
            "       Reading side (detect/list/extract) is fully functional.\n");
        return 2;
    }
    int added = 0;
    for (int i = first_input; i < argc; i++) {
        const char *disk = argv[i];
        /* archive_path = basename of disk path */
        const char *slash = strrchr(disk, '/');
        const char *name = slash ? slash + 1 : disk;
        int rc = cc_archive_add_file(w, name, disk);
        if (rc != 0) {
            fprintf(stderr, "warning: skipped %s (%d)\n", disk, rc);
            continue;
        }
        added++;
    }
    int rc = cc_archive_finish(w);
    cc_archive_writer_destroy(w);
    if (rc != 0) {
        fprintf(stderr, "error: finish failed (%d)\n", rc);
        return 1;
    }
    printf("created %s (%s, %d entries)\n", out, cc_archive_format_name(fmt), added);
    return 0;
}

static int cmd_archive(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
            "usage:\n"
            "  cutecontainer archive detect <path>\n"
            "  cutecontainer archive list <path>\n"
            "  cutecontainer archive extract <path> -o <dest> [-i <index>]\n"
            "  cutecontainer archive create [-f <fmt>] <out> <files...>\n"
            "    formats: cute zip tar tar.gz tar.bz2 tar.xz 7z\n"
        );
        return 1;
    }
    const char *sub = argv[0];
    if (!strcmp(sub, "detect")  && argc >= 2) return cmd_archive_detect(argv[1]);
    if (!strcmp(sub, "list")    && argc >= 2) return cmd_archive_list(argv[1]);
    if (!strcmp(sub, "extract")           )   return cmd_archive_extract(argc - 1, argv + 1);
    if (!strcmp(sub, "create")            )   return cmd_archive_create(argc - 1, argv + 1);

    fprintf(stderr, "error: unknown archive subcommand '%s'\n", sub);
    return 1;
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

    if (strcmp(cmd, "archive") == 0)
        return cmd_archive(argc - 2, argv + 2);

    /* auto-detect: just a file path */
    return cmd_auto(argv[1]);
}
