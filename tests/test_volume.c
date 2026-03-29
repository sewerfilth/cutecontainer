/*
 * test_volume.c — volume build, mount, query, load
 */

#include "cutecontainer/volume.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#define unlink _unlink
#endif

static int test_build_and_mount(void)
{
    printf("  build + mount ... ");
    const char *path = "/tmp/test_vol.cute";

    cc_vol_builder *b = cc_vol_builder_create(path);
    if (!b) { printf("FAIL (builder)\n"); return 1; }

    /* add some fake game assets */
    const char *tex = "RGBA pixel data here for a brick texture 1234567890";
    cc_vol_builder_add_buf(b, "textures/brick.png", tex, strlen(tex), CC_VOL_COMPRESS);
    cc_vol_builder_set_wrap(b, 0x0010); /* CC_WRAP_TEXTURE */
    cc_vol_builder_set_group(b, 1);

    const char *shader = "void main() { gl_Position = mvp * pos; }";
    cc_vol_builder_add_buf(b, "shaders/main.vert", shader, strlen(shader), CC_VOL_RAW);
    cc_vol_builder_set_wrap(b, 0x0016); /* CC_WRAP_SHADER */
    cc_vol_builder_set_group(b, 2);

    const char *cfg = "{\"version\":1,\"title\":\"My Game\"}";
    cc_vol_builder_add_buf(b, "config.json", cfg, strlen(cfg), CC_VOL_RAW);

    /* big compressible asset */
    size_t mesh_sz = 64 * 1024;
    uint8_t *mesh = malloc(mesh_sz);
    for (size_t i = 0; i < mesh_sz; i++) mesh[i] = (uint8_t)(i & 0x1F);
    cc_vol_builder_add_buf(b, "meshes/player.mesh", mesh, mesh_sz, CC_VOL_COMPRESS);
    cc_vol_builder_set_wrap(b, 0x0006); /* CC_WRAP_GEOMETRY */
    cc_vol_builder_set_group(b, 1);
    free(mesh);

    int rc = cc_vol_builder_finish(b);
    cc_vol_builder_destroy(b);
    if (rc != 0) { printf("FAIL (finish)\n"); return 1; }

    /* mount */
    cc_volume *vol = cc_vol_mount(path);
    if (!vol) { printf("FAIL (mount)\n"); return 1; }

    if (cc_vol_asset_count(vol) != 4) {
        printf("FAIL (count=%d)\n", cc_vol_asset_count(vol));
        cc_vol_unmount(vol); return 1;
    }

    cc_vol_unmount(vol);
    unlink(path);
    printf("OK (4 assets)\n");
    return 0;
}

static int test_query(void)
{
    printf("  query by path/group/prefix/type ... ");
    const char *path = "/tmp/test_vol2.cute";

    cc_vol_builder *b = cc_vol_builder_create(path);
    for (int i = 0; i < 10; i++) {
        char name[64];
        snprintf(name, sizeof(name), "textures/tile_%02d.png", i);
        char data[32]; snprintf(data, sizeof(data), "tile%d", i);
        cc_vol_builder_add_buf(b, name, data, strlen(data), CC_VOL_RAW);
        cc_vol_builder_set_wrap(b, 0x0010);
        cc_vol_builder_set_group(b, 1);
    }
    for (int i = 0; i < 5; i++) {
        char name[64];
        snprintf(name, sizeof(name), "audio/sfx_%02d.wav", i);
        char data[32]; snprintf(data, sizeof(data), "sfx%d", i);
        cc_vol_builder_add_buf(b, name, data, strlen(data), CC_VOL_RAW);
        cc_vol_builder_set_wrap(b, 0x0003);
        cc_vol_builder_set_group(b, 2);
    }
    cc_vol_builder_finish(b);
    cc_vol_builder_destroy(b);

    cc_volume *vol = cc_vol_mount(path);
    if (!vol) { printf("FAIL (mount)\n"); return 1; }

    /* find by path */
    int idx = cc_vol_find(vol, "textures/tile_05.png");
    if (idx < 0) { printf("FAIL (find)\n"); cc_vol_unmount(vol); return 1; }

    /* find by prefix */
    int found[32];
    int n = cc_vol_find_prefix(vol, "audio/", found, 32);
    if (n != 5) { printf("FAIL (prefix=%d)\n", n); cc_vol_unmount(vol); return 1; }

    /* find by group */
    n = cc_vol_find_group(vol, 1, found, 32);
    if (n != 10) { printf("FAIL (group=%d)\n", n); cc_vol_unmount(vol); return 1; }

    /* find by type */
    n = cc_vol_find_type(vol, 0x0010, found, 32);
    if (n != 10) { printf("FAIL (type=%d)\n", n); cc_vol_unmount(vol); return 1; }

    cc_vol_unmount(vol);
    unlink(path);
    printf("OK\n");
    return 0;
}

static int test_load(void)
{
    printf("  load (raw + compressed) ... ");
    const char *path = "/tmp/test_vol3.cute";

    const char *raw_data = "hello from the volume";
    size_t comp_sz = 32 * 1024;
    uint8_t *comp_data = malloc(comp_sz);
    for (size_t i = 0; i < comp_sz; i++) comp_data[i] = (uint8_t)(i % 37);

    cc_vol_builder *b = cc_vol_builder_create(path);
    cc_vol_builder_add_buf(b, "raw.txt", raw_data, strlen(raw_data), CC_VOL_RAW);
    cc_vol_builder_add_buf(b, "data.bin", comp_data, comp_sz, CC_VOL_COMPRESS);
    cc_vol_builder_finish(b);
    cc_vol_builder_destroy(b);

    cc_volume *vol = cc_vol_mount(path);

    /* load raw */
    size_t len = 0;
    char *loaded = cc_vol_load(vol, "raw.txt", &len);
    if (!loaded || len != strlen(raw_data) || memcmp(loaded, raw_data, len) != 0) {
        printf("FAIL (raw)\n");
        cc_vol_free(loaded); free(comp_data); cc_vol_unmount(vol); return 1;
    }
    cc_vol_free(loaded);

    /* load compressed */
    uint8_t *loaded2 = cc_vol_load(vol, "data.bin", &len);
    if (!loaded2 || len != comp_sz || memcmp(loaded2, comp_data, comp_sz) != 0) {
        printf("FAIL (compressed)\n");
        cc_vol_free(loaded2); free(comp_data); cc_vol_unmount(vol); return 1;
    }
    cc_vol_free(loaded2);

    /* check compression ratio */
    const cc_vol_entry *e = cc_vol_asset_entry(vol, 1);
    printf("OK (%.1f%% ratio on 32KB)\n",
           (double)e->stored_size / (double)e->original_size * 100.0);

    free(comp_data);
    cc_vol_unmount(vol);
    unlink(path);
    return 0;
}

static int test_size(void)
{
    printf("  volume overhead ... ");
    const char *path = "/tmp/test_vol4.cute";

    cc_vol_builder *b = cc_vol_builder_create(path);
    for (int i = 0; i < 100; i++) {
        char name[64]; snprintf(name, sizeof(name), "asset_%03d.dat", i);
        uint8_t data[64]; memset(data, (uint8_t)i, 64);
        cc_vol_builder_add_buf(b, name, data, 64, CC_VOL_RAW);
    }
    cc_vol_builder_finish(b);
    cc_vol_builder_destroy(b);

    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long total = ftell(f);
    fclose(f);

    long payload = 100 * 64;
    long overhead = total - payload;

    printf("%ld bytes total, %ld payload, %ld overhead (%.0f bytes/asset)\n",
           total, payload, overhead, (double)overhead / 100.0);

    unlink(path);
    return 0;
}

int main(void)
{
    int fails = 0;
    printf("volume tests:\n");
    fails += test_build_and_mount();
    fails += test_query();
    fails += test_load();
    fails += test_size();
    printf("\n%s (%d failures)\n", fails ? "FAIL" : "ALL PASSED", fails);
    return fails ? 1 : 0;
}
