/*
 * test_wrap.c — wrapper metadata roundtrip + composition tests
 */

#include "cutecontainer/wrap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_image_wrap(void)
{
    printf("  image wrapper ... ");
    cc_wrap_set ws;
    cc_wrap_init(&ws);

    cc_wrap_image img = {
        .width = 1920, .height = 1080,
        .pixel_format = CC_PF_FLOAT32,
        .channels = CC_CH_RGBA,
        .color_space = CC_CS_ACES_CG,
        .num_channels = 4,
        .dpi = 72.0f,
    };
    cc_wrap_add(&ws, CC_WRAP_IMAGE, &img, sizeof(img));

    /* serialize */
    uint8_t *buf = NULL; size_t len = 0;
    if (cc_wrap_serialize(&ws, &buf, &len) != 0) { printf("FAIL (serialize)\n"); return 1; }

    /* deserialize */
    cc_wrap_set ws2;
    if (cc_wrap_deserialize(&ws2, buf, len) != 0) { printf("FAIL (deserialize)\n"); free(buf); return 1; }
    free(buf);

    size_t sz;
    const cc_wrap_image *found = cc_wrap_find(&ws2, CC_WRAP_IMAGE, &sz);
    if (!found || sz != sizeof(cc_wrap_image)) { printf("FAIL (find)\n"); return 1; }
    if (found->width != 1920 || found->height != 1080) { printf("FAIL (data)\n"); return 1; }
    if (found->color_space != CC_CS_ACES_CG) { printf("FAIL (cs)\n"); return 1; }

    /* free wrap data */
    for (uint32_t i = 0; i < ws.count; i++) free((void*)ws.wraps[i].data);
    for (uint32_t i = 0; i < ws2.count; i++) free((void*)ws2.wraps[i].data);

    printf("OK\n"); return 0;
}

static int test_composition(void)
{
    printf("  composition (image + spectral + profile) ... ");
    cc_wrap_set ws;
    cc_wrap_init(&ws);

    cc_wrap_image img = { .width = 4096, .height = 2160, .channels = CC_CH_SPECTRAL,
                          .num_channels = 8, .pixel_format = CC_PF_FLOAT32,
                          .color_space = CC_CS_SPECTRAL };
    cc_wrap_spectral spec = { .width = 4096, .height = 2160, .num_bands = 8,
                              .bits_per_band = 32, .wavelength_min = 380.f,
                              .wavelength_max = 780.f, .spectral_mode = 1 };
    cc_wrap_profile prof = { .color_space = CC_CS_ACES_CG,
                             .white_point = {0.3127f, 0.3290f} };

    cc_wrap_add(&ws, CC_WRAP_IMAGE, &img, sizeof(img));
    cc_wrap_add(&ws, CC_WRAP_SPECTRAL, &spec, sizeof(spec));
    cc_wrap_add(&ws, CC_WRAP_PROFILE, &prof, sizeof(prof));

    if (ws.count != 3) { printf("FAIL (count)\n"); return 1; }

    /* roundtrip */
    uint8_t *buf = NULL; size_t len = 0;
    cc_wrap_serialize(&ws, &buf, &len);
    cc_wrap_set ws2;
    cc_wrap_deserialize(&ws2, buf, len);
    free(buf);

    if (ws2.count != 3) { printf("FAIL (rt count)\n"); return 1; }

    const cc_wrap_spectral *s = cc_wrap_find(&ws2, CC_WRAP_SPECTRAL, NULL);
    if (!s || s->num_bands != 8) { printf("FAIL (spectral)\n"); return 1; }

    const cc_wrap_profile *p = cc_wrap_find(&ws2, CC_WRAP_PROFILE, NULL);
    if (!p || p->color_space != CC_CS_ACES_CG) { printf("FAIL (profile)\n"); return 1; }

    for (uint32_t i = 0; i < ws.count; i++) free((void*)ws.wraps[i].data);
    for (uint32_t i = 0; i < ws2.count; i++) free((void*)ws2.wraps[i].data);

    printf("OK\n"); return 0;
}

static int test_variant(void)
{
    printf("  variants (HDR + proxy) ... ");
    cc_wrap_set ws;
    cc_wrap_init(&ws);

    cc_wrap_variant hdr = {0};
    memcpy(hdr.name, "hdr", 3);
    hdr.wrap_type = CC_WRAP_IMAGE;
    hdr.payload_offset = 0;
    hdr.payload_size = 1000000;

    cc_wrap_variant proxy = {0};
    memcpy(proxy.name, "proxy", 5);
    proxy.wrap_type = CC_WRAP_IMAGE;
    proxy.payload_offset = 1000000;
    proxy.payload_size = 50000;

    cc_wrap_add_variant(&ws, &hdr);
    cc_wrap_add_variant(&ws, &proxy);

    if (ws.variant_count != 2) { printf("FAIL\n"); return 1; }

    printf("OK\n"); return 0;
}

static int test_probe(void)
{
    printf("  file probing ... ");
    cc_wrap_set ws;

    cc_wrap_probe_file("test.png", &ws);
    if (!cc_wrap_find(&ws, CC_WRAP_IMAGE, NULL)) { printf("FAIL (png)\n"); return 1; }
    for (uint32_t i = 0; i < ws.count; i++) free((void*)ws.wraps[i].data);

    cc_wrap_probe_file("scene.usd", &ws);
    if (!cc_wrap_find(&ws, CC_WRAP_SCENE, NULL)) { printf("FAIL (usd)\n"); return 1; }
    for (uint32_t i = 0; i < ws.count; i++) free((void*)ws.wraps[i].data);

    cc_wrap_probe_file("model.onnx", &ws);
    if (!cc_wrap_find(&ws, CC_WRAP_MODEL, NULL)) { printf("FAIL (onnx)\n"); return 1; }
    for (uint32_t i = 0; i < ws.count; i++) free((void*)ws.wraps[i].data);

    printf("OK\n"); return 0;
}

static int test_type_names(void)
{
    printf("  type names ... ");
    if (strcmp(cc_wrap_type_name(CC_WRAP_SCENE), "scene") != 0) { printf("FAIL\n"); return 1; }
    if (strcmp(cc_wrap_type_name(CC_WRAP_TIMELINE), "timeline") != 0) { printf("FAIL\n"); return 1; }
    printf("OK\n"); return 0;
}

int main(void)
{
    int fails = 0;
    printf("wrap tests:\n");
    fails += test_image_wrap();
    fails += test_composition();
    fails += test_variant();
    fails += test_probe();
    fails += test_type_names();
    printf("\n%s (%d failures)\n", fails ? "FAIL" : "ALL PASSED", fails);
    return fails ? 1 : 0;
}
