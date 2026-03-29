/*
 * test_film.c — spectral codec roundtrip
 */

#include "cutecontainer/film.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

static int test_mode(cf_spectral_mode mode, const char *label) {
    uint32_t w = 64, h = 48;
    int nb = cf_bands_for_mode(mode);
    printf("  %s (%d bands) ... ", label, nb);

    cf_image *img = cf_image_create(w, h, mode);
    if (!img) { printf("FAIL (create)\n"); return 1; }

    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            float *px = cf_image_pixel(img, x, y);
            for (int b = 0; b < nb; b++) {
                float wl = cf_wavelength_for_band(img, b);
                float d = (wl - 550.0f) / 80.0f;
                px[b] = expf(-0.5f * d * d) * ((float)x / w + 0.1f);
            }
        }

    uint8_t *buf = NULL; size_t len = 0;
    int rc = cf_encode(img, &buf, &len, 5);
    if (rc != CF_OK) { printf("FAIL (encode)\n"); cf_image_destroy(img); return 1; }

    cf_image *dec = NULL;
    rc = cf_decode(buf, len, &dec); free(buf);
    if (rc != CF_OK) { printf("FAIL (decode)\n"); cf_image_destroy(img); return 1; }

    size_t total = (size_t)w * h * nb;
    for (size_t i = 0; i < total; i++)
        if (img->data[i] != dec->data[i]) { printf("FAIL (data)\n"); cf_image_destroy(img); cf_image_destroy(dec); return 1; }

    cf_image_destroy(img); cf_image_destroy(dec);
    printf("OK\n"); return 0;
}

int main(void) {
    int fails = 0;
    printf("film tests:\n");
    fails += test_mode(CF_SPECTRAL_128, "128-bit");
    fails += test_mode(CF_SPECTRAL_256, "256-bit");
    fails += test_mode(CF_SPECTRAL_512, "512-bit");
    printf("\n%s (%d failures)\n", fails ? "FAIL" : "ALL PASSED", fails);
    return fails ? 1 : 0;
}
