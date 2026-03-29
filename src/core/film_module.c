/*
 * film_module.c — built-in film module (spectral codec)
 */

#include "cutecontainer/sdk.h"
#include "cutecontainer/film.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int film_probe(const uint8_t *header, size_t len)
{
    if (len < 4) return 0;
    return memcmp(header, CF_MAGIC, 4) == 0;
}

static int film_encode(const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len,
                       const cc_opt *opts)
{
    /* film encode expects structured cf_image, not raw bytes.
     * for the SDK path, treat input as raw float BIP spectral data
     * with dimensions + mode from options. */
    uint32_t w = 0, h = 0;
    int mode_bits = 256;
    int level = 5;

    if (opts) {
        for (const cc_opt *o = opts; o->key; o++) {
            if (strcmp(o->key, "width") == 0)  w = (uint32_t)atoi(o->value);
            if (strcmp(o->key, "height") == 0) h = (uint32_t)atoi(o->value);
            if (strcmp(o->key, "mode") == 0)   mode_bits = atoi(o->value);
            if (strcmp(o->key, "level") == 0)  level = atoi(o->value);
        }
    }

    if (w == 0 || h == 0) return CC_ERR_IO;

    cf_spectral_mode mode;
    switch (mode_bits) {
    case 128: mode = CF_SPECTRAL_128; break;
    case 256: mode = CF_SPECTRAL_256; break;
    case 512: mode = CF_SPECTRAL_512; break;
    default: return CC_ERR_FORMAT;
    }

    int nb = cf_bands_for_mode(mode);
    size_t expected = (size_t)w * h * nb * sizeof(float);
    if (in_len != expected) return CC_ERR_FORMAT;

    cf_image *img = cf_image_create(w, h, mode);
    if (!img) return CC_ERR_NOMEM;
    memcpy(img->data, in, in_len);

    int rc = cf_encode(img, out, out_len, level);
    cf_image_destroy(img);
    return rc;
}

static int film_decode(const uint8_t *in, size_t in_len,
                       uint8_t **out, size_t *out_len)
{
    cf_image *img = NULL;
    int rc = cf_decode(in, in_len, &img);
    if (rc != CF_OK) return rc;

    size_t sz = (size_t)img->width * img->height * img->num_bands * sizeof(float);
    uint8_t *buf = malloc(sz);
    if (!buf) { cf_image_destroy(img); return CC_ERR_NOMEM; }

    memcpy(buf, img->data, sz);
    cf_image_destroy(img);

    *out = buf;
    *out_len = sz;
    return CC_OK;
}

static int film_info(const uint8_t *data, size_t len, char *buf, size_t cap)
{
    if (len < CF_HEADER_SIZE) return CC_ERR_FORMAT;

    uint16_t mode_raw = (uint16_t)(data[6] | (data[7] << 8));
    uint32_t w = data[8]|(data[9]<<8)|(data[10]<<16)|(data[11]<<24);
    uint32_t h = data[12]|(data[13]<<8)|(data[14]<<16)|(data[15]<<24);
    uint16_t nb = (uint16_t)(data[16] | (data[17] << 8));
    uint16_t bps = (uint16_t)(data[18] | (data[19] << 8));

    float wl_min, wl_max;
    uint32_t u;
    u = data[20]|(data[21]<<8)|(data[22]<<16)|(data[23]<<24); memcpy(&wl_min, &u, 4);
    u = data[24]|(data[25]<<8)|(data[26]<<16)|(data[27]<<24); memcpy(&wl_max, &u, 4);

    const char *mode_str = "unknown";
    switch (mode_raw) {
    case 0: mode_str = "128 (4 bands)"; break;
    case 1: mode_str = "256 (8 bands)"; break;
    case 2: mode_str = "512 (16 bands)"; break;
    }

    snprintf(buf, cap,
        "format:     cutefilm spectral (CFSP v%d)\n"
        "mode:       %s\n"
        "resolution: %u x %u\n"
        "bands:      %u @ %u bits/sample\n"
        "wavelength: %.0f – %.0f nm\n"
        "bits/pixel: %u\n",
        data[4], mode_str, w, h, nb, bps, wl_min, wl_max, nb * bps);
    return CC_OK;
}

static void film_free(void *buf) { free(buf); }

const cc_module cc_builtin_film = {
    .name        = "film",
    .description = "Spectral image codec (128/256/512-bit wavelength bands)",
    .type        = CC_TYPE_FILM,
    .sdk_version = CC_SDK_VERSION,
    .caps        = CC_CAP_ENCODE | CC_CAP_DECODE | CC_CAP_ASM | CC_CAP_GPU | CC_CAP_HARDWARE,
    .probe       = film_probe,
    .encode      = film_encode,
    .decode      = film_decode,
    .info        = film_info,
    .free_buf    = film_free,
};
