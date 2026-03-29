/*
 * spectral.c — spectral mode utilities and image lifecycle
 */

#include "cutecontainer/film.h"
#include <stdlib.h>
#include <string.h>

int cf_bands_for_mode(cf_spectral_mode mode)
{
    switch (mode) {
    case CF_SPECTRAL_128: return 4;
    case CF_SPECTRAL_256: return 8;
    case CF_SPECTRAL_512: return 16;
    default:              return -1;
    }
}

float cf_wavelength_for_band(const cf_image *img, int band)
{
    if (!img || band < 0 || band >= img->num_bands) return 0.0f;
    if (img->num_bands <= 1) return img->wavelength_min;

    /* evenly spaced band centers across the wavelength range */
    float step = (img->wavelength_max - img->wavelength_min) / (float)(img->num_bands - 1);
    return img->wavelength_min + step * (float)band;
}

cf_image *cf_image_create(uint32_t width, uint32_t height, cf_spectral_mode mode)
{
    return cf_image_create_ex(width, height, mode,
                              CF_DEFAULT_WL_MIN, CF_DEFAULT_WL_MAX);
}

cf_image *cf_image_create_ex(uint32_t width, uint32_t height, cf_spectral_mode mode,
                             float wl_min, float wl_max)
{
    int nb = cf_bands_for_mode(mode);
    if (nb < 0 || width == 0 || height == 0) return NULL;

    cf_image *img = calloc(1, sizeof(cf_image));
    if (!img) return NULL;

    size_t npixels = (size_t)width * height;
    img->data = calloc(npixels * (size_t)nb, sizeof(float));
    if (!img->data) { free(img); return NULL; }

    img->width          = width;
    img->height         = height;
    img->mode           = mode;
    img->num_bands      = (uint16_t)nb;
    img->wavelength_min = wl_min;
    img->wavelength_max = wl_max;
    return img;
}

void cf_image_destroy(cf_image *img)
{
    if (!img) return;
    free(img->data);
    free(img);
}

float *cf_image_pixel(cf_image *img, uint32_t x, uint32_t y)
{
    if (!img || x >= img->width || y >= img->height) return NULL;
    size_t idx = ((size_t)y * img->width + (size_t)x) * img->num_bands;
    return &img->data[idx];
}

const float *cf_image_pixel_const(const cf_image *img, uint32_t x, uint32_t y)
{
    if (!img || x >= img->width || y >= img->height) return NULL;
    size_t idx = ((size_t)y * img->width + (size_t)x) * img->num_bands;
    return &img->data[idx];
}
