/*
 * spectral_rgb.c — spectral → XYZ → linear sRGB conversion
 *
 * Integrates spectral bands against CIE 1931 2° standard observer
 * color matching functions using trapezoidal integration, then applies
 * the XYZ → linear sRGB (D65) matrix.
 */

#include "cutecontainer/film.h"
#include <string.h>

/* CIE 1931 data from cie1931.c */
extern const float  cf_cie1931_cmf[81][3];
extern const size_t cf_cie1931_count;
extern const float  cf_cie1931_wl_min;
extern const float  cf_cie1931_wl_max;
extern const float  cf_cie1931_wl_step;

/* ---- Interpolate CIE CMF at arbitrary wavelength ---- */

static void cmf_at(float wl, float *x_bar, float *y_bar, float *z_bar)
{
    if (wl < cf_cie1931_wl_min || wl > cf_cie1931_wl_max) {
        *x_bar = *y_bar = *z_bar = 0.0f;
        return;
    }

    float t = (wl - cf_cie1931_wl_min) / cf_cie1931_wl_step;
    int i0 = (int)t;
    if (i0 < 0) i0 = 0;
    if ((size_t)i0 >= cf_cie1931_count - 1) i0 = (int)cf_cie1931_count - 2;
    float frac = t - (float)i0;

    *x_bar = cf_cie1931_cmf[i0][0] + frac * (cf_cie1931_cmf[i0+1][0] - cf_cie1931_cmf[i0][0]);
    *y_bar = cf_cie1931_cmf[i0][1] + frac * (cf_cie1931_cmf[i0+1][1] - cf_cie1931_cmf[i0][1]);
    *z_bar = cf_cie1931_cmf[i0][2] + frac * (cf_cie1931_cmf[i0+1][2] - cf_cie1931_cmf[i0][2]);
}

/* ---- XYZ → linear sRGB (D65 illuminant, Rec. 709 primaries) ---- */

static inline float clamp01(float v) { return v < 0.f ? 0.f : (v > 1.f ? 1.f : v); }

static void xyz_to_srgb(float X, float Y, float Z, float *r, float *g, float *b)
{
    *r = clamp01( 3.2404542f * X - 1.5371385f * Y - 0.4985314f * Z);
    *g = clamp01(-0.9692660f * X + 1.8760108f * Y + 0.0415560f * Z);
    *b = clamp01( 0.0556434f * X - 0.2040259f * Y + 1.0572252f * Z);
}

/* ---- Public: convert spectral image to RGBA ---- */

int cf_spectral_to_rgba(const cf_image *img, float *rgba_out)
{
    if (!img || !rgba_out) return CF_ERR_IO;

    int nb = img->num_bands;
    size_t npixels = (size_t)img->width * img->height;

    /* precompute CMF values at each band center wavelength + delta_lambda */
    float *cmf_x = (float *)__builtin_alloca(nb * sizeof(float));
    float *cmf_y = (float *)__builtin_alloca(nb * sizeof(float));
    float *cmf_z = (float *)__builtin_alloca(nb * sizeof(float));
    float delta_lambda;

    if (nb == 1) {
        delta_lambda = 1.0f;
    } else {
        delta_lambda = (img->wavelength_max - img->wavelength_min) / (float)(nb - 1);
    }

    for (int b = 0; b < nb; b++) {
        float wl = cf_wavelength_for_band(img, b);
        cmf_at(wl, &cmf_x[b], &cmf_y[b], &cmf_z[b]);
        /* scale by delta_lambda for integration */
        cmf_x[b] *= delta_lambda;
        cmf_y[b] *= delta_lambda;
        cmf_z[b] *= delta_lambda;
    }

    /* normalize factor: integral of ȳ(λ) over visible range ≈ 106.86 for D65.
     * For equal-energy illuminant, ∫ȳ dλ ≈ 106.86.
     * We normalize so that a flat unit spectrum gives Y = 1. */
    float y_integral = 0.0f;
    for (int b = 0; b < nb; b++)
        y_integral += cmf_y[b];
    if (y_integral <= 0.0f) y_integral = 1.0f;
    float norm = 1.0f / y_integral;

    /* convert each pixel */
    for (size_t i = 0; i < npixels; i++) {
        const float *spec = &img->data[i * nb];
        float X = 0.0f, Y = 0.0f, Z = 0.0f;

        for (int b = 0; b < nb; b++) {
            float s = spec[b];
            X += s * cmf_x[b];
            Y += s * cmf_y[b];
            Z += s * cmf_z[b];
        }

        X *= norm;
        Y *= norm;
        Z *= norm;

        float *out = &rgba_out[i * 4];
        xyz_to_srgb(X, Y, Z, &out[0], &out[1], &out[2]);
        out[3] = 1.0f;
    }

    return CF_OK;
}
