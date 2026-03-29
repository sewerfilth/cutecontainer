/*
 * film_develop.c — film curve presets + CPU fold+develop fallback
 *
 * Parity with gfx_film_curve presets and _fold_tile / _dev_tile from
 * gfx_film.c. The Metal GPU path in metal_spectral.m overrides this
 * for cf_film_develop_metal().
 */

#include "cutecontainer/film.h"
#include <math.h>
#include <string.h>

/* ---- CIE data from cie1931.c ---- */
extern const float  cf_cie1931_cmf[81][3];
extern const size_t cf_cie1931_count;
extern const float  cf_cie1931_wl_min;
extern const float  cf_cie1931_wl_step;

/* ---- Film curve presets (mirror gfx_film.c) ---- */

cf_film_curve cf_film_curve_default(void) {
    return (cf_film_curve){
        .base_fog = -0.15f, .toe_limit = 0.002f,
        .shoulder_limit = 10.0f, .gamma = 0.65f,
        .max_density = 3.0f, .iso = 400.0f,
    };
}

cf_film_curve cf_film_curve_negative(void) {
    return (cf_film_curve){
        .base_fog = -0.25f, .toe_limit = 0.001f,
        .shoulder_limit = 50.0f, .gamma = 0.55f,
        .max_density = 3.5f, .iso = 800.0f,
    };
}

cf_film_curve cf_film_curve_reversal(void) {
    return (cf_film_curve){
        .base_fog = -0.08f, .toe_limit = 0.01f,
        .shoulder_limit = 5.0f, .gamma = 0.80f,
        .max_density = 4.0f, .iso = 100.0f,
    };
}

cf_film_curve cf_film_curve_cinema(void) {
    return (cf_film_curve){
        .base_fog = -0.20f, .toe_limit = 0.0005f,
        .shoulder_limit = 100.0f, .gamma = 0.50f,
        .max_density = 5.0f, .iso = 800.0f,
    };
}

/* ---- CIE interpolation ---- */

static void cmf_at(float wl, float *xb, float *yb, float *zb)
{
    if (wl < cf_cie1931_wl_min || wl > 780.0f) {
        *xb = *yb = *zb = 0.0f;
        return;
    }
    float t = (wl - cf_cie1931_wl_min) / cf_cie1931_wl_step;
    int i0 = (int)t;
    if (i0 < 0) i0 = 0;
    if ((size_t)i0 >= cf_cie1931_count - 1) i0 = (int)cf_cie1931_count - 2;
    float f = t - (float)i0;
    *xb = cf_cie1931_cmf[i0][0] + f * (cf_cie1931_cmf[i0+1][0] - cf_cie1931_cmf[i0][0]);
    *yb = cf_cie1931_cmf[i0][1] + f * (cf_cie1931_cmf[i0+1][1] - cf_cie1931_cmf[i0][1]);
    *zb = cf_cie1931_cmf[i0][2] + f * (cf_cie1931_cmf[i0+1][2] - cf_cie1931_cmf[i0][2]);
}

/* ---- CPU fold+develop (matches gfx_film _fold_tile + _dev_tile) ---- */

static inline float clamp01f(float v) { return v < 0.f ? 0.f : (v > 1.f ? 1.f : v); }

int cf_film_develop_cpu(const float *accum_energy, const float *accum_weight,
                        uint32_t width, uint32_t height,
                        int num_bands, const float *band_wavelengths,
                        const cf_film_curve *curve,
                        float *rgba_out)
{
    if (!accum_energy || !accum_weight || !band_wavelengths || !curve || !rgba_out)
        return CF_ERR_IO;
    if (num_bands < 1 || num_bands > 16) return CF_ERR_FORMAT;

    /* precompute CIE CMFs + bandwidth */
    float cmf_x[16], cmf_y[16], cmf_z[16], bw[16];
    float wl_step = (num_bands > 1)
        ? (band_wavelengths[num_bands-1] - band_wavelengths[0]) / (float)(num_bands - 1)
        : 300.0f;

    for (int b = 0; b < num_bands; b++) {
        cmf_at(band_wavelengths[b], &cmf_x[b], &cmf_y[b], &cmf_z[b]);
        bw[b] = wl_step / 300.0f;  /* normalize bandwidth (matches gfx_film.c) */
    }

    size_t npix = (size_t)width * height;

    for (size_t i = 0; i < npix; i++) {
        float X = 0, Y = 0, Z = 0;

        for (int b = 0; b < num_bands; b++) {
            size_t ai = i * num_bands + b;
            float w = accum_weight[ai];
            float val = (w > 0.0f)
                ? accum_energy[ai] / w
                : curve->base_fog;

            /* apply film curve: exposure → density → linear */
            float exposure = val * curve->iso;
            float density;

            if (exposure <= curve->toe_limit) {
                /* toe region */
                float toe_density = curve->gamma * log10f(curve->toe_limit + 1e-10f);
                density = curve->base_fog +
                    (exposure / curve->toe_limit) * (toe_density - curve->base_fog);
            } else if (exposure >= curve->shoulder_limit) {
                /* shoulder region */
                float ld = curve->gamma * log10f(exposure + 1e-10f);
                float st = (exposure - curve->shoulder_limit) / (curve->shoulder_limit * 2.0f);
                if (st > 1.0f) st = 1.0f;
                density = ld + (curve->max_density - ld) * st;
            } else {
                /* linear region */
                density = curve->gamma * log10f(exposure + 1e-10f);
            }

            if (density > curve->max_density) density = curve->max_density;
            float linear = powf(10.0f, density);

            X += linear * cmf_x[b] * bw[b];
            Y += linear * cmf_y[b] * bw[b];
            Z += linear * cmf_z[b] * bw[b];
        }

        /* XYZ → linear sRGB */
        float *out = &rgba_out[i * 4];
        out[0] = clamp01f( 3.2404542f * X - 1.5371385f * Y - 0.4985314f * Z);
        out[1] = clamp01f(-0.9692660f * X + 1.8760108f * Y + 0.0415560f * Z);
        out[2] = clamp01f( 0.0556434f * X - 0.2040259f * Y + 1.0572252f * Z);
        out[3] = 1.0f;
    }

    return CF_OK;
}
