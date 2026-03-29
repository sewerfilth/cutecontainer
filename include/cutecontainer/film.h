/*
 * film.h — spectral image codec
 *
 * 128/256/512-bit spectral bands, CIE 1931, film curves,
 * Metal GPU develop pipeline, format import.
 */

#ifndef CUTECONTAINER_FILM_H
#define CUTECONTAINER_FILM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Spectral modes */
typedef enum {
    CF_SPECTRAL_128 = 0,
    CF_SPECTRAL_256 = 1,
    CF_SPECTRAL_512 = 2
} cf_spectral_mode;

/* CFSP container constants (legacy format, used internally by encode/decode) */
#define CF_MAGIC            "CFSP"
#define CF_VERSION          0x01
#define CF_HEADER_SIZE      64
#define CF_FLAG_ENCRYPTED   0x01

#define CF_DEFAULT_WL_MIN   380.0f
#define CF_DEFAULT_WL_MAX   780.0f

/* Error codes */
#define CF_OK               0
#define CF_ERR_IO           (-1)
#define CF_ERR_FORMAT       (-2)
#define CF_ERR_CORRUPT      (-3)
#define CF_ERR_NOMEM        (-4)
#define CF_ERR_DECRYPT      (-5)

/* Image */
typedef struct {
    uint32_t          width;
    uint32_t          height;
    cf_spectral_mode  mode;
    uint16_t          num_bands;
    float             wavelength_min;
    float             wavelength_max;
    float            *data;
} cf_image;

/* Lifecycle */
cf_image *cf_image_create(uint32_t w, uint32_t h, cf_spectral_mode mode);
cf_image *cf_image_create_ex(uint32_t w, uint32_t h, cf_spectral_mode mode,
                             float wl_min, float wl_max);
void      cf_image_destroy(cf_image *img);

/* Pixel access */
float       *cf_image_pixel(cf_image *img, uint32_t x, uint32_t y);
const float *cf_image_pixel_const(const cf_image *img, uint32_t x, uint32_t y);

/* Spectral utilities */
int   cf_bands_for_mode(cf_spectral_mode mode);
float cf_wavelength_for_band(const cf_image *img, int band);

/* ASM hot paths (weak C, per-arch ASM override) */
void cf_delta_encode_row(uint32_t *row, size_t width);
void cf_delta_decode_row(uint32_t *row, size_t width);
void cf_deinterleave_band(const float *bip, float *plane, size_t npix, int nb, int band);
void cf_interleave_band(float *bip, const float *plane, size_t npix, int nb, int band);

/* Spectral ↔ RGB */
int cf_spectral_to_rgba(const cf_image *img, float *rgba_out);
int cf_spectral_to_rgba_metal(const cf_image *img, float *rgba_out);

/* RGB → spectral uplift (import from existing formats) */
int cf_rgba_to_spectral(const float *rgba, uint32_t w, uint32_t h,
                        cf_spectral_mode mode, cf_image **img_out);

/* Film curve */
typedef struct {
    float base_fog, toe_limit, shoulder_limit;
    float gamma, max_density, iso;
} cf_film_curve;

cf_film_curve cf_film_curve_default(void);
cf_film_curve cf_film_curve_negative(void);
cf_film_curve cf_film_curve_reversal(void);
cf_film_curve cf_film_curve_cinema(void);

/* GPU develop pipeline */
int cf_film_develop_metal(const float *energy, const float *weight,
                          uint32_t w, uint32_t h, int nb, const float *wl,
                          const cf_film_curve *curve, float *rgba_out);
int cf_film_develop_cpu(const float *energy, const float *weight,
                        uint32_t w, uint32_t h, int nb, const float *wl,
                        const cf_film_curve *curve, float *rgba_out);

/* Encode / decode (uses container format internally) */
int cf_encode(const cf_image *img, uint8_t **out, size_t *out_len, int level);
int cf_decode(const uint8_t *data, size_t data_len, cf_image **img);
int cf_encode_file(const cf_image *img, const char *path, int level);
int cf_decode_file(const char *path, cf_image **img);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_FILM_H */
