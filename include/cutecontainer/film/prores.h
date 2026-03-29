/*
 * prores.h — ProRes encoding via VideoToolbox / Apple media engine
 *
 * Two modes:
 *   1. Single-frame: cf_prores_encode_file() — one spectral image → .mov
 *   2. Streaming recorder: cf_recorder_* — frame-by-frame capture → .mov
 *
 * The streaming recorder is designed for parity with gfx_streambuf_t /
 * gfx_film_pipeline — accepts float32 RGBA frames (gfx_framebuf_t.pixels
 * layout), float64 HDR frames (gfx_framebuf_t.pixels_hdr layout), or
 * spectral cf_image frames. Encodes to ProRes via VTCompressionSession
 * with explicit hardware media engine request.
 *
 * macOS / iOS only. On other platforms all functions return CF_ERR_IO.
 */

#ifndef CUTEFILM_PRORES_H
#define CUTEFILM_PRORES_H

#include "../film.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CF_PRORES_PROXY   = 0,      /* ~45 Mbps @ 1080p */
    CF_PRORES_LT      = 1,      /* ~102 Mbps */
    CF_PRORES_422     = 2,      /* ~147 Mbps */
    CF_PRORES_422HQ   = 3,      /* ~220 Mbps */
    CF_PRORES_4444    = 4,      /* ~330 Mbps, alpha */
    CF_PRORES_4444XQ  = 5       /* ~500 Mbps, alpha, HDR */
} cf_prores_profile;

/* ---- Single-frame encode ---- */

int cf_prores_encode_file(const cf_image *img, const char *path,
                          cf_prores_profile profile);

int cf_prores_encode_file_metal(const cf_image *img, const char *path,
                                cf_prores_profile profile);

/* ---- Streaming recorder (parity with gfx_streambuf_t) ----
 *
 * Data flow:
 *   gfx_film_pipeline(film, src, dst)    -- produces float32 RGBA in dst
 *   cf_recorder_submit_rgba(rec, pixels) -- encodes that frame to ProRes
 *
 * The recorder owns a persistent VTCompressionSession + AVAssetWriter.
 * Each submitted frame is encoded via the media engine and muxed into
 * the .mov in presentation order.
 */

typedef struct cf_recorder cf_recorder;

/* Create a streaming ProRes recorder.
 * Opens path for writing, creates VTCompressionSession.
 * fps: frame rate (e.g. 24, 30, 60). */
cf_recorder *cf_recorder_create(uint32_t width, uint32_t height,
                                const char *path,
                                cf_prores_profile profile,
                                int fps);

/* Submit a float32 RGBA frame (linear light, w × h × 4 floats).
 * Same layout as gfx_framebuf_t.pixels. Applies sRGB gamma internally. */
int cf_recorder_submit_rgba(cf_recorder *rec, const float *rgba);

/* Submit a float64 RGBA frame (HDR linear, w × h × 4 doubles).
 * Same layout as gfx_framebuf_t.pixels_hdr. Tone-maps to output range. */
int cf_recorder_submit_rgba_f64(cf_recorder *rec, const double *rgba);

/* Submit a spectral frame (auto-converts to RGBA via CIE 1931). */
int cf_recorder_submit_spectral(cf_recorder *rec, const cf_image *img);

/* Number of frames encoded so far. */
uint64_t cf_recorder_frame_count(const cf_recorder *rec);

/* Query whether the hardware media engine is active. */
int cf_recorder_is_hardware(const cf_recorder *rec);

/* Finalize: flush encoder, close .mov, release resources.
 * The recorder is invalid after this call — destroy it. */
int cf_recorder_finish(cf_recorder *rec);

/* Destroy the recorder (calls finish if needed). */
void cf_recorder_destroy(cf_recorder *rec);

/* ---- Zero-copy GPU develop → media engine encode ----
 *
 * Submit raw accumulator data. The full fold+develop pipeline runs as
 * a fused Metal compute kernel, writing directly to an IOSurface that
 * the media engine reads for ProRes encode. No CPU pixel copy.
 *
 * This is the hardware-accelerated equivalent of:
 *   gfx_film_fold(film)          →  Metal kernel (fold + film curve)
 *   gfx_film_develop(film, fb)   →  Metal kernel (spectral→RGB)
 *   cf_recorder_submit_rgba(fb)  →  media engine encode (zero-copy)
 *
 * accum_energy/weight: width × height × num_bands floats.
 * band_wavelengths: num_bands center wavelengths in nm.
 * curve: film characteristic curve. */
int cf_recorder_submit_accum(cf_recorder *rec,
                             const float *accum_energy,
                             const float *accum_weight,
                             int num_bands,
                             const float *band_wavelengths,
                             const cf_film_curve *curve);

/* ---- ProRes decoder (media engine hardware decode) ----
 *
 * Reads a .mov / ProRes file via AVAssetReader, which routes through
 * the media engine hardware decoder on Apple Silicon.
 *
 * Data flow:
 *   .mov → media engine decode → IOSurface → float32 RGBA
 *
 * Parity with gfx_streambuf_t read interface:
 *   gfx_streambuf_read_into(sb, age, fb)  →  cf_decoder_read_rgba(dec, pixels)
 */

typedef struct cf_decoder cf_decoder;

/* Open a .mov for reading. Returns NULL on failure. */
cf_decoder *cf_decoder_open(const char *path);

/* Image dimensions of the video track. */
int cf_decoder_get_size(const cf_decoder *dec, uint32_t *width, uint32_t *height);

/* Read the next frame as float32 RGBA (linear light, w × h × 4 floats).
 * Returns CF_OK on success, CF_ERR_IO on EOF or error. */
int cf_decoder_read_rgba(cf_decoder *dec, float *rgba_out);

/* Total number of frames (0 if unknown). */
uint64_t cf_decoder_frame_count(const cf_decoder *dec);

/* Seek to a specific frame index (0-based). */
int cf_decoder_seek(cf_decoder *dec, uint64_t frame_index);

/* Close and release resources. */
void cf_decoder_destroy(cf_decoder *dec);

#ifdef __cplusplus
}
#endif

#endif /* CUTEFILM_PRORES_H */
