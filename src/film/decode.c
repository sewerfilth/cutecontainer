/*
 * decode.c — cutefilm decoder
 *
 * Pipeline:  CFSP container → cutepress decompress → XOR-delta decode → BSQ → BIP image
 * Optional:  cutecrypt pipe decrypt → CFSP container
 */

#include "cutecontainer/film.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt/sha3.h"
#include "cutecontainer/crypt/pipe.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- Little-endian helpers ---- */

static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint64_t get_u64(const uint8_t *p) {
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p+4) << 32);
}
static float get_f32(const uint8_t *p) {
    uint32_t u = get_u32(p);
    float v; memcpy(&v, &u, 4);
    return v;
}

/* ---- XOR-delta decode (uses ASM-overridable row function) ---- */

static void delta_decode_plane(float *plane, uint32_t width, uint32_t height)
{
    uint32_t *u = (uint32_t *)plane;
    for (uint32_t y = 0; y < height; y++)
        cf_delta_decode_row(u + (size_t)y * width, width);
}

/* ---- Interleave BSQ plane → BIP (uses ASM-overridable function) ---- */

static void insert_plane(cf_image *img, int band, const float *plane)
{
    size_t npixels = (size_t)img->width * img->height;
    cf_interleave_band(img->data, plane, npixels, img->num_bands, band);
}

/* ---- Parse header ---- */

static int parse_header(const uint8_t *data, size_t data_len,
                        cf_spectral_mode *mode, uint32_t *width, uint32_t *height,
                        uint16_t *num_bands, float *wl_min, float *wl_max,
                        const uint8_t **hash_out)
{
    if (data_len < CF_HEADER_SIZE) return CF_ERR_FORMAT;
    if (memcmp(data, CF_MAGIC, 4) != 0) return CF_ERR_FORMAT;
    if (data[4] != CF_VERSION) return CF_ERR_FORMAT;

    *mode      = (cf_spectral_mode)get_u16(data + 6);
    *width     = get_u32(data + 8);
    *height    = get_u32(data + 12);
    *num_bands = get_u16(data + 16);
    /* bits_per_sample at [18..19], expected 32 */
    *wl_min    = get_f32(data + 20);
    *wl_max    = get_f32(data + 24);
    *hash_out  = data + 28;

    /* validate */
    int expected = cf_bands_for_mode(*mode);
    if (expected < 0 || (uint16_t)expected != *num_bands) return CF_ERR_FORMAT;
    if (*width == 0 || *height == 0) return CF_ERR_FORMAT;

    return CF_OK;
}

/* ---- Public: decode from memory ---- */

int cf_decode(const uint8_t *data, size_t data_len, cf_image **img_out)
{
    if (!data || !img_out) return CF_ERR_IO;

    cf_spectral_mode mode;
    uint32_t w, h;
    uint16_t nb;
    float wl_min, wl_max;
    const uint8_t *stored_hash;

    int rc = parse_header(data, data_len, &mode, &w, &h, &nb, &wl_min, &wl_max, &stored_hash);
    if (rc != CF_OK) return rc;

    cf_image *img = cf_image_create_ex(w, h, mode, wl_min, wl_max);
    if (!img) return CF_ERR_NOMEM;

    size_t plane_bytes = (size_t)w * h * sizeof(float);
    const uint8_t *p = data + CF_HEADER_SIZE;
    const uint8_t *end = data + data_len;

    for (int b = 0; b < nb; b++) {
        if (p + 8 > end) { cf_image_destroy(img); return CF_ERR_FORMAT; }
        uint64_t comp_size = get_u64(p);  p += 8;
        if (p + comp_size > end) { cf_image_destroy(img); return CF_ERR_FORMAT; }

        /* decompress */
        float *plane = malloc(plane_bytes);
        if (!plane) { cf_image_destroy(img); return CF_ERR_NOMEM; }

        int64_t dec = cp_decompress(p, (size_t)comp_size,
                                    (uint8_t *)plane, plane_bytes);
        p += comp_size;

        if (dec < 0 || (size_t)dec != plane_bytes) {
            free(plane);
            cf_image_destroy(img);
            return CF_ERR_CORRUPT;
        }

        /* undo delta */
        delta_decode_plane(plane, w, h);

        /* interleave back into BIP */
        insert_plane(img, b, plane);
        free(plane);
    }

    /* verify integrity hash */
    uint8_t computed_hash[CC_SHA3_256_HASH_LEN];
    {
        cc_sha3_ctx sha;
        cc_sha3_256_init(&sha);
        cc_sha3_256_update(&sha, (const uint8_t *)img->data,
                           (size_t)w * h * nb * sizeof(float));
        cc_sha3_256_final(&sha, computed_hash);
    }

    if (memcmp(computed_hash, stored_hash, 32) != 0) {
        cf_image_destroy(img);
        return CF_ERR_CORRUPT;
    }

    *img_out = img;
    return CF_OK;
}

/* ---- Public: decode from file ---- */

int cf_decode_file(const char *path, cf_image **img)
{
    if (!path || !img) return CF_ERR_IO;

    FILE *f = fopen(path, "rb");
    if (!f) return CF_ERR_IO;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) { fclose(f); return CF_ERR_FORMAT; }

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) { fclose(f); return CF_ERR_NOMEM; }

    size_t rd = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    if (rd != (size_t)fsize) { free(buf); return CF_ERR_IO; }

    int rc = cf_decode(buf, (size_t)fsize, img);
    free(buf);
    return rc;
}

/* ---- Public: decrypt + decode ---- */

int cf_decode_encrypted(const uint8_t *data, size_t data_len,
                        cf_image **img, const uint8_t sk[2400])
{
    if (!data || !img || !sk) return CF_ERR_IO;

    /* check for cutecrypt pipe magic */
    if (data_len < 4 || memcmp(data, "CUTE", 4) != 0) return CF_ERR_FORMAT;

    cc_pipe *pipe = cc_pipe_decrypt_new(sk);
    if (!pipe) return CF_ERR_NOMEM;

    uint8_t *plaintext = NULL;
    size_t plain_len = 0;
    int prc = cc_pipe_decrypt(pipe, data, data_len, &plaintext, &plain_len);
    cc_pipe_free(pipe);

    if (prc != 0) return CF_ERR_DECRYPT;

    /* decode the inner CFSP container */
    int rc = cf_decode(plaintext, plain_len, img);
    cc_pipe_free_buf(plaintext);
    return rc;
}
