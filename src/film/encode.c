/*
 * encode.c — cutefilm encoder
 *
 * Pipeline:  BIP image → BSQ planes → XOR-delta encode → cutepress → CFSP container
 * Optional:  CFSP container → cutecrypt pipe (encrypted .cute)
 */

#include "cutecontainer/film.h"
#include "cutecontainer/press.h"
#include "cutecontainer/crypt/sha3.h"
#include "cutecontainer/crypt/pipe.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- Little-endian helpers ---- */

static void put_u16(uint8_t *p, uint16_t v) { p[0]=v; p[1]=v>>8; }
static void put_u32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put_u64(uint8_t *p, uint64_t v) {
    put_u32(p, (uint32_t)v);
    put_u32(p+4, (uint32_t)(v>>32));
}

static void put_f32(uint8_t *p, float v) {
    uint32_t u;
    memcpy(&u, &v, 4);
    put_u32(p, u);
}

/* ---- Deinterleave BIP → single BSQ plane (uses ASM-overridable function) ---- */

static float *extract_plane(const cf_image *img, int band)
{
    size_t npixels = (size_t)img->width * img->height;
    float *plane = malloc(npixels * sizeof(float));
    if (!plane) return NULL;

    cf_deinterleave_band(img->data, plane, npixels, img->num_bands, band);
    return plane;
}

/* ---- XOR-delta encode (uses ASM-overridable row function) ---- */

static void delta_encode_plane(float *plane, uint32_t width, uint32_t height)
{
    uint32_t *u = (uint32_t *)plane;
    for (uint32_t y = 0; y < height; y++)
        cf_delta_encode_row(u + (size_t)y * width, width);
}

/* ---- Write CFSP header ---- */

static void write_header(uint8_t hdr[CF_HEADER_SIZE],
                         const cf_image *img, const uint8_t hash[32])
{
    memset(hdr, 0, CF_HEADER_SIZE);

    memcpy(hdr, CF_MAGIC, 4);                          /* [0..3]   magic */
    hdr[4] = CF_VERSION;                                /* [4]      version */
    hdr[5] = 0;                                         /* [5]      flags */
    put_u16(hdr + 6, (uint16_t)img->mode);              /* [6..7]   mode */
    put_u32(hdr + 8, img->width);                       /* [8..11]  width */
    put_u32(hdr + 12, img->height);                     /* [12..15] height */
    put_u16(hdr + 16, img->num_bands);                  /* [16..17] num_bands */
    put_u16(hdr + 18, 32);                              /* [18..19] bits_per_sample */
    put_f32(hdr + 20, img->wavelength_min);             /* [20..23] wl_min */
    put_f32(hdr + 24, img->wavelength_max);             /* [24..27] wl_max */
    memcpy(hdr + 28, hash, 32);                         /* [28..59] SHA3-256 */
    /* [60..63] reserved = 0 */
}

/* ---- Public: encode to memory ---- */

int cf_encode(const cf_image *img, uint8_t **out, size_t *out_len, int level)
{
    if (!img || !out || !out_len) return CF_ERR_IO;
    if (level < 1) level = CP_LEVEL_DEFAULT;
    if (level > 9) level = CP_LEVEL_MAX;

    int nb = img->num_bands;
    size_t plane_bytes = (size_t)img->width * img->height * sizeof(float);

    /* --- Hash all uncompressed data (BIP order) for integrity --- */
    uint8_t content_hash[CC_SHA3_256_HASH_LEN];
    {
        cc_sha3_ctx sha;
        cc_sha3_256_init(&sha);
        cc_sha3_256_update(&sha, (const uint8_t *)img->data,
                           (size_t)img->width * img->height * nb * sizeof(float));
        cc_sha3_256_final(&sha, content_hash);
    }

    /* --- Compress each band plane --- */
    uint8_t **compressed   = calloc(nb, sizeof(uint8_t *));
    size_t   *comp_sizes   = calloc(nb, sizeof(size_t));
    if (!compressed || !comp_sizes) { free(compressed); free(comp_sizes); return CF_ERR_NOMEM; }

    size_t total_body = 0;

    for (int b = 0; b < nb; b++) {
        /* extract + delta-encode */
        float *plane = extract_plane(img, b);
        if (!plane) goto fail;
        delta_encode_plane(plane, img->width, img->height);

        /* compress */
        size_t bound = cp_compress_bound(plane_bytes);
        compressed[b] = malloc(bound);
        if (!compressed[b]) { free(plane); goto fail; }

        int64_t cs = cp_compress((const uint8_t *)plane, plane_bytes,
                                 compressed[b], bound, level);
        free(plane);
        if (cs < 0) goto fail;

        comp_sizes[b] = (size_t)cs;
        total_body += 8 + (size_t)cs;   /* uint64 size prefix + data */
    }

    /* --- Assemble output --- */
    size_t total = CF_HEADER_SIZE + total_body;
    uint8_t *buf = malloc(total);
    if (!buf) goto fail;

    write_header(buf, img, content_hash);

    uint8_t *p = buf + CF_HEADER_SIZE;
    for (int b = 0; b < nb; b++) {
        put_u64(p, comp_sizes[b]);  p += 8;
        memcpy(p, compressed[b], comp_sizes[b]);  p += comp_sizes[b];
        free(compressed[b]);
        compressed[b] = NULL;
    }

    free(compressed);
    free(comp_sizes);

    *out     = buf;
    *out_len = total;
    return CF_OK;

fail:
    for (int b = 0; b < nb; b++)
        free(compressed[b]);
    free(compressed);
    free(comp_sizes);
    return CF_ERR_NOMEM;
}

/* ---- Public: encode to file ---- */

int cf_encode_file(const cf_image *img, const char *path, int level)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = cf_encode(img, &buf, &len, level);
    if (rc != CF_OK) return rc;

    FILE *f = fopen(path, "wb");
    if (!f) { free(buf); return CF_ERR_IO; }

    size_t written = fwrite(buf, 1, len, f);
    fclose(f);
    free(buf);

    return (written == len) ? CF_OK : CF_ERR_IO;
}

/* ---- Public: encode + encrypt ---- */

int cf_encode_encrypted(const cf_image *img, uint8_t **out, size_t *out_len,
                        int level, const uint8_t pk[1184])
{
    if (!pk) return CF_ERR_IO;

    /* first encode the CFSP container */
    uint8_t *cfsp = NULL;
    size_t cfsp_len = 0;
    int rc = cf_encode(img, &cfsp, &cfsp_len, level);
    if (rc != CF_OK) return rc;

    /* wrap through cutecrypt pipe */
    cc_pipe *pipe = cc_pipe_encrypt_new(pk);
    if (!pipe) { free(cfsp); return CF_ERR_NOMEM; }

    uint8_t *encrypted = NULL;
    size_t enc_len = 0;
    int prc = cc_pipe_encrypt(pipe, cfsp, cfsp_len, &encrypted, &enc_len);
    cc_pipe_free(pipe);
    free(cfsp);

    if (prc != 0) return CF_ERR_IO;

    *out     = encrypted;
    *out_len = enc_len;
    return CF_OK;
}
