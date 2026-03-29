/*
 * prores.m — ProRes encoding via VideoToolbox / Apple media engine
 *
 * Streaming recorder with parity to gfx_streambuf_t capture interface.
 * Uses VTCompressionSession with explicit hardware encoder request
 * and AVAssetWriter for .mov muxing.
 */

#include "cutecontainer/film/prores.h"

#if defined(__APPLE__)

#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ──────────────────────────────────────────────────────────────────────
 * Shared helpers
 * ────────────────────────────────────────────────────────────────────── */

static CMVideoCodecType codec_for_profile(cf_prores_profile profile)
{
    switch (profile) {
    case CF_PRORES_PROXY:   return kCMVideoCodecType_AppleProRes422Proxy;
    case CF_PRORES_LT:      return kCMVideoCodecType_AppleProRes422LT;
    case CF_PRORES_422:     return kCMVideoCodecType_AppleProRes422;
    case CF_PRORES_422HQ:   return kCMVideoCodecType_AppleProRes422HQ;
    case CF_PRORES_4444:    return kCMVideoCodecType_AppleProRes4444;
    case CF_PRORES_4444XQ:  return kCMVideoCodecType_AppleProRes4444XQ;
    default:                return kCMVideoCodecType_AppleProRes422HQ;
    }
}

static OSType pixel_format_for_profile(cf_prores_profile profile)
{
    if (profile >= CF_PRORES_4444)
        return kCVPixelFormatType_64RGBALE;
    return kCVPixelFormatType_32BGRA;
}

static inline float linear_to_srgb(float c)
{
    if (c <= 0.0031308f) return c * 12.92f;
    return 1.055f * powf(c, 1.0f / 2.4f) - 0.055f;
}

static inline float clampf(float v, float lo, float hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

static void fill_pb_8bit(CVPixelBufferRef pb, const float *rgba,
                         uint32_t w, uint32_t h)
{
    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    size_t stride = CVPixelBufferGetBytesPerRow(pb);

    for (uint32_t y = 0; y < h; y++) {
        uint8_t *row = base + y * stride;
        for (uint32_t x = 0; x < w; x++) {
            const float *px = &rgba[(y * w + x) * 4];
            float r = clampf(px[0], 0.f, 1.f);
            float g = clampf(px[1], 0.f, 1.f);
            float b = clampf(px[2], 0.f, 1.f);
            float a = clampf(px[3], 0.f, 1.f);
            row[x*4+0] = (uint8_t)(linear_to_srgb(b) * 255.f + 0.5f);
            row[x*4+1] = (uint8_t)(linear_to_srgb(g) * 255.f + 0.5f);
            row[x*4+2] = (uint8_t)(linear_to_srgb(r) * 255.f + 0.5f);
            row[x*4+3] = (uint8_t)(a * 255.f + 0.5f);
        }
    }

    CVPixelBufferUnlockBaseAddress(pb, 0);
}

static void fill_pb_16bit(CVPixelBufferRef pb, const float *rgba,
                          uint32_t w, uint32_t h)
{
    CVPixelBufferLockBaseAddress(pb, 0);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(pb);
    size_t stride = CVPixelBufferGetBytesPerRow(pb);

    for (uint32_t y = 0; y < h; y++) {
        uint16_t *row = (uint16_t *)(base + y * stride);
        for (uint32_t x = 0; x < w; x++) {
            const float *px = &rgba[(y * w + x) * 4];
            float r = clampf(px[0], 0.f, 1.f);
            float g = clampf(px[1], 0.f, 1.f);
            float b = clampf(px[2], 0.f, 1.f);
            float a = clampf(px[3], 0.f, 1.f);
            row[x*4+0] = (uint16_t)(linear_to_srgb(r) * 65535.f + 0.5f);
            row[x*4+1] = (uint16_t)(linear_to_srgb(g) * 65535.f + 0.5f);
            row[x*4+2] = (uint16_t)(linear_to_srgb(b) * 65535.f + 0.5f);
            row[x*4+3] = (uint16_t)(a * 65535.f + 0.5f);
        }
    }

    CVPixelBufferUnlockBaseAddress(pb, 0);
}

/* ──────────────────────────────────────────────────────────────────────
 * VT callback — captures compressed sample
 * ────────────────────────────────────────────────────────────────────── */

typedef struct {
    CMSampleBufferRef sample;
    OSStatus          status;
} _vt_cb_ctx;

static void _vt_output_cb(void *ctx, void *src_ref,
                           OSStatus status, VTEncodeInfoFlags flags,
                           CMSampleBufferRef buf)
{
    (void)src_ref; (void)flags;
    _vt_cb_ctx *out = (_vt_cb_ctx *)ctx;
    out->status = status;
    if (status == noErr && buf) {
        CFRetain(buf);
        out->sample = buf;
    }
}

/* ──────────────────────────────────────────────────────────────────────
 * Streaming recorder
 *
 * Matches gfx_streambuf_t capture interface:
 *   gfx_streambuf_capture(sb, fb)   →  cf_recorder_submit_rgba(rec, fb->pixels)
 *   gfx_streambuf_capture_hdr(sb,fb)→  cf_recorder_submit_rgba_f64(rec, fb->pixels_hdr)
 *
 * Internal pipeline:
 *   float/double RGBA → CVPixelBuffer → VTCompressionSession (media engine)
 *   → CMSampleBuffer → AVAssetWriterInput (passthrough mux) → .mov
 * ────────────────────────────────────────────────────────────────────── */

struct cf_recorder {
    uint32_t            width;
    uint32_t            height;
    cf_prores_profile   profile;
    int                 fps;
    uint64_t            frame_count;
    int                 is_hardware;
    int                 finished;

    /* VideoToolbox session */
    VTCompressionSessionRef vt_session;
    _vt_cb_ctx              vt_ctx;

    /* AVAssetWriter (muxer) */
    AVAssetWriter          *writer;
    AVAssetWriterInput     *video_input;
    int                     writer_started;
};

cf_recorder *cf_recorder_create(uint32_t width, uint32_t height,
                                const char *path,
                                cf_prores_profile profile,
                                int fps)
{
    if (!path || width == 0 || height == 0 || fps <= 0) return NULL;

    cf_recorder *rec = calloc(1, sizeof(cf_recorder));
    if (!rec) return NULL;
    rec->width   = width;
    rec->height  = height;
    rec->profile = profile;
    rec->fps     = fps;

    @autoreleasepool {
        /* ── VTCompressionSession with hardware request ── */
        CMVideoCodecType codec = codec_for_profile(profile);

        NSDictionary *encoderSpec = @{
            (NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
            (NSString *)kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: @NO,
        };

        rec->vt_ctx = (_vt_cb_ctx){ .sample = NULL, .status = noErr };

        OSStatus err = VTCompressionSessionCreate(
            kCFAllocatorDefault,
            (int32_t)width, (int32_t)height,
            codec,
            (__bridge CFDictionaryRef)encoderSpec,
            NULL,
            kCFAllocatorDefault,
            _vt_output_cb,
            &rec->vt_ctx,
            &rec->vt_session);

        if (err != noErr || !rec->vt_session) {
            free(rec);
            return NULL;
        }

        /* check hardware status */
        CFBooleanRef hw = NULL;
        VTSessionCopyProperty(rec->vt_session,
            kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder,
            kCFAllocatorDefault, &hw);
        rec->is_hardware = (hw && CFBooleanGetValue(hw));
        if (hw) CFRelease(hw);

        /* quality over speed — not real-time capture */
        VTSessionSetProperty(rec->vt_session,
            kVTCompressionPropertyKey_RealTime, kCFBooleanFalse);
        VTSessionSetProperty(rec->vt_session,
            kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);

        /* ── AVAssetWriter (muxer) ── */
        NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
        [[NSFileManager defaultManager] removeItemAtURL:url error:nil];

        NSError *error = nil;
        rec->writer = [[AVAssetWriter alloc] initWithURL:url
                                                fileType:AVFileTypeQuickTimeMovie
                                                   error:&error];
        if (!rec->writer) {
            VTCompressionSessionInvalidate(rec->vt_session);
            CFRelease(rec->vt_session);
            free(rec);
            return NULL;
        }

        /* passthrough input — we feed pre-compressed ProRes sample buffers */
        rec->video_input =
            [AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo
                                              outputSettings:nil];
        rec->video_input.expectsMediaDataInRealTime = NO;
        [rec->writer addInput:rec->video_input];
    }

    return rec;
}

/* ── Submit one RGBA float frame ── */

static int _submit_rgba_f32(cf_recorder *rec, const float *rgba)
{
    if (!rec || !rgba || rec->finished) return CF_ERR_IO;

    @autoreleasepool {
        uint32_t w = rec->width, h = rec->height;
        OSType pixFmt = pixel_format_for_profile(rec->profile);

        /* create IOSurface-backed pixel buffer */
        NSDictionary *pbAttrs = @{
            (NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
        };

        CVPixelBufferRef pb = NULL;
        CVReturn cvrc = CVPixelBufferCreate(kCFAllocatorDefault, w, h, pixFmt,
                                            (__bridge CFDictionaryRef)pbAttrs, &pb);
        if (cvrc != kCVReturnSuccess) return CF_ERR_IO;

        /* fill pixel buffer from float RGBA (gfx_framebuf_t.pixels layout) */
        if (rec->profile >= CF_PRORES_4444)
            fill_pb_16bit(pb, rgba, w, h);
        else
            fill_pb_8bit(pb, rgba, w, h);

        /* encode via VTCompressionSession → media engine */
        CMTime pts = CMTimeMake((int64_t)rec->frame_count, rec->fps);
        CMTime dur = CMTimeMake(1, rec->fps);

        rec->vt_ctx.sample = NULL;
        rec->vt_ctx.status = noErr;

        OSStatus err = VTCompressionSessionEncodeFrame(
            rec->vt_session, pb, pts, dur, NULL, NULL, NULL);

        CVPixelBufferRelease(pb);
        if (err != noErr) return CF_ERR_IO;

        /* flush to get the callback */
        VTCompressionSessionCompleteFrames(rec->vt_session, kCMTimeInvalid);

        if (rec->vt_ctx.status != noErr || !rec->vt_ctx.sample)
            return CF_ERR_IO;

        /* start writer on first frame (need format description) */
        if (!rec->writer_started) {
            [rec->writer startWriting];
            [rec->writer startSessionAtSourceTime:kCMTimeZero];
            rec->writer_started = 1;
        }

        /* mux compressed sample into .mov */
        while (!rec->video_input.readyForMoreMediaData)
            [NSThread sleepForTimeInterval:0.001];

        BOOL ok = [rec->video_input appendSampleBuffer:rec->vt_ctx.sample];
        CFRelease(rec->vt_ctx.sample);
        rec->vt_ctx.sample = NULL;

        if (!ok) return CF_ERR_IO;
    }

    rec->frame_count++;
    return CF_OK;
}

int cf_recorder_submit_rgba(cf_recorder *rec, const float *rgba)
{
    return _submit_rgba_f32(rec, rgba);
}

/* ── Submit float64 HDR RGBA frame (gfx_framebuf_t.pixels_hdr layout) ── */

int cf_recorder_submit_rgba_f64(cf_recorder *rec, const double *rgba)
{
    if (!rec || !rgba) return CF_ERR_IO;

    size_t npix = (size_t)rec->width * rec->height;
    float *f32 = malloc(npix * 4 * sizeof(float));
    if (!f32) return CF_ERR_NOMEM;

    /* Reinhard tone-map + convert double → float */
    for (size_t i = 0; i < npix * 4; i += 4) {
        double r = rgba[i+0], g = rgba[i+1], b = rgba[i+2], a = rgba[i+3];

        /* simple Reinhard: L / (1 + L) per channel */
        if (r > 0.0) r = r / (1.0 + r);
        if (g > 0.0) g = g / (1.0 + g);
        if (b > 0.0) b = b / (1.0 + b);

        f32[i+0] = (float)r;
        f32[i+1] = (float)g;
        f32[i+2] = (float)b;
        f32[i+3] = (float)(a > 1.0 ? 1.0 : (a < 0.0 ? 0.0 : a));
    }

    int rc = _submit_rgba_f32(rec, f32);
    free(f32);
    return rc;
}

/* ── Submit spectral frame ── */

int cf_recorder_submit_spectral(cf_recorder *rec, const cf_image *img)
{
    if (!rec || !img) return CF_ERR_IO;
    if (img->width != rec->width || img->height != rec->height) return CF_ERR_FORMAT;

    size_t npix = (size_t)rec->width * rec->height;
    float *rgba = malloc(npix * 4 * sizeof(float));
    if (!rgba) return CF_ERR_NOMEM;

    int rc = cf_spectral_to_rgba(img, rgba);
    if (rc != CF_OK) { free(rgba); return rc; }

    rc = _submit_rgba_f32(rec, rgba);
    free(rgba);
    return rc;
}

/* ── Submit accumulators: GPU develop → zero-copy → media engine encode ── */

int cf_recorder_submit_accum(cf_recorder *rec,
                             const float *accum_energy,
                             const float *accum_weight,
                             int num_bands,
                             const float *band_wavelengths,
                             const cf_film_curve *curve)
{
    if (!rec || !accum_energy || !accum_weight || !band_wavelengths || !curve)
        return CF_ERR_IO;

    size_t npix = (size_t)rec->width * rec->height;
    float *rgba = malloc(npix * 4 * sizeof(float));
    if (!rgba) return CF_ERR_NOMEM;

    /* fold+develop on GPU (falls back to CPU if Metal unavailable) */
    int rc = cf_film_develop_metal(accum_energy, accum_weight,
                                    rec->width, rec->height,
                                    num_bands, band_wavelengths,
                                    curve, rgba);
    if (rc != CF_OK) { free(rgba); return rc; }

    /* encode via media engine */
    rc = _submit_rgba_f32(rec, rgba);
    free(rgba);
    return rc;
}

/* ── ProRes decoder (media engine hardware decode) ── */

struct cf_decoder {
    uint32_t        width;
    uint32_t        height;
    uint64_t        total_frames;
    uint64_t        frames_read;
    AVAssetReader  *reader;
    AVAssetReaderTrackOutput *track_output;
};

cf_decoder *cf_decoder_open(const char *path)
{
    if (!path) return NULL;

    cf_decoder *dec = calloc(1, sizeof(cf_decoder));
    if (!dec) return NULL;

    @autoreleasepool {
        NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
        AVAsset *asset = [AVAsset assetWithURL:url];

        /* get video track */
        NSArray<AVAssetTrack *> *tracks =
            [asset tracksWithMediaType:AVMediaTypeVideo];
        if (tracks.count == 0) { free(dec); return NULL; }

        AVAssetTrack *videoTrack = tracks[0];
        CGSize size = videoTrack.naturalSize;
        dec->width  = (uint32_t)size.width;
        dec->height = (uint32_t)size.height;

        /* estimate frame count from duration × framerate */
        float fps = videoTrack.nominalFrameRate;
        double dur = CMTimeGetSeconds(asset.duration);
        dec->total_frames = (uint64_t)(dur * fps + 0.5);

        /* reader + output (decode to BGRA via media engine) */
        NSError *error = nil;
        dec->reader = [AVAssetReader assetReaderWithAsset:asset error:&error];
        if (!dec->reader) { free(dec); return NULL; }

        NSDictionary *outputSettings = @{
            (NSString *)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        };

        dec->track_output =
            [AVAssetReaderTrackOutput assetReaderTrackOutputWithTrack:videoTrack
                                                      outputSettings:outputSettings];
        dec->track_output.alwaysCopiesSampleData = NO;

        [dec->reader addOutput:dec->track_output];

        if (![dec->reader startReading]) { free(dec); return NULL; }
    }

    return dec;
}

int cf_decoder_get_size(const cf_decoder *dec, uint32_t *width, uint32_t *height)
{
    if (!dec) return CF_ERR_IO;
    if (width)  *width  = dec->width;
    if (height) *height = dec->height;
    return CF_OK;
}

/* sRGB gamma → linear */
static inline float _srgb_to_linear(float s)
{
    if (s <= 0.04045f) return s / 12.92f;
    return powf((s + 0.055f) / 1.055f, 2.4f);
}

int cf_decoder_read_rgba(cf_decoder *dec, float *rgba_out)
{
    if (!dec || !rgba_out) return CF_ERR_IO;
    if (dec->reader.status != AVAssetReaderStatusReading) return CF_ERR_IO;

    @autoreleasepool {
        CMSampleBufferRef sampleBuf = [dec->track_output copyNextSampleBuffer];
        if (!sampleBuf) return CF_ERR_IO;  /* EOF or error */

        CVImageBufferRef imgBuf = CMSampleBufferGetImageBuffer(sampleBuf);
        if (!imgBuf) { CFRelease(sampleBuf); return CF_ERR_IO; }

        CVPixelBufferLockBaseAddress(imgBuf, kCVPixelBufferLock_ReadOnly);
        uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(imgBuf);
        size_t stride = CVPixelBufferGetBytesPerRow(imgBuf);
        uint32_t w = dec->width, h = dec->height;

        /* BGRA uint8 → RGBA float32 linear */
        for (uint32_t y = 0; y < h; y++) {
            uint8_t *row = base + y * stride;
            for (uint32_t x = 0; x < w; x++) {
                float *out = &rgba_out[(y * w + x) * 4];
                out[0] = _srgb_to_linear(row[x*4+2] / 255.0f);  /* R */
                out[1] = _srgb_to_linear(row[x*4+1] / 255.0f);  /* G */
                out[2] = _srgb_to_linear(row[x*4+0] / 255.0f);  /* B */
                out[3] = row[x*4+3] / 255.0f;                    /* A */
            }
        }

        CVPixelBufferUnlockBaseAddress(imgBuf, kCVPixelBufferLock_ReadOnly);
        CFRelease(sampleBuf);
    }

    dec->frames_read++;
    return CF_OK;
}

uint64_t cf_decoder_frame_count(const cf_decoder *dec)
{
    return dec ? dec->total_frames : 0;
}

int cf_decoder_seek(cf_decoder *dec, uint64_t frame_index)
{
    /* AVAssetReader doesn't support random seek — would need to recreate.
     * For now, return error if not sequential. */
    (void)dec; (void)frame_index;
    return CF_ERR_IO;
}

void cf_decoder_destroy(cf_decoder *dec)
{
    if (!dec) return;
    @autoreleasepool {
        if (dec->reader.status == AVAssetReaderStatusReading)
            [dec->reader cancelReading];
    }
    free(dec);
}

/* ── Stats ── */

uint64_t cf_recorder_frame_count(const cf_recorder *rec)
{
    return rec ? rec->frame_count : 0;
}

int cf_recorder_is_hardware(const cf_recorder *rec)
{
    return rec ? rec->is_hardware : 0;
}

/* ── Finalize ── */

int cf_recorder_finish(cf_recorder *rec)
{
    if (!rec || rec->finished) return CF_OK;
    rec->finished = 1;

    @autoreleasepool {
        VTCompressionSessionCompleteFrames(rec->vt_session, kCMTimeInvalid);
        VTCompressionSessionInvalidate(rec->vt_session);
        CFRelease(rec->vt_session);
        rec->vt_session = NULL;

        if (rec->writer_started) {
            [rec->video_input markAsFinished];

            __block BOOL done = NO;
            [rec->writer finishWritingWithCompletionHandler:^{ done = YES; }];
            while (!done)
                [NSThread sleepForTimeInterval:0.001];

            if (rec->writer.status != AVAssetWriterStatusCompleted)
                return CF_ERR_IO;
        }
    }

    return CF_OK;
}

void cf_recorder_destroy(cf_recorder *rec)
{
    if (!rec) return;
    if (!rec->finished) cf_recorder_finish(rec);
    free(rec);
}

/* ──────────────────────────────────────────────────────────────────────
 * Single-frame encode (uses recorder internally)
 * ────────────────────────────────────────────────────────────────────── */

static int prores_encode_impl(const cf_image *img, const char *path,
                               cf_prores_profile profile, int use_metal)
{
    if (!img || !path) return CF_ERR_IO;

    size_t npix = (size_t)img->width * img->height;
    float *rgba = malloc(npix * 4 * sizeof(float));
    if (!rgba) return CF_ERR_NOMEM;

    int rc = use_metal
        ? cf_spectral_to_rgba_metal(img, rgba)
        : cf_spectral_to_rgba(img, rgba);
    if (rc != CF_OK) { free(rgba); return rc; }

    cf_recorder *rec = cf_recorder_create(img->width, img->height, path, profile, 24);
    if (!rec) { free(rgba); return CF_ERR_IO; }

    rc = cf_recorder_submit_rgba(rec, rgba);
    free(rgba);

    if (rc == CF_OK)
        rc = cf_recorder_finish(rec);

    cf_recorder_destroy(rec);
    return rc;
}

int cf_prores_encode_file(const cf_image *img, const char *path,
                          cf_prores_profile profile)
{
    return prores_encode_impl(img, path, profile, 0);
}

int cf_prores_encode_file_metal(const cf_image *img, const char *path,
                                cf_prores_profile profile)
{
    return prores_encode_impl(img, path, profile, 1);
}

#else /* ── non-Apple stubs ── */

struct cf_recorder { int dummy; };

cf_recorder *cf_recorder_create(uint32_t w, uint32_t h, const char *p,
                                cf_prores_profile pr, int fps)
{ (void)w;(void)h;(void)p;(void)pr;(void)fps; return NULL; }

int cf_recorder_submit_rgba(cf_recorder *r, const float *d)
{ (void)r;(void)d; return CF_ERR_IO; }

int cf_recorder_submit_rgba_f64(cf_recorder *r, const double *d)
{ (void)r;(void)d; return CF_ERR_IO; }

int cf_recorder_submit_spectral(cf_recorder *r, const cf_image *i)
{ (void)r;(void)i; return CF_ERR_IO; }

int cf_recorder_submit_accum(cf_recorder *r, const float *e, const float *w,
                             int nb, const float *bw, const cf_film_curve *c)
{ (void)r;(void)e;(void)w;(void)nb;(void)bw;(void)c; return CF_ERR_IO; }

uint64_t cf_recorder_frame_count(const cf_recorder *r)
{ (void)r; return 0; }

int cf_recorder_is_hardware(const cf_recorder *r)
{ (void)r; return 0; }

int cf_recorder_finish(cf_recorder *r)
{ (void)r; return CF_ERR_IO; }

void cf_recorder_destroy(cf_recorder *r)
{ (void)r; }

int cf_prores_encode_file(const cf_image *i, const char *p, cf_prores_profile pr)
{ (void)i;(void)p;(void)pr; return CF_ERR_IO; }

int cf_prores_encode_file_metal(const cf_image *i, const char *p, cf_prores_profile pr)
{ (void)i;(void)p;(void)pr; return CF_ERR_IO; }

struct cf_decoder { int dummy; };
cf_decoder *cf_decoder_open(const char *p) { (void)p; return NULL; }
int cf_decoder_get_size(const cf_decoder *d, uint32_t *w, uint32_t *h)
{ (void)d;(void)w;(void)h; return CF_ERR_IO; }
int cf_decoder_read_rgba(cf_decoder *d, float *o) { (void)d;(void)o; return CF_ERR_IO; }
uint64_t cf_decoder_frame_count(const cf_decoder *d) { (void)d; return 0; }
int cf_decoder_seek(cf_decoder *d, uint64_t f) { (void)d;(void)f; return CF_ERR_IO; }
void cf_decoder_destroy(cf_decoder *d) { (void)d; }

#endif
