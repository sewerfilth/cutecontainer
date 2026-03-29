/*
 * metal_spectral.m — Metal compute host for:
 *   1. Spectral → RGBA conversion (CIE 1931)
 *   2. Fused fold+develop pipeline (film curve + spectral → RGB)
 *
 * Both kernels output to shared-mode buffers. The fold+develop kernel
 * is designed for zero-copy handoff to VTCompressionSession via IOSurface.
 *
 * macOS / iOS only.
 */

#include "cutecontainer/film.h"

#if defined(__APPLE__)

#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <string.h>

/* CIE data from cie1931.c */
extern const float  cf_cie1931_cmf[81][3];
extern const size_t cf_cie1931_count;
extern const float  cf_cie1931_wl_min;
extern const float  cf_cie1931_wl_step;

/* ── CIE interpolation ── */

static void cmf_at_wl(float wl, float *x_bar, float *y_bar, float *z_bar)
{
    if (wl < cf_cie1931_wl_min || wl > 780.0f) {
        *x_bar = *y_bar = *z_bar = 0.0f;
        return;
    }
    float t = (wl - cf_cie1931_wl_min) / cf_cie1931_wl_step;
    int i0 = (int)t;
    if (i0 < 0) i0 = 0;
    if ((size_t)i0 >= cf_cie1931_count - 1) i0 = (int)cf_cie1931_count - 2;
    float f = t - (float)i0;
    *x_bar = cf_cie1931_cmf[i0][0] + f * (cf_cie1931_cmf[i0+1][0] - cf_cie1931_cmf[i0][0]);
    *y_bar = cf_cie1931_cmf[i0][1] + f * (cf_cie1931_cmf[i0+1][1] - cf_cie1931_cmf[i0][1]);
    *z_bar = cf_cie1931_cmf[i0][2] + f * (cf_cie1931_cmf[i0+1][2] - cf_cie1931_cmf[i0][2]);
}

/* ── Embedded shader source: spectral_to_rgba kernel ── */

static NSString *const kSpectralShader = @
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"struct SpectralParams { uint num_bands; uint npixels; float norm; float pad; };\n"
"static float3 xyz_to_srgb(float3 xyz) {\n"
"    return float3(\n"
"        clamp( 3.2404542f*xyz.x - 1.5371385f*xyz.y - 0.4985314f*xyz.z, 0.0f, 1.0f),\n"
"        clamp(-0.9692660f*xyz.x + 1.8760108f*xyz.y + 0.0415560f*xyz.z, 0.0f, 1.0f),\n"
"        clamp( 0.0556434f*xyz.x - 0.2040259f*xyz.y + 1.0572252f*xyz.z, 0.0f, 1.0f));\n"
"}\n"
"kernel void spectral_to_rgba(\n"
"    device const float  *spectral  [[buffer(0)]],\n"
"    device float4       *rgba_out  [[buffer(1)]],\n"
"    device const float3 *cmf       [[buffer(2)]],\n"
"    constant SpectralParams &params [[buffer(3)]],\n"
"    uint gid [[thread_position_in_grid]]) {\n"
"    if (gid >= params.npixels) return;\n"
"    uint nb = params.num_bands;\n"
"    device const float *spec = spectral + gid * nb;\n"
"    float3 xyz = float3(0.0f);\n"
"    for (uint b = 0; b < nb; b++) {\n"
"        xyz.x += spec[b] * cmf[b].x;\n"
"        xyz.y += spec[b] * cmf[b].y;\n"
"        xyz.z += spec[b] * cmf[b].z;\n"
"    }\n"
"    xyz *= params.norm;\n"
"    rgba_out[gid] = float4(xyz_to_srgb(xyz), 1.0f);\n"
"}\n";

/* ── Embedded shader source: film_develop kernel ── */

static NSString *const kDevelopShader = @
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"struct FilmCurve { float base_fog; float toe_limit; float shoulder_limit;\n"
"                   float gamma; float max_density; float iso; };\n"
"struct FilmDevelopParams { uint num_bands; uint npixels; float pad0; float pad1;\n"
"                           FilmCurve curve; };\n"
"struct BandCMF { float cx; float cy; float cz; float bw; };\n"
"static float3 xyz_to_srgb(float3 xyz) {\n"
"    return float3(\n"
"        clamp( 3.2404542f*xyz.x - 1.5371385f*xyz.y - 0.4985314f*xyz.z, 0.0f, 1.0f),\n"
"        clamp(-0.9692660f*xyz.x + 1.8760108f*xyz.y + 0.0415560f*xyz.z, 0.0f, 1.0f),\n"
"        clamp( 0.0556434f*xyz.x - 0.2040259f*xyz.y + 1.0572252f*xyz.z, 0.0f, 1.0f));\n"
"}\n"
"kernel void film_develop(\n"
"    device const float   *energy  [[buffer(0)]],\n"
"    device const float   *weight  [[buffer(1)]],\n"
"    device float4        *rgba    [[buffer(2)]],\n"
"    device const BandCMF *cmf     [[buffer(3)]],\n"
"    constant FilmDevelopParams &params [[buffer(4)]],\n"
"    uint gid [[thread_position_in_grid]]) {\n"
"    if (gid >= params.npixels) return;\n"
"    uint nb = params.num_bands;\n"
"    FilmCurve c = params.curve;\n"
"    float3 xyz = float3(0.0f);\n"
"    for (uint b = 0; b < nb; b++) {\n"
"        uint ai = gid * nb + b;\n"
"        float w = weight[ai];\n"
"        float val = (w > 0.0f) ? energy[ai] / w : c.base_fog;\n"
"        float exposure = val * c.iso;\n"
"        float density;\n"
"        if (exposure <= c.toe_limit) {\n"
"            float td = c.gamma * log10(c.toe_limit + 1e-10f);\n"
"            density = c.base_fog + (exposure / c.toe_limit) * (td - c.base_fog);\n"
"        } else if (exposure >= c.shoulder_limit) {\n"
"            float ld = c.gamma * log10(exposure + 1e-10f);\n"
"            float st = min((exposure - c.shoulder_limit) / (c.shoulder_limit * 2.0f), 1.0f);\n"
"            density = ld + (c.max_density - ld) * st;\n"
"        } else {\n"
"            density = c.gamma * log10(exposure + 1e-10f);\n"
"        }\n"
"        density = min(density, c.max_density);\n"
"        float linear = pow(10.0f, density);\n"
"        BandCMF bc = cmf[b];\n"
"        xyz.x += linear * bc.cx * bc.bw;\n"
"        xyz.y += linear * bc.cy * bc.bw;\n"
"        xyz.z += linear * bc.cz * bc.bw;\n"
"    }\n"
"    rgba[gid] = float4(xyz_to_srgb(xyz), 1.0f);\n"
"}\n";

/* ── Helper: compile a kernel from source ── */

static id<MTLComputePipelineState> compile_kernel(id<MTLDevice> device,
                                                   NSString *source,
                                                   NSString *name)
{
    NSError *error = nil;
    id<MTLLibrary> lib = [device newLibraryWithSource:source options:nil error:&error];
    if (!lib) return nil;
    id<MTLFunction> fn = [lib newFunctionWithName:name];
    if (!fn) return nil;
    return [device newComputePipelineStateWithFunction:fn error:&error];
}

/* ── Dispatch helper ── */

static void dispatch_1d(id<MTLComputeCommandEncoder> enc,
                        id<MTLComputePipelineState> pso,
                        NSUInteger count)
{
    [enc setComputePipelineState:pso];
    NSUInteger tgs = pso.maxTotalThreadsPerThreadgroup;
    if (tgs > 256) tgs = 256;
    [enc dispatchThreads:MTLSizeMake(count, 1, 1)
   threadsPerThreadgroup:MTLSizeMake(tgs, 1, 1)];
}

/* ══════════════════════════════════════════════════════════════════════
 * 1. Spectral → RGBA (simple CIE integration)
 * ══════════════════════════════════════════════════════════════════════ */

int cf_spectral_to_rgba_metal(const cf_image *img, float *rgba_out)
{
    if (!img || !rgba_out) return CF_ERR_IO;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) return cf_spectral_to_rgba(img, rgba_out);

        id<MTLComputePipelineState> pso = compile_kernel(device, kSpectralShader, @"spectral_to_rgba");
        if (!pso) return cf_spectral_to_rgba(img, rgba_out);

        int nb = img->num_bands;
        size_t npixels = (size_t)img->width * img->height;

        /* precompute CMF weights */
        float cmf_weights[16 * 3];
        float delta_lambda = (nb > 1)
            ? (img->wavelength_max - img->wavelength_min) / (float)(nb - 1) : 1.0f;
        float y_integral = 0.0f;
        for (int b = 0; b < nb; b++) {
            float wl = cf_wavelength_for_band(img, b);
            cmf_at_wl(wl, &cmf_weights[b*3], &cmf_weights[b*3+1], &cmf_weights[b*3+2]);
            cmf_weights[b*3+0] *= delta_lambda;
            cmf_weights[b*3+1] *= delta_lambda;
            cmf_weights[b*3+2] *= delta_lambda;
            y_integral += cmf_weights[b*3+1];
        }
        if (y_integral <= 0.0f) y_integral = 1.0f;

        size_t rgba_bytes = npixels * 4 * sizeof(float);
        id<MTLBuffer> specBuf = [device newBufferWithBytes:img->data
                                                   length:npixels * nb * sizeof(float)
                                                  options:MTLResourceStorageModeShared];
        id<MTLBuffer> rgbaBuf = [device newBufferWithLength:rgba_bytes
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> cmfBuf  = [device newBufferWithBytes:cmf_weights
                                                   length:nb * 3 * sizeof(float)
                                                  options:MTLResourceStorageModeShared];

        struct { uint32_t num_bands, npixels; float norm, pad; } params = {
            (uint32_t)nb, (uint32_t)npixels, 1.0f / y_integral, 0.0f
        };

        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setBuffer:specBuf offset:0 atIndex:0];
        [enc setBuffer:rgbaBuf offset:0 atIndex:1];
        [enc setBuffer:cmfBuf  offset:0 atIndex:2];
        [enc setBytes:&params length:sizeof(params) atIndex:3];
        dispatch_1d(enc, pso, npixels);
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        memcpy(rgba_out, [rgbaBuf contents], rgba_bytes);
    }
    return CF_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. Fused fold+develop on GPU (film curve + spectral → RGB)
 * ══════════════════════════════════════════════════════════════════════ */

/* BandCMF struct matches the Metal side */
typedef struct { float cx, cy, cz, bw; } _band_cmf;

int cf_film_develop_metal(const float *accum_energy, const float *accum_weight,
                          uint32_t width, uint32_t height,
                          int num_bands, const float *band_wavelengths,
                          const cf_film_curve *curve,
                          float *rgba_out)
{
    if (!accum_energy || !accum_weight || !band_wavelengths || !curve || !rgba_out)
        return CF_ERR_IO;

    @autoreleasepool {
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            return cf_film_develop_cpu(accum_energy, accum_weight,
                                       width, height, num_bands,
                                       band_wavelengths, curve, rgba_out);
        }

        id<MTLComputePipelineState> pso = compile_kernel(device, kDevelopShader, @"film_develop");
        if (!pso) {
            return cf_film_develop_cpu(accum_energy, accum_weight,
                                       width, height, num_bands,
                                       band_wavelengths, curve, rgba_out);
        }

        size_t npixels = (size_t)width * height;
        size_t accum_bytes = npixels * num_bands * sizeof(float);
        size_t rgba_bytes  = npixels * 4 * sizeof(float);

        /* precompute band CMF data */
        _band_cmf bcmf[16];
        float wl_step = (num_bands > 1)
            ? (band_wavelengths[num_bands-1] - band_wavelengths[0]) / (float)(num_bands - 1)
            : 300.0f;

        for (int b = 0; b < num_bands; b++) {
            cmf_at_wl(band_wavelengths[b], &bcmf[b].cx, &bcmf[b].cy, &bcmf[b].cz);
            bcmf[b].bw = wl_step / 300.0f;
        }

        /* Metal buffers */
        id<MTLBuffer> eBuf = [device newBufferWithBytes:accum_energy
                                                length:accum_bytes
                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> wBuf = [device newBufferWithBytes:accum_weight
                                                length:accum_bytes
                                               options:MTLResourceStorageModeShared];
        id<MTLBuffer> rBuf = [device newBufferWithLength:rgba_bytes
                                                options:MTLResourceStorageModeShared];
        id<MTLBuffer> cBuf = [device newBufferWithBytes:bcmf
                                                length:num_bands * sizeof(_band_cmf)
                                               options:MTLResourceStorageModeShared];

        /* params — must match FilmDevelopParams layout on GPU */
        struct {
            uint32_t num_bands, npixels;
            float pad0, pad1;
            float base_fog, toe_limit, shoulder_limit, gamma, max_density, iso;
        } params = {
            (uint32_t)num_bands, (uint32_t)npixels, 0.f, 0.f,
            curve->base_fog, curve->toe_limit, curve->shoulder_limit,
            curve->gamma, curve->max_density, curve->iso,
        };

        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setBuffer:eBuf offset:0 atIndex:0];
        [enc setBuffer:wBuf offset:0 atIndex:1];
        [enc setBuffer:rBuf offset:0 atIndex:2];
        [enc setBuffer:cBuf offset:0 atIndex:3];
        [enc setBytes:&params length:sizeof(params) atIndex:4];
        dispatch_1d(enc, pso, npixels);
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];

        memcpy(rgba_out, [rBuf contents], rgba_bytes);
    }
    return CF_OK;
}

#else /* ── non-Apple ── */

int cf_spectral_to_rgba_metal(const cf_image *img, float *rgba_out)
{
    return cf_spectral_to_rgba(img, rgba_out);
}

int cf_film_develop_metal(const float *ae, const float *aw,
                          uint32_t w, uint32_t h,
                          int nb, const float *bw,
                          const cf_film_curve *c, float *out)
{
    return cf_film_develop_cpu(ae, aw, w, h, nb, bw, c, out);
}

#endif
