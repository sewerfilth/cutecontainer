/*
 * spectral_to_rgb.metal — GPU spectral → RGB conversion
 *
 * Per-pixel integration of spectral bands against CIE 1931 2°
 * observer color matching functions, then XYZ → linear sRGB.
 */

#include <metal_stdlib>
using namespace metal;

/* Uniforms passed from the host */
struct SpectralParams {
    uint  num_bands;
    uint  npixels;
    float norm;         /* 1.0 / ∫ȳ dλ  (normalization factor) */
    float pad;
};

/* XYZ → linear sRGB (D65, Rec. 709) */
static float3 xyz_to_srgb(float3 xyz) {
    float3 rgb;
    rgb.r = clamp( 3.2404542f * xyz.x - 1.5371385f * xyz.y - 0.4985314f * xyz.z, 0.0f, 1.0f);
    rgb.g = clamp(-0.9692660f * xyz.x + 1.8760108f * xyz.y + 0.0415560f * xyz.z, 0.0f, 1.0f);
    rgb.b = clamp( 0.0556434f * xyz.x - 0.2040259f * xyz.y + 1.0572252f * xyz.z, 0.0f, 1.0f);
    return rgb;
}

/*
 * Kernel: spectral_to_rgba
 *
 * buffer(0): spectral data — npixels × num_bands floats (BIP order)
 * buffer(1): RGBA output   — npixels × 4 floats
 * buffer(2): CMF weights   — num_bands × 3 floats (pre-scaled x̄·Δλ, ȳ·Δλ, z̄·Δλ)
 * buffer(3): params
 */
kernel void spectral_to_rgba(
    device const float  *spectral  [[buffer(0)]],
    device float4       *rgba_out  [[buffer(1)]],
    device const float3 *cmf       [[buffer(2)]],
    constant SpectralParams &params [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= params.npixels) return;

    uint nb = params.num_bands;
    device const float *spec = spectral + gid * nb;

    float3 xyz = float3(0.0f);
    for (uint b = 0; b < nb; b++) {
        float s = spec[b];
        xyz.x += s * cmf[b].x;
        xyz.y += s * cmf[b].y;
        xyz.z += s * cmf[b].z;
    }

    xyz *= params.norm;
    float3 rgb = xyz_to_srgb(xyz);
    rgba_out[gid] = float4(rgb, 1.0f);
}
