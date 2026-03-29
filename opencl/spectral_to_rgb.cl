/*
 * spectral_to_rgb.cl — OpenCL kernel for spectral → RGB conversion
 *
 * Cross-platform equivalent of metal/spectral_to_rgb.metal.
 * Runs on any GPU with OpenCL 1.2 support.
 */

typedef struct {
    uint num_bands;
    uint npixels;
    float norm;
    float pad;
} SpectralParams;

float3 xyz_to_srgb(float3 xyz) {
    float3 rgb;
    rgb.x = clamp( 3.2404542f * xyz.x - 1.5371385f * xyz.y - 0.4985314f * xyz.z, 0.0f, 1.0f);
    rgb.y = clamp(-0.9692660f * xyz.x + 1.8760108f * xyz.y + 0.0415560f * xyz.z, 0.0f, 1.0f);
    rgb.z = clamp( 0.0556434f * xyz.x - 0.2040259f * xyz.y + 1.0572252f * xyz.z, 0.0f, 1.0f);
    return rgb;
}

__kernel void spectral_to_rgba(
    __global const float  *spectral,
    __global float4       *rgba_out,
    __global const float3 *cmf,
    __constant SpectralParams *params)
{
    uint gid = get_global_id(0);
    if (gid >= params->npixels) return;

    uint nb = params->num_bands;
    __global const float *spec = spectral + gid * nb;

    float3 xyz = (float3)(0.0f);
    for (uint b = 0; b < nb; b++) {
        float s = spec[b];
        xyz.x += s * cmf[b].x;
        xyz.y += s * cmf[b].y;
        xyz.z += s * cmf[b].z;
    }

    xyz *= params->norm;
    float3 rgb = xyz_to_srgb(xyz);
    rgba_out[gid] = (float4)(rgb, 1.0f);
}
