/*
 * film_develop.cl — OpenCL kernel for fused fold + film curve + spectral → RGB
 *
 * Cross-platform equivalent of metal/film_develop.metal.
 * Single kernel replaces both gfx_film_fold() and gfx_film_develop().
 */

typedef struct {
    float base_fog;
    float toe_limit;
    float shoulder_limit;
    float gamma;
    float max_density;
    float iso;
} FilmCurve;

typedef struct {
    uint num_bands;
    uint npixels;
    float pad0;
    float pad1;
    FilmCurve curve;
} FilmDevelopParams;

typedef struct {
    float cx, cy, cz, bw;
} BandCMF;

float3 xyz_to_srgb_fd(float3 xyz) {
    float3 rgb;
    rgb.x = clamp( 3.2404542f * xyz.x - 1.5371385f * xyz.y - 0.4985314f * xyz.z, 0.0f, 1.0f);
    rgb.y = clamp(-0.9692660f * xyz.x + 1.8760108f * xyz.y + 0.0415560f * xyz.z, 0.0f, 1.0f);
    rgb.z = clamp( 0.0556434f * xyz.x - 0.2040259f * xyz.y + 1.0572252f * xyz.z, 0.0f, 1.0f);
    return rgb;
}

__kernel void film_develop(
    __global const float   *energy,
    __global const float   *weight,
    __global float4        *rgba,
    __global const BandCMF *cmf,
    __constant FilmDevelopParams *params)
{
    uint gid = get_global_id(0);
    if (gid >= params->npixels) return;

    uint nb = params->num_bands;
    FilmCurve c = params->curve;

    float3 xyz = (float3)(0.0f);

    for (uint b = 0; b < nb; b++) {
        uint ai = gid * nb + b;
        float w = weight[ai];
        float val = (w > 0.0f) ? energy[ai] / w : c.base_fog;

        float exposure = val * c.iso;
        float density;

        if (exposure <= c.toe_limit) {
            float td = c.gamma * log10(c.toe_limit + 1e-10f);
            density = c.base_fog + (exposure / c.toe_limit) * (td - c.base_fog);
        } else if (exposure >= c.shoulder_limit) {
            float ld = c.gamma * log10(exposure + 1e-10f);
            float st = min((exposure - c.shoulder_limit) / (c.shoulder_limit * 2.0f), 1.0f);
            density = ld + (c.max_density - ld) * st;
        } else {
            density = c.gamma * log10(exposure + 1e-10f);
        }

        density = min(density, c.max_density);
        float linear = pow(10.0f, density);

        BandCMF bc = cmf[b];
        xyz.x += linear * bc.cx * bc.bw;
        xyz.y += linear * bc.cy * bc.bw;
        xyz.z += linear * bc.cz * bc.bw;
    }

    float3 rgb = xyz_to_srgb_fd(xyz);
    rgba[gid] = (float4)(rgb, 1.0f);
}
