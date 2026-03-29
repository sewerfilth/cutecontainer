/*
 * film_develop.metal — fused fold + film curve + spectral→RGB on GPU
 *
 * Single kernel that replaces both gfx_film_fold() and gfx_film_develop().
 * Reads accumulator data, applies the characteristic curve, integrates
 * against CIE CMFs, and writes RGBA directly to the output surface.
 *
 * The output IOSurface can be handed to the media engine for ProRes
 * encode with zero CPU copy.
 */

#include <metal_stdlib>
using namespace metal;

struct FilmCurve {
    float base_fog;
    float toe_limit;
    float shoulder_limit;
    float gamma;
    float max_density;
    float iso;
};

struct FilmDevelopParams {
    uint  num_bands;
    uint  npixels;
    float pad0;
    float pad1;
    FilmCurve curve;
};

/* Band CMF data: x̄, ȳ, z̄ scaled by bandwidth */
struct BandCMF {
    float cx, cy, cz, bw;
};

/* XYZ → linear sRGB (D65, Rec. 709) */
static float3 xyz_to_srgb(float3 xyz) {
    return float3(
        clamp( 3.2404542f * xyz.x - 1.5371385f * xyz.y - 0.4985314f * xyz.z, 0.0f, 1.0f),
        clamp(-0.9692660f * xyz.x + 1.8760108f * xyz.y + 0.0415560f * xyz.z, 0.0f, 1.0f),
        clamp( 0.0556434f * xyz.x - 0.2040259f * xyz.y + 1.0572252f * xyz.z, 0.0f, 1.0f)
    );
}

/*
 * Fused fold + develop kernel.
 *
 * buffer(0): accum_energy — npixels × num_bands floats
 * buffer(1): accum_weight — npixels × num_bands floats
 * buffer(2): RGBA output  — npixels × 4 floats
 * buffer(3): band CMF data — num_bands × BandCMF
 * buffer(4): params
 */
kernel void film_develop(
    device const float   *energy  [[buffer(0)]],
    device const float   *weight  [[buffer(1)]],
    device float4        *rgba    [[buffer(2)]],
    device const BandCMF *cmf     [[buffer(3)]],
    constant FilmDevelopParams &params [[buffer(4)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= params.npixels) return;

    uint nb = params.num_bands;
    FilmCurve curve = params.curve;

    float3 xyz = float3(0.0f);

    for (uint b = 0; b < nb; b++) {
        uint ai = gid * nb + b;
        float w = weight[ai];
        float val = (w > 0.0f)
            ? energy[ai] / w
            : curve.base_fog;

        /* exposure */
        float exposure = val * curve.iso;

        /* film characteristic curve: toe → linear → shoulder */
        float density;
        if (exposure <= curve.toe_limit) {
            float toe_d = curve.gamma * log10(curve.toe_limit + 1e-10f);
            density = curve.base_fog +
                (exposure / curve.toe_limit) * (toe_d - curve.base_fog);
        } else if (exposure >= curve.shoulder_limit) {
            float ld = curve.gamma * log10(exposure + 1e-10f);
            float st = (exposure - curve.shoulder_limit) / (curve.shoulder_limit * 2.0f);
            st = min(st, 1.0f);
            density = ld + (curve.max_density - ld) * st;
        } else {
            density = curve.gamma * log10(exposure + 1e-10f);
        }

        density = min(density, curve.max_density);
        float linear = pow(10.0f, density);

        /* accumulate XYZ weighted by CIE CMF × bandwidth */
        BandCMF c = cmf[b];
        xyz.x += linear * c.cx * c.bw;
        xyz.y += linear * c.cy * c.bw;
        xyz.z += linear * c.cz * c.bw;
    }

    float3 rgb = xyz_to_srgb(xyz);
    rgba[gid] = float4(rgb, 1.0f);
}
