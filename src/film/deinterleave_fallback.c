/*
 * deinterleave_fallback.c — C fallback for BIP ↔ BSQ conversion
 *
 * Weak symbols: overridden by per-arch ASM on aarch64 / x86_64.
 */

#include "cutecontainer/film.h"

#if defined(__GNUC__) || defined(__clang__)
#define CF_WEAK __attribute__((weak))
#else
#define CF_WEAK
#endif

CF_WEAK
void cf_deinterleave_band(const float *bip, float *plane,
                          size_t npixels, int num_bands, int band)
{
    for (size_t i = 0; i < npixels; i++)
        plane[i] = bip[i * num_bands + band];
}

CF_WEAK
void cf_interleave_band(float *bip, const float *plane,
                        size_t npixels, int num_bands, int band)
{
    for (size_t i = 0; i < npixels; i++)
        bip[i * num_bands + band] = plane[i];
}
