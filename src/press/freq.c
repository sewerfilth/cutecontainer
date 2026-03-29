/*
 * Frequency table — count and normalize to rANS scale
 */

#include "cutecontainer/press.h"
#include <string.h>

void cp_freq_count(const uint8_t *data, size_t len, cp_freq_table *ft)
{
    memset(ft, 0, sizeof(*ft));
    for (size_t i = 0; i < len; i++)
        ft->freqs[data[i]]++;
    ft->total = (uint32_t)len;
}

void cp_freq_normalize(cp_freq_table *ft)
{
    if (ft->total == 0) {
        /* uniform distribution for empty input */
        for (int i = 0; i < 256; i++) {
            ft->syms[i].freq = CP_RANS_SCALE / 256;
            ft->syms[i].cumfreq = (uint16_t)(i * (CP_RANS_SCALE / 256));
        }
        return;
    }

    /* scale frequencies to sum to CP_RANS_SCALE (4096) */
    uint32_t scaled[256];
    uint32_t sum = 0;

    for (int i = 0; i < 256; i++) {
        if (ft->freqs[i] == 0) {
            scaled[i] = 0;
        } else {
            /* ensure at least 1 for any present symbol */
            scaled[i] = (ft->freqs[i] * (uint64_t)CP_RANS_SCALE) / ft->total;
            if (scaled[i] == 0) scaled[i] = 1;
        }
        sum += scaled[i];
    }

    /* adjust to hit exactly CP_RANS_SCALE */
    while (sum != CP_RANS_SCALE) {
        /* find the symbol with the largest frequency to adjust */
        int best = -1;
        uint32_t best_freq = 0;
        for (int i = 0; i < 256; i++) {
            if (scaled[i] > best_freq) {
                best_freq = scaled[i];
                best = i;
            }
        }
        if (best < 0) break;

        if (sum > CP_RANS_SCALE) {
            if (scaled[best] > 1) {
                scaled[best]--;
                sum--;
            } else {
                break;
            }
        } else {
            scaled[best]++;
            sum++;
        }
    }

    /* build sym table with cumulative frequencies */
    uint16_t cum = 0;
    for (int i = 0; i < 256; i++) {
        ft->syms[i].freq = (uint16_t)scaled[i];
        ft->syms[i].cumfreq = cum;
        cum += (uint16_t)scaled[i];
    }
}
