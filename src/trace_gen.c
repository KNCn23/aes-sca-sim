#include "trace_gen.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

static uint8_t hamming_weight(uint8_t b) {
    b = b - ((b >> 1) & 0x55);
    b = (b & 0x33) + ((b >> 2) & 0x33);
    return (b + (b >> 4)) & 0x0F;
}

/* Box-Muller Gaussian noise */
static double gauss(double sigma) {
    double u1 = (rand() + 1.0) / ((double)RAND_MAX + 2.0);
    double u2 = (rand() + 1.0) / ((double)RAND_MAX + 2.0);
    return sigma * sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

void gen_traces(const uint8_t key[16],
                int n_traces,
                int samples,
                double noise_sigma,
                const char *plaintext_csv,
                const char *traces_bin) {

    FILE *fp = fopen(plaintext_csv, "w");
    FILE *ft = fopen(traces_bin, "wb");
    if (!fp || !ft) { perror("fopen"); exit(1); }

    /* Write traces as little-endian float32 to keep the file small. */
    int32_t header[3] = { n_traces, samples, 0 };
    fwrite(header, sizeof(int32_t), 3, ft);

    fprintf(fp, "byte0,byte1,byte2,byte3,byte4,byte5,byte6,byte7,"
                "byte8,byte9,byte10,byte11,byte12,byte13,byte14,byte15\n");

    float *trace = malloc(samples * sizeof(float));
    /* One leakage sample per byte index — we place the S-box hamming
     * weight at column (8 + byte_idx) and fill the rest with noise. */

    for (int t = 0; t < n_traces; t++) {
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(rand() & 0xFF);

        /* Compute first-round S-box output for each byte. */
        uint8_t sb[16];
        for (int i = 0; i < 16; i++)
            sb[i] = AES_SBOX[pt[i] ^ key[i]];

        /* Build the trace: pure noise + leakage spikes. */
        for (int s = 0; s < samples; s++)
            trace[s] = (float)gauss(noise_sigma);

        for (int i = 0; i < 16 && (8 + i) < samples; i++) {
            int leak_pos = 8 + i;
            trace[leak_pos] += (float)hamming_weight(sb[i]);
        }

        fwrite(trace, sizeof(float), samples, ft);
        for (int i = 0; i < 16; i++)
            fprintf(fp, "%u%s", pt[i], i == 15 ? "\n" : ",");
    }

    free(trace);
    fclose(fp); fclose(ft);
    printf("Wrote %d traces (%d samples each) to %s + %s\n",
           n_traces, samples, traces_bin, plaintext_csv);
}
