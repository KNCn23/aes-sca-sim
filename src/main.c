#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "aes.h"
#include "trace_gen.h"

static const uint8_t SECRET_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

/* Standard FIPS-197 test vector for self-test */
static void self_test(void) {
    const uint8_t pt[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x4a,
    };
    const uint8_t expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    };
    uint8_t out[16];
    aes128_encrypt(SECRET_KEY, pt, out);
    if (memcmp(out, expected, 16) == 0) {
        printf("[self-test] AES-128 FIPS-197 vector PASSED\n");
    } else {
        printf("[self-test] AES-128 FIPS-197 vector FAILED\n");
        exit(1);
    }
}

static void print_key(const char *label, const uint8_t *key) {
    printf("%-16s ", label);
    for (int i = 0; i < 16; i++) printf("%02x ", key[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    int n_traces = argc > 1 ? atoi(argv[1]) : 2000;
    int samples  = argc > 2 ? atoi(argv[2]) : 64;
    double sigma = argc > 3 ? atof(argv[3]) : 1.5;

    srand((unsigned)time(NULL));

    printf("AES-128 Side-Channel Attack Simulator\n");
    printf("═════════════════════════════════════\n\n");

    self_test();
    print_key("Secret key:", SECRET_KEY);
    printf("\nGenerating traces: n=%d samples=%d noise σ=%.2f\n",
           n_traces, samples, sigma);

    gen_traces(SECRET_KEY, n_traces, samples, sigma,
               "plaintexts.csv", "traces.bin");
    printf("\nRun the attack with:\n");
    printf("  python python/cpa_attack.py traces.bin plaintexts.csv\n");
    return 0;
}
