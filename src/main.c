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

/* FIPS-197 Appendix C.1 — AES-128 official test vector */
static void self_test(void) {
    const uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    };
    const uint8_t pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    };
    const uint8_t expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a,
    };
    uint8_t out[16];
    aes128_encrypt(key, pt, out);
    if (memcmp(out, expected, 16) == 0) {
        printf("[self-test] AES-128 FIPS-197 vector PASSED\n");
    } else {
        printf("[self-test] AES-128 FIPS-197 vector FAILED\n");
        printf("  got:      ");
        for (int i = 0; i < 16; i++) printf("%02x", out[i]);
        printf("\n  expected: ");
        for (int i = 0; i < 16; i++) printf("%02x", expected[i]);
        printf("\n");
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
    printf("\nGenerating traces: n=%d samples=%d noise sigma=%.2f\n",
           n_traces, samples, sigma);

    gen_traces(SECRET_KEY, n_traces, samples, sigma,
               "plaintexts.csv", "traces.bin");
    printf("\nRun the attack with:\n");
    printf("  python python/cpa_attack.py traces.bin plaintexts.csv\n");
    return 0;
}
