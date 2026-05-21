#ifndef TRACE_GEN_H
#define TRACE_GEN_H

#include <stdint.h>
#include <stddef.h>

/* Generate N power traces.  Each trace is a sequence of `samples_per_trace`
 * floats representing simulated instantaneous power consumption.
 *
 * We model the leakage from the first-round S-box output: each S-box byte's
 * Hamming weight is added as a "power spike" at one sample, plus Gaussian
 * noise across the trace.  This mirrors what real CMOS hardware leaks. */

void gen_traces(const uint8_t key[16],
                int n_traces,
                int samples_per_trace,
                double noise_sigma,
                const char *plaintext_csv,
                const char *traces_bin);

#endif
