# AES-128 Side-Channel Attack Simulator

A self-contained demonstration of how a real-world cryptanalytic attack — **Correlation Power Analysis (CPA)** — can extract a hidden AES-128 key from leaked side-channel information, **without ever attacking the cipher math itself**. Useful for embedded security education, side-channel research, and understanding why constant-time implementations matter.

## What it does

```
┌─────────────────────────────────────────────────────────────────┐
│  trace-gen (C)                                                  │
│   • Encrypts N random plaintexts with the secret key            │
│   • Simulates power traces leaking HW(SBOX[P ⊕ K])  + Gaussian  │
│     noise — same leakage model used by real CMOS hardware       │
│   • Writes traces.bin + plaintexts.csv                          │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  cpa_attack.py (Python)                                         │
│   • For each of 16 key bytes, tries all 256 candidate values    │
│   • For each candidate, computes Hamming-weight hypothesis      │
│   • Correlates hypothesis with the simulated traces             │
│   • The maximum-correlation candidate IS the secret key byte    │
└─────────────────────────────────────────────────────────────────┘
```

The trick: even though the attacker never reads memory, never sees the key, and the cipher itself is mathematically secure, the **physical leakage from the S-box computation** is enough to recover all 16 bytes independently.

## Build & run

```bash
make
./trace-gen 2000 64 1.5      # 2000 traces, 64 samples each, σ=1.5
pip install -r python/requirements.txt
python python/cpa_attack.py
```

## Sample output

```
AES-128 Side-Channel Attack Simulator
═════════════════════════════════════

[self-test] AES-128 FIPS-197 vector PASSED
Secret key:      2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

Generating traces: n=2000 samples=64 noise σ=1.50
Wrote 2000 traces (64 samples each) to traces.bin + plaintexts.csv
```

Then the attack:

```
Loaded 2000 traces × 64 samples
Loaded 2000 plaintexts

Byte  Best    Top-5 candidates           Truth  Match
----------------------------------------------------------------
   0  0x2b    2b 6b ab 0b cb             0x2b     ✔
   1  0x7e    7e fe 3e be 9e             0x7e     ✔
   2  0x15    15 95 55 d5 35             0x15     ✔
   ...
  15  0x3c    3c bc 7c 1c fc             0x3c     ✔

Recovered key: 2b7e151628aed2a6abf7158809cf4f3c
Correct bytes: 16/16  (FULL KEY RECOVERED)
```

## Visualization

Pass `--plot` to render a 4×4 grid showing peak correlation per candidate for every key byte; the true value forms a clear spike above the noise floor:

```bash
python python/cpa_attack.py --plot
```

## Why this works (the leakage model)

In real CMOS hardware, the power dissipated when computing an intermediate value is proportional to its **Hamming weight** (number of 1-bits). The AES first-round S-box output `SBOX[P ⊕ K]` depends on both a known plaintext byte and an unknown key byte. By trying all 256 candidate keys and correlating each hypothesis against the measured trace, the correct guess **stands out statistically** — the others look like random noise.

Per FIPS countermeasures, real-world implementations defend against this with masking, hiding, shuffling, and constant-time logic. This project intentionally shows the *unprotected* case.

## Files

```
├── include/
│   ├── aes.h
│   └── trace_gen.h
├── src/
│   ├── aes.c          # FIPS-197 reference AES-128 + S-box
│   ├── trace_gen.c    # Hamming-weight leakage + Gaussian noise
│   └── main.c         # Self-test + trace generation
├── python/
│   ├── cpa_attack.py  # The CPA attack — ~120 lines, NumPy only
│   └── requirements.txt
└── Makefile
```

## Tuning the attack

| Parameter | Effect |
|---|---|
| `n_traces` | More traces → higher SNR, succeeds at higher noise. 1000–5000 is realistic for unprotected hardware. |
| `samples`  | Number of points per trace — must be ≥ 8 + byte_idx so the leakage spike falls in-window. |
| `noise σ`  | Bigger σ = harder attack. Above σ ≈ 4 you typically need 10k+ traces. |

Try `./trace-gen 500 64 0.3` for an easy run, or `./trace-gen 10000 64 4.0` for a noisy one.

## References

- Kocher, Jaffe, Jun, *"Differential Power Analysis"*, CRYPTO 1999.
- Brier, Clavier, Olivier, *"Correlation Power Analysis with a Leakage Model"*, CHES 2004.
- NIST FIPS 197, *"Advanced Encryption Standard"*.

## License

MIT
