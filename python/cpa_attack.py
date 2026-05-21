"""
Correlation Power Analysis (CPA) attack on simulated AES-128 traces.

For each of the 16 key bytes:
  1. For every candidate value k ∈ [0, 256):
       hypothetical leakage = HammingWeight(SBOX[plaintext_byte XOR k])
  2. Compute Pearson correlation between the 256 hypothesis vectors and
     each trace sample.
  3. The candidate with the largest |correlation| at any sample is the
     recovered key byte.
"""

import argparse
import struct
import sys
from pathlib import Path

import numpy as np


# ── AES S-box (must match src/aes.c) ───────────────────────────────────────
SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
], dtype=np.uint8)

HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)


def load_traces(path: Path) -> np.ndarray:
    with open(path, "rb") as f:
        n_traces, samples, _ = struct.unpack("<iii", f.read(12))
        data = np.frombuffer(f.read(), dtype=np.float32)
    return data.reshape((n_traces, samples)).astype(np.float64)


def load_plaintexts(path: Path) -> np.ndarray:
    return np.loadtxt(path, delimiter=",", skiprows=1, dtype=np.uint8)


def correlate(hypothesis: np.ndarray, traces: np.ndarray) -> np.ndarray:
    """Pearson correlation between an (N,) hypothesis vector and every
    column of an (N, S) traces matrix.  Returns an (S,) array."""
    h = hypothesis - hypothesis.mean()
    t = traces - traces.mean(axis=0)
    num = h @ t
    den = np.sqrt((h @ h) * (t * t).sum(axis=0))
    return num / np.where(den == 0, 1, den)


def attack_byte(byte_idx: int, plaintexts: np.ndarray, traces: np.ndarray,
                top_k: int = 5):
    best_corr = np.zeros(256)
    best_sample = np.zeros(256, dtype=int)
    for k in range(256):
        h = HW[SBOX[plaintexts[:, byte_idx] ^ k]]
        c = np.abs(correlate(h, traces))
        peak = c.max()
        best_corr[k] = peak
        best_sample[k] = int(c.argmax())

    order = np.argsort(-best_corr)
    top = order[:top_k]
    return int(top[0]), best_corr, top


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("traces", default="traces.bin", nargs="?")
    ap.add_argument("plaintexts", default="plaintexts.csv", nargs="?")
    ap.add_argument("--known", help="Hex string of true key, used to mark correctness",
                    default="2b7e151628aed2a6abf7158809cf4f3c")
    ap.add_argument("--plot", action="store_true",
                    help="Save correlation-vs-candidate plot")
    args = ap.parse_args()

    traces      = load_traces(Path(args.traces))
    plaintexts  = load_plaintexts(Path(args.plaintexts))
    known       = bytes.fromhex(args.known) if args.known else None

    n, s = traces.shape
    print(f"Loaded {n} traces × {s} samples")
    print(f"Loaded {len(plaintexts)} plaintexts\n")

    print(f"{'Byte':>4}  {'Best':>6}  {'Top-5 candidates':<26}  "
          f"{'Truth':>6}  {'Match':>5}")
    print("-" * 64)

    recovered = bytearray(16)
    all_corrs = []
    for i in range(16):
        best, corrs, top5 = attack_byte(i, plaintexts, traces)
        recovered[i] = best
        all_corrs.append(corrs)
        truth = known[i] if known else None
        match = "  ✔" if truth is not None and truth == best else "   "
        top5_str = " ".join(f"{c:02x}" for c in top5)
        print(f"{i:>4}  0x{best:02x}    {top5_str:<26}  "
              f"{('0x'+format(truth, '02x')) if truth is not None else '':>6}"
              f"  {match:>5}")

    print(f"\nRecovered key: {recovered.hex()}")
    if known:
        n_correct = sum(1 for a, b in zip(recovered, known) if a == b)
        print(f"Correct bytes: {n_correct}/16  "
              f"({'FULL KEY RECOVERED' if n_correct == 16 else 'partial'})")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
            fig, axes = plt.subplots(4, 4, figsize=(16, 12))
            for i in range(16):
                ax = axes[i // 4, i % 4]
                ax.plot(all_corrs[i], color="#cccccc", linewidth=0.6)
                ax.plot([recovered[i]], [all_corrs[i][recovered[i]]],
                        "ro", markersize=6, label=f"0x{recovered[i]:02x}")
                if known:
                    ax.axvline(known[i], color="green", linestyle="--",
                               linewidth=0.6, label=f"true 0x{known[i]:02x}")
                ax.set_title(f"Byte {i}", fontsize=9)
                ax.set_xlim(0, 255); ax.legend(fontsize=6, loc="upper right")
                ax.tick_params(labelsize=6)
            fig.suptitle("CPA: peak |correlation| per key candidate, per byte",
                         fontsize=12, fontweight="bold")
            plt.tight_layout()
            plt.savefig("cpa_results.png", dpi=130, bbox_inches="tight")
            print("Saved cpa_results.png")
        except ImportError:
            print("matplotlib missing — skip plot")


if __name__ == "__main__":
    main()
