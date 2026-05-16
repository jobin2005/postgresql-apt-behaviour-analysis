"""
generate_test_data.py
---------------------
Generates a HELD-OUT test set for evaluating the DQN APT detection model.

Mirrors the 7-feature schema of generate_training_data.py but with:
  1. A different seed (123 vs training seed 42) — true held-out data.
  2. Scale-aware noise — noise magnitude is proportional to each feature's
     inter-class standard deviation, not a flat 0.05 that only affects the
     [0,1]-bounded features (anomaly, seq_risk).
  3. An edge-case supplement — a small set of boundary sessions that sit
     right on the benign/suspicious border, stress-testing the model on the
     hardest inputs.

The 7 features (mirror feature_extractor.py):
    0  query_count          Total queries in session
    1  failed_query_count   Failed queries
    2  total_rows           Total rows accessed
    3  duration             Session duration (seconds)
    4  unique_tables        Distinct tables touched
    5  anomaly              Deviation from user baseline  (0-1)
    6  seq_risk             Sequence-pattern risk score   (0-1)

Labels:
    0 = benign
    1 = suspicious  (partial / early-stage APT)
    2 = confirmed APT

Usage:
    python data/generate_test_data.py --sessions 1500 --apt-ratio 0.3
    python data/generate_test_data.py --sessions 1500 --seed 999

Output:
    data/test_sessions.npz   — held-out test set for model evaluation
"""

import argparse
import os
import numpy as np
from pathlib import Path

# ── Distribution profiles (must match generate_training_data.py exactly) ──────
# Each profile: (mean, std, clip_low, clip_high) per feature

BENIGN_PROFILE = {
    "query_count":        (10,   5,    1,    30),
    "failed_query_count": (0.5,  0.8,  0,    3),
    "total_rows":         (100,  120,  1,    800),
    "duration":           (90,   60,   10,   400),
    "unique_tables":      (2,    1.2,  1,    6),
    "anomaly":            (0.08, 0.06, 0.0,  0.25),
    "seq_risk":           (0.03, 0.03, 0.0,  0.12),
}

SUSPICIOUS_PROFILE = {
    "query_count":        (35,   12,   10,   80),
    "failed_query_count": (5,    2.5,  1,    12),
    "total_rows":         (2000, 1500, 100,  8000),
    "duration":           (350,  150,  60,   900),
    "unique_tables":      (7,    2.5,  3,    15),
    "anomaly":            (0.45, 0.12, 0.25, 0.65),
    "seq_risk":           (0.35, 0.10, 0.15, 0.55),
}

APT_PROFILE = {
    "query_count":        (80,   30,   25,   200),
    "failed_query_count": (12,   5,    3,    30),
    "total_rows":         (40000,25000,500,   150000),
    "duration":           (2500, 1500, 200,  7200),
    "unique_tables":      (18,   6,    6,    40),
    "anomaly":            (0.82, 0.10, 0.55, 1.0),
    "seq_risk":           (0.75, 0.15, 0.40, 1.0),
}

FEATURE_KEYS = [
    "query_count", "failed_query_count", "total_rows",
    "duration", "unique_tables", "anomaly", "seq_risk",
]

# ── Precomputed per-feature noise scale ────────────────────────────────────────
# Noise is set to 10% of the inter-class standard deviation for each feature.
# This ensures noise is proportionally meaningful across all features —
# including high-range ones like total_rows and duration — not just the
# [0,1]-bounded anomaly and seq_risk.
#
# Formula: noise_std[i] = 0.10 * sqrt(benign_std[i]^2 + apt_std[i]^2)
#
# Derived values (computed once; must match BENIGN/APT profiles above):
_NOISE_STD = {
    "query_count":        0.10 * np.sqrt(5**2    + 30**2),     # ≈ 3.04
    "failed_query_count": 0.10 * np.sqrt(0.8**2  + 5**2),      # ≈ 0.51
    "total_rows":         0.10 * np.sqrt(120**2  + 25000**2),  # ≈ 2500.0
    "duration":           0.10 * np.sqrt(60**2   + 1500**2),   # ≈ 150.1
    "unique_tables":      0.10 * np.sqrt(1.2**2  + 6**2),      # ≈ 0.61
    "anomaly":            0.10 * np.sqrt(0.06**2 + 0.10**2),   # ≈ 0.012
    "seq_risk":           0.10 * np.sqrt(0.03**2 + 0.15**2),   # ≈ 0.015
}
_NOISE_STD_ARRAY = np.array([_NOISE_STD[k] for k in FEATURE_KEYS], dtype=np.float32)


def _sample_profile(profile: dict, n: int, rng: np.random.Generator) -> np.ndarray:
    """Sample n sessions from a statistical profile → (n, 7) array."""
    cols = []
    for key in FEATURE_KEYS:
        mean, std, lo, hi = profile[key]
        vals = rng.normal(mean, std, size=n)
        vals = np.clip(vals, lo, hi)
        cols.append(vals)
    return np.column_stack(cols).astype(np.float32)


def _add_noise_overlap(features: np.ndarray, rng: np.random.Generator,
                       noise_frac: float = 0.08) -> np.ndarray:
    """
    Add scale-aware gaussian noise to a random subset of sessions.

    Unlike the original training generator which applied a flat std=0.05 to all
    features (effectively zero noise for total_rows, duration, etc.), this
    version scales noise per-feature using the inter-class standard deviation.
    This creates realistic boundary overlap across all 7 dimensions.

    After noise, all features are clipped to a physically valid minimum of 0
    (you cannot have negative query counts, rows, or duration).
    """
    n = features.shape[0]
    n_noisy = max(1, int(n * noise_frac))
    indices = rng.choice(n, size=n_noisy, replace=False)
    for idx in indices:
        noise = rng.normal(0, _NOISE_STD_ARRAY).astype(np.float32)
        features[idx] += noise
    # Enforce physical lower bound: no feature value can be negative
    np.clip(features, 0, None, out=features)
    return features


def _generate_edge_cases(rng: np.random.Generator) -> tuple:
    """
    Generate sessions that sit on or near the benign/suspicious boundary.
    These are the hardest inputs for the model and stress-test decision boundaries.

    Returns (features, labels) arrays.
    """
    # Midpoint between benign and suspicious for each feature
    edge_cases = []
    for _ in range(50):    # 50 benign-edge cases
        row = []
        for k in FEATURE_KEYS:
            bm = BENIGN_PROFILE[k][0]
            sm = SUSPICIOUS_PROFILE[k][0]
            lo = BENIGN_PROFILE[k][2]
            hi = SUSPICIOUS_PROFILE[k][3]
            midpoint = (bm + sm) / 2
            # Add small jitter to avoid all samples being identical
            val = float(np.clip(rng.normal(midpoint, (sm - bm) * 0.1), lo, hi))
            row.append(val)
        edge_cases.append(row)

    features = np.array(edge_cases, dtype=np.float32)
    # Label as suspicious (1) since they're in the border zone
    labels = np.ones(len(edge_cases), dtype=np.int64)
    return features, labels


def generate(n_sessions: int, apt_ratio: float, seed: int = 123) -> tuple:
    """
    Generate a held-out test set.

    Args:
        n_sessions: total number of sessions to generate
        apt_ratio:  fraction of sessions that are APT (suspicious + confirmed)
        seed:       RNG seed — must differ from training seed (42)

    Returns:
        features: (N, 7) float32
        labels:   (N,)   int64  — 0=benign, 1=suspicious, 2=confirmed APT
    """
    if seed == 42:
        raise ValueError(
            "seed=42 is reserved for the training set. "
            "Use a different seed (e.g. 123) so the test set is truly held-out."
        )

    rng = np.random.default_rng(seed)

    n_apt   = int(n_sessions * apt_ratio)
    n_susp  = max(1, n_apt // 3)
    n_conf  = n_apt - n_susp
    n_benign = n_sessions - n_apt

    # Core class samples
    benign_feats = _sample_profile(BENIGN_PROFILE,     n_benign, rng)
    susp_feats   = _sample_profile(SUSPICIOUS_PROFILE, n_susp,   rng)
    apt_feats    = _sample_profile(APT_PROFILE,        n_conf,   rng)

    benign_labels = np.zeros(n_benign, dtype=np.int64)
    susp_labels   = np.ones(n_susp,   dtype=np.int64)
    apt_labels    = np.full(n_conf, 2, dtype=np.int64)

    # Edge cases (boundary sessions)
    edge_feats, edge_labels = _generate_edge_cases(rng)

    # Concatenate everything
    features = np.vstack([benign_feats, susp_feats, apt_feats, edge_feats])
    labels   = np.concatenate([benign_labels, susp_labels, apt_labels, edge_labels])

    # Scale-aware noise on random 8% of sessions
    features = _add_noise_overlap(features, rng, noise_frac=0.08)

    # Shuffle
    perm = rng.permutation(len(labels))
    features = features[perm]
    labels   = labels[perm]

    return features, labels


def _print_summary(features, labels, out_path):
    unique, counts = np.unique(labels, return_counts=True)
    dist = dict(zip(unique, counts))
    total = len(labels)

    print(f"\n{'='*56}")
    print(f"  Test Data Generated Successfully")
    print(f"{'='*56}")
    print(f"  Output file    : {out_path}")
    print(f"  Total sessions : {total}")
    print(f"  Benign    (0)  : {dist.get(0, 0):>5}  ({100*dist.get(0,0)/total:.1f}%)")
    print(f"  Suspicious(1)  : {dist.get(1, 0):>5}  ({100*dist.get(1,0)/total:.1f}%)")
    print(f"  APT       (2)  : {dist.get(2, 0):>5}  ({100*dist.get(2,0)/total:.1f}%)")
    print(f"  Feature shape  : {features.shape}")
    print(f"{'='*56}")

    print(f"\n  Per-feature statistics (raw, pre-normalization):")
    print(f"  {'Feature':<22} {'Mean':>10} {'Std':>10} {'Min':>10} {'Max':>10}")
    print(f"  {'-'*64}")
    for i, name in enumerate(FEATURE_KEYS):
        col = features[:, i]
        print(f"  {name:<22} {col.mean():>10.2f} {col.std():>10.2f} "
              f"{col.min():>10.2f} {col.max():>10.2f}")

    print(f"\n  Per-class feature means:")
    print(f"  {'Feature':<22} {'Benign':>10} {'Suspicious':>12} {'APT':>10}")
    print(f"  {'-'*58}")
    for i, name in enumerate(FEATURE_KEYS):
        bm = features[labels == 0, i].mean() if (labels == 0).any() else 0
        sm = features[labels == 1, i].mean() if (labels == 1).any() else 0
        am = features[labels == 2, i].mean() if (labels == 2).any() else 0
        print(f"  {name:<22} {bm:>10.2f} {sm:>12.2f} {am:>10.2f}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate held-out test data for APT DQN evaluation"
    )
    parser.add_argument("--sessions",  type=int,   default=1500,
                        help="Total sessions to generate (default: 1500, ~30%% of 5000 training)")
    parser.add_argument("--apt-ratio", type=float, default=0.3,
                        help="Fraction that are APT (suspicious + confirmed), default: 0.3")
    parser.add_argument("--seed",      type=int,   default=123,
                        help="RNG seed — must not be 42 (reserved for training), default: 123")
    parser.add_argument("--output",    type=str,   default=None,
                        help="Output .npz path (default: data/test_sessions.npz)")
    args = parser.parse_args()

    features, labels = generate(args.sessions, args.apt_ratio, args.seed)

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = Path(os.path.dirname(__file__)) / "data" / "test_sessions.npz"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(str(out_path), features=features, labels=labels)

    _print_summary(features, labels, out_path)


if __name__ == "__main__":
    main()