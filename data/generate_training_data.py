"""
generate_training_data.py
-------------------------
Generates synthetic 7-dimension session feature vectors for offline
DQN training.  No database connection required.

The 7 features mirror monitor/feature_extractor.py:
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
    python data/generate_training_data.py --sessions 5000 --apt-ratio 0.3
"""

import argparse
import os
import numpy as np
from pathlib import Path

# ── Distribution profiles ────────────────────────────────────────────────────
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
    """Add small gaussian noise so class boundaries are not perfectly clean.
    This makes the model learn better decision boundaries."""
    n = features.shape[0]
    n_noisy = int(n * noise_frac)
    indices = rng.choice(n, size=n_noisy, replace=False)
    for idx in indices:
        features[idx] += rng.normal(0, 0.05, size=7).astype(np.float32)
    return features


def generate(n_sessions: int, apt_ratio: float, seed: int = 42) -> tuple:
    """
    Returns (features, labels) numpy arrays.
        features: (N, 7) float32
        labels:   (N,)   int64   (0, 1, or 2)
    """
    rng = np.random.default_rng(seed)

    n_apt     = int(n_sessions * apt_ratio)
    n_susp    = max(1, n_apt // 3)          # ~10% of total
    n_conf    = n_apt - n_susp              # ~20% of total
    n_benign  = n_sessions - n_apt

    # Generate each class
    benign_feats  = _sample_profile(BENIGN_PROFILE,     n_benign, rng)
    susp_feats    = _sample_profile(SUSPICIOUS_PROFILE, n_susp,   rng)
    apt_feats     = _sample_profile(APT_PROFILE,        n_conf,   rng)

    benign_labels = np.zeros(n_benign, dtype=np.int64)
    susp_labels   = np.ones(n_susp,   dtype=np.int64)
    apt_labels    = np.full(n_conf, 2, dtype=np.int64)

    # Concatenate & shuffle
    features = np.vstack([benign_feats, susp_feats, apt_feats])
    labels   = np.concatenate([benign_labels, susp_labels, apt_labels])

    # Add realistic noise for boundary overlap
    features = _add_noise_overlap(features, rng)

    # Shuffle together
    perm = rng.permutation(len(labels))
    features = features[perm]
    labels   = labels[perm]

    return features, labels


def main():
    parser = argparse.ArgumentParser(description="Generate 7-dim training data")
    parser.add_argument("--sessions", type=int, default=5000,
                        help="Total sessions to generate (default: 5000)")
    parser.add_argument("--apt-ratio", type=float, default=0.3,
                        help="Fraction that are APT (suspicious + confirmed)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    features, labels = generate(args.sessions, args.apt_ratio, args.seed)

    out_dir = Path(os.path.dirname(__file__))
    out_path = out_dir / "training_sessions.npz"
    np.savez(out_path, features=features, labels=labels)

    # Print summary
    unique, counts = np.unique(labels, return_counts=True)
    dist = dict(zip(unique, counts))
    print(f"\n{'='*50}")
    print(f"  Training Data Generated Successfully")
    print(f"{'='*50}")
    print(f"  Output file : {out_path}")
    print(f"  Total sessions : {len(labels)}")
    print(f"  Benign (0)     : {dist.get(0, 0)}")
    print(f"  Suspicious (1) : {dist.get(1, 0)}")
    print(f"  APT (2)        : {dist.get(2, 0)}")
    print(f"  Feature shape  : {features.shape}")
    print(f"{'='*50}")

    # Print per-feature statistics
    print(f"\n  Per-feature statistics:")
    print(f"  {'Feature':<22} {'Mean':>10} {'Std':>10} {'Min':>10} {'Max':>10}")
    print(f"  {'-'*62}")
    for i, name in enumerate(FEATURE_KEYS):
        col = features[:, i]
        print(f"  {name:<22} {col.mean():>10.2f} {col.std():>10.2f} "
              f"{col.min():>10.2f} {col.max():>10.2f}")
    print()


if __name__ == "__main__":
    main()
