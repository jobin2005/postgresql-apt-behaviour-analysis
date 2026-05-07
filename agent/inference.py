"""
inference.py
------------
Loads the trained DQN model, scores a session feature vector,
and inserts the decision into the apt_alerts table.

Usage (standalone test):
    python agent/inference.py --session-id 42

Usage (from monitor/live code):
    from agent.inference import score_session, write_alert
    action, threat, taken = score_session(features)
    write_alert(conn, session_id, threat, taken)
"""

import os
import sys
import argparse
from pathlib import Path

import numpy as np
import torch
import psycopg2
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from agent.dqn_model import DQN
from agent.environment import STATE_DIM, N_ACTIONS

load_dotenv()

# ── Action → Alert mapping ──────────────────────────────────────────────────
ACTION_MAP = {
    0: {"threat_level": "safe",     "action_taken": "none"},
    1: {"threat_level": "low",      "action_taken": "alert"},
    2: {"threat_level": "medium",   "action_taken": "rate_limit"},
    3: {"threat_level": "critical", "action_taken": "block"},
}

CHECKPOINT_PATH = Path(os.path.dirname(os.path.dirname(__file__))) / "checkpoints" / "dqn_best.pt"
NORM_STATS_PATH = Path(os.path.dirname(os.path.dirname(__file__))) / "data" / "norm_stats.npz"
DEVICE = "cpu"

# ── Singleton model loader ──────────────────────────────────────────────────
_model = None
_norm_mean = None
_norm_std = None


def _load_norm_stats():
    """Load normalization stats saved during training."""
    global _norm_mean, _norm_std
    if _norm_mean is not None:
        return _norm_mean, _norm_std
    if NORM_STATS_PATH.exists():
        data = np.load(NORM_STATS_PATH)
        _norm_mean = data["mean"]
        _norm_std  = data["std"]
    else:
        # Fallback: no normalization
        _norm_mean = np.zeros(STATE_DIM, dtype=np.float32)
        _norm_std  = np.ones(STATE_DIM, dtype=np.float32)
    return _norm_mean, _norm_std


def _normalize(features: np.ndarray) -> np.ndarray:
    """Apply the same z-score normalization used during training."""
    mean, std = _load_norm_stats()
    return ((features - mean) / std).astype(np.float32)

def _load_model(checkpoint: str = None) -> DQN:
    global _model
    if _model is not None:
        return _model

    ckpt = checkpoint or str(CHECKPOINT_PATH)
    if not os.path.exists(ckpt):
        raise FileNotFoundError(
            f"Model checkpoint not found at {ckpt}. "
            "Train first: python agent/train.py --episodes 500"
        )

    model = DQN(STATE_DIM, N_ACTIONS)
    model.load_state_dict(torch.load(ckpt, map_location=DEVICE, weights_only=True))
    model.eval()
    _model = model
    return model


# ── Public API ──────────────────────────────────────────────────────────────

def score_session(features: np.ndarray, checkpoint: str = None) -> tuple:
    """
    Score a 7-dim feature vector.

    Args:
        features: np.ndarray of shape (7,)
        checkpoint: optional path to model checkpoint

    Returns:
        (action: int, threat_level: str, action_taken: str)
    """
    model = _load_model(checkpoint)
    norm_features = _normalize(features)
    action = model.predict(norm_features, device=DEVICE)
    mapping = ACTION_MAP[action]
    return action, mapping["threat_level"], mapping["action_taken"]


def get_q_values(features: np.ndarray, checkpoint: str = None) -> list:
    """Return raw Q-values for a feature vector (for debugging/explainability)."""
    model = _load_model(checkpoint)
    norm_features = _normalize(features)
    return model.q_values(norm_features, device=DEVICE)


def get_db_conn():
    """Get database connection from environment variables."""
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer"),
    )


def write_alert(conn, session_id: int, action: int, threat_level: str, action_taken: str, q_values: list):
    """
    Insert a row into the apt_alerts table.
    """
    # Supabase check constraint only allows: 'alert', 'rate_limit', 'block'
    # If action is 'none' (safe), we don't insert an alert
    if action_taken == "none":
        return None

    # Threat score approximation (mapped from threat level)
    base_scores = {"low": 30.0, "medium": 60.0, "critical": 90.0}
    threat_score = base_scores.get(threat_level, 0.0)

    import json
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO apt_alerts (session_id, threat_score, action_taken, q_values)
                   VALUES (%s, %s, %s, %s)
                   RETURNING alert_id""",
                (session_id, threat_score, action_taken, json.dumps(q_values)),
            )
            alert_id = cur.fetchone()[0]
    return alert_id


def score_and_alert(conn, session_id: int, features: np.ndarray,
                    checkpoint: str = None) -> dict:
    """
    Full pipeline: score session → write alert → return result.
    """
    action, threat_level, action_taken = score_session(features, checkpoint)
    q_vals = get_q_values(features, checkpoint)
    alert_id = write_alert(conn, session_id, action, threat_level, action_taken, q_vals)

    return {
        "session_id":   session_id,
        "action":       action,
        "threat_level": threat_level,
        "action_taken": action_taken,
        "alert_id":     alert_id,
    }


# ── CLI for quick testing ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="APT Inference & Alert Writer")
    parser.add_argument("--session-id", type=int, default=1,
                        help="Session ID to fetch and score")
    parser.add_argument("--checkpoint", type=str, default=None)
    parser.add_argument("--dry-run", action="store_true",
                        help="Score only, don't write to DB")
    args = parser.parse_args()

    print(f"\n[Inference] Loading model from {args.checkpoint or CHECKPOINT_PATH}")

    # Demo with critical APT features
    demo_features = np.array([120, 15, 80000, 3600, 25, 0.9, 0.85], dtype=np.float32)
    action, threat, taken = score_session(demo_features, args.checkpoint)
    q_vals = get_q_values(demo_features, args.checkpoint)

    print(f"\n  Demo features: {demo_features}")
    print(f"  Q-values     : {[f'{v:.3f}' for v in q_vals]}")
    print(f"  Action       : {action} ({taken})")
    print(f"  Threat level : {threat}")

    if not args.dry_run:
        try:
            conn = get_db_conn()
            alert_id = write_alert(conn, args.session_id, action, threat, taken, q_vals)
            conn.close()
            if alert_id:
                print(f"  Alert written : alert_id={alert_id}")
            else:
                print(f"  No alert written (action=none)")
        except Exception as e:
            print(f"  [!] DB write skipped: {e}")

    print()


if __name__ == "__main__":
    main()