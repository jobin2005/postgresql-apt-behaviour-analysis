"""
feature_extractor.py
--------------------
Converts a rolling window of apt_events rows for a session into a
fixed-size numpy state vector for the DQL agent.

State vector layout (per event in window, window_size default=10):
  [cmd_type_onehot × 9] + [schema_sensitivity] + [rows_norm] + [delta_t_norm]
  + [duration_norm] + [query_entropy] + [semantic_intent]
  => 15 features per event => window_size × 15 flattened

Command type encoding index:
  0=SELECT, 1=INSERT, 2=UPDATE, 3=DELETE, 4=COPY,
  5=ALTER, 6=GRANT, 7=CREATE, 8=OTHER
"""

import math
import numpy as np

# ── Constants ────────────────────────────────────────────────────────────────
CMD_INDEX = {
    "SELECT": 0, "INSERT": 1, "UPDATE": 2, "DELETE": 3,
    "COPY": 4, "ALTER ROLE": 5, "ALTER": 5, "GRANT": 6, "CREATE": 7,
}
N_CMD_TYPES = 9           # one-hot width
FEATURES_PER_EVENT = N_CMD_TYPES + 6   # 15 total
WINDOW_SIZE = 10
STATE_DIM = WINDOW_SIZE * FEATURES_PER_EVENT   # 150

# Schema sensitivity score (higher = more sensitive)
SCHEMA_SENSITIVITY = {
    "information_schema": 0.8,
    "pg_catalog": 0.9,
    "public": 0.3,
}

# Semantic intent scores — maps (object_name) to threat intent [0, 1]
# Higher = more dangerous intent
SENSITIVE_OBJECTS = {
    # Credential / auth targets
    "pg_shadow": 0.95, "pg_authid": 0.95, "pg_roles": 0.85,
    "pg_user": 0.80, "auth_tokens": 0.85, "passwords": 0.95,
    # Data exfiltration targets
    "credit_cards": 0.90, "personal_data": 0.90, "salaries": 0.85,
    # System discovery targets
    "tables": 0.60, "columns": 0.60, "pg_stat_activity": 0.70,
    # Privilege escalation indicators
    "backdoor_role": 0.95,
    # Admin / sensitive ops
    "admin_logs": 0.65,
}

# Normalisation caps
MAX_ROWS = 100_000.0
MAX_DELTA_T_SEC = 3600.0    # 1 hour
MAX_DURATION_MS = 10_000.0  # 10 s


def _cmd_onehot(cmd: str) -> np.ndarray:
    vec = np.zeros(N_CMD_TYPES, dtype=np.float32)
    idx = CMD_INDEX.get(cmd.upper(), 8)   # fall-through → OTHER
    vec[idx] = 1.0
    return vec


def _schema_score(schema: str) -> float:
    if schema is None:
        return 0.2
    return SCHEMA_SENSITIVITY.get(schema.lower(), 0.2)


def _query_entropy(query_hash: str) -> float:
    """
    Compute Shannon entropy of the query hash string, normalised to [0, 1].

    High entropy → likely obfuscated / injected SQL (automated attack tools).
    Low entropy  → simple, predictable queries (normal user behaviour).
    """
    if not query_hash:
        return 0.0
    freq = {}
    for ch in query_hash:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(query_hash)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    # Normalise: max entropy for hex hash (16 chars) ≈ 4.0 bits
    return min(entropy / 4.0, 1.0)


def _semantic_intent(cmd: str, schema: str, object_name: str) -> float:
    """
    Score the *intent* behind a query based on what it targets.

    Combines the command type danger level with the sensitivity of the
    target object to produce a threat-intent score in [0, 1].
    """
    if not object_name:
        return 0.1

    obj_lower = object_name.lower()
    base_score = SENSITIVE_OBJECTS.get(obj_lower, 0.1)

    # Amplify score for write/admin operations on sensitive objects
    cmd_upper = (cmd or "").upper()
    if cmd_upper in ("ALTER ROLE", "ALTER", "GRANT", "CREATE", "COPY"):
        base_score = min(base_score * 1.3, 1.0)
    elif cmd_upper == "DELETE":
        base_score = min(base_score * 1.2, 1.0)

    return base_score


def extract_state(events: list[dict]) -> np.ndarray:
    """
    Build a flat state vector from a list of event dicts.

    Each dict must have keys:
        command_type, object_schema, object_name, rows_affected,
        event_time (datetime), duration_ms, query_hash

    If fewer than WINDOW_SIZE events, the window is zero-padded at the front.
    If more events are supplied, only the last WINDOW_SIZE are used.
    """
    window = events[-WINDOW_SIZE:]  # keep most recent
    state = np.zeros((WINDOW_SIZE, FEATURES_PER_EVENT), dtype=np.float32)

    prev_time = None
    for i, ev in enumerate(window):
        slot = WINDOW_SIZE - len(window) + i   # right-align

        # Command one-hot
        state[slot, :N_CMD_TYPES] = _cmd_onehot(ev.get("command_type", "OTHER"))

        # Schema sensitivity
        state[slot, N_CMD_TYPES] = _schema_score(ev.get("object_schema", ""))

        # Rows normalised
        rows = float(ev.get("rows_affected", 0) or 0)
        state[slot, N_CMD_TYPES + 1] = min(rows / MAX_ROWS, 1.0)

        # Time delta normalised
        ev_time = ev.get("event_time")
        if ev_time is not None and prev_time is not None:
            try:
                delta_sec = (ev_time - prev_time).total_seconds()
            except Exception:
                delta_sec = 0.0
            state[slot, N_CMD_TYPES + 2] = min(abs(delta_sec) / MAX_DELTA_T_SEC, 1.0)
        prev_time = ev_time

        # ── NEW FEATURES (Phase 1) ──────────────────────────────────────

        # Duration normalised
        dur = float(ev.get("duration_ms", 0) or 0)
        state[slot, N_CMD_TYPES + 3] = min(dur / MAX_DURATION_MS, 1.0)

        # Query entropy
        state[slot, N_CMD_TYPES + 4] = _query_entropy(ev.get("query_hash", ""))

        # Semantic intent
        state[slot, N_CMD_TYPES + 5] = _semantic_intent(
            ev.get("command_type", ""),
            ev.get("object_schema", ""),
            ev.get("object_name", ""),
        )

    return state.flatten()   # (150,)


def state_dim() -> int:
    return STATE_DIM
