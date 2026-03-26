"""
feature_extractor.py
--------------------
Converts a rolling window of apt_events rows for a session into a
fixed-size numpy state vector for the DQL agent.

State vector layout (per event in window, window_size default=10):
  [cmd_type_onehot × 9] + [schema_sensitivity] + [rows_norm] + [delta_t_norm] + [duration_norm]
  => 12 features per event => window_size × 12 flattened

Command type encoding index:
  0=SELECT, 1=INSERT, 2=UPDATE, 3=DELETE, 4=COPY,
  5=ALTER, 6=GRANT, 7=CREATE, 8=OTHER
"""

import numpy as np

# ── Constants ────────────────────────────────────────────────────────────────
CMD_INDEX = {
    "SELECT": 0, "INSERT": 1, "UPDATE": 2, "DELETE": 3,
    "COPY": 4, "ALTER ROLE": 5, "ALTER": 5, "GRANT": 6, "CREATE": 7,
}
N_CMD_TYPES = 9           # one-hot width
FEATURES_PER_EVENT = N_CMD_TYPES + 3   # 12 total
WINDOW_SIZE = 10
STATE_DIM = WINDOW_SIZE * FEATURES_PER_EVENT   # 120

# Schema sensitivity score (higher = more sensitive)
SCHEMA_SENSITIVITY = {
    "information_schema": 0.8,
    "pg_catalog": 0.9,
    "public": 0.3,
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


def extract_state(events: list[dict]) -> np.ndarray:
    """
    Build a flat state vector from a list of event dicts.

    Each dict must have keys:
        command_type, object_schema, rows_affected,
        event_time (datetime), duration_ms

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

    return state.flatten()   # (120,)


def state_dim() -> int:
    return STATE_DIM
