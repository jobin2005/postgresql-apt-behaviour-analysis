"""
test_feature_extractor.py
--------------------------
Unit tests for the session-based feature extractor (7-dim).
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pytest
from monitor.feature_extractor import extract_state, state_dim


def _make_session(**overrides):
    """Create a mock session dict for extract_state."""
    defaults = {
        "session_id": 1,
        "user_id": "alice",
        "query_count": 10,
        "failed_query_count": 1,
        "total_rows": 200,
        "duration": 120,
        "unique_tables": 3,
    }
    defaults.update(overrides)
    return defaults


class FakeConn:
    """Minimal mock DB connection for extract_state."""
    class FakeCursor:
        def __init__(self):
            self._result = None
        def execute(self, *a, **kw):
            pass
        def fetchone(self):
            return (10, 1000, 60)  # default profile
        def fetchall(self):
            return []  # no sequence data
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    def cursor(self):
        return self.FakeCursor()


def test_state_dim_is_7():
    assert state_dim() == 7


def test_extract_state_shape():
    conn = FakeConn()
    session = _make_session()
    state = extract_state(conn, session)
    assert state.shape == (7,)
    assert state.dtype == np.float32


def test_extract_state_values():
    conn = FakeConn()
    session = _make_session(query_count=20, failed_query_count=5,
                            total_rows=500, duration=300, unique_tables=8)
    state = extract_state(conn, session)
    assert state[0] == 20      # query_count
    assert state[1] == 5       # failed_query_count
    assert state[2] == 500     # total_rows
    assert state[3] == 300     # duration
    assert state[4] == 8       # unique_tables
    assert 0.0 <= state[5] <= 1.0  # anomaly (capped at 1.0)
    assert state[6] >= 0.0         # seq_risk


def test_anomaly_increases_with_deviation():
    conn = FakeConn()
    normal = _make_session(query_count=10, total_rows=1000, duration=60)
    extreme = _make_session(query_count=200, total_rows=50000, duration=5000)
    state_n = extract_state(conn, normal)
    state_e = extract_state(conn, extreme)
    assert state_e[5] > state_n[5]  # anomaly should be higher


def test_no_nan_values():
    conn = FakeConn()
    session = _make_session()
    state = extract_state(conn, session)
    assert not np.isnan(state).any()
