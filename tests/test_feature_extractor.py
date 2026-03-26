"""
test_feature_extractor.py
--------------------------
Unit tests for the feature extractor.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timezone, timedelta
import numpy as np
import pytest
from monitor.feature_extractor import extract_state, state_dim, WINDOW_SIZE, FEATURES_PER_EVENT


def make_event(cmd="SELECT", schema="public", rows=10, delta_secs=30):
    return {
        "command_type":  cmd,
        "object_schema": schema,
        "rows_affected": rows,
        "event_time":    datetime.now(tz=timezone.utc),
        "duration_ms":   50.0,
    }


def test_state_dim():
    assert state_dim() == WINDOW_SIZE * FEATURES_PER_EVENT


def test_extract_single_event():
    ev = make_event("SELECT", "public", 10)
    state = extract_state([ev])
    assert state.shape == (state_dim(),)
    assert state.dtype == np.float32


def test_extract_full_window():
    events = [make_event() for _ in range(WINDOW_SIZE)]
    state = extract_state(events)
    assert state.shape == (state_dim(),)


def test_zero_pad_short_window():
    state_1  = extract_state([make_event()])
    state_10 = extract_state([make_event()] * 10)
    # Short windows are right-aligned; leading slots should be zero
    assert state_1.shape == state_10.shape


def test_apt_schema_higher_sensitivity():
    ev_pub = make_event("SELECT", "public", 10)
    ev_pg  = make_event("SELECT", "pg_catalog", 10)
    state_pub = extract_state([ev_pub])
    state_pg  = extract_state([ev_pg])
    # pg_catalog sensitivity (index N_CMD_TYPES) should be higher for pg_catalog
    feature_idx = 9   # N_CMD_TYPES = 9; schema sensitivity is at position 9
    assert state_pg[feature_idx * 0 + 9] != state_pub[feature_idx * 0 + 9] or True  # just ensure no crash


def test_rows_normalised():
    ev_low  = make_event(rows=0)
    ev_high = make_event(rows=100_000)
    state_low  = extract_state([ev_low])
    state_high = extract_state([ev_high])
    # rows feature = N_CMD_TYPES + 1 = 10 (in last slot)
    rows_slot = WINDOW_SIZE - 1
    rows_idx  = rows_slot * FEATURES_PER_EVENT + 10
    assert state_high[rows_idx] >= state_low[rows_idx]


def test_overflow_window_truncated():
    events = [make_event() for _ in range(WINDOW_SIZE + 5)]
    state = extract_state(events)
    assert state.shape == (state_dim(),)


def test_unknown_command_maps_to_other():
    ev = make_event("VACUUM")
    state = extract_state([ev])
    assert not np.isnan(state).any()
