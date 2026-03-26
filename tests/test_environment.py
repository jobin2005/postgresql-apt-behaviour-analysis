"""
test_environment.py
-------------------
Unit tests for the APT Gymnasium environment.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from datetime import datetime, timezone
import numpy as np
import pytest
from agent.environment import APTEnvironment, N_ACTIONS


def _make_dataset(n_sessions=4, n_events=8, apt_label=2):
    events = [
        {"event_time": datetime.now(tz=timezone.utc),
         "command_type": "SELECT", "object_schema": "public",
         "object_name": "users", "rows_affected": 5, "duration_ms": 10.0}
        for _ in range(n_events)
    ]
    dataset = []
    for i in range(n_sessions):
        label = apt_label if i % 2 == 0 else 0
        dataset.append({"session_id": i + 1, "label": label, "events": events})
    return dataset


def test_reset_returns_valid_obs():
    env = APTEnvironment(_make_dataset())
    obs, info = env.reset()
    assert obs.shape == env.observation_space.shape
    assert env.observation_space.contains(obs.astype(np.float32))


def test_step_increments_correctly():
    env = APTEnvironment(_make_dataset(n_events=5))
    env.reset()
    obs, rew, done, trunc, info = env.step(0)
    assert isinstance(rew, float)
    assert not done   # session has more events


def test_episode_ends():
    env = APTEnvironment(_make_dataset(n_events=3))
    env.reset()
    for _ in range(10):
        _, _, done, _, _ = env.step(0)
        if done:
            break
    assert done


def test_action_space_is_4():
    env = APTEnvironment(_make_dataset())
    assert env.action_space.n == N_ACTIONS


def test_block_apt_gives_positive_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=2)
    env = APTEnvironment(dataset)
    # Force episode to an APT session
    env._ep_idx  = -1   # reset() will increment to 0 (apt_label session)
    env.reset()
    _, rew, _, _, info = env.step(3)   # action=3 (Block) on APT
    assert rew > 0, f"Expected positive reward for blocking APT, got {rew}"


def test_block_benign_gives_negative_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=0)  # all benign
    env = APTEnvironment(dataset)
    env.reset()
    _, rew, _, _, _ = env.step(3)   # action=3 (Block) on benign
    assert rew < 0, f"Expected negative reward for false positive, got {rew}"
