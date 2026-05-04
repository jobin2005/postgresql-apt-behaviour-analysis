"""
test_environment.py
-------------------
Unit tests for the session-based APT Gymnasium environment.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import pytest
from agent.environment import APTEnvironment, N_ACTIONS, STATE_DIM


def _make_dataset(n_sessions=4, apt_label=2):
    """Create an in-memory dataset of 7-dim feature vectors."""
    dataset = []
    for i in range(n_sessions):
        label = apt_label if i % 2 == 0 else 0
        features = np.random.rand(STATE_DIM).astype(np.float32)
        dataset.append({"features": features, "label": label})
    return dataset


def test_reset_returns_valid_obs():
    env = APTEnvironment(_make_dataset())
    obs, info = env.reset()
    assert obs.shape == (STATE_DIM,)
    assert obs.dtype == np.float32


def test_step_returns_correct_types():
    env = APTEnvironment(_make_dataset())
    env.reset()
    obs, rew, done, trunc, info = env.step(0)
    assert isinstance(rew, float)
    assert done is True  # single-step episode


def test_episode_is_single_step():
    env = APTEnvironment(_make_dataset())
    env.reset()
    _, _, done, _, _ = env.step(0)
    assert done


def test_action_space_is_4():
    env = APTEnvironment(_make_dataset())
    assert env.action_space.n == N_ACTIONS


def test_block_apt_gives_positive_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=2)
    env = APTEnvironment(dataset)
    env._ep_idx = -1
    env.reset()
    _, rew, _, _, info = env.step(3)   # Block on APT
    assert rew > 0, f"Expected positive reward for blocking APT, got {rew}"


def test_block_benign_gives_negative_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=0)
    env = APTEnvironment(dataset)
    env.reset()
    _, rew, _, _, _ = env.step(3)   # Block on benign
    assert rew < 0, f"Expected negative reward for false positive, got {rew}"


def test_noop_benign_gives_positive_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=0)
    env = APTEnvironment(dataset)
    env.reset()
    _, rew, _, _, _ = env.step(0)   # No-op on benign
    assert rew > 0


def test_noop_apt_gives_negative_reward():
    dataset = _make_dataset(n_sessions=2, apt_label=2)
    env = APTEnvironment(dataset)
    env._ep_idx = -1
    env.reset()
    _, rew, _, _, _ = env.step(0)   # No-op on APT
    assert rew < 0
