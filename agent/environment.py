"""
environment.py
--------------
OpenAI Gymnasium-compatible environment wrapping the PostgreSQL session data.

State space:  flat numpy array of shape (STATE_DIM,)  — see feature_extractor.py
Action space: Discrete(4)
    0 = No-op     1 = Alert     2 = Rate-Limit     3 = Block

Reward shaping:
    Correct Block of APT:        +10
    Correct No-op on benign:     +1
    Alert on APT:                +3
    Rate-Limit on APT:           +5
    False Positive (block/rate on benign): -2
    Missed APT (no-op on APT):   -8
    Time-step regularisation:    -0.05  (encourages quick decisions)
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from monitor.feature_extractor import state_dim, extract_state

N_ACTIONS = 4
ACTION_NOOP       = 0
ACTION_ALERT      = 1
ACTION_RATE_LIMIT = 2
ACTION_BLOCK      = 3

# Reward table: (is_apt, action) → reward
_REWARDS = {
    (False, ACTION_NOOP):       +1.0,
    (False, ACTION_ALERT):      -0.5,
    (False, ACTION_RATE_LIMIT): -2.0,
    (False, ACTION_BLOCK):      -2.0,
    (True,  ACTION_NOOP):       -8.0,
    (True,  ACTION_ALERT):      +3.0,
    (True,  ACTION_RATE_LIMIT): +5.0,
    (True,  ACTION_BLOCK):      +10.0,
}
TIME_PENALTY = -0.05


class APTEnvironment(gym.Env):
    """
    Episode = one database session.
    Each step = one new event appended to the session window.
    The agent acts after each event.
    """

    metadata = {"render_modes": []}

    def __init__(self, dataset: list[dict]):
        """
        dataset: list of {session_id, label, events:[...]}
                 as returned by log_parser.fetch_all_labelled_sessions()
        """
        super().__init__()
        self.dataset   = dataset
        self._ep_idx   = 0
        self._step_idx = 0
        self._events   = []
        self._label    = 0

        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(state_dim(),), dtype=np.float32
        )
        self.action_space = spaces.Discrete(N_ACTIONS)

    # ── Gym API ───────────────────────────────────────────────────────────────
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._ep_idx   = (self._ep_idx + 1) % len(self.dataset)
        session        = self.dataset[self._ep_idx]
        self._events   = session["events"]
        self._label    = session["label"]
        self._step_idx = 0
        return self._obs(), {}

    def step(self, action: int):
        is_apt = self._label in (1, 2)

        # Reward from table + time penalty
        reward = _REWARDS.get((is_apt, action), 0.0) + TIME_PENALTY

        self._step_idx += 1
        done = self._step_idx >= len(self._events)

        truncated = False
        if not done:
            obs = self._obs()
        else:
            obs = np.zeros(state_dim(), dtype=np.float32)

        info = {
            "is_apt":    is_apt,
            "action":    action,
            "step":      self._step_idx,
            "session":   self.dataset[self._ep_idx]["session_id"],
        }
        return obs, reward, done, truncated, info

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _obs(self) -> np.ndarray:
        window = self._events[: self._step_idx + 1]
        return extract_state(window)
