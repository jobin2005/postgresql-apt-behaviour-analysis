"""
environment.py
--------------
OpenAI Gymnasium-compatible environment for session-based APT detection.

State space:  numpy array of shape (7,) from feature_extractor.py
Action space: Discrete(4)
    0 = No-op     1 = Alert     2 = Rate-Limit     3 = Block

Reward shaping:
    Correct Block of APT:                  +10
    Correct Rate-Limit of APT:             +5
    Correct Alert of APT:                  +3
    Correct No-op on benign:               +1
    False Positive (block/rate on benign): -2
    Missed APT (no-op on APT):            -8
"""

import numpy as np
import gymnasium as gym
from gymnasium import spaces

N_ACTIONS = 4
ACTION_NOOP       = 0
ACTION_ALERT      = 1
ACTION_RATE_LIMIT = 2
ACTION_BLOCK      = 3

STATE_DIM = 7

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


class APTEnvironment(gym.Env):
    """
    Episode = one database session.
    The agent observes the 7-dim feature vector and takes one action.
    """

    metadata = {"render_modes": []}

    def __init__(self, dataset: list[dict]):
        """
        dataset: list of dicts, each with:
            - 'features': np.ndarray of shape (7,)
            - 'label':    int (0=benign, 1=suspicious, 2=confirmed APT)
        """
        super().__init__()
        self.dataset   = dataset
        self._ep_idx   = -1
        self._done     = True

        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(STATE_DIM,), dtype=np.float32
        )
        self.action_space = spaces.Discrete(N_ACTIONS)

    # ── Gym API ───────────────────────────────────────────────────────────────
    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        self._ep_idx = (self._ep_idx + 1) % len(self.dataset)
        self._done   = False
        return self._obs(), {}

    def step(self, action: int):
        assert not self._done, "Episode already finished — call reset()"
        session = self.dataset[self._ep_idx]
        is_apt  = session["label"] in (1, 2)

        reward = _REWARDS.get((is_apt, action), 0.0)
        self._done = True

        obs = np.zeros(STATE_DIM, dtype=np.float32)
        info = {
            "is_apt":  is_apt,
            "label":   session["label"],
            "action":  action,
        }
        return obs, reward, True, False, info

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _obs(self) -> np.ndarray:
        return self.dataset[self._ep_idx]["features"].astype(np.float32)