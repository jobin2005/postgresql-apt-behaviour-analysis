"""
replay_buffer.py
----------------
Fixed-size experience replay buffer for offline DQN training.
"""

import random
import numpy as np
from collections import deque, namedtuple

Transition = namedtuple("Transition", ["state", "action", "reward", "next_state", "done"])


class ReplayBuffer:
    """Circular buffer storing (s, a, r, s', done) transitions."""

    def __init__(self, capacity: int = 50_000):
        self._buf = deque(maxlen=capacity)

    def push(self, state, action: int, reward: float, next_state, done: bool):
        self._buf.append(Transition(
            np.array(state, dtype=np.float32),
            int(action),
            float(reward),
            np.array(next_state, dtype=np.float32),
            bool(done),
        ))

    def sample(self, batch_size: int) -> list[Transition]:
        return random.sample(self._buf, batch_size)

    def __len__(self):
        return len(self._buf)

    @property
    def is_ready(self) -> bool:
        return len(self._buf) >= 512   # minimum before training starts
