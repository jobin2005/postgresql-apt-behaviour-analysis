"""
dqn_model.py
------------
Deep Q-Network for session-based APT detection.

Architecture (7-dim input):
    Input(7) → Linear(64) → ReLU → BN → Linear(64) → ReLU → BN
             → Linear(32) → ReLU → Linear(4)

Actions:
    0 = No-op        (no response)
    1 = Alert        (log + notify)
    2 = Rate-Limit   (throttle session)
    3 = Block        (terminate backend)
"""

import torch
import torch.nn as nn


class DQN(nn.Module):
    def __init__(self, state_dim: int = 7, n_actions: int = 4):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),

            nn.Linear(64, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),

            nn.Linear(64, 32),
            nn.ReLU(),

            nn.Linear(32, n_actions),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

    def predict(self, state_np, device="cpu") -> int:
        """Greedy action for a single numpy state."""
        self.eval()
        with torch.no_grad():
            s = torch.tensor(state_np, dtype=torch.float32, device=device).unsqueeze(0)
            q = self.forward(s)
        return int(q.argmax(dim=1).item())

    def q_values(self, state_np, device="cpu"):
        """Return Q-values as a plain Python list for logging."""
        self.eval()
        with torch.no_grad():
            s = torch.tensor(state_np, dtype=torch.float32, device=device).unsqueeze(0)
            q = self.forward(s)
        return q.squeeze(0).tolist()