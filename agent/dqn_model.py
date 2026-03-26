"""
dqn_model.py
------------
Deep Q-Network implemented in PyTorch.

Architecture:
    Input (state_dim=120) → Linear(256) → ReLU → Dropout(0.2)
                          → Linear(128) → ReLU → Dropout(0.2)
                          → Linear(4)   → Q-values

Actions:
    0 = No-op        (no response)
    1 = Alert        (log + notify)
    2 = Rate-Limit   (throttle session)
    3 = Block        (terminate backend)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class DQN(nn.Module):
    def __init__(self, state_dim: int = 120, n_actions: int = 4):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Dropout(p=0.2),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(p=0.2),
            nn.Linear(128, n_actions),
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
