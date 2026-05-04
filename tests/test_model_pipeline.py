"""
test_model_pipeline.py
----------------------
End-to-end tests for data generation, model forward pass, and inference.
"""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import numpy as np
import torch
import pytest

from data.generate_training_data import generate, FEATURE_KEYS
from agent.dqn_model import DQN
from agent.environment import STATE_DIM, N_ACTIONS


class TestDataGeneration:
    def test_output_shapes(self):
        features, labels = generate(500, apt_ratio=0.3, seed=123)
        assert features.shape == (500, 7)
        assert labels.shape == (500,)

    def test_label_distribution(self):
        features, labels = generate(1000, apt_ratio=0.3, seed=42)
        unique, counts = np.unique(labels, return_counts=True)
        dist = dict(zip(unique, counts))
        assert 0 in dist
        assert 1 in dist or 2 in dist  # at least one APT class
        assert dist[0] >= 600  # ~70% benign

    def test_features_are_finite(self):
        features, _ = generate(200, apt_ratio=0.3)
        assert np.all(np.isfinite(features))

    def test_feature_count_matches_keys(self):
        assert len(FEATURE_KEYS) == 7

    def test_reproducibility(self):
        f1, l1 = generate(100, 0.3, seed=99)
        f2, l2 = generate(100, 0.3, seed=99)
        np.testing.assert_array_equal(f1, f2)
        np.testing.assert_array_equal(l1, l2)


class TestDQNModel:
    def test_forward_pass_shape(self):
        model = DQN(STATE_DIM, N_ACTIONS)
        x = torch.randn(32, STATE_DIM)
        out = model(x)
        assert out.shape == (32, N_ACTIONS)

    def test_predict_returns_int(self):
        model = DQN(STATE_DIM, N_ACTIONS)
        state = np.random.rand(STATE_DIM).astype(np.float32)
        action = model.predict(state)
        assert isinstance(action, int)
        assert 0 <= action < N_ACTIONS

    def test_q_values_length(self):
        model = DQN(STATE_DIM, N_ACTIONS)
        state = np.random.rand(STATE_DIM).astype(np.float32)
        q_vals = model.q_values(state)
        assert len(q_vals) == N_ACTIONS

    def test_save_load_checkpoint(self):
        model = DQN(STATE_DIM, N_ACTIONS)
        state = np.random.rand(STATE_DIM).astype(np.float32)
        original_action = model.predict(state)

        with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
            torch.save(model.state_dict(), f.name)
            loaded = DQN(STATE_DIM, N_ACTIONS)
            loaded.load_state_dict(torch.load(f.name, weights_only=True))
            loaded_action = loaded.predict(state)

        assert original_action == loaded_action
        os.unlink(f.name)


class TestEnvironmentWithGeneratedData:
    def test_full_episode(self):
        from agent.environment import APTEnvironment
        features, labels = generate(100, 0.3, seed=42)
        dataset = [{"features": features[i], "label": int(labels[i])}
                   for i in range(len(labels))]
        env = APTEnvironment(dataset)
        obs, _ = env.reset()
        assert obs.shape == (STATE_DIM,)
        _, rew, done, _, _ = env.step(1)
        assert done
        assert isinstance(rew, float)
