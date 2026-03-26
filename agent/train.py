"""
train.py
--------
Training loop for the Deep Q-Learning APT defense agent.

Usage:
    # Train from scratch
    python agent/train.py --episodes 300

    # Evaluate a saved checkpoint
    python agent/train.py --eval --checkpoint checkpoints/dqn_best.pt
"""

import os
import sys
import json
import argparse
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from monitor.log_parser import get_conn, fetch_all_labelled_sessions
from monitor.feature_extractor import state_dim
from agent.dqn_model import DQN
from agent.replay_buffer import ReplayBuffer
from agent.environment import APTEnvironment

# ── Hyper-parameters ─────────────────────────────────────────────────────────
BATCH_SIZE       = 64
GAMMA            = 0.99       # discount factor
LR               = 1e-3
EPSILON_START    = 1.0
EPSILON_MIN      = 0.05
EPSILON_DECAY    = 0.995
TARGET_UPDATE    = 20         # sync target network every N episodes
CHECKPOINT_DIR   = Path("checkpoints")
DEVICE           = "cuda" if torch.cuda.is_available() else "cpu"


def select_action(policy_net, state, epsilon):
    if random.random() < epsilon:
        return random.randint(0, 3)
    return policy_net.predict(state, device=DEVICE)


def update(policy_net, target_net, optimizer, replay_buf):
    if not replay_buf.is_ready:
        return None

    batch      = replay_buf.sample(BATCH_SIZE)
    states     = torch.tensor(np.stack([t.state      for t in batch]), dtype=torch.float32, device=DEVICE)
    actions    = torch.tensor([t.action     for t in batch], dtype=torch.long,    device=DEVICE)
    rewards    = torch.tensor([t.reward     for t in batch], dtype=torch.float32, device=DEVICE)
    next_states= torch.tensor(np.stack([t.next_state for t in batch]), dtype=torch.float32, device=DEVICE)
    dones      = torch.tensor([t.done       for t in batch], dtype=torch.float32, device=DEVICE)

    # Double DQN: action selected by policy, value from target
    policy_net.train()
    q_vals     = policy_net(states).gather(1, actions.unsqueeze(1)).squeeze(1)
    with torch.no_grad():
        best_actions  = policy_net(next_states).argmax(dim=1)
        target_q_vals = target_net(next_states).gather(1, best_actions.unsqueeze(1)).squeeze(1)
        targets        = rewards + GAMMA * target_q_vals * (1.0 - dones)

    loss = nn.SmoothL1Loss()(q_vals, targets)
    optimizer.zero_grad()
    loss.backward()
    nn.utils.clip_grad_norm_(policy_net.parameters(), 1.0)
    optimizer.step()
    return loss.item()


def train(episodes: int):
    CHECKPOINT_DIR.mkdir(exist_ok=True)
    conn    = get_conn()
    dataset = fetch_all_labelled_sessions(conn)
    conn.close()

    if not dataset:
        print("[Train] No labelled sessions found. Run data/simulate_apt.py first.")
        sys.exit(1)

    env         = APTEnvironment(dataset)
    policy_net  = DQN(state_dim()).to(DEVICE)
    target_net  = DQN(state_dim()).to(DEVICE)
    target_net.load_state_dict(policy_net.state_dict())
    target_net.eval()
    optimizer   = optim.Adam(policy_net.parameters(), lr=LR)
    replay_buf  = ReplayBuffer(50_000)
    epsilon     = EPSILON_START

    metrics = {"episode": [], "reward": [], "epsilon": [], "loss": []}
    best_reward = float("-inf")

    for ep in tqdm(range(1, episodes + 1), desc="Training"):
        state, _ = env.reset()
        ep_reward = 0.0
        ep_loss   = []
        done = truncated = False

        while not (done or truncated):
            action           = select_action(policy_net, state, epsilon)
            next_state, rew, done, truncated, _ = env.step(action)
            replay_buf.push(state, action, rew, next_state, done)
            state       = next_state
            ep_reward  += rew
            loss = update(policy_net, target_net, optimizer, replay_buf)
            if loss is not None:
                ep_loss.append(loss)

        epsilon = max(EPSILON_MIN, epsilon * EPSILON_DECAY)

        if ep % TARGET_UPDATE == 0:
            target_net.load_state_dict(policy_net.state_dict())

        avg_loss = float(np.mean(ep_loss)) if ep_loss else 0.0
        metrics["episode"].append(ep)
        metrics["reward"].append(ep_reward)
        metrics["epsilon"].append(round(epsilon, 4))
        metrics["loss"].append(round(avg_loss, 6))

        if ep_reward > best_reward:
            best_reward = ep_reward
            torch.save(policy_net.state_dict(), CHECKPOINT_DIR / "dqn_best.pt")

        if ep % 50 == 0:
            torch.save(policy_net.state_dict(), CHECKPOINT_DIR / f"dqn_ep{ep}.pt")
            print(f"\n  [ep {ep}] reward={ep_reward:.2f}  ε={epsilon:.3f}  loss={avg_loss:.5f}")

    # Save metrics
    with open(CHECKPOINT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n[Train] Done. Best reward: {best_reward:.2f}. Checkpoints in {CHECKPOINT_DIR}/")


def evaluate(checkpoint: str):
    conn    = get_conn()
    dataset = fetch_all_labelled_sessions(conn)
    conn.close()

    env        = APTEnvironment(dataset)
    policy_net = DQN(state_dim()).to(DEVICE)
    policy_net.load_state_dict(torch.load(checkpoint, map_location=DEVICE))
    policy_net.eval()

    tp = fp = tn = fn = 0
    for session in dataset:
        env._events = session["events"]
        env._label  = session["label"]
        env._step_idx = 0
        state = env._obs()
        action = policy_net.predict(state, device=DEVICE)
        is_apt = session["label"] in (1, 2)
        predicted_threat = action in (2, 3)   # rate-limit or block = threat detected
        if is_apt and predicted_threat:   tp += 1
        elif is_apt and not predicted_threat: fn += 1
        elif not is_apt and predicted_threat: fp += 1
        else: tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp + 1e-9)
    recall    = tp / (tp + fn + 1e-9)
    f1        = 2 * precision * recall / (precision + recall + 1e-9)
    fpr       = fp / (fp + tn + 1e-9)

    print("\n" + "=" * 48)
    print("      APT DQL Agent — Evaluation Report")
    print("=" * 48)
    print(f"  Total sessions : {total}")
    print(f"  True Positives : {tp}")
    print(f"  True Negatives : {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  Precision      : {precision:.3f}")
    print(f"  Recall         : {recall:.3f}")
    print(f"  F1 Score       : {f1:.3f}")
    print(f"  False Pos. Rate: {fpr:.3f}")
    print("=" * 48)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train/Evaluate APT DQL Agent")
    parser.add_argument("--episodes",   type=int,  default=300)
    parser.add_argument("--eval",       action="store_true")
    parser.add_argument("--checkpoint", type=str,  default="checkpoints/dqn_best.pt")
    args = parser.parse_args()

    if args.eval:
        evaluate(args.checkpoint)
    else:
        train(args.episodes)
