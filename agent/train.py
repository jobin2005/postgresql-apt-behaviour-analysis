"""
train.py
--------
Self-contained training loop for the DQN APT defense agent.
Loads 7-dim data from data/training_sessions.npz — no DB needed.

Usage:
    python agent/train.py --episodes 500
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
from agent.dqn_model import DQN
from agent.replay_buffer import ReplayBuffer
from agent.environment import APTEnvironment, STATE_DIM, N_ACTIONS

# ── Hyper-parameters ─────────────────────────────────────────────────────────
BATCH_SIZE       = 64
GAMMA            = 0.99
LR               = 3e-4
EPSILON_START    = 1.0
EPSILON_MIN      = 0.05
EPSILON_DECAY    = 0.997
TARGET_UPDATE    = 10
CHECKPOINT_DIR   = Path("checkpoints")
DATA_PATH        = Path(os.path.dirname(os.path.dirname(__file__))) / "data" / "training_sessions.npz"
DEVICE           = "cuda" if torch.cuda.is_available() else "cpu"


def load_dataset(path: Path) -> list[dict]:
    """Load npz, normalize features (z-score), return list of {features, label}."""
    data = np.load(path)
    features = data["features"].astype(np.float32)   # (N, 7)
    labels   = data["labels"]                         # (N,)

    # Z-score normalization — critical because raw features span wildly
    # different ranges (query_count ~1-200 vs total_rows ~1-150000)
    mean = features.mean(axis=0)
    std  = features.std(axis=0) + 1e-8
    features = (features - mean) / std

    # Save normalization stats for inference
    stats_path = path.parent / "norm_stats.npz"
    np.savez(stats_path, mean=mean, std=std)
    print(f"[Train] Normalization stats saved to {stats_path}")

    dataset = []
    for i in range(len(labels)):
        dataset.append({
            "features": features[i],
            "label":    int(labels[i]),
        })
    return dataset


def select_action(policy_net, state, epsilon):
    if random.random() < epsilon:
        return random.randint(0, N_ACTIONS - 1)
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

    # Double DQN
    policy_net.train()
    q_vals     = policy_net(states).gather(1, actions.unsqueeze(1)).squeeze(1)
    with torch.no_grad():
        best_actions  = policy_net(next_states).argmax(dim=1)
        target_q_vals = target_net(next_states).gather(1, best_actions.unsqueeze(1)).squeeze(1)
        targets       = rewards + GAMMA * target_q_vals * (1.0 - dones)

    loss = nn.SmoothL1Loss()(q_vals, targets)
    optimizer.zero_grad()
    loss.backward()
    nn.utils.clip_grad_norm_(policy_net.parameters(), 1.0)
    optimizer.step()
    return loss.item()


def train(episodes: int, resume_from: str = None):
    CHECKPOINT_DIR.mkdir(exist_ok=True)

    if not DATA_PATH.exists():
        print(f"[Train] Data not found at {DATA_PATH}")
        print("[Train] Run: python data/generate_training_data.py --sessions 5000")
        sys.exit(1)

    dataset = load_dataset(DATA_PATH)
    print(f"[Train] Loaded {len(dataset)} sessions from {DATA_PATH}")

    # Class distribution
    labels = [s["label"] for s in dataset]
    for lbl in sorted(set(labels)):
        count = labels.count(lbl)
        print(f"  Label {lbl}: {count} ({100*count/len(labels):.1f}%)")

    env         = APTEnvironment(dataset)
    policy_net  = DQN(STATE_DIM, N_ACTIONS).to(DEVICE)
    target_net  = DQN(STATE_DIM, N_ACTIONS).to(DEVICE)

    if resume_from and os.path.exists(resume_from):
        print(f"[Train] Resuming from checkpoint: {resume_from}")
        policy_net.load_state_dict(torch.load(resume_from, map_location=DEVICE))

    target_net.load_state_dict(policy_net.state_dict())
    target_net.eval()
    optimizer   = optim.Adam(policy_net.parameters(), lr=LR)
    replay_buf  = ReplayBuffer(50_000)
    epsilon     = EPSILON_START

    metrics = {"episode": [], "reward": [], "epsilon": [], "loss": []}
    best_avg_reward = float("-inf")

    # Rolling window for smoothed reward
    reward_window = []

    for ep in tqdm(range(1, episodes + 1), desc="Training"):
        state, _ = env.reset()
        action = select_action(policy_net, state, epsilon)
        next_state, reward, done, truncated, info = env.step(action)
        replay_buf.push(state, action, reward, next_state, done)

        # Do multiple gradient updates per episode once buffer is ready
        losses = []
        for _ in range(8):
            loss = update(policy_net, target_net, optimizer, replay_buf)
            if loss is not None:
                losses.append(loss)

        epsilon = max(EPSILON_MIN, epsilon * EPSILON_DECAY)

        if ep % TARGET_UPDATE == 0:
            target_net.load_state_dict(policy_net.state_dict())

        avg_loss = float(np.mean(losses)) if losses else 0.0
        metrics["episode"].append(ep)
        metrics["reward"].append(reward)
        metrics["epsilon"].append(round(epsilon, 4))
        metrics["loss"].append(round(avg_loss, 6))

        reward_window.append(reward)
        if len(reward_window) > 100:
            reward_window.pop(0)

        avg_reward = np.mean(reward_window)
        if avg_reward > best_avg_reward and ep > 100:
            best_avg_reward = avg_reward
            torch.save(policy_net.state_dict(), CHECKPOINT_DIR / "dqn_best.pt")

        if ep % 100 == 0:
            torch.save(policy_net.state_dict(), CHECKPOINT_DIR / f"dqn_ep{ep}.pt")
            print(f"\n  [ep {ep}] avg_reward={avg_reward:.2f}  ε={epsilon:.3f}  loss={avg_loss:.5f}")

    # Save final checkpoint
    torch.save(policy_net.state_dict(), CHECKPOINT_DIR / "dqn_final.pt")

    # Save metrics
    with open(CHECKPOINT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n[Train] Done. Best avg reward: {best_avg_reward:.2f}")
    print(f"[Train] Checkpoints saved to {CHECKPOINT_DIR}/")

    # Auto-evaluate after training
    print("\n[Train] Running evaluation on full dataset...")
    evaluate(str(CHECKPOINT_DIR / "dqn_best.pt"), dataset)


def evaluate(checkpoint: str, dataset: list[dict] = None):
    """Evaluate the model on the full dataset."""
    if dataset is None:
        dataset = load_dataset(DATA_PATH)

    policy_net = DQN(STATE_DIM, N_ACTIONS).to(DEVICE)
    policy_net.load_state_dict(torch.load(checkpoint, map_location=DEVICE, weights_only=True))
    policy_net.eval()

    # Action names for readability
    action_names = {0: "No-op", 1: "Alert", 2: "Rate-Limit", 3: "Block"}

    tp = fp = tn = fn = 0
    action_counts = {a: 0 for a in range(N_ACTIONS)}
    correct_actions = {a: 0 for a in range(N_ACTIONS)}

    for session in dataset:
        features = session["features"]
        label    = session["label"]
        action   = policy_net.predict(features, device=DEVICE)

        action_counts[action] += 1
        is_apt = label in (1, 2)
        predicted_threat = action in (2, 3)   # rate-limit or block

        if is_apt and predicted_threat:
            tp += 1
            correct_actions[action] += 1
        elif is_apt and not predicted_threat:
            fn += 1
        elif not is_apt and predicted_threat:
            fp += 1
        else:
            tn += 1
            correct_actions[action] += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n" + "=" * 52)
    print("    APT DQN Agent — Evaluation Report")
    print("=" * 52)
    print(f"  Total sessions   : {total}")
    print(f"  True Positives   : {tp}")
    print(f"  True Negatives   : {tn}")
    print(f"  False Positives  : {fp}")
    print(f"  False Negatives  : {fn}")
    print(f"  ─────────────────────────────────")
    print(f"  Accuracy         : {accuracy:.4f}")
    print(f"  Precision        : {precision:.4f}")
    print(f"  Recall           : {recall:.4f}")
    print(f"  F1 Score         : {f1:.4f}")
    print(f"  False Pos. Rate  : {fpr:.4f}")
    print(f"  ─────────────────────────────────")
    print(f"  Action Distribution:")
    for a in range(N_ACTIONS):
        pct = 100 * action_counts[a] / total if total > 0 else 0
        print(f"    {action_names[a]:>12}: {action_counts[a]:>5} ({pct:.1f}%)")
    print("=" * 52)

    return {
        "accuracy": accuracy, "precision": precision,
        "recall": recall, "f1": f1, "fpr": fpr,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train/Evaluate APT DQN Agent")
    parser.add_argument("--episodes",   type=int,  default=2000)
    parser.add_argument("--eval",       action="store_true")
    parser.add_argument("--checkpoint", type=str,  default="checkpoints/dqn_best.pt")
    parser.add_argument("--resume",     action="store_true",
                        help="Resume training from existing checkpoint")
    args = parser.parse_args()

    if args.eval:
        evaluate(args.checkpoint)
    else:
        train(args.episodes, resume_from=args.checkpoint if args.resume else None)
