# APT Behaviour Analysis in PostgreSQL — ShakthiDB Security Extension

## Team
| Name | Role |
|------|------|
| Adithyan M C | DQL Model & Training |
| Asiya Salam | Feature Engineering & Data Pipeline |
| Jobin A J | PostgreSQL Integration & Monitor Daemon |
| Sreedeep Rajeevan | Dashboard & Evaluation |

**Affiliation:** Pravartak Technologies, IIT Madras (ShakthiDB Project)

---

## Overview

A **Deep Q-Learning (DQL)** agent that monitors PostgreSQL database activity in real-time to detect and automatically respond to **Advanced Persistent Threats (APTs)** — slow-moving, multi-stage attacks that evade traditional point-in-time IDS.

```
pg_audit logs → Feature Extractor → DQL Agent → Defense Actions
                                         ↑
                               (trained on labelled sessions)
```

---

## Project Structure

```
Postgre/
├── data/
│   ├── schema.sql          # DB schema (apt_sessions, apt_events, apt_alerts)
│   └── simulate_apt.py     # APT + benign session simulator
├── agent/
│   ├── environment.py      # Gymnasium-compatible RL environment
│   ├── dqn_model.py        # PyTorch Deep Q-Network
│   ├── replay_buffer.py    # Experience replay buffer
│   └── train.py            # Training + evaluation loop
├── monitor/
│   ├── feature_extractor.py # SQL events → 120-dim state vector
│   ├── log_parser.py        # DB & pg_audit log ingestion
│   └── monitor.py           # Live monitoring daemon
├── defense/
│   └── actions.py           # alert / rate-limit / block actions
├── api/
│   ├── app.py               # Flask REST API
│   └── templates/dashboard.html  # Real-time threat dashboard
└── tests/                   # Unit tests
```

---

## Quick Start (One-Time Setup)

### 1. Prerequisites
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Create DB Schema
```bash
psql -U postgres -d demo -f data/schema.sql
```

### 3. Generate Training Data & Train (required at least once)
```bash
python data/simulate_apt.py --sessions 100 --apt-ratio 0.3
python agent/train.py --episodes 300
```

---

## Running the System (Each Time)

To start the full system (Monitor + Dashboard) in one command:
```bash
python start_all.py
```

### Viewing Output
1. **System Activity**: Watch the terminal console for session analysis logs.
2. **Threat Dashboard**: Open your browser at **http://localhost:5000**.
3. **DB Alerts**: Check the `apt_alerts` table in your Postgres database.

---

## Agent Design

| Component | Detail |
|-----------|--------|
| State space | 120-dim vector: 10-event window × 12 features |
| Action space | Discrete(4): No-op, Alert, Rate-Limit, Block |
| Algorithm | Double DQN with experience replay |
| Reward | +10 correct block, -8 missed APT, −2 false positive |

---

## References
1. LogShield — Transformer-based APT Detection (arXiv:2311.05733)
2. MAGIC — Masked Graph Representation Learning (arXiv:2310.09831)
3. ACM DL 10.1145/3736654 — RL-based Adaptive DB Defense
