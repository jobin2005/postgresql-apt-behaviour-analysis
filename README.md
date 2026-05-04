# APT Behaviour Analysis in PostgreSQL — ShakthiDB Security Extension

## Team
| Name | Role (Phase 2 Focus) |
|------|------|
| Adithyan M C | DQL Concept Drift Handling & Adaptive Learning |
| Asiya Salam | Schema Isolation & Multi-DB Sentinel Feature Extraction |
| Jobin A J | C-Extension (`apt_guard.c`) Native Logging & Hooking |
| Sreedeep Rajeevan | Active Defense Execution (Rate-Limits) & Dashboard Visualization |

**Affiliation:** Pravartak Technologies, IIT Madras (ShakthiDB Project)

---

## Overview

A **Deep Q-Learning (DQL)** agent that monitors PostgreSQL database activity in real-time to detect and automatically respond to **Advanced Persistent Threats (APTs)** — slow-moving, multi-stage attacks that evade traditional point-in-time IDS.

```
pg_audit logs → Feature Extractor (7-Dim) → DQL Agent → Supabase Alerts
                                              ↑
                            (trained offline on simulated sessions)
```

---

## Project Structure

```
Postgre/
├── data/
│   ├── generate_training_data.py # Offline simulation (5000+ sessions)
│   └── schema.sql            # DB schema (apt_sessions, apt_events, apt_alerts)
├── agent/
│   ├── environment.py        # In-memory session RL environment
│   ├── dqn_model.py          # PyTorch Deep Q-Network (7-Dim, BatchNorm)
│   ├── replay_buffer.py      # Experience replay buffer
│   ├── train.py              # Training + evaluation loop
│   └── inference.py          # Inference + remote Supabase alerting
├── monitor/
│   ├── feature_extractor.py  # Session features → 7-dim state vector
│   ├── log_parser.py         # DB & pg_audit log ingestion
│   └── monitor.py            # Live monitoring daemon
├── api/
│   ├── app.py                # Flask REST API
│   └── templates/dashboard.html  # Real-time threat dashboard
├── src/
│   └── apt_guard.c           # PostgreSQL C extension (executor hook + BGW)
├── sql/
│   └── apt_guard--1.0.sql    # Extension SQL definitions
├── simulate_apt.py           # APT + benign session simulator
├── start_all.py              # Launch monitor + dashboard
└── tests/                    # Unit tests
```

## How to Run (Scratch Setup)

### 1. Start the Containers
This launches the Database and the ML Service (Dashboard + Monitor).
```bash
docker compose up -d
```
> [!NOTE]
> The code is mounted as a volume (`.:/app`), so any changes you make to the Python files will reflect inside the container instantly without needing a rebuild!

### 2. Generate Training Data
Run this inside the container to create 5000 simulated sessions:
```bash
docker compose exec ml_service python data/generate_training_data.py --sessions 5000
```

### 3. Train the AI Agent
Train the 7-dimension DQN (usually achieves ~99.9% accuracy):
```bash
docker compose exec ml_service python agent/train.py --episodes 2000
```
*Once training finishes, the **Monitor Daemon** will automatically detect the new model and start protecting the database.*

### 4. Verify & Watch Logs
You can see the system working in real-time:
```bash
docker compose logs -f ml_service
```

---

## Agent Pipeline Details

| Component | Detail |
|-----------|--------|
| State space | 7-dim vector (Session Profile incl. Query Count, Anomaly, Seq Risk) |
| Action space | Discrete(4): No-op, Alert, Rate-Limit, Block |
| Algorithm | Double DQN with BatchNorm and experience replay |
| Reward | +10 correct block, -8 missed APT, −2 false positive |

---

## Roadmap (Next 2 Months)

To complete the "Hardened" architecture, the team will focus on the following core deliverables over the next 8 weeks:

1.  **C-Extension Native Logging (Jobin)**: Transition from simulated Python data injection to direct SQL interception in `apt_guard.c`. The extension must reliably parse `MyProcPid` and `queryDesc->sourceText` and insert it into `apt_events` with negligible latency.
2.  **Sentinel Pattern & Schema Isolation (Asiya)**: Ensure the extension can monitor multiple databases (e.g., University DB) while securely isolating the threat-analysis tables within a dedicated `apt_guard` schema.
3.  **Functional Rate-Limiting Responses (Sreedeep)**: Upgrade the `rate_limit` action placeholder in `actions.py` to enforce actual database-level connection throttling or `pg_sleep` injections for suspicious users.
4.  **Concept Drift & Adaptive Evasion (Adithyan)**: Implement mechanisms for the DQL Agent to recognize when attackers change their methodology (concept drift) and continuously fine-tune the model against evolving APT behaviour.

---

## Syncing Training Data Across the Team (Development Phase)
Since everyone uses an isolated local database, pushing code (`git push`) does **not** push database rows. If you generate a massive "golden dataset" and want to share it with your teammates so they can train the agent:

**1. Export the Data (The person who generated the data):**
```bash
docker compose exec db pg_dump -U postgres -d postgres --data-only --inserts > data/apt_data_seed.sql
git add data/apt_data_seed.sql
git commit -m "chore(data): export team training dataset"
git push
```

**2. Import the Data (The teammates):**
```bash
git pull
docker compose exec -T db psql -U postgres -d postgres < data/apt_data_seed.sql
```

## References
1. LogShield — Transformer-based APT Detection (arXiv:2311.05733)
2. MAGIC — Masked Graph Representation Learning (arXiv:2310.09831)
3. ACM DL 10.1145/3736654 — RL-based Adaptive DB Defense
