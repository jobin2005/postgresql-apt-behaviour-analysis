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
pg_audit logs → Feature Extractor → DQL Agent → Defense Actions
                                         ↑
                               (trained on labelled sessions)
```

---

## Project Structure

```
Postgre/
├── data/
│   └── schema.sql            # DB schema (apt_sessions, apt_events, apt_alerts)
├── agent/
│   ├── environment.py        # Gymnasium-compatible RL environment
│   ├── dqn_model.py          # PyTorch Deep Q-Network
│   ├── replay_buffer.py      # Experience replay buffer
│   └── train.py              # Training + evaluation loop
├── monitor/
│   ├── feature_extractor.py  # SQL events → 150-dim state vector
│   ├── log_parser.py         # DB & pg_audit log ingestion
│   └── monitor.py            # Live monitoring daemon
├── defense/
│   └── actions.py            # alert / rate-limit / block actions
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

---

## Quick Start (Using Docker - Recommended for Team Collaboration)

### 1. Prerequisites
Ensure you have Docker and Docker Compose installed on your system.

### 2. Build and Start the System
This command will build the custom PostgreSQL image (compiling the `apt_guard.c` extension automatically) and start the ML python service:
```bash
docker compose up --build -d
```
*Note: The database schema is automatically initialized on the first run.*

### 3. Generate Training Data & Train (required at least once)
Run these inside the ML container to prepare the agent:
```bash
docker compose exec ml_service python simulate_apt.py --sessions 100 --apt-ratio 0.3
docker compose exec ml_service python agent/train.py --episodes 300
```

---

## Running the System (Each Time)

If the containers are stopped, just start them with:
```bash
docker compose up -d
```
The `ml_service` container automatically runs `start_all.py` which launches the Monitor Daemon and the Flask Dashboard.

### Viewing Output
1. **System Activity**: Watch the terminal console for session analysis logs.
2. **Threat Dashboard**: Open your browser at **http://localhost:5000**.
3. **DB Alerts**: Check the `apt_alerts` table in your Postgres database.

---

## Agent Design

| Component | Detail |
|-----------|--------|
| State space | 150-dim vector: 10-event window × 15 features |
| Action space | Discrete(4): No-op, Alert, Rate-Limit, Block |
| Algorithm | Double DQN with experience replay |
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
