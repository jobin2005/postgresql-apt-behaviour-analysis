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

---

## 🚀 Community Testing (How to Try It)
You have two ways to test this extension on your own database (Bank, Office, University):

### Option 1: The "Easy" Way (Docker)
We recommend this for teammates and new users.
```bash
# 1. Start everything (DB + AI + Dashboard)
docker compose up --build -d

# 2. Activate the extension in the database
docker compose exec db psql -U postgres -d postgres -c "CREATE EXTENSION apt_guard;"
```
*Result: Open your dashboard at **http://localhost:5000***

### Option 2: The "Manual" Way (Direct Linux)
Use this if you already have a local PostgreSQL 18 installation:
```bash
# 1. Compile and install
cd src/
make && sudo make install

# 2. Add to your configuration (/etc/postgresql/18/main/postgresql.conf)
# Set: shared_preload_libraries = 'apt_guard'

# 3. Restart Postgres
sudo systemctl restart postgresql
```
*Step 4: Go into any database and run `CREATE EXTENSION apt_guard;`*

---

## 🏗️ Project Architecture
The system follows a **Sentinel Pattern**:
*   **The Guard** (`apt_guard.c`): Direct SQL interception using PostgreSQL hooks.
*   **The Brain** (`monitor.py`): A DQL agent that processes a 150-dim feature vector (10 queries x 15 features).
*   **The Voice** (`api/app.py`): A real-time dashboard visualizing threats as they happen.

---

## ✅ Milestones Completed
1.  **[x] Native Logging**: Successfully implemented `ExecutorRun` and `ProcessUtility` hooks to capture all SQL actions.
2.  **[x] AI Feature Extraction**: Implemented a 150-dimension vector for deep session analysis.
3.  **[x] Multi-DB Support**: The extension can now be installed in any database independently.
4.  **[x] Docker Orchestration**: Automated the entire database + monitor + dashboard setup.

---

## 🔮 Future Roadmap (Next Phases)
*   **Functional Rate-Limiting**: Enforce actual database-level connection throttling for blocked sessions.
*   **Concept Drift Detection**: Adapt the DQL models as attacker behavior changes over time.
*   **Dashboard Enhancements**: Add user-specific forensic views and historic threat replay.

---

## 📡 Viewing the Dashboard
Open your browser at **http://localhost:5000** to see the live APT Shield dashboard.

## References
1. LogShield — Transformer-based APT Detection (arXiv:2311.05733)
2. MAGIC — Masked Graph Representation Learning (arXiv:2310.09831)
3. ACM DL 10.1145/3736654 — RL-based Adaptive DB Defense
