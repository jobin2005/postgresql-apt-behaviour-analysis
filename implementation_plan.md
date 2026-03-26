# Deep Q-Learning Agent for APT Behavioural Analysis in PostgreSQL

This project implements a **Deep Q-Learning (DQL)** agent that monitors PostgreSQL
database activity over time, detects multi-stage Advanced Persistent Threat (APT)
behaviour, and triggers adaptive defensive responses. It is designed to enhance the
security posture of **ShakthiDB (Pravartak Technologies, IIT Madras)**.

Unlike point-in-time anomaly detectors, the agent maintains a stateful session history
and uses reinforcement learning to improve its defense strategy as attackers adapt tactics.

---

## Reference Papers
| # | Title | Key Insight Used |
|---|-------|-----------------|
| 1 | LogShield (arXiv:2311.05733) | Event-sequence modelling for APT detection |
| 2 | MAGIC (arXiv:2310.09831) | Graph-based behavioural abstraction, concept drift handling |
| 3 | ACM DL 10.1145/3736654 | RL-based adaptive defense at DB layer |

---

## Proposed Project Structure

```
Postgre/
├── .env                        # DB credentials (existing)
├── requirements.txt            # [NEW]
├── README.md                   # [MODIFY] — full description
│
├── data/
│   ├── schema.sql              # [NEW] apt_events + sessions table DDL
│   └── simulate_apt.py         # [NEW] APT attack scenario simulator
│
├── agent/
│   ├── environment.py          # [NEW] OpenAI-Gym-style Postgres environment
│   ├── dqn_model.py            # [NEW] PyTorch Deep Q-Network
│   ├── replay_buffer.py        # [NEW] Experience replay buffer
│   └── train.py                # [NEW] Training loop
│
├── monitor/
│   ├── log_parser.py           # [NEW] pg_audit log ingestion
│   ├── feature_extractor.py    # [NEW] Encode SQL events → state vectors
│   └── monitor.py              # [NEW] Live monitoring daemon
│
├── defense/
│   └── actions.py              # [NEW] Adaptive defense actions (block/alert/rate-limit)
│
├── api/
│   ├── app.py                  # [NEW] Flask API (threat scores, alerts)
│   └── templates/
│       └── dashboard.html      # [NEW] Real-time threat dashboard
│
└── tests/
    ├── test_feature_extractor.py
    ├── test_environment.py
    └── test_integration.py
```

---

## Phase-by-Phase Breakdown

### Phase 0 — Bootstrap
#### [MODIFY] [README.md](file:///home/jobin/Desktop/IITM/Postgre/README.md)
- Full project description, setup instructions, architecture diagram

#### [NEW] requirements.txt
```
psycopg2-binary
python-dotenv
torch
numpy
pandas
flask
gymnasium
tqdm
```

---

### Phase 1 — Data Layer
#### [NEW] data/schema.sql
DDL for:
- `apt_sessions(session_id, user_name, start_time, end_time, threat_label)`
- `apt_events(event_id, session_id, timestamp, command_type, object_name, schema_name, rows_affected)`

#### [NEW] data/simulate_apt.py
Scripted multi-stage APT sequences:
1. **Recon** — `INFORMATION_SCHEMA` probing, `\d` enumeration
2. **Lateral Movement** — repeated login attempts, role changes
3. **Exfiltration** — mass `SELECT`, `COPY TO` on sensitive tables
4. **Privilege Escalation** — `ALTER ROLE`, `GRANT`

#### [NEW] monitor/log_parser.py
Parses `pg_audit` CSV log format → structured Python dicts → inserts into `apt_events`.

#### [NEW] monitor/feature_extractor.py
Converts a rolling window of events into a **state vector**:
- Command-type one-hot encoding
- Time-delta between events
- Object sensitivity score
- Session age
- Rolling anomaly score (z-score of command frequency)

---

### Phase 2 — DQL Agent
#### [NEW] agent/environment.py
OpenAI Gymnasium-compatible environment:
- **State**: (window_size × feature_dim) flattened numpy array
- **Actions**: {0: No-op, 1: Alert, 2: Rate-Limit, 3: Block}
- **Reward**: +10 correctly blocked APT, -1 false positive, +1 correct no-op, -5 missed APT

#### [NEW] agent/dqn_model.py
PyTorch model:
```
Input → Linear(state_dim, 256) → ReLU
      → Linear(256, 128)       → ReLU
      → Linear(128, 4)         → Q-values per action
```
Target network for stable training (updated every N steps).

#### [NEW] agent/replay_buffer.py
Circular deque replay buffer with `sample(batch_size)`.

#### [NEW] agent/train.py
- ε-greedy policy with decay
- Double DQN update rule
- Checkpoint saving every epoch

---

### Phase 3 — PostgreSQL Integration
#### [NEW] monitor/monitor.py
Background daemon:
1. Tails `postgresql.log` / reads `pg_audit` via a Postgres function
2. Calls `feature_extractor.py` per session window
3. Runs inference with loaded DQL agent
4. Calls `defense/actions.py` based on predicted action

#### [NEW] defense/actions.py
```python
def block_user(conn, pid):     # pg_terminate_backend(pid)
def alert_user(session_id):    # Writes to apt_alerts table
def rate_limit(session_id):    # Inserts throttle record
```

---

### Phase 4 — Evaluation
Metrics computed per simulation run:
| Metric | Target |
|--------|--------|
| Detection Rate (Recall) | > 90% |
| False Positive Rate | < 5% |
| F1 Score | > 0.88 |
| Avg. Response Latency | < 500 ms |

---

### Phase 5 — Dashboard
#### [NEW] api/app.py
Flask REST API:
- `GET /api/threats` — recent threat events with scores
- `GET /api/alerts` — active alerts
- `POST /api/feedback` — human-in-the-loop label correction

#### [NEW] api/templates/dashboard.html
Real-time threat timeline with Chart.js, auto-refreshing every 5 s.

---

## Verification Plan

### Automated Tests

```bash
# Install deps
cd /home/jobin/Desktop/IITM/Postgre
source venv/bin/activate
pip install -r requirements.txt

# Unit tests
python -m pytest tests/test_feature_extractor.py -v
python -m pytest tests/test_environment.py -v

# Integration test (requires running Postgres)
python -m pytest tests/test_integration.py -v

# Full simulation run
python data/simulate_apt.py          # inject APT events
python agent/train.py --episodes 200 # train the agent
python agent/train.py --eval         # print metrics
```

### Manual Verification
1. Start the monitor daemon: `python monitor/monitor.py`
2. Run `data/simulate_apt.py` in another terminal to inject a slow-burn APT sequence
3. Observe console alerts and check the `apt_alerts` table:
   ```sql
   SELECT * FROM apt_alerts ORDER BY created_at DESC LIMIT 20;
   ```
4. Open the dashboard at `http://localhost:5000` and confirm threats appear on the timeline
5. Verify that `pg_terminate_backend` successfully blocks the simulated attacker session

---

> [!IMPORTANT]
> **PostgreSQL `pg_audit` extension must be installed** on the target Postgres instance for
> live log parsing to work. If not available, the project falls back to parsing
> `log_statement = 'all'` text logs.

> [!NOTE]
> The C extension (`apt_guard`) is an optional advanced deliverable for Week 7–8. It is
> not required for the core DQL functionality and can be added if time permits.
