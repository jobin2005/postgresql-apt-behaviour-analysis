"""
monitor.py
----------
Live monitoring daemon.  Polls the database for new events, runs
inference through the loaded DQL agent, and triggers defense actions.

Usage:
    python monitor/monitor.py [--checkpoint checkpoints/dqn_best.pt] [--interval 5]
"""

import os
import sys
import time
import math
import logging
import argparse
import psutil

import torch
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from monitor.log_parser   import get_conn, fetch_active_sessions, fetch_session_events
from monitor.feature_extractor import extract_state, state_dim
from agent.dqn_model      import DQN
from defense.actions       import execute_action

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("apt.monitor")


def load_agent(checkpoint: str) -> DQN:
    net = DQN(state_dim())
    net.load_state_dict(torch.load(checkpoint, map_location="cpu", weights_only=True))
    net.eval()
    logger.info("Loaded DQL agent from %s", checkpoint)
    return net


def update_process_lineage(conn, session_id, pid):
    """Resolve a Linux PID to a process name and update the session record."""
    if not pid:
        return
    
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        # Include full path if possible
        exe = proc.exe()
        origin = f"{name} ({exe})"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        origin = "unknown process"
    except Exception:
        origin = "simulation process"

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE apt_sessions SET backend_pid = %s, origin_process = %s WHERE session_id = %s",
            (pid, origin, session_id)
        )
    conn.commit()


def run_monitor(checkpoint: str, interval: int = 5):
    agent = load_agent(checkpoint)
    conn  = get_conn()
    logger.info("APT Monitor started. Poll interval: %ds", interval)

    seen_events: dict[int, int] = {}   # session_id → last event_id seen

    try:
        while True:
            try:
                active = fetch_active_sessions(conn)
            except Exception as exc:
                logger.warning("DB connection lost, reconnecting: %s", exc)
                try:
                    conn.close()
                except Exception:
                    pass
                conn = get_conn()
                continue

            for sid in active:
                # Resolve lineage if not already done
                if isinstance(sid, dict) and not sid.get("origin_process"):
                    update_process_lineage(conn, sid["session_id"], sid.get("backend_pid"))
                    sid = sid["session_id"]

                last_id = seen_events.get(sid, 0)
                
                # Step 1: Check for NEW event IDs since we last looked
                # (using a tiny limit=1 for speed)
                new_check = fetch_session_events(conn, sid, limit=1, since_id=last_id)
                if not new_check:
                    continue   # no new activity

                # Step 2: Activity detected! Fetch FULL context window (last 50) for the AI
                events = fetch_session_events(conn, sid, limit=50, since_id=0)
                
                if not events:
                    continue

                # Update the last seen event_id for this session to mark progress
                seen_events[sid] = events[-1]["event_id"]
                
                state     = extract_state(events)
                q_vals    = agent.q_values(state)
                action    = int(max(range(4), key=lambda i: q_vals[i]))
                max_q     = max(q_vals)
                # Normalise threat score to [0, 1] using sigmoid
                threat_score = 1.0 / (1.0 + math.exp(-max_q))

                logger.info(
                    "session=%d  context_len=%d  action=%d  threat=%.3f  q=%s",
                    sid, len(events), action, threat_score,
                    [round(q, 2) for q in q_vals],
                )
                execute_action(action, sid, threat_score, q_vals)

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("Monitor stopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APT Live Monitor Daemon")
    parser.add_argument("--checkpoint", default="checkpoints/dqn_best.pt")
    parser.add_argument("--interval",   type=int, default=5,
                        help="Polling interval in seconds (default: 5)")
    args = parser.parse_args()

    if not os.path.exists(args.checkpoint):
        logger.error("Checkpoint not found: %s — train the agent first.", args.checkpoint)
        sys.exit(1)

    run_monitor(args.checkpoint, args.interval)
