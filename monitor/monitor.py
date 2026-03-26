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
import logging
import argparse

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
    net.load_state_dict(torch.load(checkpoint, map_location="cpu"))
    net.eval()
    logger.info("Loaded DQL agent from %s", checkpoint)
    return net


def run_monitor(checkpoint: str, interval: int = 5):
    agent = load_agent(checkpoint)
    conn  = get_conn()
    logger.info("APT Monitor started. Poll interval: %ds", interval)

    seen_events: dict[int, int] = {}   # session_id → last event count seen

    try:
        while True:
            active = fetch_active_sessions(conn)
            for sid in active:
                events = fetch_session_events(conn, sid, limit=50)
                prev_count = seen_events.get(sid, 0)

                if len(events) == prev_count:
                    continue   # no new events

                seen_events[sid] = len(events)
                state     = extract_state(events)
                q_vals    = agent.q_values(state)
                action    = int(max(range(4), key=lambda i: q_vals[i]))
                max_q     = max(q_vals)
                # Normalise threat score to [0, 1] using sigmoid
                import math
                threat_score = 1.0 / (1.0 + math.exp(-max_q))

                logger.info(
                    "session=%d  events=%d  action=%d  threat=%.3f  q=%s",
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
