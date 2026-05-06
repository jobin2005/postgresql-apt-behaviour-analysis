#!/usr/bin/env python3
"""
start_all.py
------------
Convenience script to start both the APT Monitor Daemon and the 
Threat Dashboard in parallel.
"""

import subprocess
import time
import sys
import os
from pathlib import Path

# Paths relative to project root
ROOT = Path(__file__).parent.resolve()
MONITOR_SCRIPT = ROOT / "monitor" / "monitor.py"
DASHBOARD_SCRIPT = ROOT / "api" / "app.py"
CHECKPOINT = ROOT / "checkpoints" / "dqn_best.pt"

def main():
    if not CHECKPOINT.exists():
        print(f"Error: Model checkpoint not found at {CHECKPOINT}")
        print("Please train the agent first: python agent/train.py --episodes 300")
        sys.exit(1)

    print(" Starting APT Shield System...")
    
    # 1. Start the Monitor Daemon
    print(f" Launching Monitor Daemon (polling DB for threats)...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    monitor_proc = subprocess.Popen(
        [sys.executable, "-m", "monitor.monitor", "--checkpoint", str(CHECKPOINT)],
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=env
    )

    # 2. Start the Flask Dashboard
    print(f"Launching Dashboard at http://localhost:5000 ...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) # ensure absolute imports work
    dashboard_proc = subprocess.Popen(
        [sys.executable, str(DASHBOARD_SCRIPT)],
        cwd=str(ROOT / "api"),
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=env
    )

    print("\nSystem is RUNNING. Press Ctrl+C to stop everything.\n")

    try:
        while True:
            time.sleep(1)
            if monitor_proc.poll() is not None:
                print("Error: Monitor process died.")
                break
            if dashboard_proc.poll() is not None:
                print("Error: Dashboard process died.")
                break
    except KeyboardInterrupt:
        print("\n Shutting down...")
    finally:
        monitor_proc.terminate()
        dashboard_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    main()
