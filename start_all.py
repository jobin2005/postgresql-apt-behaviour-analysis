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
    print(" Starting APT Shield System...")
    
    # 1. Start the Flask Dashboard immediately
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

    monitor_proc = None

    if not CHECKPOINT.exists():
        print(f"\n[!] Warning: Model checkpoint not found at {CHECKPOINT}")
        print("The Monitor Daemon is paused. To start it, generate data and train FIRST:")
        print("  1. docker compose exec ml_service python data/generate_training_data.py --sessions 5000")
        print("  2. docker compose exec ml_service python agent/train.py --episodes 2000")
        print("The Monitor will automatically start once training completes.\n")

    print("System is RUNNING. Press Ctrl+C to stop everything.\n")

    try:
        while True:
            time.sleep(2)
            
            # Check if dashboard died
            if dashboard_proc.poll() is not None:
                print("Error: Dashboard process died.")
                break
                
            # If monitor hasn't started but checkpoint now exists, start it
            if monitor_proc is None and CHECKPOINT.exists():
                print(f"\n Detected checkpoint at {CHECKPOINT}! Launching Monitor Daemon...")
                # Use same env with PYTHONPATH as dashboard
                monitor_proc = subprocess.Popen(
                    [sys.executable, str(MONITOR_SCRIPT)],
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                    env=env
                )
                
            # If monitor started and then died, report it
            if monitor_proc is not None and monitor_proc.poll() is not None:
                print("Error: Monitor process died.")
                break

    except KeyboardInterrupt:
        print("\n Shutting down...")
    finally:
        if monitor_proc is not None:
            monitor_proc.terminate()
        dashboard_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    main()
