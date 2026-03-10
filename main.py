"""
main.py — RanSAP Ransomware Detection System
Entry point — starts file system monitoring
"""

import os
import sys
import time
import signal
from watchdog.observers import Observer
from monitor import FileMonitor

# ── CONFIG ───────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WATCH_PATH = os.path.join(BASE_DIR, "test_folder")   # Folder to monitor
BACKUP_PATH = os.path.join(BASE_DIR, "backup_folder")
# ─────────────────────────────────────────────────────────────


def main():
    print("=" * 50)
    print("  RANSOMWARE DETECTION & PREVENTION SYSTEM")
    print("  Powered by LSTM Deep Learning (RanSAP 2022)")
    print("=" * 50)

    # Make sure watch folder exists
    os.makedirs(WATCH_PATH, exist_ok=True)
    os.makedirs(BACKUP_PATH, exist_ok=True)

    print(f"\n  Watching    : {os.path.abspath(WATCH_PATH)}")
    print(f"  Model       : model/ransomware_lstm_model.keras")
    print(f"  Threshold   : 70% confidence")
    print(f"  Window size : 100 events")
    print(f"\n  Press Ctrl+C to stop\n")

    event_handler = FileMonitor()
    observer      = Observer()
    observer.schedule(event_handler, WATCH_PATH, recursive=True)

    def shutdown(sig, frame):
        print("\n\nShutting down...")
        observer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    observer.start()
    print("  Monitoring started...\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitoring stopped.")

    observer.join()


if __name__ == "__main__":
    main()