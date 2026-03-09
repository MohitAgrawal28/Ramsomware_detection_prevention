"""
monitor.py — File system monitor using ML detection
"""

import os
import time
from watchdog.events import FileSystemEventHandler
from detector import detect_ransomware, reset_window
from backup import backup_files, restore_files
from prevention import stop_encryption


class FileMonitor(FileSystemEventHandler):
    """
    Watches a directory for file events and runs ML detection
    on every create/modify/rename event.
    """

    def __init__(self):
        super().__init__()
        self._last_alert = 0
        self._alert_cooldown = 10  # seconds between alerts

    def process(self, event_path: str, event_type: str):
        """Process a file event through the ML detector."""

        result = detect_ransomware(event_path, event_type)
        label  = result["label"]
        prob   = result["probability"]
        fill   = result["window_fill"]

        if label == "collecting":
            print(f"  [{fill:3d}/100] Collecting events... ({event_type})")
            backup_files()
            return

        if label == "ransomware":
            now = time.time()
            if now - self._last_alert < self._alert_cooldown:
                return  # Prevent alert spam
            self._last_alert = now

            print("\n" + "=" * 50)
            print("  RANSOMWARE DETECTED!")
            print(f"  Confidence   : {prob:.2%}")
            print(f"  File         : {os.path.basename(event_path)}")
            print(f"  Event        : {event_type}")
            print("=" * 50)

            # Prevention actions
            print("\n  Taking action...")
            stop_encryption()     # Kill suspicious processes
            restore_files()       # Restore from backup
            reset_window()        # Reset detection window

            print("\n  System protected. Monitoring continues...")

        else:
            # Benign — backup and log
            backup_files()
            print(f"  [SAFE] {event_type} | {os.path.basename(event_path)} "
                  f"| prob={prob:.3f}")

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path, "create")

    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path, "modify")

    def on_moved(self, event):
        if not event.is_directory:
            self.process(event.dest_path, "rename")

    def on_deleted(self, event):
        if not event.is_directory:
            # Log deletion but don't score (no file to read)
            print(f"  [DEL] {os.path.basename(event.src_path)}")