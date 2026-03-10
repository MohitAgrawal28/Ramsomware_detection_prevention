"""
prevention.py — Process termination and system protection
"""

import os
import psutil
import logging

log = logging.getLogger("Prevention")

# Processes we should NEVER kill (system critical)
PROTECTED = {
    "system", "svchost.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "explorer.exe",
    "python.exe", "python3.exe", "code.exe",
    "node.exe", "esbuild.exe", "npm.exe",
    "language_server_windows_x64.exe",
    "vite.exe", "cmd.exe", "powershell.exe",
}

# Keywords that suggest ransomware process
SUSPICIOUS_KEYWORDS = [
    "encrypt", "ransom", "crypt", "locker",
    "cipher", "wannacry", "wncry",
]


def stop_encryption():
    """
    Scan running processes and kill any that look suspicious.
    Uses multiple signals to avoid false positives.
    """
    print("  Scanning processes...")
    killed = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
        try:
            name    = proc.info["name"].lower()
            pid     = proc.info["pid"]
            cmdline = " ".join(proc.info["cmdline"] or []).lower()

            # Skip protected processes
            if name in PROTECTED or pid < 100:
                continue

            # Check for suspicious keywords in name or command line
            is_suspicious = any(
                kw in name or kw in cmdline
                for kw in SUSPICIOUS_KEYWORDS
            )

            if is_suspicious:
                print(f"  Terminating: {name} (PID {pid})")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                killed.append(name)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            print(f"  [WARN] {e}")

    if killed:
        print(f"  Killed {len(killed)} suspicious process(es): {killed}")
    else:
        print("  No suspicious processes found to kill.")

    return killed


def block_file_writes(directory: str):
    """
    Make directory read-only to block further writes.
    Works on Windows and Linux.
    """
    import stat
    try:
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                os.chmod(fpath, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        print(f"  Directory locked (read-only): {directory}")
    except Exception as e:
        print(f"  [WARN] Could not lock directory: {e}")


def restore_write_permissions(directory: str):
    """Restore write permissions after threat is cleared."""
    import stat
    try:
        for root, dirs, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                os.chmod(fpath, stat.S_IWRITE | stat.S_IREAD)
        print(f"  Write permissions restored: {directory}")
    except Exception as e:
        print(f"  [WARN] Could not restore permissions: {e}")