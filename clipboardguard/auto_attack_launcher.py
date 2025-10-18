# clipboardguard/auto_attack_launcher.py
"""
Monitor clipboard for the first manual copy, then launch the attacker script
in a new PowerShell window (Terminal B) using the project's venv python.

Usage:
  # from project root (with venv active)
  .\venv\Scripts\python.exe -m clipboardguard.auto_attack_launcher
"""

import time
import pyperclip
import subprocess
import sys
import os
from pathlib import Path

POLL_INTERVAL = 0.5  # seconds (clipboard polling)
SPAWNED = False

def get_project_root():
    # this file is in clipboardguard/, so project root is parent of parent if run as module
    # fallback: use current working dir
    try:
        return Path(__file__).resolve().parents[1]
    except Exception:
        return Path.cwd()

def build_powershell_command(project_root: Path):
    """
    Build a PowerShell command that opens a new window and runs the attacker
    using the venv python executable so the venv packages are used.
    """
    venv_python = project_root / "venv" / "Scripts" / "python.exe"
    attacker = project_root / "tests" / "simulate_attacker.py"

    # Use full paths and escape quotes
    vpython = str(venv_python).replace("'", "''")
    pattacker = str(attacker).replace("'", "''")

    # The -NoExit keeps the new PowerShell window open so you can see output.
    # We use & '<path>' '<script>' to invoke the venv python explicitly.
    cmd = f"Start-Process powershell -ArgumentList '-NoExit','-Command','& \"{vpython}\" \"{pattacker}\"'"

    return cmd

def main():
    global SPAWNED
    project_root = get_project_root()
    print(f"Project root detected: {project_root}")
    print("Monitoring clipboard. Copy any text (Ctrl+C) to trigger attacker spawn once.")

    last = ""
    try:
        last = pyperclip.paste() or ""
    except Exception:
        last = ""

    ps_command = build_powershell_command(project_root)
    # We will run the powershell command via subprocess when a new copy is detected.

    while True:
        try:
            current = pyperclip.paste() or ""
        except Exception:
            current = ""

        if current != last:
            print(f"[+] Clipboard changed. New value (first 80 chars): {current[:80]!r}")
            # If not spawned yet, spawn attacker in new PowerShell window
            if not SPAWNED:
                print("[*] Spawning attacker in new PowerShell window...")
                # Use powershell to run the Start-Process call
                # Note: We call powershell.exe with -Command to execute the Start-Process string.
                try:
                    subprocess.Popen(["powershell.exe", "-NoProfile", "-Command", ps_command],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     creationflags=0)
                    print("[*] Attacker launched (Terminal B).")
                except Exception as e:
                    print("[!] Failed to spawn attacker:", e)
                SPAWNED = True
            else:
                # if attacker already spawned, just print and continue monitoring
                print("[*] Attacker already spawned. Monitoring continues.")
            last = current

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
