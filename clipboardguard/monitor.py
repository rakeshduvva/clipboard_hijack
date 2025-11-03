# clipboardguard/monitor.py
"""
ClipboardGuard main monitor.

Features:
- Clipboard polling and sensitive-pattern detection (uses detector.py)
- Attribution heuristics (uses attributor.py)
- Trusted-value handling (uses trust_db.py)
- User-copy detection via keyboard (uses user_intent.py)
- Notifications (plyer) and CSV logging (logger.py)
- Optional GUI confirmation for unknown sensitive values (tkinter)
"""

import time
import pyperclip
import os
import psutil
from plyer import notification
from .detector import is_suspicious_change
from .sync_web import sync_trusted, sync_untrusted
from .logger import log_event
from .config import (
    POLL_INTERVAL,
    ATTRIBUTION_SNAPSHOT_INTERVAL,
    WHITELIST_NAMES,
    AUTO_TERMINATE,
    TERMINATE_WAIT_SECONDS,
    ATTRIBUTION_TOP_K,
)
from .attributor import identify_suspects, format_suspect
from .user_intent import start_listener, was_recent_user_copy
from .trust_db import is_trusted, add_trusted
from typing import List

# Optional: GUI confirmation for unknown sensitive values (fallback if no Ctrl+C detected)
def ask_user_trust_prompt(value: str) -> bool:
    """
    Show a small Tkinter yes/no dialog asking whether to trust this clipboard value.
    Returns True if user clicks Yes, False otherwise.
    Non-blocking concerns: This will block the monitor loop while dialog is open (intended).
    """
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        # Ensure dialog is on top
        root.attributes("-topmost", True)
        # Trim long values for display but allow full in details
        display_val = value if len(value) <= 300 else value[:300] + "..."
        prompt = (
            f"New sensitive clipboard value detected:\n\n{display_val}\n\n"
            "Do you trust this value and want to keep it on the clipboard?"
        )
        answer = messagebox.askyesno("ClipboardGuard - Trust clipboard?", prompt)
        root.destroy()
        return bool(answer)
    except Exception:
        # If GUI not available or something fails, default to False (do not trust)
        return False


class ClipboardGuardCore:
    def __init__(self):
        self._last = ""
        try:
            self._last = pyperclip.paste() or ""
        except Exception:
            self._last = ""
        self.running = False
        self.self_pid = os.getpid()
        # start keyboard listener to detect Ctrl+C user intent
        try:
            start_listener()
        except Exception:
            pass
        # get trusted addresses list from config if present (useful to preload your own wallets)
        from . import config as _cfg

        self._pretrusted = getattr(_cfg, "TRUSTED_ADDRESSES", []) or []

    def _notify(self, title: str, message: str):
        try:
            notification.notify(title=title, message=message, timeout=6)
        except Exception:
            # plyer may fail silently on some systems; ignore
            pass

    def restore_clipboard(self, value: str) -> bool:
        try:
            pyperclip.copy(value)
            return True
        except Exception:
            return False

    def _is_whitelisted(self, name: str, exe: str) -> bool:
        if not name and not exe:
            return False
        name_l = (name or "").lower()
        exe_basename = (os.path.basename(exe) or "").lower()
        for w in WHITELIST_NAMES:
            if w.lower() in name_l or w.lower() == exe_basename:
                return True
        return False

    def _attempt_terminate(self, pid: int):
        """
        Graceful attempt to terminate a process, then force-kill after timeout.
        Disabled by default (use config.AUTO_TERMINATE = True to enable).
        """
        try:
            p = psutil.Process(pid)
        except Exception:
            return False, "process_not_found"
        try:
            p.terminate()
            try:
                p.wait(timeout=TERMINATE_WAIT_SECONDS)
                return True, "terminated_gracefully"
            except psutil.TimeoutExpired:
                p.kill()
                return True, "killed_forcibly"
        except Exception as e:
            return False, f"terminate_failed:{e}"
class ClipboardGuardCore:
    def __init__(self):
        self._last = ""
        try:
            self._last = pyperclip.paste() or ""
        except Exception:
            self._last = ""
        self.running = False
        self.self_pid = os.getpid()
        try:
            start_listener()
        except Exception:
            pass
        from . import config as _cfg
        self._pretrusted = getattr(_cfg, "TRUSTED_ADDRESSES", []) or []

    def _notify(self, title: str, message: str):
        try:
            notification.notify(title=title, message=message, timeout=6)
        except Exception:
            pass

    def restore_clipboard(self, value: str) -> bool:
        try:
            pyperclip.copy(value)
            return True
        except Exception:
            return False

    def _is_whitelisted(self, name: str, exe: str) -> bool:
        if not name and not exe:
            return False
        name_l = (name or "").lower()
        exe_basename = (os.path.basename(exe) or "").lower()
        for w in WHITELIST_NAMES:
            if w.lower() in name_l or w.lower() == exe_basename:
                return True
        return False

    def _attempt_terminate(self, pid: int):
        try:
            p = psutil.Process(pid)
        except Exception:
            return False, "process_not_found"
        try:
            p.terminate()
            try:
                p.wait(timeout=TERMINATE_WAIT_SECONDS)
                return True, "terminated_gracefully"
            except psutil.TimeoutExpired:
                p.kill()
                return True, "killed_forcibly"
        except Exception as e:
            return False, f"terminate_failed:{e}"

    # ✅ FIXED: moved inside class
    def _should_accept_new(self, new_text: str, new_matches: List[tuple]) -> bool:
        trusted = False
        try:
            if is_trusted(new_text):
                return True
        except Exception:
            pass
        try:
            for addr in getattr(self, "_pretrusted", []):
                if addr in new_text:
                    trusted = True
                    break
        except Exception:
            pass
        try:
            if was_recent_user_copy():
                trusted = True
        except Exception:
            pass
        if not trusted:
            try:
                trusted = ask_user_trust_prompt(new_text)
            except Exception:
                trusted = False
        if trusted:
            try:
                add_trusted(new_text)
                sync_trusted(new_text)
            except Exception:
                pass
            return True
        return False

    # ✅ FIXED: moved inside class
    def start(self):
        self.running = True
        print("[*] ClipboardGuard started. Monitoring clipboard...")
        while self.running:
            try:
                current = pyperclip.paste() or ""
            except Exception:
                current = ""
            if current != self._last:
                suspicious, new_matches = is_suspicious_change(self._last, current)
                if new_matches:
                    if self._should_accept_new(current, new_matches):
                        print("[*] Sensitive clipboard value accepted (trusted or user-copied).")
                        log_event("accepted_trusted", self._last, current, [t for t, _ in new_matches])
                        self._last = current
                        time.sleep(POLL_INTERVAL)
                        continue
                if suspicious:
                    types = [t for t, _ in new_matches] if new_matches else []
                    print(f"[!] Suspicious clipboard change detected. Types: {types}")
                    suspects = identify_suspects(window_seconds=ATTRIBUTION_SNAPSHOT_INTERVAL, top_k=ATTRIBUTION_TOP_K)
                    filtered = []
                    for s in suspects:
                        if s.get("pid") == self.self_pid:
                            continue
                        if self._is_whitelisted(s.get("name", ""), s.get("exe", "")):
                            continue
                        filtered.append(s)
                    suspect_info = [format_suspect(s) for s in filtered] or ["unknown_or_whitelisted"]
                    log_event("suspicious_change", self._last, current, types + suspect_info)
                    top_msg = suspect_info[0]
                    try:
                        self._notify("ClipboardGuard - Suspicious change", f"Detected {types}. Suspect: {top_msg}")
                    except Exception:
                        pass
                    restored = self.restore_clipboard(self._last)
                    if restored:
                        print("[*] Restored previous clipboard value.")
                        self._notify("ClipboardGuard", "Clipboard restored due to suspected hijack.")
                        log_event("restored", self._last, current, types + ["restored"])
                    else:
                        print("[!] Failed to restore clipboard.")
                        self._notify("ClipboardGuard", "Warning: clipboard hijack suspected but restore failed.")
                        log_event("restore_failed", self._last, current, types)
                    if AUTO_TERMINATE and filtered:
                        top_pid = filtered[0]["pid"]
                        ok, status = self._attempt_terminate(top_pid)
                        if ok:
                            self._notify("ClipboardGuard", f"Terminated suspect pid={top_pid} ({status})")
                            log_event("terminated", self._last, current, [f"pid={top_pid}", status])
                        else:
                            self._notify("ClipboardGuard", f"Failed to terminate pid={top_pid}: {status}")
                            log_event("terminate_failed", self._last, current, [f"pid={top_pid}", status])
                try:
                    self._last = pyperclip.paste() or ""
                except Exception:
                    self._last = ""
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    guard = ClipboardGuardCore()
    try:
        guard.start()
    except KeyboardInterrupt:
        print("Exiting...")
