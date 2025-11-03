# clipboardguard/monitor.py
import time
import pyperclip
from plyer import notification
from .detector import is_suspicious_change, find_sensitive_matches
from .logger import log_event
from .config import POLL_INTERVAL, ATTRIBUTION_SNAPSHOT_INTERVAL, WHITELIST_NAMES, AUTO_TERMINATE, TERMINATE_WAIT_SECONDS, ATTRIBUTION_TOP_K
from .attributor import identify_suspects, format_suspect
import psutil
import os

class ClipboardGuardCore:
    def __init__(self):
        self._last = ""
        try:
            self._last = pyperclip.paste()
        except Exception:
            self._last = ""
        self.running = False
        self.self_pid = os.getpid()

    def _notify(self, title, message):
        try:
            notification.notify(title=title, message=message, timeout=6)
        except Exception:
            pass

    def restore_clipboard(self, value):
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

    def start(self):
        self.running = True
        print("[*] ClipboardGuard started. Monitoring clipboard...")
        while self.running:
            try:
                current = pyperclip.paste()
            except Exception:
                current = ""
            if current != self._last:
                suspicious, new_matches = is_suspicious_change(self._last, current)
                if suspicious:
                    types = [t for t, _ in new_matches] if new_matches else []
                    print(f"[!] Suspicious clipboard change detected. Types: {types}")
                    # Attribution: find likely suspects
                    suspects = identify_suspects(window_seconds=ATTRIBUTION_SNAPSHOT_INTERVAL, top_k=ATTRIBUTION_TOP_K)
                    # Filter out self and whitelist
                    filtered = []
                    for s in suspects:
                        if s['pid'] == self.self_pid:
                            continue
                        if self._is_whitelisted(s['name'], s['exe']):
                            continue
                        filtered.append(s)
                    # Log event with suspect info (top candidate if any)
                    suspect_info = []
                    for s in filtered:
                        suspect_info.append(format_suspect(s))
                    if not suspect_info:
                        suspect_info = ["unknown_or_whitelisted"]
                    log_event("suspicious_change", self._last, current, types + suspect_info)
                    # Notify user with top suspect summary (if any)
                    top_msg = suspect_info[0] if suspect_info else "unknown"
                    self._notify("ClipboardGuard - Suspicious change", f"Detected {types}. Suspect: {top_msg}")
                    # Restore clipboard
                    restored = self.restore_clipboard(self._last)
                    if restored:
                        print("[*] Restored previous clipboard value.")
                        self._notify("ClipboardGuard", "Clipboard restored due to suspected hijack.")
                        log_event("restored", self._last, current, types + ["restored"])
                    else:
                        print("[!] Failed to restore clipboard.")
                        self._notify("ClipboardGuard", "Warning: clipboard hijack suspected but restore failed.")
                        log_event("restore_failed", self._last, current, types)
                    # Optionally terminate top suspect (disabled by default)
                    if AUTO_TERMINATE and filtered:
                        top_pid = filtered[0]['pid']
                        ok, status = self._attempt_terminate(top_pid)
                        if ok:
                            self._notify("ClipboardGuard", f"Terminated suspect pid={top_pid} ({status})")
                            log_event("terminated", self._last, current, [f"pid={top_pid}", status])
                        else:
                            self._notify("ClipboardGuard", f"Failed to terminate pid={top_pid}: {status}")
                            log_event("terminate_failed", self._last, current, [f"pid={top_pid}", status])
                # update last (we set it back above if restored)
                self._last = pyperclip.paste()
            time.sleep(POLL_INTERVAL)

    def stop(self):
        self.running = False

if __name__ == "__main__":
    guard = ClipboardGuardCore()
    try:
        guard.start()
    except KeyboardInterrupt:
        print("Exiting...")
