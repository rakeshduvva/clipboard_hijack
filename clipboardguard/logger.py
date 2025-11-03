# clipboardguard/logger.py
"""
Simple, thread-safe CSV logger for ClipboardGuard.

Creates LOG_CSV if missing and appends incidents with a UTC timestamp.
Fields: timestamp,event,prev_clipboard,new_clipboard,detected_types
"""

import csv
import os
import threading
from datetime import datetime
from .config import LOG_CSV

HEADER = ["timestamp", "event", "prev_clipboard", "new_clipboard", "detected_types"]
_lock = threading.Lock()

def ensure_log():
    """Ensure the log directory and file exist and have a header."""
    log_dir = os.path.dirname(LOG_CSV)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    if not os.path.exists(LOG_CSV):
        # create file and write header
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(HEADER)

def _sanitize_field(value: str) -> str:
    """Prepare field for CSV: convert to str and replace newlines/carriage returns."""
    if value is None:
        return ""
    # replace newlines which can break CSV readability
    return str(value).replace("\r", " ").replace("\n", " ")

def log_event(event: str, prev: str, new: str, det_types):
    """
    Append an event row to the CSV log.

    Args:
        event: short event name, e.g., "suspicious_change", "restored"
        prev: previous clipboard value
        new: new clipboard value
        det_types: iterable of detected pattern types (e.g., ["crypto_address", "jwt"])
    """
    ensure_log()
    types_field = ";".join(det_types) if det_types else ""
    row = [
        datetime.utcnow().isoformat() + "Z",
        _sanitize_field(event),
        _sanitize_field(prev),
        _sanitize_field(new),
        _sanitize_field(types_field),
    ]
    with _lock:
        with open(LOG_CSV, "a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(row)

def read_recent(n=50):
    """
    Return the last `n` log rows (excluding header) as a list of dicts.
    Useful for showing recent events in a GUI.
    """
    ensure_log()
    rows = []
    with _lock:
        with open(LOG_CSV, "r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                rows.append(r)
    return rows[-n:]
