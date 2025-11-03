# clipboardguard/trust_db.py
"""
Small trust database to remember user-approved clipboard values.
We store hashes (sha256) so we don't keep raw clipboard values in plaintext logs.
"""

import json
import os
import hashlib
from threading import Lock

from .config import BASE_DIR

_TRUST_FILE = os.path.join(BASE_DIR, "trusted_clipboard.json")
_lock = Lock()

def _hash_value(val: str) -> str:
    return hashlib.sha256((val or "").encode('utf-8')).hexdigest()

def load_trusted() -> set:
    if not os.path.exists(_TRUST_FILE):
        return set()
    try:
        with open(_TRUST_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            return set(data.get("hashes", []))
    except Exception:
        return set()

def save_trusted(hashes: set):
    try:
        with _lock:
            with open(_TRUST_FILE, 'w', encoding='utf-8') as fh:
                json.dump({"hashes": list(hashes)}, fh, indent=2)
    except Exception:
        pass

# In-memory cache
_trusted_hashes = None

def get_trusted_hashes():
    global _trusted_hashes
    if _trusted_hashes is None:
        _trusted_hashes = load_trusted()
    return _trusted_hashes

def add_trusted(value: str):
    global _trusted_hashes
    h = _hash_value(value)
    th = get_trusted_hashes()
    if h not in th:
        th.add(h)
        save_trusted(th)

def is_trusted(value: str) -> bool:
    h = _hash_value(value)
    return h in get_trusted_hashes()
