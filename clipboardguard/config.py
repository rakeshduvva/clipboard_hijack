# clipboardguard/config.py
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
LOG_CSV = os.path.join(BASE_DIR, "logs.csv")

# Patterns considered sensitive (extendable)
PATTERNS = {
    "crypto_address": [
        r"\b(0x[a-fA-F0-9]{40})\b",         # Ethereum-like
        r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"  # BTC-like (simplified)
    ],
    "email": [r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"],
    "jwt": [r"\b[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"]
}

# How many seconds between clipboard polls
POLL_INTERVAL = 0.6

# Attribution & safety
ATTRIBUTION_SNAPSHOT_INTERVAL = 0.6   # seconds between process snapshots for delta
ATTRIBUTION_TOP_K = 3                 # if multiple candidates, use up-to-top_k for logging
# Basic whitelist (names or exe basenames). Add common system/known safe names here.
WHITELIST_NAMES = {
    "explorer.exe",
    "System",
    "Idle",
    "svchost.exe",
    # add more like "chrome.exe", "code.exe" if you trust them
}
# If True the monitor will try to terminate suspected malicious process (USE WITH CARE)
AUTO_TERMINATE = False
# If AUTO_TERMINATE True, this is the graceful timeout before force-kill (secs)
TERMINATE_WAIT_SECONDS = 3
