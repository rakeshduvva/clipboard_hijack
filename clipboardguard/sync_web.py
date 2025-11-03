# clipboardguard/sync_web.py
import requests
import os

# Adjust this URL if Flask runs on a different port
WEB_API_BASE = "http://127.0.0.1:5000/api"

def sync_trusted(value: str):
    """Send newly trusted value to Flask app."""
    try:
        requests.post(f"{WEB_API_BASE}/trusted_sync", json={"address": value}, timeout=2)
    except Exception as e:
        print(f"[!] Failed to sync trusted value: {e}")

def sync_untrusted(value: str):
    """Notify Flask app about untrusted/suspicious value."""
    try:
        requests.post(f"{WEB_API_BASE}/untrusted_sync", json={"address": value}, timeout=2)
    except Exception as e:
        print(f"[!] Failed to sync untrusted value: {e}")
