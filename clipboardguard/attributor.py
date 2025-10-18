# clipboardguard/attributor.py
"""
Simple process-attribution heuristics using psutil snapshots.

We capture per-process I/O and CPU times at two moments and compute deltas.
We prefer processes with the largest write_bytes delta; fallback to cpu_time delta.

This is heuristic-based and not guaranteed. It is intended for audit/logging and
to provide a "most-likely" suspect for the GUI/alerts.
"""

import psutil
import time
from typing import Dict, Tuple, Optional, List

def snapshot_processes() -> Dict[int, dict]:
    """
    Return a mapping pid -> metrics snapshot for currently running processes.
    Metrics include: write_bytes (from io_counters when available), cpu_times (user+system),
    name and exe path.
    """
    snap = {}
    for p in psutil.process_iter(attrs=['pid', 'name', 'exe']):
        try:
            info = p.info
            pid = info['pid']
            name = info.get('name') or ""
            exe = info.get('exe') or ""
            # safe attempt to get io counters and cpu times
            write_bytes = 0
            try:
                io = p.io_counters()
                write_bytes = getattr(io, "write_bytes", 0) or 0
            except Exception:
                write_bytes = 0
            cpu_time = 0.0
            try:
                ct = p.cpu_times()
                cpu_time = (getattr(ct, "user", 0.0) or 0.0) + (getattr(ct, "system", 0.0) or 0.0)
            except Exception:
                cpu_time = 0.0

            snap[pid] = {
                "pid": pid,
                "name": name,
                "exe": exe,
                "write_bytes": write_bytes,
                "cpu_time": cpu_time
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snap

def compute_deltas(before: Dict[int, dict], after: Dict[int, dict]) -> List[dict]:
    """
    Compute deltas for processes present in either snapshot.
    Returns a list of candidate dicts with delta metrics.
    """
    candidates = []
    pids = set(before.keys()) | set(after.keys())
    for pid in pids:
        b = before.get(pid, {})
        a = after.get(pid, {})
        write_b = b.get("write_bytes", 0)
        write_a = a.get("write_bytes", 0)
        cpu_b = b.get("cpu_time", 0.0)
        cpu_a = a.get("cpu_time", 0.0)
        delta_write = max(0, write_a - write_b)
        delta_cpu = max(0.0, cpu_a - cpu_b)
        name = a.get("name") or b.get("name") or ""
        exe = a.get("exe") or b.get("exe") or ""
        candidates.append({
            "pid": pid,
            "name": name,
            "exe": exe,
            "delta_write": delta_write,
            "delta_cpu": delta_cpu
        })
    # sort by delta_write desc, then delta_cpu desc
    candidates.sort(key=lambda x: (x['delta_write'], x['delta_cpu']), reverse=True)
    return candidates

def identify_suspects(window_seconds: float = 0.6, top_k: int = 3) -> list:
    """
    Take two snapshots separated by window_seconds, compute deltas, and return top_k suspects.
    Each suspect is a dict with pid,name,exe,delta_write,delta_cpu.
    """
    before = snapshot_processes()
    time.sleep(window_seconds)
    after = snapshot_processes()
    deltas = compute_deltas(before, after)
    return deltas[:top_k]

def format_suspect(s: dict) -> str:
    return f"pid={s['pid']} name={s['name']} exe={s['exe']} write_delta={s['delta_write']} cpu_delta={s['delta_cpu']}"
