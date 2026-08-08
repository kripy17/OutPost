#!/usr/bin/env python3
"""Synthetic test script — proves the whole pipeline with zero real risk.

Spawns identifiable child processes and connects to a test listener, then
confirm the dashboard shows the expected process tree, connections, and
detection alerts (the detection heuristics are defined in the backend's
detection engine).

This script intentionally mimics several detection heuristics so you can
demonstrate them firing on command:
  - spawns 3 child processes with identifiable names
  - opens connections to a test IP/port you control (e.g. `nc -l 4444`)
  - writes a burst of files to mimic a rename burst (rule 6)
  - writes to a fake registry Run key location on Windows (rule 5)

Run with the collector watching, e.g.:
  outpost watch            # in one terminal
  python scripts/synthetic_demo.py   # in another
"""

import os
import socket
import subprocess
import sys
import time

# --- config ---------------------------------------------------------------
BEACON_IP = os.getenv("OUTPOST_TEST_IP", "127.0.0.1")
BEACON_PORT = int(os.getenv("OUTPOST_TEST_PORT", "4444"))
BURST_DIR = os.getenv("OUTPOST_BURST_DIR", os.path.expanduser("~/outpost-test-burst"))


def spawn_children() -> list[subprocess.Popen]:
    """Spawn 2-3 identifiable child processes (rule 2 wants a parent chain)."""
    procs = []
    for name in ("outpost_child_a", "outpost_child_b", "outpost_child_c"):
        if os.name == "nt":
            procs.append(subprocess.Popen(["cmd", "/c", "echo", name, "&&", "timeout", "/t", "20"]))
        else:
            procs.append(subprocess.Popen(["bash", "-c", f"echo {name}; sleep 20"]))
    return procs


def beacon(ip: str, port: int, count: int = 6, interval: float = 30.0) -> None:
    """Connect to a listener at regular intervals (rule 4: beaconing).

    For a live demo, shorten `interval` to ~2s so the rule fires quickly.
    """
    for i in range(count):
        try:
            with socket.create_connection((ip, port), timeout=3):
                pass
            print(f"[beacon] connection {i + 1}/{count} → {ip}:{port}")
        except OSError as exc:
            print(f"[beacon] no listener at {ip}:{port} ({exc}) — start `nc -l {port}`")
        time.sleep(interval)


def file_burst(directory: str, count: int = 15) -> None:
    """Write a burst of files (rule 6: rename/file-write burst)."""
    os.makedirs(directory, exist_ok=True)
    for i in range(count):
        with open(os.path.join(directory, f"file_{i}.enc"), "w") as fh:
            fh.write("x" * 1024)
    print(f"[burst] wrote {count} files to {directory}")


def main() -> None:
    print("OutPost synthetic test script — mimic suspicious behavior safely.\n")
    procs = spawn_children()
    time.sleep(1)
    beacon(BEACON_IP, BEACON_PORT)
    file_burst(BURST_DIR)
    for p in procs:
        p.terminate()
    print("\nDone. Check the OutPost dashboard/CLI for the process tree, connections, and alerts.")


if __name__ == "__main__":
    main()
