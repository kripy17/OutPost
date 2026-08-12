#!/usr/bin/env python3
"""Gate: the collector's live-session claim flow, end to end.

The REAL Linux collector (`collectors/linux/collector_linux.py --mode live`,
no `--run-id`) is exercised against an isolated backend, exactly as a user
running the one-line Monitor command would use it:

  Phase 1 — webapp parity claim. With an open live session on the backend,
  the collector must claim it (via GET /runs/active-live) and stream events
  into THAT session — not create a rogue agent run. Three REAL long-lived
  bash processes run the enumeration chain (whoami / uname -a / getent
  passwd) and their auditd-format records are appended to the temp audit
  log, so the collector's /proc reads return the true command lines and
  enumeration-burst must fire with exactly those three recon-actor PIDs.
  The collector's heartbeat must also make the host read online with
  identity=collector and the auditd channel.

  Phase 2 — agent self-sufficiency. With NO open live session, the
  collector must create its own `agent-<host>-<date>` live run and stream
  into it (the systemd-service path).

Only the auditd log tail and the /proc reads are host-side reads (the
records reference real processes spawned by this script); parsing,
shipping, ingest, and every detection rule are the production path.

Run: .venv/bin/python scripts/gate_live_claim.py \
       [--backend http://127.0.0.1:8015] [--host gate-host] [--db /path/db]
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "collectors" / "linux" / "collector_linux.py"

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> bool:
    print(f"  {'✓' if cond else '✗'} {name}{' — ' + detail if detail else ''}")
    (PASSED if cond else FAILED).append(name)
    return cond


def _req(base: str, path: str, method: str = "GET", body: dict | None = None, timeout: int = 8):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def post(base: str, path: str, body: dict):
    return _req(base, path, "POST", body)


def get(base: str, path: str):
    return _req(base, path)


def wait_until(fn, timeout: float, step: float = 0.5):
    end = time.time() + timeout
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(step)
    return None


def audit_exec(ts: float, seq: int, pid: int, comm: str) -> str:
    """One process_create as auditd emits it (SYSCALL execve record)."""
    return (f"type=SYSCALL msg=audit({ts:.3f}:{seq}): arch=c000003e syscall=59 "
            f"success=yes exit=0 pid={pid} comm=\"{comm}\"")


def spawn_enum_bash(cmd: str) -> subprocess.Popen:
    """A REAL bash -c running the command, kept alive with a compound last
    command (bash never exec-replaces itself) so the collector's /proc read
    returns the true command line with the enum pattern intact. Output is
    silenced — only /proc matters; the collector reads the real cmdline."""
    return subprocess.Popen(
        ["bash", "-c", f"{cmd}; {{ sleep 30; }}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def start_collector(base: str, audit_log: Path, host: str, collector_log: Path) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-u", str(COLLECTOR), "--backend-url", base, "--mode", "live"],
        env={
            **os.environ,
            "AUDIT_LOG": str(audit_log),
            "OUTPOST_HOST_ID": host,
            "HEARTBEAT_INTERVAL": "2",
            "SNAPSHOT_INTERVAL": "9999",
        },
        stdout=open(collector_log, "w"),
        stderr=subprocess.STDOUT,
    )
    return proc


def stop_collector(proc: subprocess.Popen, collector_log: Path) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=6)
    except subprocess.TimeoutExpired:
        proc.kill()
    # Flush the collector's buffered stdout for diagnostics on failure.
    tail = ""
    try:
        tail = collector_log.read_text()[-400:]
    except OSError:
        pass
    return tail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default="http://127.0.0.1:8015")
    ap.add_argument("--host", default="gate-host")
    ap.add_argument("--db", default=None, help="isolated DB path (unstamped-event gate)")
    args = ap.parse_args()
    base = args.backend.rstrip("/")
    host = args.host

    scratch = ROOT / ".freebuff"
    scratch.mkdir(exist_ok=True)
    audit_log = scratch / "gate-live-claim-audit.log"
    collector_log = scratch / "gate-live-claim-collector.log"
    audit_log.write_text("")
    seq = [1000]

    # ------------------------------------------------------------------
    # Phase 1 — webapp parity claim
    # ------------------------------------------------------------------
    print(f"Phase 1 — collector claims the open webapp live session (host={host})")
    webapp = post(base, "/runs", {
        "sample_name": "gate-claim-webapp", "platform": "linux", "session_type": "live",
    })
    webapp_id = webapp["run_id"]
    print(f"  open webapp live session {webapp_id} (gate-claim-webapp)")

    collector = start_collector(base, audit_log, host, collector_log)
    try:
        # The collector seeks the audit log to EOF when it starts — records
        # written before it opens the file are skipped. Wait for it to claim
        # the session and enter its loop (the 2s heartbeat is that signal)
        # before feeding anything.
        def collector_ready():
            agents = get(base, "/agents") or {}
            return next((a for a in (agents.get("agents") or [])
                         if a.get("host_id") == host and a.get("online")), None)

        ready = wait_until(collector_ready, 15)
        check("1 · collector claims the session and heartbeats",
              bool(ready), f"online={bool(ready)}")

        # Three real long-lived enumeration processes; the collector reads
        # /proc while they are alive, so command_line carries the real chain.
        enum_cmds = ("whoami", "uname -a", "getent passwd")
        procs = [spawn_enum_bash(c) for c in enum_cmds]
        try:
            for p, cmd in zip(procs, enum_cmds):
                seq[0] += 1
                with open(audit_log, "a", encoding="utf-8") as fh:
                    fh.write(audit_exec(time.time(), seq[0], p.pid, "bash") + "\n")
                print(f"  fed enum record pid={p.pid} cmd='{cmd}'")
                time.sleep(0.4)

            # Events must land in the WEBAPP session (claimed), not a new run.
            def webapp_events():
                d = get(base, f"/runs/{webapp_id}")
                tl = d.get("timeline") or []
                return tl if len(tl) >= 3 else None

            timeline = wait_until(webapp_events, 20)
            check("1 · events stream into the claimed webapp session",
                  timeline is not None and len(timeline) >= 3,
                  f"timeline={len(timeline) if timeline else 0}")
            ev = (timeline or [{}])[0]
            check("1 · event attributed to host + auditd channel",
                  (ev.get("host_id") == host and ev.get("log_source") == "auditd"
                   and ev.get("platform") == "linux"),
                  f"host={ev.get('host_id')} source={ev.get('log_source')}")

            # No rogue agent run may exist while a webapp session was open.
            runs = get(base, "/runs") or []
            rogue = [r for r in runs
                     if r.get("session_type") == "live" and not r.get("completed_at")
                     and r.get("run_id") != webapp_id]
            check("1 · no rogue agent run created while claiming",
                  not rogue, f"rogue={[r['sample_name'] for r in rogue]}")

            # The detection chain through the collector: enumeration-burst
            # with exactly the three recon-actor PIDs.
            def enum_alert():
                for a in get(base, f"/runs/{webapp_id}/alerts") or []:
                    if a.get("rule_id") == "enumeration-burst":
                        return a
                return None

            alert = wait_until(enum_alert, 20)
            actor_pids = sorted((alert or {}).get("related_pids") or [])
            check("1 · enumeration-burst fires through the collector path",
                  alert is not None, str((alert or {}).get("details") or "")[:90])
            check("1 · recon actors are exactly the three real PIDs",
                  actor_pids == sorted(p.pid for p in procs),
                  f"actors={actor_pids}")

            # The heartbeat makes the fleet read the host as a live collector.
            def host_row():
                agents = get(base, "/agents") or {}
                return next((a for a in (agents.get("agents") or [])
                             if a.get("host_id") == host), None)

            row = host_row()
            check("1 · fleet identity=collector with auditd channel",
                  bool(row and row.get("identity") == "collector"
                       and "auditd" in (row.get("channels") or [])),
                  f"identity={row.get('identity') if row else None} "
                  f"channels={row.get('channels') if row else None}")

            post(base, f"/runs/{webapp_id}/complete", {})
            print("  webapp session completed\n")
        finally:
            for p in procs:
                p.terminate()
    finally:
        tail = stop_collector(collector, collector_log)
        if FAILED:
            print(f"  [collector log tail]\n{tail or '(empty)'}")

    # ------------------------------------------------------------------
    # Phase 2 — agent self-sufficiency (no open live session)
    # ------------------------------------------------------------------
    print(f"Phase 2 — collector creates its own agent run (no webapp session open)")
    audit_log.write_text("")
    today = time.strftime("%Y-%m-%d")
    agent_name = f"agent-{host}-{today}"

    collector = start_collector(base, audit_log, host, collector_log)
    try:
        def agent_run():
            for r in get(base, "/runs") or []:
                if (r.get("sample_name") == agent_name and r.get("session_type") == "live"
                        and not r.get("completed_at")):
                    return r
            return None

        run = wait_until(agent_run, 20)
        check("2 · collector creates its own agent-<host>-<date> live run",
              run is not None, agent_name)

        if run:
            # One real short-lived process (kept alive long enough for /proc).
            holder = subprocess.Popen(["sleep", "20"])
            try:
                seq[0] += 1
                with open(audit_log, "a", encoding="utf-8") as fh:
                    fh.write(audit_exec(time.time(), seq[0], holder.pid, "sleep") + "\n")
            finally:
                holder.terminate()

            def agent_events():
                d = get(base, f"/runs/{run['run_id']}")
                tl = d.get("timeline") or []
                return tl if tl else None

            timeline = wait_until(agent_events, 15)
            check("2 · events stream into the collector's own run",
                  bool(timeline), f"timeline={len(timeline) if timeline else 0}")
            ev = (timeline or [{}])[0]
            check("2 · event attributed to host + auditd channel",
                  (ev.get("host_id") == host and ev.get("log_source") == "auditd"),
                  f"host={ev.get('host_id')} source={ev.get('log_source')}")
            if run:
                post(base, f"/runs/{run['run_id']}/complete", {})
    finally:
        stop_collector(collector, collector_log)

    # ------------------------------------------------------------------
    # DB gate — no unstamped collector event may survive the gate.
    # ------------------------------------------------------------------
    if args.db:
        try:
            conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
            try:
                unstamped = conn.execute(
                    "SELECT COUNT(*) FROM events e "
                    "JOIN runs r ON r.run_id = e.run_id "
                    "WHERE r.source = 'live' AND e.host_id != 'local' "
                    "AND e.log_source IS NULL"
                ).fetchone()[0]
            finally:
                conn.close()
            check("gate · no unstamped collector event survives", unstamped == 0,
                  f"unstamped={unstamped}")
        except sqlite3.Error as exc:
            check("gate · no unstamped collector event survives", False,
                  f"db read failed: {exc}")

    print("\n══════════════════════════════════════════════════════")
    print(f"Live-claim gate: {len(PASSED)} passed, {len(FAILED)} failed")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
