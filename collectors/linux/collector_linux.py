"""Linux collector — tails auditd's log for execve/connect syscalls.

Per docs/03-COLLECTOR-SPEC.md: read telemetry → normalize → ship. No business
logic lives here. Requires auditd with `audit.rules` loaded:

    sudo auditctl -R collectors/linux/audit.rules

Modes:
  --mode live       run indefinitely (used by `outpost watch`)
  --mode analysis --timeout N   run for N seconds, then exit (`outpost run`)
"""

import argparse
import datetime
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from shipper import Shipper, resolve_live_run_id  # noqa: E402

AUDIT_LOG = "/var/log/audit/audit.log"
# AUDIT_LOG env override — lets the collector tail a test/simulated feed
# (the post-deploy walk feeds a temp log so the real live-mode collector can
# be exercised without root). Default stays the real auditd path.

# Real auditd emits separate record types for the same event: type=SYSCALL
# (syscall + pid), type=EXECVE (program args), type=SOCKADDR (connect dest).
# Match all three so execve and connect are actually parsed; the body decides
# which handler applies.
_AUDIT_RE = re.compile(r"type=([A-Z]+) msg=audit\(([\d.]+):\d+\):\s*(.+)")


def _pid_from_syscall(body: str) -> int | None:
    m = re.search(r"pid=(\d+)", body)
    return int(m.group(1)) if m else None


def _ppid_and_comm(pid: int) -> tuple[int | None, str | None]:
    """Read PPID and comm from /proc at capture time."""
    try:
        with open(f"/proc/{pid}/stat", "r") as fh:
            fields = fh.read().split()
        # stat: pid (comm) state ppid ...
        comm = fields[1].strip("()")
        ppid = int(fields[3]) if len(fields) > 3 else None
        return ppid, comm
    except (FileNotFoundError, IndexError, ValueError):
        return None, None


def _cmdline(pid: int) -> str | None:
    """Read the full command line from /proc at capture time."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read().replace(b"\x00", b" ")
        return raw.decode("utf-8", errors="replace").strip() or None
    except (FileNotFoundError, OSError):
        return None


def parse_audit_line(line: str, pid_cache: dict) -> dict | None:
    """Parse one audit.log line into a unified-schema event dict."""
    if "audit(" not in line:
        return None

    m = _AUDIT_RE.match(line)
    if not m:
        return None
    record_type, ts, body = m.groups()

    if record_type == "EXECVE" or "execve" in body or "syscall=59" in body:
        # Process-create: pid lives on the SYSCALL record (EXECVE records
        # carry a0= program args instead). comm falls back to a0="name".
        pid = _pid_from_syscall(body)
        if pid in pid_cache:
            return None  # execve may repeat; dedup per pid
        pid_cache[pid] = True
        ppid, comm = _ppid_and_comm(pid) if pid else (None, None)
        if not comm:
            a0 = re.search(r'a0="([^"]*)"', body)
            comm = a0.group(1) if a0 else None
        return {
            "platform": "linux",
            "log_source": "auditd",  # the collector's own channel — explicit
            "event_type": "process_create",
            "timestamp": _ts(ts),
            "pid": pid,
            "ppid": ppid,
            "process_name": comm,
            "command_line": _cmdline(pid) if pid else None,
        }

    if "connect" in body or "saddr=" in body:
        pid = _pid_from_syscall(body)
        _, comm = _ppid_and_comm(pid) if pid else (None, None)
        ip, port = _parse_saddr(body)
        return {
            "platform": "linux",
            "log_source": "auditd",  # the collector's own channel — explicit
            "event_type": "network_connection",
            "timestamp": _ts(ts),
            "pid": pid,
            "ppid": None,
            "process_name": comm,
            "dest_ip": ip,
            "dest_port": port,
            "protocol": "TCP",
        }

    return None


def _parse_saddr(body: str) -> tuple[str | None, int | None]:
    """Extract dest IP:port from connect's `saddr` hex (AF_INET = 2).

    auditd serializes sockaddr_in as: family (2B) + port (2B) + addr (4B)
    = 16 hex chars, e.g. 02000050C0A80101 → port 80, IP 192.168.1.1.
    """
    m = re.search(r"saddr=([0-9A-Fa-f]+)", body)
    if not m:
        return None, None
    raw = m.group(1)
    if len(raw) < 16:
        return None, None
    try:
        port = int(raw[4:8], 16)
        # Network byte order: first addr byte is the first octet.
        ip = ".".join(str(int(raw[i : i + 2], 16)) for i in range(8, 16, 2))
        return ip, port
    except ValueError:
        return None, None


def _ts(audit_ts: str) -> str:
    """auditd epoch timestamp (e.g. 1721234567.890) → UTC ISO-8601."""
    try:
        return datetime.datetime.fromtimestamp(float(audit_ts), datetime.timezone.utc).isoformat()
    except ValueError:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main(run_id: str | None, backend_url: str, mode: str = "analysis", timeout: int = 240) -> None:
    log_path = os.environ.get("AUDIT_LOG", AUDIT_LOG)
    if not os.path.exists(log_path):
        print(f"ERROR: {log_path} not found — is auditd installed and running?", file=sys.stderr)
        sys.exit(2)

    # Standalone session resolution when no run_id was given: claim the
    # webapp's open live session, else reuse/create today's agent run — so
    # the systemd service streams with no browser session open.
    if not run_id:
        run_id = resolve_live_run_id(backend_url, platform="linux")
        print(f"[collector-linux] live session {run_id}")

    shipper = Shipper(backend_url, run_id)
    pid_cache: dict = {}
    start = time.time()
    snapshot_interval = float(os.getenv("SNAPSHOT_INTERVAL", "30"))
    last_snapshot = 0.0
    heartbeat_interval = float(os.getenv("HEARTBEAT_INTERVAL", "60"))

    print(f"[collector-linux] run_id={run_id} mode={mode} backend={backend_url}")
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            # Start at EOF: only new records.
            fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if line:
                    ev = parse_audit_line(line, pid_cache)
                    if ev:
                        shipper.add(ev)
                else:
                    shipper.flush()
                    # Live system snapshot on an interval — the "running now"
                    # view for the Agents page / Live Monitor (best-effort).
                    if time.time() - last_snapshot > snapshot_interval:
                        shipper.ship_snapshot(platform="linux")
                        last_snapshot = time.time()
                    # Liveness ping — the fleet view's last-seen/silent signal.
                    shipper.maybe_heartbeat(platform="linux", interval=heartbeat_interval)
                    time.sleep(0.5)
                if mode == "analysis" and time.time() - start > timeout:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        shipper.flush()
        print("[collector-linux] stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OutPost Linux collector (auditd)")
    parser.add_argument(
        "--run-id",
        default=None,
        help="Target run id. Omit to claim the newest open live session from the "
        "webapp's Live Monitor (empty/omitted both claim).",
    )
    parser.add_argument("--backend-url", default=os.environ.get("OUTPOST_API_URL", "http://localhost:8001"))
    parser.add_argument("--mode", choices=["live", "analysis"], default="analysis")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    main(args.run_id, args.backend_url, args.mode, args.timeout)
