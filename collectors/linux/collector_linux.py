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
import ipaddress
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from shipper import Shipper, resolve_live_run_id

AUDIT_LOG = "/var/log/audit/audit.log"
# AUDIT_LOG env override — lets the collector tail a test/simulated feed
# (the post-deploy walk feeds a temp log so the real live-mode collector can
# be exercised without root). Default stays the real auditd path.

# Real auditd emits separate record types for the same event: type=SYSCALL
# (syscall + pid), type=EXECVE (program args), type=SOCKADDR (connect dest).
# Match all three so execve and connect are actually parsed; the body decides
# which handler applies.
_AUDIT_RE = re.compile(r"type=([A-Z]+) msg=audit\(([\d.]+):(\d+)\):\s*(.+)")

_BOOT_TIME: int | None = None
_CLK_TCK: int | None = None


def _get_boot_time() -> int | None:
    global _BOOT_TIME
    if _BOOT_TIME is None:
        try:
            with open("/proc/stat", "r") as f:
                for line in f:
                    if line.startswith("btime "):
                        _BOOT_TIME = int(line.split()[1])
                        break
        except Exception:
            pass
    return _BOOT_TIME


def _get_clk_tck() -> int:
    global _CLK_TCK
    if _CLK_TCK is None:
        try:
            _CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        except Exception:
            _CLK_TCK = 100
    return _CLK_TCK or 100


def _proc_start_time(pid: int) -> str | None:
    """Read authoritative process start time from /proc/{pid}/stat (field 22)."""
    try:
        with open(f"/proc/{pid}/stat", "r") as fh:
            content = fh.read()
        rparen = content.rfind(")")
        if rparen == -1:
            return None
        rest = content[rparen + 2:].split()
        if len(rest) < 20:
            return None
        starttime_ticks = int(rest[19])
        btime = _get_boot_time()
        if not btime:
            return None
        clk_tck = _get_clk_tck()
        start_epoch = btime + (starttime_ticks / clk_tck)
        return datetime.datetime.fromtimestamp(start_epoch, datetime.timezone.utc).isoformat()
    except (FileNotFoundError, IndexError, ValueError, OSError):
        return None


def _pid_from_syscall(body: str) -> int | None:
    # \b is required: real auditd emits `ppid=… pid=…` (ppid first), and a
    # bare `pid=(\d+)` matches INSIDE "ppid=" — silently reading the parent
    # PID as the event's PID (real-feed fidelity bug: connect/execve events
    # carried their PPID, corrupting the process map and recon-actor PIDs).
    m = re.search(r"\bpid=(\d+)", body)
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


def _body_comm_exe(body: str) -> tuple[str | None, str | None]:
    """The SYSCALL record's `comm="…"` / `exe="…"` fields.

    The kernel stamps these on the execve/connect syscall: `comm` is the
    (truncated) process name, `exe` is the fully-resolved executable path —
    symlinks already followed. They are the fallback when the process is
    gone from /proc by parse time (the real-auditd soak: ~61% of events had
    process_name None because short-lived processes exited before the
    collector read /proc). `exe` is also the authoritative masquerading
    signal: a kernel-resolved path cannot be spoofed by argv[0].
    """
    comm = re.search(r'comm="([^"]*)"', body)
    exe = re.search(r'exe="([^"]*)"', body)
    return (comm.group(1) if comm else None, exe.group(1) if exe else None)



def _ppid_from_syscall(body: str) -> int | None:
    m = re.search(r"\bppid=(\d+)", body)
    return int(m.group(1)) if m else None


def _decode_audit_arg(val: str) -> str:
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    try:
        return bytes.fromhex(val).decode("utf-8", errors="replace")
    except Exception:
        return val


def _parse_execve_args(body: str) -> str | None:
    # Match args="a,b,c" or a0="val" a1="val"
    m_args = re.search(r'args="([^"]*)"', body)
    if m_args:
        return " ".join(m_args.group(1).split(","))
    matches = re.findall(r'\ba\d+=("[^"]*"|\S+)', body)
    if matches:
        return " ".join(_decode_audit_arg(m) for m in matches)
    return None


def parse_audit_line(line: str, pid_cache: dict, conn_state: dict | None = None) -> dict | None:
    """Parse one audit.log line into a unified-schema event dict.

    Extracts parent PID, process arguments, exit status, and user directly from
    kernel audit records, surviving short-lived processes without racy /proc reads.
    `conn_state` correlates multi-record syscalls (SYSCALL + SOCKADDR, SYSCALL + EXECVE).
    """
    if "audit(" not in line:
        return None

    m = _AUDIT_RE.match(line)
    if not m:
        return None
    record_type, ts, seq, body = m.groups()
    source_event_id = f"auditd:{ts}:{seq}"

    if record_type == "EXECVE" or "execve" in body or "syscall=59" in body:
        pid = _pid_from_syscall(body)
        if pid is not None:
            if pid in pid_cache:
                return None  # execve may repeat; dedup per pid
            pid_cache[pid] = True

        # Kernel-stamped fields directly from the audit record
        ppid = _ppid_from_syscall(body)
        proc_comm = None
        if ppid is None and pid:
            ppid, proc_comm = _ppid_and_comm(pid)

        body_comm, exe_path = _body_comm_exe(body)
        comm = body_comm or proc_comm
        if not comm:
            a0 = re.search(r'a0="([^"]*)"', body)
            comm = a0.group(1) if a0 else None

        # Command line: prefer kernel-stamped EXECVE/args over racy /proc
        cmdline = _parse_execve_args(body)
        if not cmdline and pid:
            cmdline = _cmdline(pid)

        # Correlate EXECVE argument records with previous SYSCALL record if needed
        ts_float = float(ts)
        if conn_state is not None:
            if record_type == "SYSCALL" and not cmdline:
                # Hold pending EXECVE record
                conn_state["execve"] = (ts_float, seq, pid, ppid, comm, exe_path, source_event_id)
            elif record_type == "EXECVE":
                stashed = conn_state.get("execve")
                if stashed and abs(stashed[0] - ts_float) < 1.0:
                    _ts_f, _seq, s_pid, s_ppid, s_comm, s_exe, s_sid = stashed
                    pid = s_pid or pid
                    ppid = s_ppid or ppid
                    comm = s_comm or comm
                    exe_path = s_exe or exe_path
                    source_event_id = s_sid or source_event_id
                    conn_state["execve"] = None

        m_uid = re.search(r"\b(?:uid|euid|auid)=(\d+)", body)
        user = m_uid.group(1) if m_uid else None

        return {
            "platform": "linux",
            "log_source": "auditd",
            "event_type": "process_create",
            "timestamp": _ts(ts),
            "pid": pid,
            "ppid": ppid,
            "process_name": comm,
            "command_line": cmdline,
            "exe_path": exe_path,
            "user": user,
            "source_event_id": source_event_id,
            "process_start_time": (_proc_start_time(pid) if pid else None) or _ts(ts),
            "raw_record": line.strip(),
        }

    if "connect" in body or "saddr=" in body or "syscall=42" in body:
        pid = _pid_from_syscall(body)
        _, proc_comm = _ppid_and_comm(pid) if pid else (None, None)
        body_comm, exe_path = _body_comm_exe(body)
        # Same preference as the execve branch: kernel-stamped body comm= is
        # authoritative; /proc reads are racy (gone procs, reused pids).
        comm = body_comm or proc_comm
        ip, port = _parse_saddr(body)
        ts_float = float(ts)
        succ_m = re.search(r"\bsuccess=(yes|no)", body)
        exit_m = re.search(r"\bexit=(-?\d+)", body)
        conn_status = "established" if (succ_m and succ_m.group(1) == "yes") or (exit_m and exit_m.group(1) == "0") else "attempted"

        if conn_state is not None:
            if pid is not None and ip is None:
                # The SYSCALL half: identity without a destination. Hold it
                # for the SOCKADDR record that follows at the same timestamp.
                conn_state["identity"] = (ts_float, pid, comm, exe_path, source_event_id, conn_status)
                return None
            if pid is None:
                stashed = conn_state.get("identity")
                if stashed and abs(stashed[0] - ts_float) < 1.0:
                    _ts_s, _pid, _comm, _exe = stashed[:4]
                    if len(stashed) > 4:
                        source_event_id = stashed[4]
                    if len(stashed) > 5 and stashed[5]:
                        conn_status = stashed[5]
                    pid, comm, exe_path = _pid, _comm or comm, _exe or exe_path
                    conn_state["identity"] = None  # consumed
        if ip is None:
            # No routable destination (AF_UNIX / AF_NETLINK sockets, malformed
            # saddr) — a connect without a destination is useless to the
            # network rules and only bloats the Event Log. The real-feed
            # re-measurement showed ~44% of events were these.
            return None

        return {
            "platform": "linux",
            "log_source": "auditd",  # the collector's own channel — explicit
            "event_type": "network_connection",
            "timestamp": _ts(ts),
            "pid": pid,
            "ppid": None,
            "process_name": comm,
            "exe_path": exe_path,
            "dest_ip": ip,
            "dest_port": port,
            "protocol": "TCP",
            "connection_status": conn_status,
            "source_event_id": source_event_id,
            # See the process_create branch — same raw-record pivot.
            "raw_record": line.strip(),
        }

    # File creation, deletion, rename, and permission modifications
    is_file_syscall = any(
        k in body
        for k in (
            "vantage_file",
            "syscall=5",
            "syscall=85",
            "syscall=82",
            "syscall=257",
            "syscall=87",
            "syscall=263",
            "syscall=90",
            "syscall=268",
            "syscall=264",
            "syscall=316",
            "syscall=92",
            "syscall=260",
        )
    )

    if is_file_syscall and record_type == "SYSCALL":
        pid = _pid_from_syscall(body)
        ppid = _ppid_from_syscall(body)
        body_comm, exe_path = _body_comm_exe(body)
        name_m = re.search(r'name="([^"]*)"', body)

        if "rename" in body or any(k in body for k in ("vantage_file_rename", "syscall=82", "syscall=264", "syscall=316")):
            ev_type = "file_rename"
        elif any(k in body for k in ("vantage_file_perm", "syscall=90", "syscall=268", "syscall=92", "syscall=260", "chmod", "chown", "xattr")):
            ev_type = "file_permission"
        elif any(k in body for k in ("vantage_file_delete", "syscall=87", "syscall=263", "unlink")):
            ev_type = "file_delete"
        else:
            ev_type = "file_write"

        if name_m:
            return {
                "platform": "linux",
                "log_source": "auditd",
                "event_type": ev_type,
                "timestamp": _ts(ts),
                "pid": pid,
                "ppid": ppid,
                "process_name": body_comm,
                "exe_path": exe_path,
                "file_path": name_m.group(1),
                "source_event_id": source_event_id,
                "raw_record": line.strip(),
            }
        elif conn_state is not None:
            conn_state["file"] = (float(ts), seq, pid, ppid, body_comm, exe_path, source_event_id, ev_type)
            return None

    if record_type == "PATH":
        name_m = re.search(r'name="([^"]*)"', body)
        if name_m:
            path = name_m.group(1)
            if not path or path == "(null)":
                return None
            if conn_state is not None and "file" in conn_state:
                stashed = conn_state.get("file")
                if stashed and abs(stashed[0] - float(ts)) < 2.0:
                    _ts_f, _seq, s_pid, s_ppid, s_comm, s_exe, s_sid, s_type = stashed
                    nametype_m = re.search(r'\bnametype=(\w+)', body)
                    nametype = nametype_m.group(1) if nametype_m else ""
                    if s_type == "file_rename" and nametype == "DELETE" and "item=0" in body:
                        conn_state["file_old_path"] = path
                        return None
                    return {
                        "platform": "linux",
                        "log_source": "auditd",
                        "event_type": s_type,
                        "timestamp": _ts(ts),
                        "pid": s_pid,
                        "ppid": s_ppid,
                        "process_name": s_comm,
                        "exe_path": s_exe,
                        "file_path": path,
                        "source_event_id": s_sid or source_event_id,
                        "raw_record": line.strip(),
                    }

            is_del = "unlink" in body or "syscall=87" in body or "syscall=263" in body or "nametype=DELETE" in body
            pid = _pid_from_syscall(body)
            body_comm, exe_path = _body_comm_exe(body)
            return {
                "platform": "linux",
                "log_source": "auditd",
                "event_type": "file_delete" if is_del else "file_write",
                "timestamp": _ts(ts),
                "pid": pid,
                "ppid": _ppid_from_syscall(body),
                "process_name": body_comm,
                "exe_path": exe_path,
                "file_path": path,
                "source_event_id": source_event_id,
                "raw_record": line.strip(),
            }

    return None


def _parse_saddr(body: str) -> tuple[str | None, int | None]:
    """Extract dest IP:port from connect's `saddr` hex, family-aware.

    auditd serializes the sockaddr as: family (2B, host byte order) + port
    (2B, network order) + address bytes — 16 hex for AF_INET, 40 hex for
    AF_INET6, e.g.:
      02000050C0A80101 → AF_INET, port 80, 192.168.1.1
      0A001F90<32 hex> → AF_INET6, port 8080, expanded v6 address

    Family-aware parsing matters: before this, AF_INET6 records were parsed
    as v4 — the first 16 hex chars became a FAKE v4 IP (real-auditd soak:
    ~240 garbage "117.110.47.x:12146" connections from v6 dests, two of
    which fired beaconing). Unknown families are skipped, not misparsed.
    """
    m = re.search(r"saddr=([0-9A-Fa-f]+)", body)
    if not m:
        return None, None
    raw = m.group(1)
    family = raw[:4].lower()
    if family in ("0200", "0002"):  # AF_INET
        if len(raw) < 16:
            return None, None
        try:
            port = int(raw[4:8], 16)
            # Network byte order: first addr byte is the first octet.
            ip = ".".join(str(int(raw[i : i + 2], 16)) for i in range(8, 16, 2))
            return ip, port
        except ValueError:
            return None, None
    if family in ("0a00", "000a"):  # AF_INET6
        # sockaddr_in6 is family(2B) + port(2B) + flowinfo(4B) + addr(16B) =
        # 48 hex chars total. auditd emits flowinfo (usually zero), so the
        # address starts at hex offset 16 — the elevated fidelity run stored
        # "0000:0000:2001:4860:…" (16 hex of zero flowinfo + a cut-off Google
        # DNS v6) when the slice ignored it. Older records without flowinfo
        # (40 hex, address at offset 8) are tolerated defensively.
        try:
            port = int(raw[4:8], 16)
            if len(raw) >= 48:
                start, end = 16, 48
            elif len(raw) >= 40:
                start, end = 8, 40
            else:
                return None, None
            # 16 addr bytes → 8 groups of 4 hex, colon-joined, then compressed
            # to the canonical form (2001:db8:85a3::8a2e:370:7334) — the same
            # representation the detection exclusions (DoH resolvers, baseline
            # seen-sets) key on, so v6 and v4 are treated uniformly.
            ip = ipaddress.ip_address(":".join(raw[i : i + 4] for i in range(start, end, 4))).compressed
            return ip, port
        except ValueError:
            return None, None
    return None, None  # AF_UNIX (family 01), AF_NETLINK (10), etc. — not TCP dests


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
    conn_state: dict = {}  # SYSCALL-connect identity held for its SOCKADDR half
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
                    ev = parse_audit_line(line, pid_cache, conn_state)
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
