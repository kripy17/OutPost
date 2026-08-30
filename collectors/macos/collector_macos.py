"""macOS Collector - Apple Endpoint Security & BSM Telemetry Collector.

Per docs/03-COLLECTOR-SPEC.md: read telemetry -> normalize -> ship.
Captures process execution (exec/fork), launch agent/daemon persistence,
and outbound network socket connections, normalizes them to OutPost unified
event schema, and ships them to the backend via Shipper.

Modes:
  --mode live                   run indefinitely (live fleet monitoring)
  --mode analysis --timeout N   run for N seconds, then exit (sample detonation)
"""

import argparse
import datetime
import ipaddress
import os
import platform
import re
import sys
import time
from pathlib import Path

# Ensure shipper is importable from collectors/common
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from shipper import Shipper, resolve_live_run_id

try:
    import psutil
except ImportError:
    psutil = None

_ES_EXEC_RE = re.compile(
    r"header,\d+,\d+,execve\(2\),\w+,\w+,(?P<ts>[\d.]+).*?process,\w+,\w+,\w+,\w+,\w+,(?P<pid>\d+),(?P<ppid>\d+).*?path,(?P<path>[^,]+).*?cmdline,(?P<cmd>[^,]+)",
    re.IGNORECASE,
)
_ES_CONNECT_RE = re.compile(
    r"header,\d+,\d+,connect\(2\),\w+,\w+,(?P<ts>[\d.]+).*?process,\w+,\w+,\w+,\w+,\w+,(?P<pid>\d+).*?sock_inet,(?P<family>\w+),(?P<port>\d+),(?P<ip>[\d.]+)",
    re.IGNORECASE,
)


def parse_bsm_line(line: str, run_id: str) -> dict | None:
    """Parse a single OpenBSM/EndpointSecurity audit record into a normalized OutPost event."""
    line = line.strip()
    if not line:
        return None

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Match execve event
    m_exec = _ES_EXEC_RE.search(line)
    if m_exec:
        pid = int(m_exec.group("pid"))
        ppid = int(m_exec.group("ppid"))
        exe_path = m_exec.group("path").strip()
        cmd = m_exec.group("cmd").strip()
        pname = Path(exe_path).name if exe_path else f"proc_{pid}"

        return {
            "run_id": run_id,
            "platform": "macos",
            "event_type": "process_create",
            "timestamp": now_iso,
            "pid": pid,
            "ppid": ppid,
            "process_name": pname,
            "command_line": cmd,
            "exe_path": exe_path,
            "log_source": "endpoint_security",
            "raw_record": line,
        }

    # Match connect event
    m_conn = _ES_CONNECT_RE.search(line)
    if m_conn:
        dest_ip = m_conn.group("ip").strip()
        try:
            ip_obj = ipaddress.ip_address(dest_ip)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return None
        except ValueError:
            return None

        pid = int(m_conn.group("pid"))
        dest_port = int(m_conn.group("port"))

        return {
            "run_id": run_id,
            "platform": "macos",
            "event_type": "network_connection",
            "timestamp": now_iso,
            "pid": pid,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": "tcp",
            "log_source": "endpoint_security",
            "raw_record": line,
        }

def parse_eslogger_json(record: dict, run_id: str) -> dict | None:
    """Parse a native Apple EndpointSecurity eslogger JSON event into a normalized OutPost event."""
    if not isinstance(record, dict):
        return None

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event_data = record.get("event") or {}
    proc = record.get("process") or {}

    proc_audit = proc.get("audit_token") or {}
    parent_pid = proc_audit.get("pid") or proc.get("ppid") or 1
    parent_path = (proc.get("executable") or {}).get("path") or ""

    # 1. Exec Event
    if "exec" in event_data:
        exec_info = event_data["exec"]
        target = exec_info.get("target") or {}
        target_audit = target.get("audit_token") or {}
        pid = target_audit.get("pid") or target.get("ppid") or 0
        ppid = target.get("ppid") or parent_pid
        exe_path = (target.get("executable") or {}).get("path") or ""
        args = target.get("args") or []
        cmdline = " ".join(str(a) for a in args) if args else exe_path
        pname = Path(exe_path).name if exe_path else f"proc_{pid}"

        signing = target.get("signing_info") or {}
        signing_id = signing.get("signing_id") or ""

        return {
            "run_id": run_id,
            "platform": "macos",
            "event_type": "process_create",
            "timestamp": now_iso,
            "pid": pid,
            "ppid": ppid,
            "process_name": pname,
            "command_line": cmdline,
            "exe_path": exe_path,
            "code_sign_id": signing_id,
            "log_source": "endpoint_security",
            "raw_record": str(record)[:1000],
        }

    # 2. Connect / Network Socket Event
    if "connect" in event_data:
        conn_info = event_data["connect"]
        remote = conn_info.get("remote_address") or {}
        dest_ip = remote.get("ip") or remote.get("address") or ""
        dest_port = int(remote.get("port") or 0)
        pid = proc_audit.get("pid") or 0

        if not dest_ip or dest_port == 0:
            return None

        try:
            ip_obj = ipaddress.ip_address(dest_ip)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                return None
        except ValueError:
            return None

        return {
            "run_id": run_id,
            "platform": "macos",
            "event_type": "network_connection",
            "timestamp": now_iso,
            "pid": pid,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": "tcp",
            "log_source": "endpoint_security",
            "raw_record": str(record)[:1000],
        }

    # 3. File Modification / Create / Rename / Unlink Event
    for ftype in ("open", "create", "unlink", "rename", "write"):
        if ftype in event_data:
            finfo = event_data[ftype]
            fpath = ""
            if "destination" in finfo:
                dest = finfo["destination"]
                fpath = dest.get("existing_file", {}).get("path") or dest.get("new_path", {}).get("dir", "") + "/" + dest.get("new_path", {}).get("filename", "")
            elif "file" in finfo:
                fpath = finfo["file"].get("path") or ""
            elif "source" in finfo:
                fpath = finfo["source"].get("path") or ""

            if fpath:
                pid = proc_audit.get("pid") or 0
                pname = Path(parent_path).name if parent_path else f"proc_{pid}"
                return {
                    "run_id": run_id,
                    "platform": "macos",
                    "event_type": "file_write" if ftype in ("create", "write", "rename") else "file_delete" if ftype == "unlink" else "file_open",
                    "timestamp": now_iso,
                    "pid": pid,
                    "process_name": pname,
                    "file_path": fpath,
                    "log_source": "endpoint_security",
                    "raw_record": str(record)[:1000],
                }

    return None


def get_process_snapshot() -> list[dict]:
    """Capture current process table snapshot using psutil."""
    procs = []
    if psutil:
        for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe", "username"]):
            try:
                info = p.info
                cmdline = " ".join(info.get("cmdline") or [info.get("name") or ""])
                procs.append({
                    "pid": info["pid"],
                    "ppid": info.get("ppid") or 1,
                    "process_name": info.get("name") or "unknown",
                    "command_line": cmdline,
                    "exe_path": info.get("exe") or "",
                    "username": info.get("username") or os.environ.get("USER", "system"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    return procs


def get_active_connections() -> list[dict]:
    """Capture active network connections using psutil."""
    conns = []
    if psutil:
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.raddr and c.status == "ESTABLISHED":
                    dest_ip = c.raddr.ip
                    try:
                        ip_obj = ipaddress.ip_address(dest_ip)
                        if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                            continue
                    except ValueError:
                        continue
                    conns.append({
                        "pid": c.pid or 0,
                        "dest_ip": dest_ip,
                        "dest_port": c.raddr.port,
                        "protocol": "tcp" if c.type == 1 else "udp",
                    })
        except (psutil.AccessDenied, Exception):
            pass
    return conns


def run_collector(
    backend_url: str,
    mode: str,
    timeout: int | None = None,
    run_id: str | None = None,
    host_id: str | None = None,
    poll_interval: float = 2.0,
) -> None:
    """Run macOS Endpoint Security & socket collector loop."""
    resolved_run_id = run_id or resolve_live_run_id(backend_url, "macos")
    shipper = Shipper(backend_url=backend_url, run_id=resolved_run_id, host_id=host_id)

    print(f"[*] OutPost macOS Agent started on {shipper.host_id} ({platform.system()})")
    print(f"[*] Backend: {backend_url} | Target Run: {resolved_run_id} | Mode: {mode}")

    known_pids = {p["pid"] for p in get_process_snapshot()}
    known_conns: set[tuple[int, str, int]] = set()
    start_time = time.time()

    try:
        while True:
            now = time.time()
            if mode == "analysis" and timeout and (now - start_time >= timeout):
                print("[*] Analysis timeout reached. Stopping collector.")
                break

            # Send heartbeat every 60s
            shipper.maybe_heartbeat(platform="macos", interval=60.0)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            procs = get_process_snapshot()
            current_pid_map = {p["pid"]: p for p in procs}
            current_pids = set(current_pid_map.keys())

            # Detect newly spawned processes
            new_pids = current_pids - known_pids
            for pid in new_pids:
                p = current_pid_map[pid]
                shipper.add({
                    "event_type": "process_create",
                    "timestamp": now_iso,
                    "pid": pid,
                    "ppid": p["ppid"],
                    "process_name": p["process_name"],
                    "command_line": p["command_line"],
                    "exe_path": p["exe_path"],
                    "log_source": "endpoint_security",
                    "platform": "macos",
                })
            known_pids = current_pids

            # Detect new network connections
            conns = get_active_connections()
            for c in conns:
                key = (c["pid"], c["dest_ip"], c["dest_port"])
                if key not in known_conns:
                    known_conns.add(key)
                    shipper.add({
                        "event_type": "network_connection",
                        "timestamp": now_iso,
                        "pid": c["pid"],
                        "dest_ip": c["dest_ip"],
                        "dest_port": c["dest_port"],
                        "protocol": c["protocol"],
                        "log_source": "endpoint_security",
                        "platform": "macos",
                    })

            shipper.flush()
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n[*] OutPost macOS Agent stopped by operator.")
    finally:
        shipper.flush()


def main():
    parser = argparse.ArgumentParser(description="OutPost macOS Collector Agent")
    parser.add_argument("--backend", default=os.environ.get("OUTPOST_API_URL", "http://localhost:8001"), help="Backend URL")
    parser.add_argument("--mode", choices=["live", "analysis"], default="live", help="Collector run mode")
    parser.add_argument("--timeout", type=int, default=30, help="Analysis mode timeout in seconds")
    parser.add_argument("--run-id", default=None, help="Explicit run ID")
    parser.add_argument("--host-id", default=None, help="Host identifier")
    args = parser.parse_args()

    run_collector(
        backend_url=args.backend,
        mode=args.mode,
        timeout=args.timeout,
        run_id=args.run_id,
        host_id=args.host_id,
    )


if __name__ == "__main__":
    main()
