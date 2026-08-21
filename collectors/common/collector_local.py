"""OutPost Local Collector — Universal Cross-Platform Live Agent.

Runs unprivileged on Linux, macOS, and Windows. Polls process lifecycle and
active network sockets, normalizes telemetry to OutPost's unified event schema,
and streams events directly to the OutPost backend.
"""

import argparse
import datetime
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any

# Ensure shipper is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from shipper import Shipper, resolve_live_run_id

try:
    import psutil
except ImportError:
    psutil = None


def get_process_snapshot() -> list[dict[str, Any]]:
    """Capture current process table snapshot."""
    procs = []
    if psutil:
        for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe", "username"]):
            try:
                info = p.info
                cmdline = " ".join(info.get("cmdline") or [info.get("name") or ""])
                procs.append({
                    "pid": info["pid"],
                    "ppid": info.get("ppid") or 1,
                    "name": info.get("name") or "unknown",
                    "cmdline": cmdline,
                    "exe": info.get("exe") or "",
                    "username": info.get("username") or os.environ.get("USER", "system"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    elif platform.system().lower() == "linux" and os.path.exists("/proc"):
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pid = int(entry)
                try:
                    cmd_path = f"/proc/{pid}/cmdline"
                    if os.path.exists(cmd_path):
                        with open(cmd_path, "rb") as f:
                            raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                        procs.append({
                            "pid": pid,
                            "ppid": 1,
                            "name": raw.split()[0] if raw else f"proc_{pid}",
                            "cmdline": raw,
                            "exe": "",
                            "username": os.environ.get("USER", "system"),
                        })
                except Exception:
                    continue
    return procs


def get_active_connections() -> list[dict[str, Any]]:
    """Capture established outbound connections."""
    conns = []
    if psutil:
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr:
                    conns.append({
                        "pid": c.pid or os.getpid(),
                        "local_ip": c.laddr.ip,
                        "local_port": c.laddr.port,
                        "dest_ip": c.raddr.ip,
                        "dest_port": c.raddr.port,
                        "protocol": "tcp",
                        "direction": "outbound",
                    })
        except (psutil.AccessDenied, Exception):
            pass
    return conns


def main():
    parser = argparse.ArgumentParser(description="OutPost Universal Live Collector Agent")
    parser.add_argument("--backend", default=os.environ.get("OUTPOST_API_URL", "http://localhost:8001"), help="Backend URL")
    parser.add_argument("--host-id", default=socket.gethostname() or "local-agent", help="Host identifier")
    parser.add_argument("--run-id", default=None, help="Explicit run ID to ship events to")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0 = run indefinitely)")
    args = parser.parse_args()

    shipper = Shipper(backend_url=args.backend, host_id=args.host_id)
    run_id = args.run_id or resolve_live_run_id(args.backend, args.host_id)

    print(f"[*] OutPost Live Agent started on {args.host_id} ({platform.system()})")
    print(f"[*] Backend: {args.backend} | Target Run: {run_id}")

    known_pids = {p["pid"] for p in get_process_snapshot()}
    known_conns: set[tuple[str, int, str, int]] = set()
    start_time = time.time()
    last_heartbeat = 0.0

    try:
        while True:
            now = time.time()
            if args.timeout > 0 and (now - start_time) >= args.timeout:
                print("[*] Timeout reached. Stopping collector.")
                break

            # Send heartbeat every 60 seconds
            if now - last_heartbeat >= 60.0:
                shipper.heartbeat(
                    platform_str=platform.system().lower(),
                    version="outpost-local-agent/1.0",
                )
                last_heartbeat = now

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            procs = get_process_snapshot()
            current_pid_map = {p["pid"]: p for p in procs}
            current_pids = set(current_pid_map.keys())

            batch: list[dict[str, Any]] = []

            # Check new processes
            new_pids = current_pids - known_pids
            for pid in new_pids:
                p = current_pid_map[pid]
                batch.append({
                    "event_type": "process_create",
                    "timestamp": now_iso,
                    "pid": pid,
                    "ppid": p["ppid"],
                    "process_name": p["name"],
                    "command_line": p["cmdline"],
                    "exe_path": p["exe"],
                    "username": p["username"],
                    "run_id": run_id,
                    "host_id": args.host_id,
                    "source": "live_host",
                })
            known_pids = current_pids

            # Check connections
            conns = get_active_connections()
            for c in conns:
                k = (c["local_ip"], c["local_port"], c["dest_ip"], c["dest_port"])
                if k not in known_conns:
                    known_conns.add(k)
                    if not c["dest_ip"].startswith(("127.", "0.", "::1")):
                        batch.append({
                            "event_type": "network_connection",
                            "timestamp": now_iso,
                            "pid": c["pid"],
                            "dest_ip": c["dest_ip"],
                            "dest_port": c["dest_port"],
                            "protocol": c["protocol"],
                            "direction": c["direction"],
                            "run_id": run_id,
                            "host_id": args.host_id,
                            "source": "live_host",
                        })

            if batch:
                shipper.ship_batch(run_id, batch)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] OutPost Live Agent stopped by user.")
    finally:
        shipper.flush()


if __name__ == "__main__":
    main()
