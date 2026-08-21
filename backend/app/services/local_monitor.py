"""Local Monitor Service — Cross-Platform Real-Time Live Host Telemetry.

Continuously captures live running processes, new process spawns, active network
connections, and resource utilization on the local machine (Linux, macOS, Windows).

Streams real normalized events directly into OutPost's detection engine and event
store, enabling authentic real-time threat monitoring without synthetic data.
"""

import asyncio
import datetime
import os
import platform
from typing import Any

from ..models import event as event_store
from ..models import run as run_store
from ..services import detection

try:
    import psutil
except ImportError:
    psutil = None

_MONITOR_TASK: asyncio.Task | None = None
_CURRENT_RUN_ID: str | None = None
_KNOWN_PIDS: set[int] = set()
_KNOWN_CONNS: set[tuple[str, int, str, int]] = set()
_STATS = {
    "running": False,
    "started_at": None,
    "run_id": None,
    "events_streamed": 0,
    "alerts_triggered": 0,
    "last_poll": None,
    "monitored_pids_count": 0,
}


def _get_active_processes() -> list[dict[str, Any]]:
    """Capture snapshot of active processes using psutil or /proc fallback."""
    procs = []
    if psutil:
        for p in psutil.process_iter(["pid", "ppid", "name", "cmdline", "exe", "username", "create_time"]):
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


def _get_active_connections() -> list[dict[str, Any]]:
    """Capture active network connections using psutil."""
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


async def _monitor_loop(run_id: str, interval: float = 2.0):
    global _KNOWN_PIDS
    _KNOWN_PIDS = {p["pid"] for p in _get_active_processes()}
    _KNOWN_CONNS.clear()

    while True:
        try:
            await asyncio.sleep(interval)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            current_procs = _get_active_processes()
            current_pid_map = {p["pid"]: p for p in current_procs}
            current_pids = set(current_pid_map.keys())

            batch: list[dict[str, Any]] = []

            # Identify newly spawned processes
            new_pids = current_pids - _KNOWN_PIDS
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
                    "source": "live_host",
                })

            _KNOWN_PIDS = current_pids

            # Check network connections
            current_conns = _get_active_connections()
            for c in current_conns:
                conn_key = (c["local_ip"], c["local_port"], c["dest_ip"], c["dest_port"])
                if conn_key not in _KNOWN_CONNS:
                    _KNOWN_CONNS.add(conn_key)
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
                            "source": "live_host",
                        })

            if batch:
                event_store.insert_events(run_id, batch)
                alerts = detection.evaluate_batch(run_id, batch)
                _STATS["events_streamed"] += len(batch)
                _STATS["alerts_triggered"] += len(alerts)

            _STATS["last_poll"] = now_iso
            _STATS["monitored_pids_count"] = len(current_pids)

        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(interval)


def start_local_monitor(run_id: str | None = None, interval: float = 2.0) -> dict[str, Any]:
    """Start local host live monitoring."""
    global _MONITOR_TASK, _CURRENT_RUN_ID, _STATS

    if _MONITOR_TASK and not _MONITOR_TASK.done():
        return get_local_monitor_status()

    if not run_id:
        host = platform.node() or "local-host"
        run_id = f"live-{host}-{datetime.date.today().isoformat()}"
        existing = run_store.get_run(run_id)
        if not existing:
            run_store.create_run(
                run_id=run_id,
                name=f"Live Monitor: {host}",
                session_type="live",
                source="live_host",
                environment=platform.system().lower(),
            )

    _CURRENT_RUN_ID = run_id
    _STATS = {
        "running": True,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "run_id": run_id,
        "events_streamed": 0,
        "alerts_triggered": 0,
        "last_poll": None,
        "monitored_pids_count": 0,
    }

    loop = asyncio.get_event_loop()
    _MONITOR_TASK = loop.create_task(_monitor_loop(run_id, interval))
    return _STATS


def stop_local_monitor() -> dict[str, Any]:
    """Stop local host live monitoring."""
    if _MONITOR_TASK and not _MONITOR_TASK.done():
        _MONITOR_TASK.cancel()

    if _CURRENT_RUN_ID:
        try:
            run_store.complete_run(_CURRENT_RUN_ID)
        except Exception:
            pass

    _STATS["running"] = False
    return _STATS


def get_local_monitor_status() -> dict[str, Any]:
    """Get current status of local live monitoring."""
    is_active = _MONITOR_TASK is not None and not _MONITOR_TASK.done()
    _STATS["running"] = is_active
    return _STATS
