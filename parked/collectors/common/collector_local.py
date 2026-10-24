"""OutPost Local Collector — Universal Cross-Platform Live Agent.

Runs unprivileged on Linux, macOS, and Windows. Polls process lifecycle and
active network sockets, normalizes telemetry to OutPost's unified event schema,
and streams events directly to the OutPost backend.
"""

import argparse
import datetime
import hashlib
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


DEFAULT_LINUX_FIM = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
]

DEFAULT_WINDOWS_FIM = [
    r"C:\Windows\System32\drivers\etc\hosts",
]


class FileIntegrityMonitor:
    """Real-time File Integrity Monitor (FIM) for critical system and security files."""

    def __init__(self, watch_paths: list[str] | None = None):
        if watch_paths:
            self.watch_paths = [Path(p) for p in watch_paths]
        else:
            plat = platform.system().lower()
            if plat == "windows":
                candidates = DEFAULT_WINDOWS_FIM
            else:
                candidates = DEFAULT_LINUX_FIM
            self.watch_paths = [Path(p) for p in candidates]
            # Also watch user's authorized_keys if present
            auth_keys = Path.home() / ".ssh" / "authorized_keys"
            if auth_keys.exists() and auth_keys not in self.watch_paths:
                self.watch_paths.append(auth_keys)

        self.state: dict[Path, dict[str, Any]] = {}
        self._initialize_baseline()

    def _hash_file(self, path: Path) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _initialize_baseline(self) -> None:
        for p in self.watch_paths:
            if p.is_file():
                try:
                    stat = p.stat()
                    sha = self._hash_file(p)
                    self.state[p] = {
                        "exists": True,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "sha256": sha,
                    }
                except Exception:
                    self.state[p] = {"exists": False, "mtime": 0, "size": 0, "sha256": ""}
            else:
                self.state[p] = {"exists": False, "mtime": 0, "size": 0, "sha256": ""}

    def poll_changes(self) -> list[dict[str, Any]]:
        """Poll monitored paths and return file_modify, file_create, and file_delete events."""
        events = []
        for p in self.watch_paths:
            prev = self.state.get(p, {"exists": False, "mtime": 0, "size": 0, "sha256": ""})
            exists_now = p.is_file()

            if not prev["exists"] and exists_now:
                try:
                    stat = p.stat()
                    sha = self._hash_file(p)
                    self.state[p] = {
                        "exists": True,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "sha256": sha,
                    }
                    events.append({
                        "event_type": "file_create",
                        "file_path": str(p),
                        "file_name": p.name,
                        "file_size": stat.st_size,
                        "hash_sha256": sha,
                        "details": f"Critical security file created: {p}",
                    })
                except Exception:
                    pass

            elif prev["exists"] and not exists_now:
                self.state[p] = {"exists": False, "mtime": 0, "size": 0, "sha256": ""}
                events.append({
                    "event_type": "file_delete",
                    "file_path": str(p),
                    "file_name": p.name,
                    "file_size": 0,
                    "hash_sha256": prev.get("sha256", ""),
                    "details": f"Critical security file deleted: {p}",
                })

            elif prev["exists"] and exists_now:
                try:
                    stat = p.stat()
                    if stat.st_mtime != prev["mtime"] or stat.st_size != prev["size"]:
                        sha = self._hash_file(p)
                        if sha != prev["sha256"]:
                            self.state[p] = {
                                "exists": True,
                                "mtime": stat.st_mtime,
                                "size": stat.st_size,
                                "sha256": sha,
                            }
                            events.append({
                                "event_type": "file_modify",
                                "file_path": str(p),
                                "file_name": p.name,
                                "file_size": stat.st_size,
                                "hash_sha256": sha,
                                "prev_sha256": prev.get("sha256", ""),
                                "details": f"Critical security file modified: {p}",
                            })
                except Exception:
                    pass

        return events


def main():
    parser = argparse.ArgumentParser(description="OutPost Universal Live Collector Agent")
    parser.add_argument("--backend", default=os.environ.get("OUTPOST_API_URL", "http://localhost:8001"), help="Backend URL")
    parser.add_argument("--host-id", default=socket.gethostname() or "local-agent", help="Host identifier")
    parser.add_argument("--run-id", default=None, help="Explicit run ID to ship events to")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0 = run indefinitely)")
    parser.add_argument("--fim-paths", default=None, help="Comma-separated file paths to monitor for integrity changes")
    args = parser.parse_args()

    run_id = args.run_id or resolve_live_run_id(args.backend, platform.system().lower())
    shipper = Shipper(backend_url=args.backend, run_id=run_id, host_id=args.host_id)

    fim_watch = [p.strip() for p in args.fim_paths.split(",")] if args.fim_paths else None
    fim = FileIntegrityMonitor(watch_paths=fim_watch)

    print(f"[*] OutPost Live Agent started on {args.host_id} ({platform.system()})")
    print(f"[*] Backend: {args.backend} | Target Run: {run_id}")
    print(f"[*] File Integrity Monitoring (FIM): {len(fim.watch_paths)} critical paths registered")

    known_pids = {p["pid"] for p in get_process_snapshot()}
    known_conns: set[tuple[str, int, str, int]] = set()
    start_time = time.time()

    try:
        while True:
            now = time.time()
            if args.timeout > 0 and (now - start_time) >= args.timeout:
                print("[*] Timeout reached. Stopping collector.")
                break

            # Send heartbeat if interval elapsed
            shipper.maybe_heartbeat(platform=platform.system().lower(), interval=60.0)

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            procs = get_process_snapshot()
            current_pid_map = {p["pid"]: p for p in procs}
            current_pids = set(current_pid_map.keys())

            # Check new processes
            new_pids = current_pids - known_pids
            for pid in new_pids:
                p = current_pid_map[pid]
                shipper.add({
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
                        shipper.add({
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

            # Check File Integrity Monitoring (FIM)
            fim_events = fim.poll_changes()
            for fe in fim_events:
                shipper.add({
                    **fe,
                    "timestamp": now_iso,
                    "run_id": run_id,
                    "host_id": args.host_id,
                    "source": "live_host_fim",
                })

            shipper.flush()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] OutPost Live Agent stopped by user.")
    finally:
        shipper.flush()


if __name__ == "__main__":
    main()
