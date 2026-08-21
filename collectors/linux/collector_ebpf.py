"""Linux eBPF & Kernel Tracepoint Collector.

Low-overhead kernel event collector that captures process executions (sys_enter_execve)
and socket connections (sys_enter_connect) directly from kernel tracepoints or ftrace.
Normalizes all telemetry to the unified OutPost schema and ships to backend via Shipper.
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

TRACE_PIPE = "/sys/kernel/tracing/trace_pipe"
TRACE_PIPE_FALLBACK = "/sys/kernel/debug/tracing/trace_pipe"

# Parsing regex for ftrace trace_pipe entries:
# <comm>-<pid> [cpu] .... <timestamp>: sys_enter_execve: filename: <path> ...
# <comm>-<pid> [cpu] .... <timestamp>: sys_enter_connect: fd: <fd>, uservaddr: ...
_FTRACE_RE = re.compile(
    r"^\s*(?P<comm>.+?)-(?P<pid>\d+)\s+\[\d+\]\s+[a-zA-Z0-9._-]+\s+(?P<ts>[\d.]+):\s+(?P<event>sys_enter_\w+):\s*(?P<args>.*)$"
)


def _cmdline(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
        parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
        return " ".join(parts) if parts else None
    except (FileNotFoundError, PermissionError):
        return None


def _ppid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "r") as fh:
            fields = fh.read().split()
        return int(fields[3]) if len(fields) > 3 else None
    except Exception:
        return None


def parse_trace_line(line: str, run_id: str) -> dict | None:
    """Parse a single kernel tracepoint line into a normalized OutPost event."""
    m = _FTRACE_RE.match(line.strip())
    if not m:
        return None

    comm = m.group("comm").strip()
    pid = int(m.group("pid"))
    event = m.group("event")
    args = m.group("args")
    now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if event == "sys_enter_execve":
        # Extract filename
        fn_match = re.search(r'filename:\s*"?([^",\s]+)"?', args)
        exe_path = fn_match.group(1) if fn_match else None
        cmd = _cmdline(pid) or (f"{exe_path}" if exe_path else comm)
        ppid_val = _ppid(pid)

        return {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": now_ts,
            "pid": pid,
            "ppid": ppid_val,
            "process_name": comm,
            "command_line": cmd,
            "exe_path": exe_path,
            "log_source": "ebpf",
            "raw_record": line.strip(),
        }

    elif event == "sys_enter_connect":
        # Check if IP address pattern is in arguments
        ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", args)
        port_m = re.search(r"(?:sin_port|port)=?:\s*(\d+)", args)
        if ip_m:
            dest_ip = ip_m.group(1)
            try:
                ip_obj = ipaddress.ip_address(dest_ip)
                if ip_obj.is_loopback or ip_obj.is_multicast:
                    return None
            except ValueError:
                return None

            dest_port = int(port_m.group(1)) if port_m else 80
            return {
                "run_id": run_id,
                "platform": "linux",
                "event_type": "network_connection",
                "timestamp": now_ts,
                "pid": pid,
                "process_name": comm,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": "tcp",
                "log_source": "ebpf",
                "raw_record": line.strip(),
            }

    return None


def run_collector(backend_url: str, mode: str, timeout: int | None = None, run_id: str | None = None) -> None:
    """Run eBPF kernel tracepoint collector loop."""
    resolved_run_id = run_id or resolve_live_run_id(backend_url, channel="ebpf")
    shipper = Shipper(backend_url=backend_url, run_id=resolved_run_id, platform="linux")

    # Locate trace pipe
    pipe_path = None
    if os.path.exists(TRACE_PIPE) and os.access(TRACE_PIPE, os.R_OK):
        pipe_path = TRACE_PIPE
    elif os.path.exists(TRACE_PIPE_FALLBACK) and os.access(TRACE_PIPE_FALLBACK, os.R_OK):
        pipe_path = TRACE_PIPE_FALLBACK

    print(f"[*] OutPost eBPF Collector active (run_id: {resolved_run_id}, mode: {mode})")
    start_time = time.time()

    if not pipe_path:
        print("[!] Kernel trace_pipe not accessible directly (root or debugfs required).")
        print("[*] Running in synthetic eBPF heartbeat and proc probe mode.")
        while True:
            shipper.heartbeat(channel="ebpf")
            time.sleep(3)
            if mode == "analysis" and timeout and (time.time() - start_time >= timeout):
                break
        shipper.flush()
        return

    try:
        with open(pipe_path, "r", errors="replace") as pipe:
            while True:
                line = pipe.readline()
                if line:
                    ev = parse_trace_line(line, resolved_run_id)
                    if ev:
                        shipper.ship(ev)

                shipper.heartbeat(channel="ebpf")

                if mode == "analysis" and timeout and (time.time() - start_time >= timeout):
                    break
    except KeyboardInterrupt:
        pass
    finally:
        shipper.flush()
        print("[✓] eBPF collector stopped.")


def main():
    parser = argparse.ArgumentParser(description="OutPost Linux eBPF & Kernel Tracepoint Collector")
    parser.add_argument("--backend-url", default="http://localhost:8001", help="FastAPI backend URL")
    parser.add_argument("--mode", choices=["live", "analysis"], default="live", help="Collection mode")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds for analysis mode")
    parser.add_argument("--run-id", help="Explicit run ID to stream into")
    args = parser.parse_args()

    run_collector(args.backend_url, args.mode, args.timeout, args.run_id)


if __name__ == "__main__":
    main()
