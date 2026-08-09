"""Windows collector — tails the Sysmon Event Log channel.

Per docs/03-COLLECTOR-SPEC.md: read telemetry → normalize → ship. No business
logic lives here. Requires Sysmon with `sysmon_config.xml` installed.

Modes:
  --mode live       run indefinitely (used by `outpost watch`)
  --mode analysis --timeout N   run for N seconds, then exit (`outpost run`)

Maps Sysmon Event IDs to the unified schema:
  1  → process_create
  3  → network_connection
  11 → file_write
  12/13/14 → registry_write
"""

import argparse
import datetime
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from shipper import Shipper, resolve_live_run_id  # noqa: E402

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sysmon Event ID → unified event_type
EVENT_TYPE_MAP = {
    1: "process_create",
    3: "network_connection",
    11: "file_write",
    12: "registry_write",
    13: "registry_write",
    14: "registry_write",
}


def parse_sysmon_event(record) -> dict | None:
    """Convert one win32evtlog record into a unified-schema event dict."""
    try:
        event_id = record.EventID
    except AttributeError:
        return None
    if event_id not in EVENT_TYPE_MAP:
        return None

    # Record.Data is a list of (name, value) tuples for EventData fields.
    data = {}
    try:
        raw = record.Data
        if isinstance(raw, (list, tuple)):
            for i in range(0, len(raw) - 1, 2):
                data[str(raw[i])] = str(raw[i + 1])
    except Exception:
        return None

    ts = datetime.datetime.fromtimestamp(record.TimeGenerated.timestamp(), datetime.timezone.utc).isoformat()
    ev = {
        "platform": "windows",
        "event_type": EVENT_TYPE_MAP[event_id],
        "timestamp": ts,
        "pid": _int(data.get("ProcessId")),
        "ppid": _int(data.get("ParentProcessId")),
        "process_name": _basename(data.get("Image")),
        "command_line": data.get("CommandLine"),
        "dest_ip": data.get("DestinationIp") or data.get("SourceIp"),
        "dest_port": _int(data.get("DestinationPort")),
        "protocol": data.get("Protocol"),
        "file_path": data.get("TargetFilename"),
        "registry_key": data.get("TargetObject"),
    }
    return ev


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path.replace("\\", "/")).name


def main(run_id: str | None, backend_url: str, mode: str = "analysis", timeout: int = 240) -> None:
    try:
        import win32evtlog
    except ImportError:
        print("ERROR: pywin32 required — install with: pip install pywin32", file=sys.stderr)
        sys.exit(2)

    # Resolve the live session when no run_id was given: webapp Live Monitor
    # > today's open agent run > create a fresh source=agent session — the
    # standalone nssm service needs no browser open (Linux parity).
    if not run_id:
        run_id = resolve_live_run_id(backend_url, platform="windows")
        print(f"[collector-win] resolved live session {run_id}")

    shipper = Shipper(backend_url, run_id)
    handle = win32evtlog.OpenEventLog(None, CHANNEL)

    # Read only new records (skip what's already in the channel).
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    start = time.time()
    snapshot_interval = float(os.getenv("SNAPSHOT_INTERVAL", "30"))
    last_snapshot = 0.0
    heartbeat_interval = float(os.getenv("HEARTBEAT_INTERVAL", "60"))

    print(f"[collector-win] run_id={run_id} mode={mode} backend={backend_url}")
    try:
        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            for record in records:
                ev = parse_sysmon_event(record)
                if ev:
                    shipper.add(ev)
            shipper.flush()
            # Live system snapshot on an interval — the "running now" view.
            if time.time() - last_snapshot > snapshot_interval:
                shipper.ship_snapshot(platform="windows")
                last_snapshot = time.time()
            # Liveness ping — the fleet view's last-seen/silent signal.
            shipper.maybe_heartbeat(platform="windows", interval=heartbeat_interval)
            time.sleep(1)
            if mode == "analysis" and time.time() - start > timeout:
                break
    except KeyboardInterrupt:
        pass
    finally:
        shipper.flush()
        win32evtlog.CloseEventLog(handle)
        print("[collector-win] stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OutPost Windows collector (Sysmon)")
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
