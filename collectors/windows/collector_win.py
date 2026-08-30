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
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))

from shipper import Shipper, resolve_live_run_id

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sysmon Event ID → unified event_type
EVENT_TYPE_MAP = {
    1: "process_create",
    3: "network_connection",
    6: "driver_load",
    7: "module_load",
    8: "remote_thread",
    10: "process_access",
    11: "file_write",
    12: "registry_write",
    13: "registry_write",
    14: "registry_write",
    23: "file_delete",
}


def parse_sysmon_event(record) -> dict | None:
    """Convert one win32evtlog record into a unified-schema event dict."""
    try:
        event_id = record.EventID & 0xFFFF  # Mask qualifier bits
    except AttributeError:
        return None
    if event_id not in EVENT_TYPE_MAP:
        return None

    data: dict[str, Any] = {}

    # 1. Try StringInserts (standard for Win32 Event Log provider)
    inserts = getattr(record, "StringInserts", None)
    if inserts and isinstance(inserts, (list, tuple)):
        # For Sysmon Event 1 (Process Create)
        if event_id == 1 and len(inserts) >= 12:
            data["UtcTime"] = inserts[1] if len(inserts) > 1 else ""
            data["ProcessId"] = inserts[3] if len(inserts) > 3 else ""
            data["Image"] = inserts[4] if len(inserts) > 4 else ""
            data["CommandLine"] = inserts[10] if len(inserts) > 10 else ""
            if len(inserts) >= 21:
                data["ParentProcessId"] = inserts[19]
                data["ParentImage"] = inserts[20]
        # For Sysmon Event 3 (Network Connection)
        elif event_id == 3 and len(inserts) >= 17:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[4]
            data["Protocol"] = inserts[6]
            data["SourceIp"] = inserts[9]
            data["DestinationIp"] = inserts[14]
            data["DestinationHostname"] = inserts[15]
            data["DestinationPort"] = inserts[16]
        # For Sysmon Event 6 (Driver Load)
        elif event_id == 6 and len(inserts) >= 5:
            data["UtcTime"] = inserts[1]
            data["Image"] = inserts[3]
            data["TargetFilename"] = inserts[3]
        # For Sysmon Event 7 (Module Load)
        elif event_id == 7 and len(inserts) >= 6:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[4]
            data["TargetFilename"] = inserts[5]
        # For Sysmon Event 8 (CreateRemoteThread)
        elif event_id == 8 and len(inserts) >= 8:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[4]
            data["TargetProcessId"] = inserts[6]
            data["TargetImage"] = inserts[7]
            data["TargetFilename"] = inserts[7]
        # For Sysmon Event 10 (ProcessAccess)
        elif event_id == 10 and len(inserts) >= 9:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[5]
            data["TargetProcessId"] = inserts[7]
            data["TargetImage"] = inserts[8]
        # For Sysmon Event 11 (FileCreate / FileWrite)
        elif event_id == 11 and len(inserts) >= 6:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[4]
            data["TargetFilename"] = inserts[5]
        # For Sysmon Event 12/13/14 (Registry Write/Delete)
        elif event_id in (12, 13, 14) and len(inserts) >= 7:
            data["UtcTime"] = inserts[2]
            data["ProcessId"] = inserts[4]
            data["Image"] = inserts[5]
            data["TargetObject"] = inserts[6]
        # For Sysmon Event 23 (FileDelete)
        elif event_id == 23 and len(inserts) >= 6:
            data["UtcTime"] = inserts[1]
            data["ProcessId"] = inserts[3]
            data["Image"] = inserts[4]
            data["TargetFilename"] = inserts[5]

    # 2. Record.Data fallback for structured event receivers
    try:
        raw = getattr(record, "Data", None)
        if isinstance(raw, (list, tuple)):
            for i in range(0, len(raw) - 1, 2):
                data[str(raw[i])] = str(raw[i + 1])
        elif isinstance(raw, dict):
            data.update(raw)
    except Exception:
        pass

    ts = datetime.datetime.fromtimestamp(record.TimeGenerated.timestamp(), datetime.timezone.utc).isoformat()
    ev = {
        "platform": "windows",
        "log_source": "sysmon",  # the collector's own channel — explicit
        "event_type": EVENT_TYPE_MAP[event_id],
        "timestamp": ts,
        "pid": _int(data.get("ProcessId")),
        "ppid": _int(data.get("ParentProcessId")),
        "process_name": _basename(data.get("Image")),
        # Sysmon's Image IS the ETW-resolved executable path (the Windows
        # equivalent of auditd's exe= — symlinks/junction followed, immune to
        # argv[0] spoofing). The masquerading rule keys on it authoritatively;
        # Linux parity: the collector ships the resolved path, the backend
        # decides.
        "exe_path": data.get("Image"),
        "command_line": data.get("CommandLine"),
        "dest_ip": data.get("DestinationIp") or data.get("SourceIp"),
        "dest_port": _int(data.get("DestinationPort")),
        "protocol": data.get("Protocol"),
        "file_path": data.get("TargetFilename"),
        "registry_key": data.get("TargetObject"),
        # TLS Server Name Indication — Sysmon Event ID 3's DestinationHostname
        # (present when the connection carried a TLS handshake). Feeds the
        # TLS-SNI and DNS-over-HTTPS detection rules.
        "tls_sni": data.get("DestinationHostname"),
        # The raw EventData as shipped — the Event Viewer's "raw record" pane
        # pivots a normalized row back to the exact Sysmon fields (the
        # backend keeps it when the collector provides it).
        "raw_record": json.dumps(data, default=str),
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
