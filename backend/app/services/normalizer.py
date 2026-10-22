"""Event normalization — final safety net before storage.

Collectors already normalize platform telemetry into the unified schema
(docs/03), but the backend applies a second pass so no malformed or
platform-specific field ever reaches the events table. This keeps the
AGENTS.md rule "one unified event schema" enforceable server-side.
"""

import re
from datetime import datetime, timezone
from typing import Any

# Fields that are always safe to persist as-is (possibly None).
_PASSTHROUGH = (
    "run_id", "platform", "event_type", "timestamp", "pid", "ppid",
    "process_name", "command_line", "exe_path", "dest_ip", "dest_port",
    "protocol", "file_path", "registry_key", "host_id", "log_source",
    "query", "tls_sni", "ja3", "tls_ja3", "raw_record",
    "source_event_id", "boot_id", "process_start_time",
    "user", "parent_image", "parent_command_line", "hashes",
    "integrity_level", "session_id", "connection_status", "process_guid",
    "missing_process_start_time",
)

_AUDIT_MSG_RE = re.compile(r"audit\(([\d.]+):(\d+)\)")


def _coerce_timestamp(val: Any) -> str:
    """Normalize any timestamp representation (datetime, epoch float, ISO string) to UTC ISO."""
    if val is None or val == "":
        return datetime.now(timezone.utc).isoformat()
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(float(val), timezone.utc).isoformat()
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    if isinstance(val, str):
        v = val.strip()
        try:
            # Handle epoch string e.g. "1692950000.123"
            epoch = float(v)
            return datetime.fromtimestamp(epoch, timezone.utc).isoformat()
        except ValueError:
            pass
        return v
    return datetime.now(timezone.utc).isoformat()


def normalize_event(raw: dict) -> dict:
    """Return a dict with only schema fields, types coerced where possible."""
    out: dict[str, Any] = {}
    for field in _PASSTHROUGH:
        out[field] = raw.get(field)

    # Coerce known numeric fields from string forms (e.g. from auditd/evtx XML).
    for field in ("pid", "ppid", "dest_port"):
        value = out.get(field)
        if isinstance(value, str) and value.strip().isdigit():
            out[field] = int(value.strip())
        elif isinstance(value, str):
            out[field] = None

    # Timestamps: normalize epoch numbers, strings, and missing timestamps.
    raw_ts = raw.get("timestamp")
    if raw_ts is None and out.get("timestamp") is None:
        out["timestamp"] = datetime.now(timezone.utc).isoformat()
    elif isinstance(raw_ts, (int, float, datetime)):
        out["timestamp"] = _coerce_timestamp(raw_ts)
    elif isinstance(out.get("timestamp"), (int, float, datetime)):
        out["timestamp"] = _coerce_timestamp(out["timestamp"])
    elif isinstance(out.get("timestamp"), str):
        out["timestamp"] = _coerce_timestamp(out["timestamp"])
    elif out.get("timestamp") is None:
        out["timestamp"] = datetime.now(timezone.utc).isoformat()

    # Fleet identity: events that don't name a host (webapp detonations,
    # sandbox runs) belong to the machine running the backend.
    host = str(out.get("host_id") or "").strip()
    out["host_id"] = host if host else "local"

    # Boot session identity: default to "default" if missing.
    boot = str(out.get("boot_id") or "").strip()
    out["boot_id"] = boot if boot else "default"

    # Process start time for compound process identity:
    # process_create events inherit the event timestamp if start time is omitted.
    pst = out.get("process_start_time")
    if pst is not None and pst != "":
        out["process_start_time"] = _coerce_timestamp(pst)
    elif out.get("event_type") == "process_create":
        out["process_start_time"] = out["timestamp"]
    else:
        out["process_start_time"] = None

    # Flag events that carry a PID but lack an authoritative process start time
    if out.get("pid") is not None and out.get("pid") != 0 and not out.get("process_start_time"):
        out["missing_process_start_time"] = True
    else:
        out["missing_process_start_time"] = False

    # Source event ID: preserve provided string; if missing, try extracting from raw_record.
    sid = out.get("source_event_id")
    if sid is not None and str(sid).strip():
        out["source_event_id"] = str(sid).strip()
    else:
        raw_rec = out.get("raw_record") or raw.get("raw_record")
        if isinstance(raw_rec, str) and raw_rec:
            m = _AUDIT_MSG_RE.search(raw_rec)
            if m:
                out["source_event_id"] = f"auditd:{m.group(1)}:{m.group(2)}"
            else:
                out["source_event_id"] = None
        else:
            out["source_event_id"] = None

    return out
