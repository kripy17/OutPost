"""Event normalization — final safety net before storage.

Collectors already normalize platform telemetry into the unified schema
(docs/03), but the backend applies a second pass so no malformed or
platform-specific field ever reaches the events table. This keeps the
AGENTS.md rule "one unified event schema" enforceable server-side.
"""

from typing import Any

# Fields that are always safe to persist as-is (possibly None).
_PASSTHROUGH = (
    "run_id", "platform", "event_type", "timestamp", "pid", "ppid",
    "process_name", "command_line", "dest_ip", "dest_port", "protocol",
    "file_path", "registry_key",
)


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

    # Timestamps: accept ISO strings as-is; anything else becomes now (UTC).
    if not isinstance(out.get("timestamp"), str):
        out["timestamp"] = raw.get("timestamp")

    return out
