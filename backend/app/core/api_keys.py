"""Threat-intel API keys — DB-backed with an env fallback (roadmap: Settings UI).

Keys live in the `settings` table under `api_key_<name>` so operators can set
AbuseIPDB / VirusTotal keys from the webapp without an env edit + restart. The
env vars (ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY) remain the zero-config
fallback: an unset DB row resolves to the env value, so existing deployments
keep working untouched. The webapp never sees a raw key — GET returns only
whether it's set (and where it came from) plus a masked suffix.

The raw value MUST be readable by the backend (it's sent to the provider in
cleartext), so this is storage, not password hashing — the same trust model as
the SMTP password in notification settings.
"""

import sqlite3
from datetime import datetime, timezone

from . import config

# Canonical key names → settings-table row names. `name` is the API-facing id
# used in routes and the frontend; the env var is <NAME>_API_KEY.
API_KEY_NAMES: dict[str, str] = {
    "abuseipdb": "api_key_abuseipdb",
    "virustotal": "api_key_virustotal",
}

_VALID = set(API_KEY_NAMES)


def is_valid_key_name(name: str) -> bool:
    return name in _VALID


def get_api_key(conn: sqlite3.Connection, name: str) -> str:
    """The effective key for `name`: the DB-stored value if set, else env."""
    if name not in API_KEY_NAMES:
        return ""
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?",
        (API_KEY_NAMES[name],),
    ).fetchone()
    if row and row["value"]:
        return str(row["value"]).strip()
    return str(getattr(config, f"{name.upper()}_API_KEY", "") or "").strip()


def set_api_key(conn: sqlite3.Connection, name: str, value: str) -> None:
    """Store a key in the DB (overrides the env fallback until cleared),
    stamping a set-at companion row so the Settings UI can suggest rotation."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (API_KEY_NAMES[name], value.strip()),
    )
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (f"{API_KEY_NAMES[name]}_set_at", now),
    )


def clear_api_key(conn: sqlite3.Connection, name: str) -> None:
    """Delete the DB row (and its set-at stamp) — the env fallback (if any)
    becomes effective again."""
    conn.execute("DELETE FROM settings WHERE key = ?", (API_KEY_NAMES[name],))
    conn.execute("DELETE FROM settings WHERE key = ?", (f"{API_KEY_NAMES[name]}_set_at",))


def api_key_status(conn: sqlite3.Connection, name: str) -> dict:
    """Per-key status for the Settings UI — never the raw value."""
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?",
        (API_KEY_NAMES[name],),
    ).fetchone()
    db_value = str(row["value"]).strip() if row and row["value"] else ""
    env_value = str(getattr(config, f"{name.upper()}_API_KEY", "") or "").strip()
    if db_value:
        # Rotation hint: how old the stored key is (the Settings UI flags
        # keys past a sensible rotation age). Companion row may be missing on
        # pre-upgrade rows — age then reads as None (no hint).
        age_days = None
        stamp = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (f"{API_KEY_NAMES[name]}_set_at",)
        ).fetchone()
        if stamp and stamp["value"]:
            try:
                set_at = datetime.fromisoformat(str(stamp["value"]))
                age_days = max(0, int((datetime.now(timezone.utc) - set_at).total_seconds() // 86400))
            except (ValueError, TypeError):
                age_days = None
        return {
            "name": name,
            "set": True,
            "source": "db",
            "suffix": db_value[-4:] if len(db_value) >= 4 else db_value,
            "set_at": stamp["value"] if stamp else None,
            "age_days": age_days,
        }
    if env_value:
        return {
            "name": name,
            "set": True,
            "source": "env",
            "suffix": env_value[-4:] if len(env_value) >= 4 else env_value,
            "set_at": None,
            "age_days": None,
        }
    return {"name": name, "set": False, "source": "none", "suffix": "", "set_at": None, "age_days": None}
