"""Client-side preferences — the terminal mirror of the webapp's localStorage
queue/archive keys (per-status-tab provenance split + the archive's
show-synthetic fallback).

The webapp keeps these in browser localStorage; the CLI keeps the same keys in
a small JSON file so `outpost settings clear-prefs` wipes them in one command
and the real-first preference stays consistent across both surfaces. The file
lives in the same config dir as the agent's generated service configs
(OUTPOST_HOME override, else ~/.config/outpost), so tests isolate it via
OUTPOST_HOME. Never throws — a missing or corrupted file reads as empty.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Mirrors the webapp's PROVENANCE_STORAGE_PREFIX keys, one per status tab.
QUEUE_KEYS = (
    "queue_provenance_open",
    "queue_provenance_acknowledged",
    "queue_provenance_resolved",
    "queue_provenance_all",
)
# Mirrors the webapp's outpost-history-synthetic legacy fallback key.
ARCHIVE_KEY = "archive_show_synthetic"

ALL_KEYS = (*QUEUE_KEYS, ARCHIVE_KEY)


def prefs_path() -> Path:
    base = os.environ.get("OUTPOST_HOME") or Path.home() / ".config"
    return Path(base) / "outpost" / "prefs.json"


def read_prefs() -> dict[str, str]:
    """Every saved preference as {key: value} — empty when unset or corrupted."""
    try:
        raw = json.loads(prefs_path().read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {k: str(v) for k, v in raw.items() if k in ALL_KEYS and str(v)}
    except (OSError, ValueError):
        pass  # missing or corrupted — read as empty, never throw
    return {}


def write_pref(key: str, value: str) -> None:
    """Persist one preference; clearing ("") removes the key. Failures are
    swallowed — the choice still applies for this run."""
    prefs = read_prefs()
    if value:
        prefs[key] = value
    else:
        prefs.pop(key, None)
    try:
        p = prefs_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(prefs, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def clear_prefs() -> dict[str, str]:
    """Wipe every saved preference, returning what was cleared ({} when the
    store was already empty) so the caller can report it."""
    cleared = read_prefs()
    try:
        p = prefs_path()
        if p.exists():
            p.unlink()
    except OSError:
        pass
    return cleared
