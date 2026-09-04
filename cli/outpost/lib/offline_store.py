"""Offline SQLite store fallback for OutPost CLI.

Enables the CLI to read past runs, alerts, samples, and watchlist entries
directly from the local SQLite database when the backend HTTP service is offline.
"""

import os
import sqlite3
from pathlib import Path
from typing import Any


def find_db_path() -> Path | None:
    """Locate the OutPost SQLite database file."""
    # 1. Explicit env var
    env_path = os.getenv("DATABASE_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    # 2. Known repo locations
    root = Path(__file__).resolve().parent.parent.parent.parent
    candidates = [
        root / "backend" / "data" / "outpost.db",
        root / ".freebuff" / "outpost.db",
        root / "outpost.db",
        Path.cwd() / "backend" / "data" / "outpost.db",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return None


def get_offline_runs(limit: int = 50) -> list[dict[str, Any]] | None:
    """Query runs directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT r.run_id, r.sample_name, r.platform, r.session_type, r.started_at, r.completed_at,
                   COUNT(a.id) as alert_count,
                   MAX(CASE WHEN a.severity = 'malicious' THEN 'malicious'
                            WHEN a.severity = 'suspicious' THEN 'suspicious'
                            ELSE 'clean' END) as highest_severity
            FROM runs r
            LEFT JOIN alerts a ON r.run_id = a.run_id
            GROUP BY r.run_id
            ORDER BY r.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        runs = []
        for r in rows:
            d = dict(r)
            d["risk_score"] = 48 if d.get("highest_severity") == "malicious" else 14 if d.get("highest_severity") == "suspicious" else 0
            runs.append(d)
        conn.close()
        return runs
    except Exception:
        return None


def get_offline_alerts(status: str = "all", limit: int = 50) -> list[dict[str, Any]] | None:
    """Query alerts directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        if status == "open":
            rows = cur.execute(
                "SELECT * FROM alerts WHERE status = 'open' ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        alerts = [dict(r) for r in rows]
        conn.close()
        return alerts
    except Exception:
        return None


def get_offline_samples() -> list[dict[str, Any]] | None:
    """Query samples directly from SQLite."""
    db_path = find_db_path()
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        rows = cur.execute("SELECT * FROM samples ORDER BY first_seen DESC LIMIT 50").fetchall()
        samples = [dict(r) for r in rows]
        conn.close()
        return samples
    except Exception:
        return None
