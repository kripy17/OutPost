"""Idempotent API request handling for OutPost backend (Milestone 5).

Guarantees safe retries on network interruptions, timeouts, and collector reconnects:
- Records (key, endpoint, response_code, response_json, created_at) atomically.
- Yields cached responses on key replay, preventing double-execution of mutations or audits.
- Rolls back on failure — failed requests never cache phantom success.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def get_idempotent_response(
    conn: sqlite3.Connection, key: str, endpoint: str
) -> dict[str, Any] | None:
    """Retrieve previously committed response for (key, endpoint) if present."""
    row = conn.execute(
        "SELECT response_code, response_json FROM idempotency_keys WHERE key = ? AND endpoint = ?",
        (key, endpoint),
    ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["response_json"])
    except Exception:
        return None


def save_idempotent_response(
    conn: sqlite3.Connection,
    key: str,
    endpoint: str,
    response_code: int,
    response_data: dict[str, Any],
) -> None:
    """Persist idempotent response inside the caller's active database transaction."""
    now_utc = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO idempotency_keys (key, endpoint, response_code, response_json, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            endpoint = excluded.endpoint,
            response_code = excluded.response_code,
            response_json = excluded.response_json,
            created_at = excluded.created_at
        """,
        (key, endpoint, response_code, json.dumps(response_data), now_utc),
    )
