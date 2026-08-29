"""Finding-level intel evidence.

Joins the IOCs observed on a finding (``ioc_findings``) to their enrichment
state (the denormalized ``iocs`` columns written by the extraction/enrichment
pipeline: reputation verdict, AbuseIPDB score, VT malicious count, cache age).
Attached read-side by the alert surfaces so every C2-flavored finding ships
its corroborating intel without an extra round-trip.
"""

from __future__ import annotations

import sqlite3


def intel_for_finding(conn: sqlite3.Connection, finding_id: int) -> list[dict]:
    """Enrichment evidence for one alert, newest-checked first.

    Returns [] when the finding has no linked IOCs (most heuristic hits don't)
    — callers render nothing rather than an empty block.
    """
    rows = conn.execute(
        """
        SELECT i.value, i.type, i.disposition, i.reputation,
               i.abuse_score, i.vt_malicious_count, i.label, i.checked_at
        FROM ioc_findings f
        JOIN iocs i ON i.ioc_id = f.ioc_id
        WHERE f.finding_id = ?
        ORDER BY i.checked_at DESC NULLS LAST, i.value ASC
        """,
        (finding_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def attach_intel(rows: list[dict], conn: sqlite3.Connection | None) -> None:
    """In-place: set ``intel`` on each alert dict (empty list when none).

    ``conn=None`` short-circuits (used by surfaces that run outside a session).
    """
    if conn is None:
        return
    for d in rows:
        try:
            d["intel"] = intel_for_finding(conn, int(d.get("id", 0)))
        except (TypeError, ValueError):
            d["intel"] = []
