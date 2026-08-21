"""Cross-run IOC search (Phase 6 Task 24 — docs/10-STANDOUT-FEATURES.md #2).

Turns your own run history into a personal threat-intel database: "have I
seen this IP/domain/hash before?" across every run.
"""

import re

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..models import samples as samples_store

router = APIRouter(tags=["ioc"])

_SEARCH_LIMIT = 200


def _like(value: str) -> str:
    """Escape LIKE metacharacters so user input is matched literally."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("/ioc/search", response_model=None)
def search_ioc(value: str = Query(..., min_length=1)):
    value = value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="value must not be empty")

    like = _like(value)
    where = (
        "e.dest_ip = ? OR e.process_name = ? OR e.file_path LIKE ? ESCAPE '\\' "
        "OR e.registry_key LIKE ? ESCAPE '\\' OR e.command_line LIKE ? ESCAPE '\\'"
    )

    with db_session() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM events e WHERE {where}",
            (value, value, like, like, like),
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT e.run_id, r.sample_name, r.platform, e.event_type, e.timestamp,
                   e.dest_ip, e.process_name, e.file_path, e.registry_key
            FROM events e
            JOIN runs r ON r.run_id = e.run_id
            WHERE {where}
            ORDER BY e.timestamp DESC
            LIMIT {_SEARCH_LIMIT}
            """,
            (value, value, like, like, like),
        ).fetchall()
        matches = [dict(r) for r in rows]

        # Hash lookup against uploaded samples (roadmap 1.4): a SHA-256 (or
        # prefix) that matches a stored binary is returned alongside the event
        # matches, so "have I seen this file before?" works for uploads too.
        # Only hash-style input reaches the SHA-256 LIKE lookup — hex-only,
        # so stray % or _ wildcards can never match every stored sample.
        if re.fullmatch(r"[0-9a-fA-F]{6,64}", value):
            sample_hits = samples_store.list_by_sha_prefix(conn, value.lower(), limit=10)
        else:
            sample_hits = []

        # Reputation ride-along: when the searched value is a cached IP, carry
        # its enrichment evidence (abuse score, VT positives, verdict, age) so
        # the search page answers "have I seen this — and is it bad?" in one
        # glance, instead of sending the analyst to the run-detail network
        # table for the verdict. Null when the value was never enriched.
        rep = conn.execute(
            "SELECT abuse_score, vt_malicious_count, reputation, checked_at "
            "FROM enrichment_cache WHERE ip = ?",
            (value,),
        ).fetchone()
        reputation = dict(rep) if rep else None

    return {
        "value": value,
        "count": total,
        "returned": len(matches),
        "reputation": reputation,
        "matches": matches,
        "samples": [
            {
                "sample_id": s["sample_id"],
                "original_name": s["original_name"],
                "sha256": s["sha256"],
                "detected_platform": s["detected_platform"],
                "size": s["size"],
                "created_at": s["created_at"],
            }
            for s in sample_hits
        ],
    }
