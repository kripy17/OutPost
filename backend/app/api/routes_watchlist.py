"""Personal IOC watchlist (Phase 6 Task 26 — docs/10 #6).

Entries are checked against every run's connections during enrichment,
independent of AbuseIPDB/VirusTotal — your own tracked infrastructure.
"""

import csv
import io
import json

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from ..core.db import db_session
from ..core.schema import WatchlistEntry
from ..models import watchlist as watchlist_store

router = APIRouter(tags=["watchlist"])


class WatchlistIn(BaseModel):
    value: str
    label: str = ""


@router.get("/watchlist", response_model=list[WatchlistEntry])
def list_entries() -> list[WatchlistEntry]:
    with db_session() as conn:
        rows = watchlist_store.list_watchlist(conn)
        return [WatchlistEntry(**r) for r in rows]


@router.post("/watchlist", status_code=201, response_model=WatchlistEntry)
def add_entry(body: WatchlistIn) -> WatchlistEntry:
    value = body.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="value must not be empty")
    label = body.label.strip() or value
    with db_session() as conn:
        watchlist_store.add_watchlist(conn, value, label)
        row = watchlist_store.get_watchlist(conn, value)
    return WatchlistEntry(**row)


@router.delete("/watchlist/{value}", status_code=204)
def remove_entry(value: str) -> None:
    with db_session() as conn:
        if not watchlist_store.remove_watchlist(conn, value):
            raise HTTPException(status_code=404, detail=f"Not in watchlist: {value}")
    return None


# ---------------------------------------------------------------------------
# Roadmap 3.3 — shared watchlists: CSV/JSON export + import
# ---------------------------------------------------------------------------


@router.get("/watchlist/export")
def export_watchlist(format: str = "json") -> Response:
    """Dump the watchlist for sharing between analysts/teams.

    `?format=json` → [{"value", "label"}] (added_at omitted — machine
    round-trip friendly); `?format=csv` → value,label rows.
    """
    if format not in ("json", "csv"):
        raise HTTPException(status_code=422, detail="format must be json or csv")
    with db_session() as conn:
        entries = watchlist_store.list_watchlist(conn)
    rows = [{"value": e["value"], "label": e["label"]} for e in entries]

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["value", "label"])
        for row in rows:
            writer.writerow([row["value"], row["label"]])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="outpost-watchlist.csv"'},
        )
    return Response(
        content=json.dumps(rows, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="outpost-watchlist.json"'},
    )


@router.post("/watchlist/import", response_model=None)
def import_watchlist(body: dict) -> dict:
    """Bulk-import entries. Expects {"entries": [{"value", "label"}, …]}.

    Idempotent — existing values are upserted (label refreshed).
    """
    raw = body.get("entries")
    if not isinstance(raw, list):
        raise HTTPException(status_code=422, detail="Expected {\"entries\": [...]}")

    added = 0
    with db_session() as conn:
        for item in raw:
            value = str(item.get("value", "")).strip() if isinstance(item, dict) else ""
            if not value:
                continue
            label = str(item.get("label", "")).strip() or value
            watchlist_store.add_watchlist(conn, value, label)
            added += 1
    return {"imported": added}
