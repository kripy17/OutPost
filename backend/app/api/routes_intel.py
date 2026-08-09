"""Enrichment-cache operations — freshness, stale sweep, one-shot per-IP refresh.

The intel lifecycle's operations surface:

- `GET /intel/freshness` — how old the oldest cached verdict is and how many
  rows are past the TTL. Feeds the Overview's one-line freshness posture.
- `POST /intel/refresh-stale?max=N` — the "stale-only" maintenance sweep:
  re-query just the cache rows older than the TTL (oldest first, capped),
  leaving fresh rows untouched. Driven by the Settings button and the CLI's
  `outpost refresh --stale`.
- `POST /enrichment/{ip}/refresh` — a GLOBAL one-shot TTL bypass for any IP
  (no run-scoping), for the Footprint page's per-seed refresh. The run-scoped
  variant stays on routes_runs (it also validates membership + re-enriches
  the sample hash).

All writes are audited.
"""

from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, HTTPException, Query, Request

from ..core import auth, config
from ..core.db import db_session
from ..models import audit
from ..services import enrichment

router = APIRouter(tags=["intel"])


def _stale_cutoff() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=config.ENRICHMENT_TTL_DAYS)).isoformat()


async def _refresh_ip_row(conn, ip: str) -> dict:
    """Shared one-shot refresh: drop the cache row (TTL bypass once), re-query
    with the CURRENT keys, persist. Caller commits + audits."""
    conn.execute("DELETE FROM enrichment_cache WHERE ip = ?", (ip,))
    async with httpx.AsyncClient() as client:
        data = await enrichment.enrich_ip(client, conn, ip)
    conn.commit()
    return data


@router.get("/intel/freshness", response_model=None)
def intel_freshness() -> dict:
    """Cache-age summary over the enrichment cache: total rows, how many are
    past the TTL, and the oldest verdict's stamp + age in hours. Cheap — one
    indexed-ish aggregate, no external calls (the Overview calls it on poll)."""
    with db_session() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "COALESCE(MIN(checked_at), '') AS oldest FROM enrichment_cache",
        ).fetchone()
        total = row["total"] or 0
        oldest = row["oldest"] or None
        stale_count = 0
        if total:
            stale_count = conn.execute(
                "SELECT COUNT(*) AS n FROM enrichment_cache WHERE checked_at < ?",
                (_stale_cutoff(),),
            ).fetchone()["n"] or 0

    oldest_age_hours = None
    if oldest:
        try:
            oldest_age_hours = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(oldest)).total_seconds() // 3600))
        except ValueError:
            oldest_age_hours = None
    return {"total": total, "stale_count": stale_count, "oldest_checked_at": oldest, "oldest_age_hours": oldest_age_hours}


@router.post("/intel/refresh-stale", response_model=None)
async def refresh_stale(
    limit: int = Query(50, ge=1, le=200, alias="max", description="Max stale rows to refresh (oldest first)"),
    request: Request = None,
) -> dict:
    """The stale-only sweep: re-query just the cache rows older than the TTL,
    oldest first, up to `max`. Fresh rows are left untouched — the opposite
    of the whole-run re-enrich's shotgun clear."""
    with db_session() as conn:
        rows = conn.execute(
            "SELECT ip FROM enrichment_cache WHERE checked_at < ? ORDER BY checked_at ASC LIMIT ?",
            (_stale_cutoff(), limit),
        ).fetchall()
        refreshed = []
        for r in rows:
            data = await _refresh_ip_row(conn, r["ip"])
            refreshed.append(
                {"ip": r["ip"], "reputation": data.get("reputation") or "unknown", "checked_at": data.get("checked_at")}
            )
        if refreshed:
            audit.log(
                conn, auth.role_from_request(request), "intel.refresh-stale",
                target_type="intel", target_id="cache",
                detail=f"stale-only sweep: refreshed {len(refreshed)} row(s) past the {config.ENRICHMENT_TTL_DAYS}d TTL",
            )
    return {"refreshed": len(refreshed), "rows": refreshed}


@router.post("/enrichment/{ip}/refresh", response_model=None)
async def refresh_ip_global(ip: str, request: Request = None) -> dict:
    """Global one-shot TTL bypass for any IP — the Footprint page's per-seed
    refresh (sample-scoped, across runs, so the run-scoped endpoint doesn't
    fit). Same semantics as the run-scoped variant: drop the row, re-query
    with current keys, audit."""
    if not ip.strip():
        raise HTTPException(status_code=422, detail="ip must not be empty")
    with db_session() as conn:
        data = await _refresh_ip_row(conn, ip.strip())
        audit.log(
            conn, auth.role_from_request(request), "intel.refresh-ip",
            target_type="intel", target_id=ip.strip(),
            detail="global force-refresh (TTL bypassed) — footprint seed",
        )
    return {
        "ip": ip.strip(),
        "abuse_score": data.get("abuse_score"),
        "vt_malicious_count": data.get("vt_malicious_count"),
        "reputation": data.get("reputation") or "unknown",
        "checked_at": data.get("checked_at"),
    }
