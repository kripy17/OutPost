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

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from ..core import auth, config
from ..core.db import db_session
from ..models import audit, watchlist as watchlist_store
from ..services import enrichment

router = APIRouter(tags=["intel"])


class IntelImportIn(BaseModel):
    """A threat-intel feed to pull into the watchlist + IOC layer.

    `content` is either a raw STIX 2.1 bundle (source=stix / auto-detect) or
    a plain one-IOC-per-line text list; `url` fetches a STIX feed instead of
    pasting it. Imported values are upserted into the watchlist labeled
    `intel:<source>` so they read honestly as feed-derived, and every
    existing run that touches an imported value is reported back so the UI
    can flag it immediately.
    """

    source: Literal["stix", "text", "auto"] = "auto"
    content: Optional[str] = None
    url: Optional[str] = None


# -- Feed parsing ------------------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_URL_RE = re.compile(r"^https?://[^\s]+$")
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE)


def _classify(value: str) -> str:
    """Best-guess IOC kind for a plain-text line."""
    v = value.strip().lower()
    if _IP_RE.match(v):
        return "ip"
    if _SHA_RE.match(v):
        return "hash"
    if _URL_RE.match(v):
        return "url"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "other"


_STIX_PATTERN_RE = re.compile(r"\[([a-z0-9-]+):(?:value|hashes\.['\"][^'\"]+['\"])\s*=\s*['\"]([^'\"]+)['\"]")


def _extract_from_stix(obj: dict, out: dict) -> None:
    """Pull indicator values from one STIX object into `out` (kind → value)."""
    otype = obj.get("type", "")
    if otype == "indicator":
        pattern = obj.get("pattern") or ""
        for match in _STIX_PATTERN_RE.finditer(pattern):
            stix_type, value = match.group(1), match.group(2)
            kind = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url", "file": "hash"}.get(stix_type, "other")
            out.setdefault(kind, set()).add(value.lower())
    elif otype in ("domain-name", "url"):
        value = (obj.get("value") or "").strip().lower()
        if value:
            out.setdefault("domain" if otype == "domain-name" else "url", set()).add(value)
    elif otype in ("ipv4-addr", "ipv6-addr"):
        value = (obj.get("value") or "").strip().lower()
        if value:
            out.setdefault("ip", set()).add(value)
    elif otype == "file":
        hashes = obj.get("hashes") or {}
        sha = hashes.get("SHA-256") or hashes.get("sha256")
        if sha:
            out.setdefault("hash", set()).add(sha.lower())


def _parse_feed(source: str, content: str) -> dict[str, set[str]]:
    """Return {kind: {value}} from a STIX bundle or text list."""
    stripped = content.strip()
    kind = source if source != "auto" else ("stix" if stripped.startswith("{") else "text")
    if kind == "stix":
        try:
            bundle = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid STIX bundle JSON: {exc}")
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        out: dict[str, set[str]] = {}
        for obj in objects:
            if isinstance(obj, dict):
                _extract_from_stix(obj, out)
        return out
    out = {}
    for line in stripped.splitlines():
        value = line.strip().strip("'").strip('"')
        if not value or value.startswith("#") or value.startswith("//"):
            continue
        out.setdefault(_classify(value), set()).add(value.lower())
    return out


def _matching_runs(conn, value: str, kind: str) -> list[str]:
    """Runs whose events touch this value (exact IP/name/hash, LIKE elsewhere)."""
    like = f"%{value}%"
    if kind in ("ip", "domain", "url"):
        rows = conn.execute(
            "SELECT DISTINCT run_id FROM events WHERE dest_ip = ? OR command_line LIKE ? ESCAPE '\\' OR query = ?",
            (value, like, value),
        ).fetchall()
    elif kind == "hash":
        rows = conn.execute(
            "SELECT DISTINCT run_id FROM events WHERE command_line LIKE ? ESCAPE '\\' OR file_path LIKE ? ESCAPE '\\' OR process_name = ?",
            (f"%{value}%", f"%{value}%", value),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT DISTINCT run_id FROM events WHERE command_line LIKE ? ESCAPE '\\' OR process_name = ? OR file_path LIKE ? ESCAPE '\\' OR registry_key LIKE ? ESCAPE '\\'",
            (like, value, like, like),
        ).fetchall()
    return [r["run_id"] for r in rows]


@router.post("/intel/import", response_model=None)
async def import_intel_feed(body: IntelImportIn, request: Request):
    """Pull a threat-intel feed into the watchlist + IOC layer and flag the
    runs that already touch it. Audited (writes the store)."""
    actor = auth.role_from_request(request)
    content = body.content
    if body.url:
        if not body.url.startswith(("https://", "http://")):
            raise HTTPException(status_code=422, detail="url must be http(s)")
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(body.url)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"feed fetch failed: HTTP {resp.status_code}")
            content = resp.text
    if not content or not content.strip():
        raise HTTPException(status_code=422, detail="content or url required")

    parsed = _parse_feed(body.source, content)
    total_values = sum(len(v) for v in parsed.values())
    if total_values == 0:
        raise HTTPException(status_code=422, detail="no indicators found in feed")

    source_label = f"intel:{body.source}" if body.source != "auto" else "intel:feed"
    imported = 0
    matched_runs: dict[str, list[str]] = {}
    with db_session() as conn:
        for kind, values in parsed.items():
            for value in sorted(values):
                watchlist_store.add_watchlist(conn, value, source_label)
                imported += 1
                runs = _matching_runs(conn, value, kind)
                if runs:
                    matched_runs[value] = runs
        audit.log(conn, actor, "intel.import", target_type="watchlist", detail=f"{imported} values from {source_label}")

    return {
        "imported": imported,
        "source": source_label,
        "kinds": {k: len(v) for k, v in parsed.items()},
        "matched_values": len(matched_runs),
        "matched_runs": matched_runs,
    }


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
