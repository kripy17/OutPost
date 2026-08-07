"""Threat-intel enrichment — AbuseIPDB + VirusTotal, cache-first.

Logic per docs/02-BACKEND-SPEC.md:
1. Collect distinct dest_ips for a run
2. Check enrichment_cache first (TTL 7 days) — never re-query a cached IP
3. Query AbuseIPDB + VirusTotal, store result
4. Derive reputation label from combined scores
5. Attach to NetworkConnection records

Roadmap 2.2 adds file/hash reputation: `enrich_hash` looks up a SHA-256 on
VirusTotal's file search, cached in `hash_cache` with the same TTL discipline.

If no API keys are configured (empty .env), lookups are skipped and IPs
report "unknown" — the pipeline still works for dev/demo (AGENTS.md rule 5).
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from ..core import config
from ..models.event import get_cache, upsert_cache
from ..models.watchlist import get_watchlist
from ..models.samples import get_hash_cache, upsert_hash_cache

# Rate-limit friendly: both APIs accept one key per request.
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def _reputation_from_scores(abuse_score: Optional[int], vt_count: Optional[int]) -> str:
    """Derive a reputation label per docs/02 guidance.

    abuse > 50 or vt > 3  -> malicious
    moderate (abuse > 20 or vt > 0) -> suspicious
    else -> clean
    """
    if abuse_score is None and vt_count is None:
        return "unknown"
    if (abuse_score or 0) > 50 or (vt_count or 0) > 3:
        return "malicious"
    if (abuse_score or 0) > 20 or (vt_count or 0) > 0:
        return "suspicious"
    return "clean"


def _cache_fresh(cached: dict) -> bool:
    try:
        checked = datetime.fromisoformat(cached["checked_at"])
    except (ValueError, KeyError):
        return False
    return datetime.now(timezone.utc) - checked < timedelta(days=config.ENRICHMENT_TTL_DAYS)


async def _query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Optional[int]:
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("abuseConfidenceScore")
    except (httpx.HTTPError, ValueError, KeyError):
        return None


async def _query_virustotal(client: httpx.AsyncClient, ip: str) -> Optional[int]:
    if not config.VIRUSTOTAL_API_KEY:
        return None
    try:
        resp = await client.get(
            f"{VIRUSTOTAL_URL}/{ip}",
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats.get("malicious")
    except (httpx.HTTPError, ValueError, KeyError):
        return None


VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"


async def enrich_hash(client: httpx.AsyncClient, conn, sha256: str) -> dict:
    """Cache-first VirusTotal reputation for a file SHA-256 (roadmap 2.2).

    Returns {"sha256", "vt_detections", "malware_family"}; without an API key
    the result is an honest all-None row ("no intel configured") rather than
    an error — same graceful degradation as IP enrichment.
    """
    cached = get_hash_cache(conn, sha256)
    if cached and _cache_fresh({"checked_at": cached["checked_at"]}):
        return {
            "sha256": sha256,
            "vt_detections": cached["vt_detections"],
            "malware_family": cached["malware_family"],
        }

    vt_detections: Optional[int] = None
    family: Optional[str] = None
    if config.VIRUSTOTAL_API_KEY:
        try:
            resp = await client.get(
                f"{VIRUSTOTAL_FILE_URL}/{sha256}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                vt_detections = stats.get("malicious") or 0
                family = (attrs.get("meaningful_name") or "") or None
                if not family and attrs.get("popular_threat_classification"):
                    fam = attrs["popular_threat_classification"].get("suggested_threat_label")
                    family = fam or None
        except (httpx.HTTPError, ValueError, KeyError):
            pass

    upsert_hash_cache(conn, sha256, vt_detections, family)
    return {"sha256": sha256, "vt_detections": vt_detections, "malware_family": family}


async def enrich_ip(client: httpx.AsyncClient, conn, ip: str) -> dict:
    """Cache-first enrichment for a single IP. Returns an enrichment dict."""
    cached = get_cache(conn, ip)
    if cached and _cache_fresh(cached):
        return {
            "ip": ip,
            "abuse_score": cached["abuse_score"],
            "vt_malicious_count": cached["vt_malicious_count"],
            "reputation": cached["reputation"],
        }

    abuse_score = await _query_abuseipdb(client, ip)
    vt_count = await _query_virustotal(client, ip)
    reputation = _reputation_from_scores(abuse_score, vt_count)

    upsert_cache(conn, ip, abuse_score, vt_count, reputation)
    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "vt_malicious_count": vt_count,
        "reputation": reputation,
    }


async def enrich_run(conn, run_id: str) -> dict[str, dict]:
    """Enrich every distinct dest_ip for a run. Returns {ip: enrichment_dict}."""
    rows = conn.execute(
        "SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND dest_ip IS NOT NULL",
        (run_id,),
    ).fetchall()
    ips = [r["dest_ip"] for r in rows]
    if not ips:
        return {}

    results: dict[str, dict] = {}
    async with httpx.AsyncClient() as client:
        for ip in ips:
            data = await enrich_ip(client, conn, ip)
            # Personal watchlist check (Task 26) — independent of external feeds.
            # Overrides a neutral verdict; a user-flagged entry is at least
            # suspicious by definition.
            wl = get_watchlist(conn, ip)
            if wl:
                data["watchlist"] = True
                data["watchlist_label"] = wl["label"]
                if data["reputation"] in (None, "unknown", "clean"):
                    data["reputation"] = "suspicious"
            results[ip] = data
    return results
