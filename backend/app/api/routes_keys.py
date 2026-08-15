"""Threat-intel API keys — configure AbuseIPDB / VirusTotal from Settings.

- GET    /settings/keys          — per-key status (set?, source db/env, masked
                                   suffix) — the raw value is NEVER returned
- PUT    /settings/keys/{name}   — store a key in the settings table
- DELETE /settings/keys/{name}   — clear the DB row (env fallback returns)
- POST   /settings/keys/{name}/test — live probe of the EFFECTIVE key

Keys take effect immediately: the enrichment service resolves them from the
DB on every call (core/api_keys.get_api_key), so no backend restart is needed
— the env vars remain the zero-config fallback.
"""

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ..core import auth
from ..core.api_keys import (
    api_key_status,
    clear_api_key,
    get_api_key,
    is_valid_key_name,
    set_api_key,
)
from ..core.db import db_session
from ..models import audit

router = APIRouter(tags=["keys"])

# One lightweight probe per provider (both accept a single key per request):
# AbuseIPDB check on a well-known IP; VirusTotal IP lookup. A 2xx proves the
# key is valid; 401/403 means rejected; network failure = unreachable.
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"
PROBE_IP = "8.8.8.8"


class KeyIn(BaseModel):
    value: str


def _key_or_404(name: str) -> None:
    if not is_valid_key_name(name):
        raise HTTPException(status_code=404, detail=f"Unknown key: {name} (want abuseipdb | virustotal)")


@router.get("/settings/keys", response_model=None)
def list_keys() -> dict:
    with db_session() as conn:
        keys = [api_key_status(conn, name) for name in ("abuseipdb", "virustotal")]
    return {"keys": keys}


@router.put("/settings/keys/{name}", response_model=None)
def set_key(name: str, body: KeyIn, request: Request) -> dict:
    """Store a key (DB overrides the env fallback until cleared). Takes effect
    on the next enrichment call — no restart."""
    _key_or_404(name)
    value = body.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="Key must not be empty")
    if len(value) > 256 or any(ch.isspace() for ch in value):
        raise HTTPException(status_code=422, detail="Key looks malformed — no whitespace, max 256 chars")
    with db_session() as conn:
        set_api_key(conn, name, value)
        audit.log(
            conn, auth.role_from_request(request), "keys.set",
            target_type="settings", target_id=f"api_key_{name}",
            detail=f"{name} key stored (…{value[-4:]})",
        )
        return api_key_status(conn, name)


@router.delete("/settings/keys/{name}", status_code=204)
def clear_key(name: str, request: Request) -> None:
    """Delete the DB row — the env fallback (if any) becomes effective again."""
    _key_or_404(name)
    with db_session() as conn:
        clear_api_key(conn, name)
        audit.log(
            conn, auth.role_from_request(request), "keys.clear",
            target_type="settings", target_id=f"api_key_{name}",
            detail=f"{name} key cleared (env fallback may apply)",
        )


@router.post("/settings/keys/{name}/test", response_model=None)
async def test_key(name: str, request: Request) -> dict:
    """Live probe of the effective key (DB or env fallback) against the
    provider. Costs one quota unit on free tiers — deliberate per-click."""
    _key_or_404(name)
    with db_session() as conn:
        key = get_api_key(conn, name)
        status = api_key_status(conn, name)
    if not key:
        raise HTTPException(status_code=422, detail="No key configured for this provider")
    async with httpx.AsyncClient(timeout=12) as client:
        try:
            if name == "abuseipdb":
                resp = await client.get(
                    ABUSEIPDB_URL,
                    params={"ipAddress": PROBE_IP, "maxAgeInDays": 90},
                    headers={"Key": key, "Accept": "application/json"},
                )
            else:
                resp = await client.get(f"{VIRUSTOTAL_URL}/{PROBE_IP}", headers={"x-apikey": key})
        except httpx.HTTPError:
            return {**status, "ok": False, "detail": "provider unreachable — network error"}
    if resp.status_code == 200:
        return {**status, "ok": True, "detail": "key accepted — provider replied 200"}
    if resp.status_code in (401, 403):
        return {**status, "ok": False, "detail": f"key rejected — provider replied {resp.status_code}"}
    return {**status, "ok": False, "detail": f"unexpected reply {resp.status_code}"}
