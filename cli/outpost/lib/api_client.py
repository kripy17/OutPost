"""Thin REST client for the OutPost backend.

Mirrors `frontend/src/lib/api.ts` — same endpoints, same response shapes —
so a new backend endpoint is wired into both clients without redesign.
"""

import os
from typing import Any

import requests

BASE_URL = os.getenv("OUTPOST_API_URL", "http://localhost:8000").rstrip("/")


class APIError(RuntimeError):
    pass


def _auth_headers() -> dict:
    """Authorization for the shared agent credential (OUTPOST_AGENT_TOKEN).

    The agent service (daily summary, `outpost agent run`'s own calls) runs
    under the host credential when the backend is fail-closed — same env the
    collector's shipper reads. Empty when unset (zero-config default).
    """
    tok = os.getenv("OUTPOST_AGENT_TOKEN", "").strip()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def _get(path: str) -> Any:
    resp = requests.get(f"{BASE_URL}{path}", headers=_auth_headers(), timeout=15)
    if not resp.ok:
        raise APIError(f"GET {path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _post(path: str, body: dict | None = None) -> Any:
    resp = requests.post(f"{BASE_URL}{path}", json=body or {}, headers=_auth_headers(), timeout=15)
    if not resp.ok:
        raise APIError(f"POST {path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def backfill_channels(admin_password: str) -> dict:
    """Admin-only: stamp `log_source` on legacy collector events on demand
    (the startup migration, no restart needed). Logs in as admin, POSTs
    /admin/backfill-channels, and returns {"updated": n} — 0 once the
    channel data is complete, so it doubles as a health check.

    Degrades to the zero-config default: when the backend has no auth
    configured (login 404s), the endpoint is open (actor 'local'), so the
    POST proceeds without a token. Under fail-closed auth a bad login still
    fails loudly."""
    login = requests.post(f"{BASE_URL}/auth/login", json={"password": admin_password or ""}, timeout=15)
    headers: dict[str, str] = {}
    if login.status_code == 200:
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
    elif login.status_code == 404 and "not configured" in login.text:
        pass  # zero-config default — auth off, the endpoint accepts any actor
    else:
        raise APIError(f"POST /auth/login → {login.status_code}: {login.text[:200]}")
    resp = requests.post(f"{BASE_URL}/admin/backfill-channels", headers=headers, timeout=15)
    if not resp.ok:
        raise APIError(f"POST /admin/backfill-channels → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


# -- runs --------------------------------------------------------------------
def create_run(sample_name: str, platform: str, session_type: str = "analysis") -> str:
    return _post(
        "/runs",
        {"sample_name": sample_name, "platform": platform, "session_type": session_type, "source": "cli"},
    )["run_id"]


def complete_run(run_id: str) -> dict:
    return _post(f"/runs/{run_id}/complete")


def list_runs() -> list[dict]:
    # Opt back in to synthetic provenance (seeds / webapp detonations / the
    # sandbox demo) AND soak-named collector baselines — the API hides both
    # by default now, but the CLI is the parity mirror and should keep
    # showing everything.
    return _get("/runs?include_synthetic=true&include_soak=true")


def get_run(run_id: str) -> dict:
    return _get(f"/runs/{run_id}")


def get_alerts(run_id: str) -> list[dict]:
    return _get(f"/runs/{run_id}/alerts")


def export_run(run_id: str) -> dict:
    return _get(f"/runs/{run_id}/export")


# -- Phase 6 standout features (docs/10) -------------------------------------
def search_iocs(value: str) -> dict:
    from urllib.parse import quote

    return _get(f"/ioc/search?value={quote(value)}")


def export_iocs_csv(run_id: str) -> bytes:
    resp = requests.get(f"{BASE_URL}/runs/{run_id}/iocs?format=csv", timeout=15)
    if not resp.ok:
        raise APIError(f"GET /runs/{run_id}/iocs → {resp.status_code}: {resp.text[:200]}")
    return resp.content


def compare_runs(run_id_a: str, run_id_b: str) -> dict:
    return _get(f"/runs/{run_id_a}/compare/{run_id_b}")


def get_rules(run_id: str, format: str = "suricata") -> str:
    resp = requests.get(f"{BASE_URL}/runs/{run_id}/rules?format={format}", timeout=15)
    if not resp.ok:
        raise APIError(f"GET /runs/{run_id}/rules → {resp.status_code}: {resp.text[:200]}")
    return resp.text


def watchlist_list() -> list[dict]:
    return _get("/watchlist")


def watchlist_add(value: str, label: str = "") -> dict:
    return _post("/watchlist", {"value": value, "label": label})


def watchlist_remove(value: str) -> None:
    resp = requests.delete(f"{BASE_URL}/watchlist/{value}", timeout=15)
    if resp.status_code not in (200, 204):
        raise APIError(f"DELETE /watchlist/{value} → {resp.status_code}: {resp.text[:200]}")


def get_agents(identity: str = "") -> dict:
    """The fleet grouped by host_id (`GET /agents`). `?identity=` narrows
    to collector/webapp/silent — same param the webapp's Agents page uses.
    """
    q = f"?identity={identity}" if identity else ""
    return _get(f"/agents{q}")


def get_campaigns() -> list[dict]:
    # Opt into synthetic-provenance members explicitly — the terminal mirror
    # shows the full story (same parity rule as list_runs).
    return _get("/campaigns?include_synthetic=true")


def list_samples(q: str = "") -> dict:
    """Sample vault (webapp /samples parity) — rows carry YARA + runs_count."""
    from urllib.parse import quote

    suffix = f"?q={quote(q)}" if q else ""
    return _get(f"/samples{suffix}")


def export_stix(run_id: str) -> dict:
    """STIX 2.1 bundle of the run's indicators (roadmap 3.3)."""
    return _get(f"/runs/{run_id}/export?format=stix")


def export_campaign_stix(campaign_key: str) -> dict:
    """STIX 2.1 bundle of a campaign cluster (webapp per-card export parity)."""
    from urllib.parse import quote

    return _get(f"/campaigns/{quote(campaign_key)}/export?format=stix")


def get_navigator_layer() -> dict:
    """The coverage matrix as a MITRE ATT&CK Navigator v4.3 layer (webapp
    Coverage-page export parity) — importable into attack-navigator."""
    return _get("/coverage/navigator")


def watchlist_export(format: str = "json") -> bytes:
    resp = requests.get(f"{BASE_URL}/watchlist/export?format={format}", timeout=15)
    if not resp.ok:
        raise APIError(f"GET /watchlist/export → {resp.status_code}: {resp.text[:200]}")
    return resp.content


def watchlist_import(entries: list[dict]) -> dict:
    return _post("/watchlist/import", {"entries": entries})


def notes_list(run_id: str) -> list[dict]:
    return _get(f"/runs/{run_id}/notes")


def notes_add(run_id: str, note: str) -> dict:
    return _post(f"/runs/{run_id}/notes", {"note": note})


def get_rules_meta() -> list[dict]:
    """ATT&CK technique/tactic + risk weight per rule (webapp parity)."""
    return _get("/rules/meta")


def get_tuning() -> dict:
    """Every tunable knob with default/current/tuned — `outpost rules knobs`."""
    return _get("/rules/tuning")


def get_log_patterns() -> dict:
    """The anti-forensics pattern tables (service_stop / log_clear) per
    platform — `outpost rules log-patterns`."""
    return _get("/rules/log-patterns")


def refresh_ip(run_id: str, ip: str) -> dict:
    """Bypass the enrichment TTL ONCE for one destination IP of a run — the
    terminal mirror of the run-detail force-refresh button."""
    from urllib.parse import quote

    return _post(f"/runs/{run_id}/enrichment/refresh?ip={quote(ip)}", {})


def refresh_stale(limit: int = 50) -> dict:
    """The stale-only maintenance sweep — re-query just the cached verdicts
    past the TTL (oldest first), the Settings sweep's terminal mirror."""
    return _post(f"/intel/refresh-stale?max={limit}", {})


def intel_import(source: str, content: str = "", url: str = "") -> dict:
    """Pull a threat-intel feed (STIX bundle or IOC list) into the watchlist
    + IOC layer; the response lists which existing runs already touch it."""
    body: dict = {"source": source}
    if url:
        body["url"] = url
    if content:
        body["content"] = content
    return _post("/intel/import", body)


def yara_list() -> dict:
    """Persisted custom YARA rules (parsed: name/family/strings/source)."""
    return _get("/yara/rules")


def yara_test(rule: str, sample_ids: list[str] | None = None) -> dict:
    """Compile + scan a rule against the vault (or a sample subset) without
    persisting — the signature lab's terminal mirror."""
    body: dict = {"rule": rule}
    if sample_ids:
        body["sample_ids"] = sample_ids
    return _post("/yara/test", body)


def footprint(sample_id: str, mock: bool = False) -> dict:
    """Passive digital footprint for one uploaded sample (reverse-DNS, CT
    certs, RDAP org, ASN) with an honest synthetic fallback flag."""
    return _get(f"/footprint/{sample_id}?mock={1 if mock else 0}")


def export_footprint(sample_id: str, format: str = "json", mock: bool = False) -> bytes:
    """Threat-intel handoff export — the same JSON/CSV artifact the webapp's
    Export buttons download. Raw bytes: JSON arrives pre-indented from the
    backend; CSV is the flat collection sheet."""
    resp = requests.get(
        f"{BASE_URL}/footprint/{sample_id}/export?format={format}&mock={1 if mock else 0}", timeout=20
    )
    if not resp.ok:
        raise APIError(f"GET /footprint/{sample_id}/export → {resp.status_code}: {resp.text[:200]}")
    return resp.content
