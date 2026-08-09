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


def _get(path: str) -> Any:
    resp = requests.get(f"{BASE_URL}{path}", timeout=15)
    if not resp.ok:
        raise APIError(f"GET {path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _post(path: str, body: dict | None = None) -> Any:
    resp = requests.post(f"{BASE_URL}{path}", json=body or {}, timeout=15)
    if not resp.ok:
        raise APIError(f"POST {path} → {resp.status_code}: {resp.text[:200]}")
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
    return _get("/runs")


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


def get_campaigns() -> list[dict]:
    return _get("/campaigns")


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


def refresh_ip(run_id: str, ip: str) -> dict:
    """Bypass the enrichment TTL ONCE for one destination IP of a run — the
    terminal mirror of the run-detail force-refresh button."""
    from urllib.parse import quote

    return _post(f"/runs/{run_id}/enrichment/refresh?ip={quote(ip)}", {})


def refresh_stale(limit: int = 50) -> dict:
    """The stale-only maintenance sweep — re-query just the cached verdicts
    past the TTL (oldest first), the Settings sweep's terminal mirror."""
    return _post(f"/intel/refresh-stale?max={limit}", {})
