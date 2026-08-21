"""Thin REST client for the OutPost backend.

Mirrors `frontend/src/lib/api.ts` — same endpoints, same response shapes —
so a new backend endpoint is wired into both clients without redesign.
"""

import os
from typing import Any
from urllib.parse import quote

import requests

BASE_URL = os.getenv("OUTPOST_API_URL", "http://localhost:8001").rstrip("/")


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


def _patch(path: str, body: dict | None = None) -> Any:
    resp = requests.patch(f"{BASE_URL}{path}", json=body or {}, headers=_auth_headers(), timeout=15)
    if not resp.ok:
        raise APIError(f"PATCH {path} → {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _delete(path: str) -> None:
    """DELETE that accepts both 200 and 204 — the CLI parity rule for
    DELETE (mirror of the webapp's relaxed `del()`; a backend that 200s a
    DELETE with a body must not throw a misleading error)."""
    resp = requests.delete(f"{BASE_URL}{path}", headers=_auth_headers(), timeout=15)
    if resp.status_code not in (200, 204):
        raise APIError(f"DELETE {path} → {resp.status_code}: {resp.text[:200]}")


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


def get_alert_queue(
    status: str = "open",
    provenance: str | None = None,
    q: str = "",
    limit: int = 25,
    offset: int = 0,
) -> dict:
    """The analyst triage queue — the webapp's Open Findings mirror, with the
    same status / provenance (real vs synthetic) split."""
    path = f"/alerts/queue?status={status}&limit={limit}&offset={offset}"
    if provenance:
        path += f"&provenance={provenance}"
    if q:
        path += f"&q={quote(q)}"
    return _get(path)


def update_alert_status(alert_id: int, status: str, comment: str = "") -> dict:
    """Move one alert through the triage lifecycle — the terminal mirror of
    the webapp's run-detail panel (PATCH /alerts/{id} → the updated alert).

    Same transition-comment contract as the backend: the comment is recorded
    at the transition, and an empty comment is sent as "" (the backend
    strips it to NULL) — so a bare resolve clears a prior comment.
    """
    return _patch(f"/alerts/{alert_id}", {"status": status, "comment": comment})


def bulk_update_alert_status(alert_ids: list[int], status: str, comment: str = "") -> dict:
    """Apply one triage transition to many alerts at once — the terminal
    mirror of the webapp's bulk bar (POST /alerts/bulk → {"updated": n}).
    Same transition-comment contract as PATCH.
    """
    return _post("/alerts/bulk", {"ids": alert_ids, "status": status, "comment": comment})


# -- Alert triage: per-run IOC allowlists ------------------------------------
def get_run_allowlist(run_id: str) -> list[dict]:
    """IOCs allowlisted for a run (oldest first) — the webapp's
    AllowlistPanel mirror (GET /runs/{run_id}/allowlist)."""
    return _get(f"/runs/{run_id}/allowlist")


def add_run_allowlist(run_id: str, kind: str, value: str, note: str = "") -> dict:
    """Allowlist an IOC for a run: matching alerts stop firing on future
    batches and already-open matches are auto-acked (the response's `acked`
    count). Mirror of the webapp's QuickAllowlist/AllowlistPanel."""
    return _post(f"/runs/{run_id}/allowlist", {"kind": kind, "value": value, "note": note})


def remove_run_allowlist(run_id: str, entry_id: int) -> None:
    """Remove an allowlist entry (already-acked alerts stay acked)."""
    resp = requests.delete(f"{BASE_URL}/runs/{run_id}/allowlist/{entry_id}", timeout=15)
    if resp.status_code not in (200, 204):
        raise APIError(f"DELETE /runs/{run_id}/allowlist/{entry_id} → {resp.status_code}: {resp.text[:200]}")


# -- Alert triage: rule suppressions -----------------------------------------
def get_suppressions() -> list[dict]:
    """All rule suppressions (global + run/value scoped) — the webapp's
    Rules-page + SuppressionPanel mirror (GET /rules/suppressions)."""
    return _get("/rules/suppressions")


def add_suppression(rule_id: str, reason: str = "", run_id: str | None = None, value: str | None = None) -> dict:
    """Suppress a rule — run-scoped (a run), value-scoped (a sample/IP), or
    global (neither). Mirror of the webapp's SuppressionPanel + queue sweep."""
    return _post("/rules/suppressions", {"rule_id": rule_id, "reason": reason, "run_id": run_id, "value": value})


def remove_suppression(suppression_id: int) -> None:
    resp = requests.delete(f"{BASE_URL}/rules/suppressions/{suppression_id}", timeout=15)
    if resp.status_code not in (200, 204):
        raise APIError(f"DELETE /rules/suppressions/{suppression_id} → {resp.status_code}: {resp.text[:200]}")


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


# -- P0.5/P0.6/P0.7 client surfaces (terminal parity with frontend/src/lib/api.ts)


def global_search(q: str, limit: int = 10) -> dict:
    """Global search (GET /search) — grouped results across every
    analyst-facing resource; `q` may carry qualifiers (type: status:
    severity: disposition: host: rule: case:)."""
    return _get(f"/search?q={quote(q)}&limit={limit}")


def host_timeline(
    host_id: str,
    kind: str | None = None,
    event_type: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Host aggregate timeline (GET /hosts/{host_id}/timeline) — the merged
    chronological feed of events/findings/sessions/iocs/investigations."""
    params = []
    if kind:
        params.append(f"kind={quote(kind)}")
    if event_type:
        params.append(f"event_type={quote(event_type)}")
    if q:
        params.append(f"q={quote(q)}")
    params.append(f"limit={limit}")
    params.append(f"offset={offset}")
    return _get(f"/hosts/{quote(host_id)}/timeline?{'&'.join(params)}")


def create_analysis_job(
    backend: str,
    sample_id: str | None = None,
    sample_name: str | None = None,
    platform: str | None = None,
    timeout_seconds: int | None = None,
) -> dict:
    """Start an analysis job (POST /analysis). `isolated-outpost` returns
    501 until an isolated execution environment exists."""
    body: dict = {"backend": backend}
    if sample_id:
        body["sample_id"] = sample_id
    if sample_name:
        body["sample_name"] = sample_name
    if platform:
        body["platform"] = platform
    if timeout_seconds is not None:
        body["timeout_seconds"] = timeout_seconds
    return _post("/analysis", body)


def list_analysis_jobs(
    backend: str | None = None,
    status: str | None = None,
    artifact_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List/filter persisted analysis jobs (GET /analysis)."""
    params = []
    if backend:
        params.append(f"backend={quote(backend)}")
    if status:
        params.append(f"status={quote(status)}")
    if artifact_id:
        params.append(f"artifact_id={quote(artifact_id)}")
    params.append(f"limit={limit}")
    params.append(f"offset={offset}")
    return _get(f"/analysis?{'&'.join(params)}")


def get_analysis_job(run_id: str) -> dict:
    """One persisted job (GET /analysis/{run_id})."""
    return _get(f"/analysis/{quote(run_id)}")


def cancel_analysis_job(run_id: str) -> dict:
    """Cancel a queued/running job (POST /analysis/{run_id}/cancel)."""
    return _post(f"/analysis/{quote(run_id)}/cancel", {})


def get_analysis_observations(run_id: str) -> dict:
    """The observations-shaped payload (GET /analysis/{run_id}/observations):
    static jobs return the stored analysis result, dynamic jobs the run's
    events — no observations table exists (P0 defers it)."""
    return _get(f"/analysis/{quote(run_id)}/observations")


def get_analysis_findings(run_id: str) -> list[dict]:
    """Findings tied to the analysis run (GET /analysis/{run_id}/findings) —
    the existing alerts/run relationship, same as /runs/{id}/alerts."""
    return _get(f"/analysis/{quote(run_id)}/findings")


# -- P0.3 investigation surface (terminal parity with frontend/src/lib/api.ts)


def list_investigations(
    status: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List/filter investigations (GET /investigations) — status filter + q
    over title/tags/notes. Returns {total, limit, offset, investigations}."""
    params = []
    if status:
        params.append(f"status={quote(status)}")
    if q:
        params.append(f"q={quote(q)}")
    params.append(f"limit={limit}")
    params.append(f"offset={offset}")
    return _get(f"/investigations?{'&'.join(params)}")


def get_investigation(investigation_id: str) -> dict:
    """One investigation workspace payload (GET /investigations/{id}): the
    header with derived counts + findings / refs / notes."""
    return _get(f"/investigations/{quote(investigation_id)}")


def create_investigation(title: str, tags: list[str] | None = None) -> dict:
    """Create an investigation (POST /investigations) — initial status is
    'created', severity NULL until findings attach."""
    body: dict = {"title": title}
    if tags:
        body["tags"] = tags
    return _post("/investigations", body)


def patch_investigation(
    investigation_id: str,
    title: str | None = None,
    status: str | None = None,
    conclusion: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Update an investigation (PATCH /investigations/{id}) — forward-only
    status transitions; close/reopen are their own routes."""
    body: dict = {}
    if title is not None:
        body["title"] = title
    if status is not None:
        body["status"] = status
    if conclusion is not None:
        body["conclusion"] = conclusion
    if tags is not None:
        body["tags"] = tags
    return _patch(f"/investigations/{quote(investigation_id)}", body)


def add_investigation_ref(investigation_id: str, ref_type: str, ref_id: str) -> dict:
    """Attach one evidence ref (POST /investigations/{id}/refs) — a pointer,
    never a copy. Idempotent on (investigation, ref_type, ref_id)."""
    return _post(f"/investigations/{quote(investigation_id)}/refs", {"ref_type": ref_type, "ref_id": ref_id})


def remove_investigation_ref(investigation_id: str, ref_id: str) -> None:
    """Remove every ref of this investigation pointing at ref_id."""
    _delete(f"/investigations/{quote(investigation_id)}/refs/{quote(ref_id)}")


def add_investigation_note(investigation_id: str, note: str) -> dict:
    """Add an analyst note (POST /investigations/{id}/notes)."""
    return _post(f"/investigations/{quote(investigation_id)}/notes", {"note": note})


def close_investigation(investigation_id: str, conclusion: str) -> dict:
    """Close an investigation (POST /investigations/{id}/close) — requires a
    conclusion; the backend rejects blank ones."""
    return _post(f"/investigations/{quote(investigation_id)}/close", {"conclusion": conclusion})


def reopen_investigation(investigation_id: str) -> dict:
    """Reopen a closed investigation (POST /investigations/{id}/reopen) —
    returns to the active lifecycle state and clears closed_at."""
    return _post(f"/investigations/{quote(investigation_id)}/reopen", {})


def set_alert_investigation(alert_id: int, investigation_id: str | None, current_status: str) -> dict:
    """Attach/detach a finding to/from an investigation (PATCH /alerts/{id}).

    The backend PATCH requires `status`, so the caller passes the finding's
    CURRENT status — the link change never moves the triage state (the
    exact parity rule the webapp's setAlertInvestigation enforces). Pass
    None to detach."""
    return _patch(f"/alerts/{alert_id}", {"status": current_status, "investigation_id": investigation_id})


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
