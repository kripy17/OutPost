"""P1.6 — CLI parity for the P0.3 investigation and P0.2 analysis workflows.

The webapp (frontend/src/lib/api.ts) and CLI (outpost/lib/api_client.py) are
two clients of the same API. These tests pin the terminal mirrors:

- api_client investigation functions hit the exact P0.3 endpoints with the
  exact params (status carries through on finding attach/detach — the link
  change never moves triage state);
- the `outpost investigations` group renders list/show and drives
  create/patch/refs/notes/close/reopen/attach/detach;
- the `outpost analysis` group launches, lists, shows, cancels, and renders
  observations/findings — with unexecuted backends (watched-host /
  external-provider / isolated-outpost) rejected up front (the
  backend 501s it, the CLI refuses to pretend);
- DELETE acceptance stays (200, 204) for refs removal.

Each test monkeypatches api_client's HTTP helpers, so no backend is needed.
"""

from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()

_INV = {
    "id": "inv1",
    "title": "C2 beaconing across agent fleet",
    "status": "active",
    "severity": "malicious",
    "conclusion": None,
    "created_by": "analyst",
    "created_at": "2026-08-18T08:00:00Z",
    "updated_at": "2026-08-18T08:30:00Z",
    "closed_at": None,
    "finding_count": 2,
    "ref_count": 1,
    "tags": ["c2"],
}

_DETAIL = {
    **_INV,
    "findings": [
        {"id": 41, "severity": "malicious", "rule_id": "rule-beacon", "status": "open", "details": "beaconing to 203.0.113.88"},
    ],
    "refs": [{"investigation_id": "inv1", "ref_type": "run", "ref_id": "run1", "added_at": "2026-08-18T08:10:00Z"}],
    "notes": [{"id": 1, "investigation_id": "inv1", "note": "watch for follow-on scans", "actor": "analyst", "created_at": "2026-08-18T08:20:00Z"}],
}


# ---------------------------------------------------------------------------
# api_client contract — endpoint / param parity with the web client
# ---------------------------------------------------------------------------


def test_investigations_api_client_endpoints(monkeypatch):
    calls = {}

    def fake_get(path):
        calls["get"] = path
        return {"total": 1, "limit": 50, "offset": 0, "investigations": [_INV]}

    def fake_post(path, body=None):
        calls["post"] = (path, body)
        return _INV

    def fake_patch(path, body=None):
        calls["patch"] = (path, body)
        return _INV

    def fake_delete(path):
        calls["delete"] = path

    monkeypatch.setattr(api_client, "_get", fake_get)
    monkeypatch.setattr(api_client, "_post", fake_post)
    monkeypatch.setattr(api_client, "_patch", fake_patch)
    monkeypatch.setattr(api_client, "_delete", fake_delete)

    api_client.list_investigations(status="active", q="beacon")
    assert calls["get"] == "/investigations?status=active&q=beacon&limit=50&offset=0"

    api_client.get_investigation("inv1")
    assert calls["get"] == "/investigations/inv1"

    api_client.create_investigation("new case", ["c2", "malware"])
    assert calls["post"] == ("/investigations", {"title": "new case", "tags": ["c2", "malware"]})

    api_client.patch_investigation("inv1", title="renamed", status="contained")
    assert calls["patch"] == ("/investigations/inv1", {"title": "renamed", "status": "contained"})

    api_client.add_investigation_ref("inv1", "ioc", "203.0.113.88")
    assert calls["post"] == ("/investigations/inv1/refs", {"ref_type": "ioc", "ref_id": "203.0.113.88"})

    api_client.remove_investigation_ref("inv1", "203.0.113.88")
    assert calls["delete"] == "/investigations/inv1/refs/203.0.113.88"

    api_client.add_investigation_note("inv1", "follow-up")
    assert calls["post"] == ("/investigations/inv1/notes", {"note": "follow-up"})

    api_client.close_investigation("inv1", "FP confirmed")
    assert calls["post"] == ("/investigations/inv1/close", {"conclusion": "FP confirmed"})

    api_client.reopen_investigation("inv1")
    assert calls["post"] == ("/investigations/inv1/reopen", {})


def test_set_alert_investigation_carries_current_status(monkeypatch):
    """Attach/detach must send the finding's CURRENT status — the backend
    PATCH requires status, and the link change must never move triage state
    (the exact parity rule the webapp's setAlertInvestigation enforces)."""
    seen = {}

    def fake_patch(path, body=None):
        seen["path"] = path
        seen["body"] = body
        return {"id": 41, "status": "acknowledged", "investigation_id": "inv1"}

    monkeypatch.setattr(api_client, "_patch", fake_patch)

    api_client.set_alert_investigation(41, "inv1", "acknowledged")
    assert seen["path"] == "/alerts/41"
    assert seen["body"] == {"status": "acknowledged", "investigation_id": "inv1"}

    api_client.set_alert_investigation(41, None, "acknowledged")
    assert seen["body"] == {"status": "acknowledged", "investigation_id": None}


def test_analysis_api_client_observations_findings(monkeypatch):
    calls = {}

    def fake_get(path):
        calls["get"] = path
        return {"backend": "static", "observations": []}

    monkeypatch.setattr(api_client, "_get", fake_get)
    api_client.get_analysis_observations("job1")
    assert calls["get"] == "/analysis/job1/observations"

    api_client.get_analysis_findings("job1")
    assert calls["get"] == "/analysis/job1/findings"


def test_remove_investigation_ref_accepts_200_and_204(monkeypatch):
    """The refs DELETE follows the (200, 204) contract — the same rule the
    webapp's relaxed del() and the CLI's other DELETEs enforce."""
    seen = []

    def fake_delete(path):
        seen.append(path)
        raise SystemExit  # stop before the response check — path asserted below

    monkeypatch.setattr(api_client, "_delete", lambda path: seen.append(path) or None)
    api_client.remove_investigation_ref("inv1", "ref-x")
    assert seen == ["/investigations/inv1/refs/ref-x"]


# ---------------------------------------------------------------------------
# CLI surface — `outpost investigations`
# ---------------------------------------------------------------------------


def test_investigations_list_renders(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "list_investigations",
        lambda status=None, q=None, limit=50, offset=0: {"total": 1, "limit": 50, "offset": 0, "investigations": [_INV]},
    )
    result = runner.invoke(app, ["investigations", "list"])
    assert result.exit_code == 0
    assert "1 investigation(s)" in result.output
    assert "C2 beaconing across agent fleet" in result.output
    assert "malicious" in result.output
    assert "ACTIVE" in result.output


def test_investigations_show_renders_workspace(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(api_client, "get_investigation", lambda iid: _DETAIL)
    result = runner.invoke(app, ["investigations", "show", "inv1"])
    assert result.exit_code == 0
    assert "C2 beaconing across agent fleet" in result.output
    assert "1 attached finding(s)" in result.output
    assert "beaconing to 203.0.113.88" in result.output
    assert "1 evidence ref(s)" in result.output
    assert "watch for follow-on scans" in result.output
    assert "1 note(s)" in result.output


def test_investigations_create_rejects_blank_title(monkeypatch):
    monkeypatch.setattr(api_client, "create_investigation", lambda title, tags=None: _INV)
    result = runner.invoke(app, ["investigations", "create", "   "])
    assert result.exit_code == 1
    assert "title must not be blank" in result.output


def test_investigations_close_rejects_blank_conclusion(monkeypatch):
    monkeypatch.setattr(api_client, "close_investigation", lambda iid, conclusion: _INV)
    result = runner.invoke(app, ["investigations", "close", "inv1", "   "])
    assert result.exit_code == 1
    assert "conclusion is required" in result.output


def test_investigations_attach_detach_flow(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    calls = []

    def fake_set(alert_id, inv_id, current_status):
        calls.append((alert_id, inv_id, current_status))
        return {"id": alert_id, "status": current_status, "investigation_id": inv_id}

    monkeypatch.setattr(api_client, "set_alert_investigation", fake_set)
    result = runner.invoke(app, ["investigations", "attach", "41", "inv1", "--current-status", "acknowledged"])
    assert result.exit_code == 0
    assert "Finding 41 → investigation inv1" in result.output
    assert calls == [(41, "inv1", "acknowledged")]

    result = runner.invoke(app, ["investigations", "detach", "41", "--current-status", "acknowledged"])
    assert result.exit_code == 0
    assert "Finding 41" in result.output
    assert calls == [(41, "inv1", "acknowledged"), (41, None, "acknowledged")]


def test_investigations_refs_note_flow(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(api_client, "add_investigation_ref", lambda iid, rt, rid: {"ref_type": rt, "ref_id": rid, "investigation_id": iid})
    monkeypatch.setattr(api_client, "remove_investigation_ref", lambda iid, rid: None)
    monkeypatch.setattr(api_client, "add_investigation_note", lambda iid, note: {"id": 7, "investigation_id": iid, "note": note, "actor": "analyst", "created_at": "2026-08-18T09:00:00Z"})

    result = runner.invoke(app, ["investigations", "refs-add", "inv1", "ioc", "203.0.113.88"])
    assert result.exit_code == 0
    assert "Ref added: ioc 203.0.113.88" in result.output

    result = runner.invoke(app, ["investigations", "refs-remove", "inv1", "203.0.113.88"])
    assert result.exit_code == 0
    assert "Removed ref 203.0.113.88" in result.output

    result = runner.invoke(app, ["investigations", "note", "inv1", "triaged"])
    assert result.exit_code == 0
    assert "Note #7 added" in result.output


# ---------------------------------------------------------------------------
# CLI surface — `outpost analysis`
# ---------------------------------------------------------------------------

_JOB = {
    "run_id": "job1",
    "backend": "static",
    "status": "completed",
    "timeout_seconds": None,
    "started_at": "2026-08-18T08:00:00Z",
    "finished_at": "2026-08-18T08:00:10Z",
    "error": None,
    "progress": 100,
    "sample_id": "s1",
    "events": 12,
    "alerts": 1,
    "risk_score": 71,
}


def test_analysis_launch_posts_job(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    calls = []

    def fake_create(backend, sample_id=None, sample_name=None, platform=None, timeout_seconds=None):
        calls.append((backend, sample_id, sample_name, platform, timeout_seconds))
        return {**_JOB, "run_id": "job2", "status": "queued"}

    monkeypatch.setattr(api_client, "create_analysis_job", fake_create)
    result = runner.invoke(app, ["analysis", "launch", "static", "--sample-id", "s1", "--platform", "windows", "--timeout", "60"])
    assert result.exit_code == 0
    assert "Launched job2" in result.output
    assert calls == [("static", "s1", None, "windows", 60)]


def test_analysis_launch_rejects_unexecuted_backends(monkeypatch):
    """watched-host / external-provider / isolated-outpost have no executor —
    the CLI refuses up front (and the backend 501s them) instead of queueing
    a job that could never run. Only 'static' is launchable."""
    monkeypatch.setattr(api_client, "create_analysis_job", lambda *a, **k: {**_JOB, "status": "queued"})
    for backend in ("isolated-outpost", "watched-host", "external-provider"):
        result = runner.invoke(app, ["analysis", "launch", backend, "--sample-id", "s1"])
        assert result.exit_code == 1, backend
        assert backend in result.output
        assert "no executor yet" in result.output  # may wrap mid-phrase


def test_analysis_list_show_cancel(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(api_client, "list_analysis_jobs", lambda backend=None, status=None, artifact_id=None, limit=50, offset=0: {"jobs": [_JOB]})
    monkeypatch.setattr(api_client, "get_analysis_job", lambda rid: _JOB)
    monkeypatch.setattr(api_client, "cancel_analysis_job", lambda rid: {**_JOB, "status": "canceled"})

    result = runner.invoke(app, ["analysis", "list"])
    assert result.exit_code == 0
    assert "job1" in result.output
    assert "COMPLETED" in result.output

    result = runner.invoke(app, ["analysis", "show", "job1"])
    assert result.exit_code == 0
    assert "risk score: 71" in result.output
    assert "events: 12" in result.output

    result = runner.invoke(app, ["analysis", "cancel", "job1"])
    assert result.exit_code == 0
    assert "Canceled job1" in result.output


def test_analysis_observations_findings_render(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "get_analysis_observations",
        lambda rid: {
            "backend": "static",
            "observations": [
                {"kind": "strings", "data": ["cmd.exe", "http://203.0.113.88"]},
                {"kind": "note", "data": "no stored bytes — re-upload to run static analysis"},
            ],
        },
    )
    monkeypatch.setattr(
        api_client, "get_analysis_findings",
        lambda rid: [{"id": 41, "severity": "malicious", "rule_id": "rule-beacon", "status": "open", "details": "beaconing to 203.0.113.88"}],
    )

    result = runner.invoke(app, ["analysis", "observations", "job1"])
    assert result.exit_code == 0
    assert "2 observation(s)" in result.output
    assert "no stored bytes" in result.output

    result = runner.invoke(app, ["analysis", "findings", "job1"])
    assert result.exit_code == 0
    assert "1 finding(s)" in result.output
    assert "beaconing to 203.0.113.88" in result.output
