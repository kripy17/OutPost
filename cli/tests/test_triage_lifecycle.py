"""CLI parity test for the alert-triage lifecycle — the terminal mirror of
`frontend/src/test/triageLifecycle.test.tsx`.

The audit finding: the CLI's alert surface had the queue mirror (`outpost
alerts`) but NO status-transition command, so the webapp's triage panel had
no terminal counterpart. This pins the new surface — `api_client
.update_alert_status` + the `outpost triage` command — against the same
transition-comment contract the webapp test exercises:

  - PATCH /alerts/{id} with {status, comment} (the URL + payload contract).
  - The comment is recorded at the transition; an empty comment is sent as
    "" and the backend stores NULL — so a BARE resolve clears a prior ack
    comment (the webapp test caught the same semantic when a first draft
    asserted the comment survives a bare transition).
  - open → acknowledged → resolved → open (reopen) closes the cycle.

The lifecycle test drives the REAL command + REAL api_client function with
only the transport (`requests.patch`) stubbed against a stateful store —
the same shape as the webapp's stateful-fetch lifecycle test.
"""

import pytest
from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.text = text or str(payload)
        self._payload = payload

    def json(self):
        return self._payload


def _row(alert_id: int, status: str = "open") -> dict:
    return {
        "id": alert_id, "run_id": f"run-{alert_id}", "rule_id": "beaconing",
        "rule_name": "Beaconing to a fixed destination", "severity": "suspicious",
        "triggered_at": "2026-08-16T10:00:00Z", "status": status,
        "status_comment": None, "status_at": None, "related_pid": None,
        "related_ip": "203.0.113.88", "related_pids": [], "details": "beacon to C2",
    }


# -- contract: the real api_client function -----------------------------------

def test_update_alert_status_patches_url_and_body(monkeypatch):
    calls = []

    def fake_patch(url, json=None, headers=None, timeout=None):
        calls.append((url, json))
        return _FakeResponse(200, _row(1, status="acknowledged"))

    monkeypatch.setattr(api_client.requests, "patch", fake_patch)
    updated = api_client.update_alert_status(1, "acknowledged", "seen, will resolve")

    url, body = calls[0]
    assert url == f"{api_client.BASE_URL}/alerts/1"
    assert body == {"status": "acknowledged", "comment": "seen, will resolve"}
    assert updated["status"] == "acknowledged"


def test_update_alert_status_sends_empty_comment(monkeypatch):
    """A bare transition sends comment \"\" — the backend strips it to NULL,
    clearing any prior comment (the transition-comment contract)."""
    calls = []
    monkeypatch.setattr(
        api_client.requests,
        "patch",
        lambda url, json=None, headers=None, timeout=None: (calls.append((url, json)), _FakeResponse(200, _row(2, status="resolved")))[1],
    )
    api_client.update_alert_status(2, "resolved")
    assert calls[0][1] == {"status": "resolved", "comment": ""}


def test_update_alert_status_error_raises_api_error(monkeypatch):
    monkeypatch.setattr(
        api_client.requests,
        "patch",
        lambda url, json=None, headers=None, timeout=None: _FakeResponse(500, text="boom"),
    )
    with pytest.raises(api_client.APIError) as exc:
        api_client.update_alert_status(9, "resolved")
    assert "PATCH /alerts/9 → 500" in str(exc.value)
    assert "boom" in str(exc.value)


# -- lifecycle: the real command against a stateful backend stub ---------------

def _stateful_patch(store):
    """Mirror routes_alerts.update_alert_status: apply the transition, strip
    the comment (empty → NULL), and return the updated row."""
    def fake_patch(url, json=None, headers=None, timeout=None):
        alert_id = int(url.rsplit("/", 1)[1])
        status = json["status"]
        comment = (json.get("comment") or "").strip() or None
        row = store[alert_id]
        row["status"] = status
        row["status_comment"] = comment
        row["status_at"] = "2026-08-16T13:00:00Z"
        return _FakeResponse(200, row)

    return fake_patch


def test_triage_command_full_lifecycle(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    store = {1: _row(1)}
    monkeypatch.setattr(api_client.requests, "patch", _stateful_patch(store))

    # open → acknowledged with a comment.
    r = runner.invoke(app, ["triage", "acknowledged", "1", "--comment", "seen, will resolve"])
    assert r.exit_code == 0
    assert "Alert 1 → acknowledged" in r.output
    assert "comment: seen, will resolve" in r.output
    assert store[1]["status"] == "acknowledged"
    assert store[1]["status_comment"] == "seen, will resolve"

    # acknowledged → resolved with NO comment — the bare transition clears
    # the ack comment (empty → NULL). The exact semantic the webapp test
    # pins, mirrored here.
    r = runner.invoke(app, ["triage", "resolved", "1"])
    assert r.exit_code == 0
    assert "Alert 1 → resolved" in r.output
    assert store[1]["status"] == "resolved"
    assert store[1]["status_comment"] is None

    # resolved → open (reopen) — the cycle closes.
    r = runner.invoke(app, ["triage", "open", "1"])
    assert r.exit_code == 0
    assert "Alert 1 → open" in r.output
    assert store[1]["status"] == "open"


def _stateful_post(store):
    """Mirror routes_alerts.bulk_update_alert_status: transition many ids in
    one POST /alerts/bulk, strip the comment (empty → NULL), return the count."""
    def fake_post(url, json=None, headers=None, timeout=None):
        assert url.endswith("/alerts/bulk")
        status = json["status"]
        comment = (json.get("comment") or "").strip() or None
        for alert_id in json["ids"]:
            row = store[alert_id]
            row["status"] = status
            row["status_comment"] = comment
            row["status_at"] = "2026-08-16T13:00:00Z"
        return _FakeResponse(200, {"updated": len(json["ids"])})

    return fake_post


def test_triage_command_bulk_acks_and_resolves_many(monkeypatch):
    """Many ids → one POST /alerts/bulk (the webapp's bulk bar, mirrored).
    Untouched alerts stay untouched; the transition-comment contract holds
    for the whole batch."""
    monkeypatch.setattr(console, "width", 160)
    store = {1: _row(1), 2: _row(2), 3: _row(3)}
    monkeypatch.setattr(api_client.requests, "post", _stateful_post(store))

    r = runner.invoke(app, ["triage", "acknowledged", "1", "2"])
    assert r.exit_code == 0
    assert "2 alert(s) → acknowledged" in r.output
    assert store[1]["status"] == "acknowledged"
    assert store[2]["status"] == "acknowledged"
    assert store[3]["status"] == "open"  # untouched

    # Bulk resolve all three — the full set closes.
    r = runner.invoke(app, ["triage", "resolved", "1", "2", "3"])
    assert r.exit_code == 0
    assert "3 alert(s) → resolved" in r.output
    assert all(store[i]["status"] == "resolved" for i in (1, 2, 3))


def test_triage_command_invalid_status_exits_1():
    result = runner.invoke(app, ["triage", "banana", "1"])
    assert result.exit_code == 1
    assert "status must be open, acknowledged, or resolved" in result.output


def test_triage_command_api_error_exits_1(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):
        raise api_client.APIError("backend down")

    monkeypatch.setattr(api_client.requests, "patch", boom)
    result = runner.invoke(app, ["triage", "resolved", "1"])
    assert result.exit_code == 1
    assert "Triage failed" in result.output
