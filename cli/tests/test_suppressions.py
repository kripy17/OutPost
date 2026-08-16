"""CLI regression tests for `outpost rules suppressions add|list|remove` —
the terminal mirror of the webapp's SuppressionPanel (run-scoped) and the
Rules page (global), plus the queue sweep's value-scoped form.
"""

import pytest
from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()


def _row(suppression_id: int, rule: str = "beaconing", run_id=None, value=None, reason: str = "") -> dict:
    return {"id": suppression_id, "rule_id": rule, "run_id": run_id, "value": value,
            "reason": reason or None, "created_at": "2026-08-16T10:00:00Z"}


def test_suppressions_list_renders_scopes(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "get_suppressions",
        lambda: [
            _row(1, "beaconing", run_id="run-abc123", reason="demo noise"),
            _row(2, "lolbin-abuse", value="detonate-demo.sh"),
            _row(3, "masquerading"),
        ],
    )
    result = runner.invoke(app, ["rules", "suppressions", "list"])
    assert result.exit_code == 0
    assert "run run-abc123" in result.output
    assert "value detonate-demo.sh" in result.output
    assert "global" in result.output
    assert "demo noise" in result.output


def test_suppressions_list_empty_message(monkeypatch):
    monkeypatch.setattr(api_client, "get_suppressions", lambda: [])
    result = runner.invoke(app, ["rules", "suppressions", "list"])
    assert result.exit_code == 0
    assert "No rule suppressions" in result.output


def test_suppressions_add_run_scoped(monkeypatch):
    captured = {}

    def fake_add(rule_id, reason="", run_id=None, value=None):
        captured.update(rule_id=rule_id, reason=reason, run_id=run_id, value=value)
        return _row(9, rule=rule_id, run_id=run_id, reason=reason)

    monkeypatch.setattr(api_client, "add_suppression", fake_add)
    result = runner.invoke(app, ["rules", "suppressions", "add", "beaconing", "--run-id", "run-x", "--reason", "FP"])
    assert result.exit_code == 0
    assert captured == {"rule_id": "beaconing", "reason": "FP", "run_id": "run-x", "value": None}
    assert "Suppressed beaconing (run run-x)" in result.output


def test_suppressions_add_value_scoped(monkeypatch):
    captured = {}

    def fake_add(rule_id, reason="", run_id=None, value=None):
        captured.update(rule_id=rule_id, reason=reason, run_id=run_id, value=value)
        return _row(9, rule=rule_id, value=value)

    monkeypatch.setattr(api_client, "add_suppression", fake_add)
    result = runner.invoke(app, ["rules", "suppressions", "add", "beaconing", "--value", "detonate-demo.sh"])
    assert result.exit_code == 0
    assert captured == {"rule_id": "beaconing", "reason": "", "run_id": None, "value": "detonate-demo.sh"}
    assert "Suppressed beaconing (value detonate-demo.sh)" in result.output


def test_suppressions_add_global(monkeypatch):
    captured = {}

    def fake_add(rule_id, reason="", run_id=None, value=None):
        captured.update(rule_id=rule_id, reason=reason, run_id=run_id, value=value)
        return _row(9, rule=rule_id)

    monkeypatch.setattr(api_client, "add_suppression", fake_add)
    result = runner.invoke(app, ["rules", "suppressions", "add", "masquerading"])
    assert result.exit_code == 0
    assert captured == {"rule_id": "masquerading", "reason": "", "run_id": None, "value": None}
    assert "Suppressed masquerading (global)" in result.output


def test_suppressions_remove(monkeypatch):
    captured = {}

    def fake_remove(suppression_id):
        captured["id"] = suppression_id

    monkeypatch.setattr(api_client, "remove_suppression", fake_remove)
    result = runner.invoke(app, ["rules", "suppressions", "remove", "5"])
    assert result.exit_code == 0
    assert captured == {"id": 5}
    assert "Removed suppression 5" in result.output


def test_suppressions_api_error_exits_1(monkeypatch):
    def boom(rule_id, reason="", run_id=None, value=None):
        raise api_client.APIError("backend down")

    monkeypatch.setattr(api_client, "add_suppression", boom)
    result = runner.invoke(app, ["rules", "suppressions", "add", "beaconing"])
    assert result.exit_code == 1
    assert "Failed" in result.output


def test_remove_suppression_accepts_204_and_200(monkeypatch):
    """The relaxed DELETE contract (200/204 both success) on the suppression
    path — same rule as the webapp's del() and the CLI's watchlist/allowlist
    deletes, pinned so it can't silently regress to 204-only."""
    class _FakeResponse:
        def __init__(self, status_code: int, text: str = ""):
            self.status_code = status_code
            self.text = text

    calls = []
    monkeypatch.setattr(api_client.requests, "delete", lambda url, **kw: (calls.append(url), _FakeResponse(204))[1])
    api_client.remove_suppression(3)
    assert calls == [f"{api_client.BASE_URL}/rules/suppressions/3"]

    monkeypatch.setattr(api_client.requests, "delete", lambda url, **kw: _FakeResponse(200))
    api_client.remove_suppression(4)  # must not raise

    monkeypatch.setattr(api_client.requests, "delete", lambda url, **kw: _FakeResponse(500, "oops"))
    with pytest.raises(api_client.APIError) as exc:
        api_client.remove_suppression(5)
    assert "DELETE /rules/suppressions/5 → 500: oops" in str(exc.value)
