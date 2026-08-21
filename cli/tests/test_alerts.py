"""CLI regression tests for `outpost alerts` — the terminal mirror of the
webapp's Open Findings sweep, including the status + provenance split that
lets operators separate host findings from demo/seed noise."""

from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()


def _row(alert_id: int, rule: str = "beaconing", sev: str = "suspicious", sample: str = "host-a", status: str = "open") -> dict:
    return {
        "id": alert_id, "run_id": f"run-{alert_id}", "sample_name": sample, "rule_id": rule,
        "rule_name": rule, "severity": sev, "triggered_at": "2026-08-15T10:00:00Z",
        "status": status, "status_comment": None, "status_at": None, "assignee": None,
        "related_pid": None, "related_ip": "203.0.113.88", "related_pids": [], "host_ids": [],
        "details": "5 connections to 203.0.113.88 at regular intervals",
    }


def test_alerts_prints_queue_with_provenance_passthrough(monkeypatch):
    captured = {}

    def fake_queue(**kwargs):
        captured.update(kwargs)
        return {
            "total": 1, "open": 1, "acknowledged": 0, "resolved": 0,
            "alerts": [_row(1, sample="host-soak-2026-08-09")],
        }

    # A realistic terminal width — the default 80-col capture ellipsizes
    # the Sample cell before the assertion settles.
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(api_client, "get_alert_queue", fake_queue)
    result = runner.invoke(app, ["alerts", "--provenance", "real"])
    assert result.exit_code == 0
    assert captured["provenance"] == "real" and captured["status"] == "open"
    assert "1 open finding(s)" in result.output
    assert "host-soak-2026-08-09" in result.output
    assert "beaconing" in result.output


def test_alerts_synthetic_filter_and_counts(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client,
        "get_alert_queue",
        lambda **kw: {
            "total": 2, "open": 0, "acknowledged": 2, "resolved": 0,
            "alerts": [
                _row(1, sample="detonate-demo.sh", status="acknowledged"),
                _row(2, sample="detonate-demo.sh", status="acknowledged"),
            ],
        },
    )
    result = runner.invoke(app, ["alerts", "--provenance", "synthetic", "--status", "acknowledged"])
    assert result.exit_code == 0
    assert "provenance=synthetic" in result.output


def _fake_queue(captured, sample="host-soak-2026-08-09"):
    def fake(**kw):
        captured.update(kw)
        return {"total": 1, "open": 1, "acknowledged": 0, "resolved": 0, "alerts": [_row(1, sample=sample)]}

    return fake


def test_alerts_save_persists_provenance_default(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setattr(console, "width", 160)
    captured = {}
    monkeypatch.setattr(api_client, "get_alert_queue", _fake_queue(captured))
    result = runner.invoke(app, ["alerts", "--provenance", "real", "--status", "open", "--save"])
    assert result.exit_code == 0
    assert captured["provenance"] == "real"
    from outpost.lib import prefs

    assert prefs.read_prefs()["queue_provenance_open"] == "real"
    assert "(saved)" not in result.output  # explicit choice, not a fallback


def test_alerts_uses_saved_default(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    from outpost.lib import prefs

    prefs.write_pref("queue_provenance_open", "real")
    monkeypatch.setattr(console, "width", 160)
    captured = {}
    monkeypatch.setattr(api_client, "get_alert_queue", _fake_queue(captured))
    result = runner.invoke(app, ["alerts"])
    assert result.exit_code == 0
    assert captured["provenance"] == "real"
    assert "provenance=real (saved)" in result.output


def test_alerts_explicit_provenance_overrides_saved(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    from outpost.lib import prefs

    prefs.write_pref("queue_provenance_open", "real")
    monkeypatch.setattr(console, "width", 160)
    captured = {}
    monkeypatch.setattr(api_client, "get_alert_queue", _fake_queue(captured))
    result = runner.invoke(app, ["alerts", "--provenance", "synthetic"])
    assert result.exit_code == 0
    assert captured["provenance"] == "synthetic"
    assert "(saved)" not in result.output


def test_alerts_save_without_provenance_errors(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setattr(console, "width", 160)
    result = runner.invoke(app, ["alerts", "--save"])
    assert result.exit_code == 1
    assert "--save needs --provenance" in result.output


def test_alerts_empty_queue_message(monkeypatch):
    monkeypatch.setattr(
        api_client, "get_alert_queue",
        lambda **kw: {"total": 0, "open": 0, "acknowledged": 0, "resolved": 0, "alerts": []},
    )
    result = runner.invoke(app, ["alerts", "--provenance", "real"])
    assert result.exit_code == 0
    assert "the queue is clear" in result.output


def test_alerts_validation_exits_1():
    result = runner.invoke(app, ["alerts", "--provenance", "banana"])
    assert result.exit_code == 1
    assert "must be real or synthetic" in result.output
    result = runner.invoke(app, ["alerts", "--status", "banana"])
    assert result.exit_code == 1
    assert "must be open" in result.output


def test_alerts_api_error_exits_1(monkeypatch):
    def boom(**kwargs):
        raise api_client.APIError("backend down")

    monkeypatch.setattr(api_client, "get_alert_queue", boom)
    result = runner.invoke(app, ["alerts"])
    assert result.exit_code == 1
    assert "Queue failed" in result.output
