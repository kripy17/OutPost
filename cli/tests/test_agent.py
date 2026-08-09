"""`outpost agent` bootstrap — install generates a persistent service config
with the exact enable command, and never self-elevates; status reports
installed/running honestly; run streams in live mode."""

import os
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_agent_install_writes_systemd_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setenv("OUTPOST_API_URL", "http://localhost:8123")
    result = runner.invoke(app, ["agent", "install"])
    assert result.exit_code == 0
    d = Path(tmp_path) / "outpost"
    unit = d / "outpost-agent.service"
    assert unit.exists()
    text = unit.read_text()
    # Unit names the collector, the backend, live mode, and the hourly
    # snapshot cadence (the continuous-soak requirement).
    assert "collector_linux.py" in text or "collector_win.py" in text
    assert "http://localhost:8123" in text
    assert "--mode live" in text
    assert "SNAPSHOT_INTERVAL=3600" in text
    # The daily fired-rule summary pair is generated alongside.
    assert (d / "outpost-agent-summary.service").exists()
    assert (d / "outpost-agent-summary.timer").exists()
    assert "agent summary --days 1 --json" in (d / "outpost-agent-summary.service").read_text()
    assert "OnCalendar" in (d / "outpost-agent-summary.timer").read_text()
    # The enable command is printed for the operator — never executed here.
    assert "systemctl enable" in result.output
    assert "outpost-agent" in result.output
    assert "sudo" in result.output


def test_agent_status_reports_not_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    result = runner.invoke(app, ["agent", "status"])
    assert result.exit_code == 0
    assert "not installed" in result.output
    assert "`outpost agent install`" in result.output


def test_agent_status_reports_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    d = Path(tmp_path) / "outpost"
    d.mkdir(parents=True)
    (d / "outpost-collector.service").write_text("x")
    result = runner.invoke(app, ["agent", "status"])
    assert result.exit_code == 0
    assert "installed" in result.output


def test_agent_install_never_elevates(tmp_path, monkeypatch):
    """The install command must not itself run sudo / schtasks — it only
    prints the enable command. Guard against a future regression that calls
    the admin command directly from the CLI."""
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setattr(
        "outpost.commands.agent.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("agent must not spawn processes on install")),
    )
    result = runner.invoke(app, ["agent", "install"])
    assert result.exit_code == 0
    # The config file was written (rich may wrap the printed path, so assert
    # on disk rather than the wrapped console output).
    d = Path(tmp_path) / "outpost"
    assert (d / "outpost-agent.service").exists() or (d / "outpost-collector.bat").exists()


def test_agent_install_windows_emits_nssm_service_and_schtasks_summary(tmp_path, monkeypatch):
    """Windows parity for the continuous soak: the collector becomes a real
    nssm service (auto-restart, hourly snapshots) and the daily fired-rule
    summary a scheduled task — both generated, never executed here."""
    import outpost.commands.agent as agent_mod

    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setenv("OUTPOST_API_URL", "http://localhost:8123")
    monkeypatch.setattr(agent_mod.monitor, "detect_platform", lambda: "windows")
    result = runner.invoke(app, ["agent", "install"])
    assert result.exit_code == 0
    d = Path(tmp_path) / "outpost"

    # Collector wrapper: live mode + hourly snapshots.
    bat = d / "outpost-agent.bat"
    assert bat.exists()
    text = bat.read_text()
    assert "collector_win.py" in text
    assert "--mode live" in text
    assert "SNAPSHOT_INTERVAL=3600" in text

    # Daily summary: same JSON feed as the systemd timer, appended to a log.
    summary = d / "outpost-agent-summary.bat"
    assert summary.exists()
    assert "agent summary --days 1 --json" in summary.read_text()
    assert "outpost-agent-summary.log" in summary.read_text()

    # The elevated installer: nssm service + schtasks daily task.
    installer = d / "outpost-agent-install.bat"
    assert installer.exists()
    inst = installer.read_text()
    assert "nssm install OutPostAgent" in inst
    assert "nssm set OutPostAgent AppExit Default Restart" in inst
    assert "nssm set OutPostAgent AppEnvironmentExtra SNAPSHOT_INTERVAL=3600" in inst
    assert 'schtasks /Create /F /TN "OutPostAgentSummary" /SC DAILY /ST 06:00' in inst

    # The printed enable command names the nssm prerequisite (rich wraps long
    # paths, so the installer filename is asserted on disk above instead).
    assert "nssm" in result.output
    assert "elevated prompt" in result.output


def test_agent_install_windows_never_elevates(tmp_path, monkeypatch):
    """The Windows installer script is generated as a file — the CLI itself
    never spawns nssm/schtasks, even on Windows hosts."""
    import outpost.commands.agent as agent_mod

    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    monkeypatch.setattr(agent_mod.monitor, "detect_platform", lambda: "windows")
    monkeypatch.setattr(
        "outpost.commands.agent.subprocess.run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("agent must not spawn processes on install")),
    )
    result = runner.invoke(app, ["agent", "install"])
    assert result.exit_code == 0
    assert (Path(tmp_path) / "outpost" / "outpost-agent-install.bat").exists()


# ---------------------------------------------------------------------------
# outpost agent summary — the continuous FP-rate measurement
# ---------------------------------------------------------------------------


def _agent_runs():
    return [
        {
            "run_id": "agent-run-1", "sample_name": "agent-archlinux-2026-08-09",
            "session_type": "live", "started_at": "2026-08-09T00:10:00+00:00",
            "completed_at": None, "risk_score": 35,
        },
        {
            "run_id": "agent-run-2", "sample_name": "agent-archlinux-2026-08-09",
            "session_type": "live", "started_at": "2026-08-09T07:10:00+00:00",
            "completed_at": None, "risk_score": 0,
        },
        # Not an agent session — must never appear in the summary.
        {
            "run_id": "detonate-1", "sample_name": "evil.exe",
            "session_type": "analysis", "started_at": "2026-08-09T08:00:00+00:00",
            "completed_at": None, "risk_score": 100,
        },
    ]


_AGENT_ALERTS = {
    "agent-run-1": [
        {"rule_id": "beaconing", "severity": "suspicious"},
        {"rule_id": "beaconing", "severity": "suspicious"},
        {"rule_id": "masquerading", "severity": "malicious"},
    ],
    "agent-run-2": [
        {"rule_id": "lolbin-abuse", "severity": "malicious"},
    ],
}


def test_agent_summary_aggregates_fired_rules(monkeypatch):
    """One row per rule, count + severity split + session blast radius; only
    `agent-*` runs count (the daily FP measurement is agent-scoped)."""
    from outpost.lib import api_client

    monkeypatch.setattr(api_client, "list_runs", lambda: _agent_runs())
    monkeypatch.setattr(api_client, "get_alerts", lambda rid: _AGENT_ALERTS.get(rid, []))
    result = runner.invoke(app, ["agent", "summary", "--days", "1"])
    assert result.exit_code == 0
    out = result.output
    assert "Agent telemetry — last 1 day(s)" in out
    assert "2 session(s)" in out  # the detonate-1 analysis run is excluded
    assert "4 alert(s)" in out
    # Rule rows: beaconing 2 (0 mal / 2 sus), masquerading 1/1, lolbin 1/1.
    assert "beaconing" in out and "masquerading" in out and "lolbin-abuse" in out
    assert "evil.exe" not in out and "detonate-1" not in out
    # The table's columns are present (header row).
    assert "Alerts" in out and "Malicious" in out and "Suspicious" in out and "Sessions" in out


def test_agent_summary_json_feeds_the_timer_log(monkeypatch):
    """--json is the systemd daily log format: parseable, with per-rule and
    per-run aggregation."""
    import json

    from outpost.lib import api_client

    monkeypatch.setattr(api_client, "list_runs", lambda: _agent_runs())
    monkeypatch.setattr(api_client, "get_alerts", lambda rid: _AGENT_ALERTS.get(rid, []))
    result = runner.invoke(app, ["agent", "summary", "--days", "1", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["runs"] == 2 and data["alerts"] == 4
    by_rule = {r["rule_id"]: r for r in data["by_rule"]}
    assert by_rule["beaconing"]["count"] == 2
    assert by_rule["beaconing"]["suspicious"] == 2
    assert by_rule["beaconing"]["runs"] == ["agent-run-1"]
    assert by_rule["masquerading"]["malicious"] == 1
    assert len(data["per_run"]) == 2
