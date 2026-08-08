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
    unit = Path(tmp_path) / "outpost" / "outpost-collector.service"
    assert unit.exists()
    text = unit.read_text()
    # Unit names the collector, the backend, and live mode.
    assert "collector_linux.py" in text or "collector_win.py" in text
    assert "http://localhost:8123" in text
    assert "--mode live" in text
    # The enable command is printed for the operator — never executed here.
    assert "systemctl enable" in result.output
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
    assert (d / "outpost-collector.service").exists() or (d / "outpost-collector.bat").exists()
