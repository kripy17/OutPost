"""Tests for the Adversary Technique CLI commands in `outpost playbooks`."""

from typer.testing import CliRunner
from outpost.commands.playbooks import app
from outpost.lib import api_client

runner = CliRunner()


def test_playbooks_techniques_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_technique_tests",
        lambda tactic=None, platform=None, q=None: [
            {
                "id": "T1059.004-bash-pipe",
                "technique_id": "T1059.004",
                "technique_name": "Unix Shell",
                "tactic": "Execution",
                "name": "Base64 Obfuscated Shell Command",
                "supported_platforms": ["linux", "darwin"],
            }
        ],
    )
    res = runner.invoke(app, ["techniques"])
    assert res.exit_code == 0
    assert "Adversary Technique Unit Tests" in res.stdout
    assert "T1059.004" in res.stdout
    assert "Base64" in res.stdout
    assert "T1059.004-bash-pipe" in res.stdout


def test_playbooks_test_technique_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "run_technique_test",
        lambda test_id, platform=None: {
            "test_id": test_id,
            "technique_id": "T1059.004",
            "name": "Base64 Obfuscated Shell Command",
            "tactic": "Execution",
            "status": "success",
            "exit_code": 0,
            "elapsed_ms": 42,
            "prereqs_met": True,
            "cleanup_status": "success",
            "events_count": 2,
            "alerts_count": 0,
            "stdout": "SIM_PASS",
            "stderr": "",
        },
    )
    res = runner.invoke(app, ["test", "T1059.004-bash-pipe"])
    assert res.exit_code == 0
    assert "Adversary Technique Test Result" in res.stdout
    assert "T1059.004" in res.stdout
    assert "SUCCESS" in res.stdout
    assert "SIM_PASS" in res.stdout
