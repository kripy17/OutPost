"""Tests for Double-Layer Dynamic Analysis & Behavioral Forecasting in CLI."""

from typer.testing import CliRunner
from outpost.main import app
from outpost.lib import api_client

runner = CliRunner()

MOCK_FORECAST = {
    "sample_name": "trojan_miner.elf",
    "platform": "linux",
    "predicted_threat_level": "malicious",
    "confidence_score": 85,
    "static_risk_score": 90,
    "summary": "Sample exhibits outbound C2 socket activity to 198.51.100.44 with shell process execution.",
    "anticipated_actions": [
        {
            "id": "act_net_c2",
            "category": "c2_beaconing",
            "title": "Outbound C2 Communication & Network Beaconing",
            "severity": "critical",
            "description": "Anticipated outbound socket creation targeting 198.51.100.44.",
            "confidence": "high",
            "indicators": ["198.51.100.44"],
        },
        {
            "id": "act_subshell",
            "category": "subshell_execution",
            "title": "Subshell & Process Execution",
            "severity": "high",
            "description": "Subprocess spawn signatures (/bin/sh).",
            "confidence": "high",
            "indicators": ["/bin/sh"],
        },
    ],
    "predicted_endpoints": [
        {
            "endpoint": "198.51.100.44",
            "type": "ipv4",
            "protocol": "TCP",
            "port": 443,
            "confidence": "high",
        }
    ],
    "predicted_mitre_techniques": [
        {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
        {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    ],
    "predicted_file_drops": [
        {"path": "/tmp/payload.bin", "reason": "Extracted from strings table"},
    ],
}

MOCK_DETONATION_RESULT = {
    "run_id": "dyn_test_run_123",
    "sample_id": "s_test_456",
    "sample_name": "trojan_miner.elf",
    "isolation_driver": "bubblewrap",
    "exit_code": 0,
    "events_count": 5,
    "alerts_count": 2,
    "risk_score": 85,
    "terminal_output": "[OutPost Sandbox Cage Active]\nExecuting trojan_miner.elf...\nOutbound socket connected to 198.51.100.44:443\nExit 0",
    "forecast": MOCK_FORECAST,
    "reconciliation": {
        "accuracy_score": 100,
        "confirmed_count": 2,
        "dormant_count": 0,
        "discovered_count": 1,
        "confirmed_predictions": [
            {
                "title": "Network C2 Connection (198.51.100.44)",
                "evidence": "Observed network socket connection targeting predicted endpoint 198.51.100.44",
            },
            {
                "title": "Subshell & Process Execution",
                "evidence": "Observed process execution: /bin/sh",
            },
        ],
        "dormant_predictions": [],
        "discovered_runtime_actions": [
            {
                "title": "Triggered 2 Detection Rule Alert(s)",
                "evidence": "Rules: rule_c2_beaconing",
            }
        ],
        "evasion_detected": False,
    },
}


def test_cli_samples_forecast(monkeypatch):
    monkeypatch.setattr(api_client, "get_sample_forecast", lambda sample_id: MOCK_FORECAST)

    res = runner.invoke(app, ["samples", "--forecast", "s_test_456"])
    assert res.exit_code == 0
    assert "Layer 1: Pre-Execution Behavioral Threat Forecast" in res.stdout
    assert "MALICIOUS" in res.stdout
    assert "198.51.100.44" in res.stdout
    assert "T1071.001" in res.stdout
    assert "T1059.004" in res.stdout


def test_cli_samples_detonate_two_layer_yes(monkeypatch):
    monkeypatch.setattr(api_client, "get_sample_forecast", lambda sample_id: MOCK_FORECAST)
    monkeypatch.setattr(api_client, "detonate_sample", lambda sample_id, timeout=15: MOCK_DETONATION_RESULT)

    res = runner.invoke(app, ["samples", "--detonate", "s_test_456", "--yes"])
    assert res.exit_code == 0
    # Layer 1
    assert "Layer 1: Pre-Execution Behavioral Threat Forecast" in res.stdout
    # Layer 2
    assert "Layer 2: Live Dynamic Sandbox Execution" in res.stdout
    assert "dyn_test_run_123" in res.stdout
    assert "bubblewrap" in res.stdout
    # Verification matrix
    assert "Forecast Verification Matrix" in res.stdout
    assert "Accuracy: 100%" in res.stdout
    assert "CONFIRMED" in res.stdout


def test_cli_samples_detonate_abort(monkeypatch):
    monkeypatch.setattr(api_client, "get_sample_forecast", lambda sample_id: MOCK_FORECAST)

    res = runner.invoke(app, ["samples", "--detonate", "s_test_456"], input="n\n")
    assert res.exit_code == 0
    assert "Layer 1: Pre-Execution Behavioral Threat Forecast" in res.stdout
    assert "Detonation cancelled by user" in res.stdout
