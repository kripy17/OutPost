"""Tests for OutPost CLI status, doctor, version, and launcher script."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import typer
from typer.testing import CliRunner

from outpost.main import app
from outpost.commands.status import status, doctor
from outpost.rendering.terminal_views import console

runner = CliRunner()


def test_cli_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "OutPost v0.1.0" in result.stdout


def test_cli_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "OutPost v0.1.0" in result.stdout


def test_cli_status_command_offline(monkeypatch):
    # Ensure offline by pointing to invalid port
    monkeypatch.setenv("OUTPOST_API_URL", "http://127.0.0.1:59999")
    with console.capture() as capture:
        status(ctx=MagicMock(invoked_subcommand=None))
    out = capture.get()

    assert "OutPost Platform Status" in out
    assert "Backend API" in out
    assert "SQLite Store" in out
    assert "OFFLINE" in out


def test_cli_status_command_online(monkeypatch):
    def mock_get(url, *args, **kwargs):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.json.return_value = {"demo_mode": False}
        return resp

    monkeypatch.setattr("requests.get", mock_get)

    with console.capture() as capture:
        status(ctx=MagicMock(invoked_subcommand=None))
    out = capture.get()

    assert "OutPost Platform Status" in out
    assert "ONLINE" in out


def test_cli_doctor_command():
    with console.capture() as capture:
        doctor()
    out = capture.get()

    assert "OutPost Diagnostic Doctor" in out
    assert "Python >= 3.10" in out
    assert "Virtualenv Active" in out
    assert "PASS" in out


def test_samples_offline_fallback(monkeypatch):
    from outpost.commands.samples import samples
    from outpost.lib import api_client

    def mock_fail(q=""):
        raise api_client.APIError("Backend unreachable")

    monkeypatch.setattr(api_client, "list_samples", mock_fail)

    with console.capture() as capture:
        samples()
    out = capture.get()

    assert "Backend offline — showing samples directly from local SQLite database" in out or "No samples in the vault yet" in out


def test_outpost_sh_script_execution():
    root = Path(__file__).resolve().parent.parent.parent
    script = root / "outpost.sh"
    assert script.exists()

    # Test --help
    res_help = subprocess.run([str(script), "--help"], capture_output=True, text=True, cwd=str(root))
    assert res_help.returncode == 0
    assert "OutPost" in res_help.stdout
    assert "SERVICE STACK OPERATIONS" in res_help.stdout

    # Test --version
    res_ver = subprocess.run([str(script), "--version"], capture_output=True, text=True, cwd=str(root))
    assert res_ver.returncode == 0
    assert "OutPost v0.1.0" in res_ver.stdout

    # Test status
    res_status = subprocess.run([str(script), "status"], capture_output=True, text=True, cwd=str(root))
    assert res_status.returncode == 0
    assert "OutPost Platform Status" in res_status.stdout
