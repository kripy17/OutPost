"""CLI regression tests for the intel force-refresh (mocked API):

- `outpost refresh <run_id> <ip>` prints the fresh verdict line (terminal
  mirror of the run-detail force-refresh button) and surfaces API errors.
- `render_network_table` carries the Checked (cache-age) column, matching the
  webapp's "checked Xh ago" label.

Run from cli/:  ../.venv/bin/pytest
"""

import typer
from rich.console import Console

from outpost.commands.refresh import refresh
from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console, render_network_table
from typer.testing import CliRunner

runner = CliRunner()


def test_refresh_prints_fresh_verdict(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "refresh_ip",
        lambda run_id, ip: {
            "ip": ip,
            "abuse_score": 55,
            "vt_malicious_count": None,
            "reputation": "malicious",
            "checked_at": "2026-08-09T11:50:37+00:00",
        },
    )
    with console.capture() as capture:
        # Direct call bypasses typer's bool coercion — pass stale=False
        # explicitly so the single-IP path runs (a bare typer.Option default
        # object is truthy).
        refresh("abc123", "203.0.113.77", stale=False)
    out = capture.get()
    assert "203.0.113.77" in out
    assert "malicious" in out and "abuse 55" in out
    assert "✓" in out


def test_refresh_stale_sweep_prints_count(monkeypatch):
    monkeypatch.setattr(api_client, "refresh_stale", lambda limit: {"refreshed": 3, "rows": []})
    result = runner.invoke(app, ["refresh", "--stale"])
    assert result.exit_code == 0
    assert "3" in result.output and "stale" in result.output


def test_refresh_stale_sweep_error_exits_1(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "refresh_stale",
        lambda limit: (_ for _ in ()).throw(api_client.APIError("POST /intel/refresh-stale → 500")),
    )
    result = runner.invoke(app, ["refresh", "--stale"])
    assert result.exit_code == 1
    assert "Refresh failed" in result.output


def test_refresh_missing_args_without_stale_exits_1():
    result = runner.invoke(app, ["refresh"])
    assert result.exit_code == 1


def test_refresh_api_error_exits_1(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "refresh_ip",
        lambda run_id, ip: (_ for _ in ()).throw(api_client.APIError("POST /runs/x/enrichment/refresh → 404")),
    )
    result = runner.invoke(app, ["refresh", "nope", "203.0.113.77"])
    assert result.exit_code == 1
    assert "Refresh failed" in result.output


def test_network_table_checked_column_matches_webapp_label():
    from datetime import datetime, timedelta, timezone

    conn = {
        "dest_ip": "203.0.113.88",
        "dest_port": 4444,
        "protocol": "TCP",
        "first_seen": "2026-08-09T10:00:00Z",
        "reputation": "suspicious",
        "abuse_score": None,
        "vt_malicious_count": None,
        "checked_at": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
    }
    table = render_network_table([conn])
    with console.capture() as capture:
        console.print(table)
    out = capture.get()
    assert "Checked" in out
    assert "5h ago" in out


def test_network_table_checked_dash_when_never_checked():
    conn = {
        "dest_ip": "203.0.113.88",
        "dest_port": 443,
        "protocol": "TCP",
        "first_seen": "2026-08-09T10:00:00Z",
        "reputation": "unknown",
        "abuse_score": None,
        "vt_malicious_count": None,
        "checked_at": None,
    }
    table = render_network_table([conn])
    with console.capture() as capture:
        console.print(table)
    out = capture.get()
    assert "Checked" in out
    # The row renders "-" for never-checked (not a bare "just now").
    assert "\n-\n" in out or "│ - " in out
