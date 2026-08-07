"""Regression tests for `outpost campaigns` rendering (mocked API).

The command is the terminal mirror of the webapp Campaigns view; these tests
lock its output: the signature IP, reputation badge, member rows, IOC
evidence, timeline tail, and the empty/error states.

Run from cli/:  ../.venv/bin/pytest
"""

import pytest
import typer
from rich.console import Console

import outpost.commands.campaigns as campaigns_mod
from outpost.commands.campaigns import campaigns
from outpost.lib import api_client
from outpost.rendering.terminal_views import console

# --- fixture: the live Shelf-Stack campaign, shaped exactly like GET /campaigns

_RUN_DETONATE = {
    "run_id": "c09f56bddca4", "sample_name": "detonate-demo.exe", "platform": "windows",
    "session_type": "analysis", "started_at": "2026-08-07T09:33:49+00:00",
    "completed_at": "2026-08-07T09:34:05+00:00", "process_count": 3, "unique_ips": 1,
    "alert_count": 6, "highest_severity": "malicious",
}
_RUN_VARIANT_A = {
    "run_id": "0302aa600d1d", "sample_name": "ACME_invoice.docm", "platform": "windows",
    "session_type": "analysis", "started_at": "2026-08-07T09:32:37+00:00",
    "completed_at": "2026-08-07T09:33:46+00:00", "process_count": 3, "unique_ips": 3,
    "alert_count": 5, "highest_severity": "malicious",
}
_RUN_VARIANT_B = {
    "run_id": "e4f15e059839", "sample_name": "invoice_lure.lnk", "platform": "windows",
    "session_type": "analysis", "started_at": "2026-08-07T09:32:44+00:00",
    "completed_at": "2026-08-07T09:33:00+00:00", "process_count": 2, "unique_ips": 2,
    "alert_count": 5, "highest_severity": "malicious",
}

_REGKEY = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"


def _event(run: dict, event_type: str, ts: str, pid: int, **extra) -> dict:
    base = {
        "id": None, "run_id": run["run_id"], "sample_name": run["sample_name"],
        "platform": "windows", "event_type": event_type, "timestamp": ts, "pid": pid,
        "ppid": None, "process_name": None, "command_line": None, "dest_ip": None,
        "dest_port": None, "protocol": None, "file_path": None, "registry_key": None,
    }
    base.update(extra)
    return base


def shelf_stack_fixture() -> list[dict]:
    return [
        {
            "key": "203.0.113.88",
            "reputation": "suspicious",
            "watchlist": True,
            "watchlist_label": "Shelf-Stack C2",
            "runs": [_RUN_DETONATE, _RUN_VARIANT_A, _RUN_VARIANT_B],
            "span_start": "2026-08-07T09:32:37+00:00",
            "span_end": "2026-08-07T09:34:05+00:00",
            "iocs": {
                "ips": [{"value": "203.0.113.88", "runs": 3}],
                "registry_keys": [{"value": _REGKEY, "runs": 3}],
                "file_paths": [{"value": r"C:\Users\victim\Documents\invoice_000.enc", "runs": 2}],
                "processes": [
                    {"value": "powershell.exe", "runs": 3},
                    {"value": "winword.exe", "runs": 2},
                    {"value": "wscript.exe", "runs": 1},
                ],
            },
            "timeline": [
                _event(_RUN_VARIANT_A, "process_create", "2026-08-07T09:32:37+00:00", 1000,
                       process_name="winword.exe",
                       command_line=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE /q /n"),
                _event(_RUN_DETONATE, "network_connection", "2026-08-07T09:33:54+00:00", 2002,
                       dest_ip="203.0.113.88", dest_port=4444, protocol="TCP"),
                _event(_RUN_VARIANT_B, "registry_write", "2026-08-07T09:32:56+00:00", 2000,
                       registry_key=_REGKEY),
            ],
        }
    ]


def test_campaigns_renders_signature_ip_badge_and_member_rows(monkeypatch):
    monkeypatch.setattr(api_client, "get_campaigns", lambda: shelf_stack_fixture())

    # Render at a realistic terminal width: the default 80-col capture would
    # ellipsize long IOC values (regkeys, file paths) and hide them entirely.
    wide = Console(width=160)
    monkeypatch.setattr(campaigns_mod, "console", wide)
    with wide.capture() as capture:
        campaigns()
    out = capture.get()

    # Signature IP + reputation badge + span.
    assert "203.0.113.88" in out
    assert "★ suspicious (Shelf-Stack C2)" in out
    assert "3 run(s)" in out

    # Member rows.
    for sample in ("detonate-demo.exe", "ACME_invoice.docm", "invoice_lure.lnk"):
        assert sample in out
    assert "c09f56bddca4" in out
    assert "● malicious" in out

    # IOC evidence + run-attributed timeline tail.
    assert _REGKEY in out
    assert "powershell.exe" in out
    assert "network_connection" in out
    assert "invoice_000.enc" in out


def test_campaigns_empty_state(monkeypatch):
    monkeypatch.setattr(api_client, "get_campaigns", lambda: [])

    with console.capture() as capture:
        campaigns()

    assert "No campaigns yet" in capture.get()


def test_campaigns_api_error_exits_with_message(monkeypatch):
    def boom():
        raise api_client.APIError("GET /campaigns → 500")

    monkeypatch.setattr(api_client, "get_campaigns", boom)

    with console.capture() as capture:
        with pytest.raises(typer.Exit) as exc:
            campaigns()

    assert exc.value.exit_code == 1
    assert "Campaigns failed" in capture.get()
