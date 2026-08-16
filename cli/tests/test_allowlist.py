"""CLI regression tests for `outpost allowlist add|list|remove` — the
terminal mirror of the webapp's run-detail IOC allowlist panel. Same
contract: an entry stops matching alerts from firing on the run's future
batches and auto-acks already-open matches (the `acked` count).
"""

import pytest
from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()

RUN = "run-abc123"


def _entry(entry_id: int = 1, kind: str = "ip", value: str = "203.0.113.88", note: str = "scanner") -> dict:
    return {"id": entry_id, "run_id": RUN, "kind": kind, "value": value, "note": note,
            "created_at": "2026-08-16T10:00:00Z", "acked": 0}


def test_allowlist_add_posts_kind_value_note(monkeypatch):
    captured = {}

    def fake_add(run_id, kind, value, note=""):
        captured.update(run_id=run_id, kind=kind, value=value, note=note)
        return {**_entry(), "acked": 2}

    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(api_client, "add_run_allowlist", fake_add)
    result = runner.invoke(app, ["allowlist", "add", RUN, "ip", "203.0.113.88", "--note", "our scanner"])
    assert result.exit_code == 0
    assert captured == {"run_id": RUN, "kind": "ip", "value": "203.0.113.88", "note": "our scanner"}
    assert "Allowlisted ip 203.0.113.88" in result.output
    assert "2 matching alert(s) auto-acknowledged" in result.output


def test_allowlist_add_invalid_kind_exits_1(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    result = runner.invoke(app, ["allowlist", "add", RUN, "banana", "203.0.113.88"])
    assert result.exit_code == 1
    assert "kind must be one of" in result.output


def test_allowlist_list_renders_table(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "get_run_allowlist",
        lambda run_id: [_entry(1, "ip", "203.0.113.88", "scanner"), _entry(2, "process", "powershell.exe", "")],
    )
    result = runner.invoke(app, ["allowlist", "list", RUN])
    assert result.exit_code == 0
    assert "203.0.113.88" in result.output
    assert "powershell.exe" in result.output
    assert "scanner" in result.output


def test_allowlist_list_empty_message(monkeypatch):
    monkeypatch.setattr(api_client, "get_run_allowlist", lambda run_id: [])
    result = runner.invoke(app, ["allowlist", "list", RUN])
    assert result.exit_code == 0
    assert "No allowlisted IOCs" in result.output


def test_allowlist_remove_deletes_by_id(monkeypatch):
    captured = {}

    def fake_remove(run_id, entry_id):
        captured.update(run_id=run_id, entry_id=entry_id)

    monkeypatch.setattr(api_client, "remove_run_allowlist", fake_remove)
    result = runner.invoke(app, ["allowlist", "remove", RUN, "7"])
    assert result.exit_code == 0
    assert captured == {"run_id": RUN, "entry_id": 7}
    assert "Removed allowlist entry 7" in result.output


def test_allowlist_api_error_exits_1(monkeypatch):
    def boom(run_id, kind, value, note=""):
        raise api_client.APIError("backend down")

    monkeypatch.setattr(api_client, "add_run_allowlist", boom)
    result = runner.invoke(app, ["allowlist", "add", RUN, "ip", "203.0.113.88"])
    assert result.exit_code == 1
    assert "Allowlist failed" in result.output


# -- DELETE contract (the webapp's relaxed 200/204 rule, terminal side) -------

class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


def _fake_delete(monkeypatch, status_code: int):
    calls = []

    def fake_delete(url, **kwargs):
        calls.append(url)
        return _FakeResponse(status_code)

    monkeypatch.setattr(api_client.requests, "delete", fake_delete)
    return calls


def test_remove_run_allowlist_accepts_204_and_200(monkeypatch):
    calls = _fake_delete(monkeypatch, 204)
    api_client.remove_run_allowlist(RUN, 1)
    assert calls == [f"{api_client.BASE_URL}/runs/{RUN}/allowlist/1"]

    calls = _fake_delete(monkeypatch, 200)
    api_client.remove_run_allowlist(RUN, 2)  # must not raise


def test_remove_run_allowlist_rejects_500(monkeypatch):
    _fake_delete(monkeypatch, 500)
    with pytest.raises(api_client.APIError) as exc:
        api_client.remove_run_allowlist(RUN, 1)
    assert "DELETE /runs/run-abc123/allowlist/1 → 500" in str(exc.value)
