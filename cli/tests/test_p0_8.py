"""P0.8 — CLI parity for the P0.5/P0.6/P0.7 client contracts.

The webapp (frontend/src/lib/api.ts) and CLI (outpost/lib/api_client.py) are
two clients of the same API. These tests pin the terminal mirrors:
- `outpost search --global` renders the grouped GET /search envelope
- `outpost hosts timeline <host>` renders the host aggregate timeline
- api_client.global_search / host_timeline / analysis-job functions hit the
  right endpoints with the right params (checked via monkeypatched _get).

Each test monkeypatches api_client's HTTP helpers, so no backend is needed.
"""

from outpost.lib import api_client
from outpost.main import app
from outpost.rendering.terminal_views import console
from typer.testing import CliRunner

runner = CliRunner()


def _search_response(groups_with: dict[str, int]) -> dict:
    groups = {
        "findings": {"total": 0, "hits": []},
        "iocs": {"total": 0, "hits": []},
        "artifacts": {"total": 0, "hits": []},
        "hosts": {"total": 0, "hits": []},
        "sessions": {"total": 0, "hits": []},
        "investigations": {"total": 0, "hits": []},
        "campaigns": {"total": 0, "hits": []},
    }
    for g, total in groups_with.items():
        groups[g] = {"total": total, "hits": [{"group": g, "id": "x1", "kind": "malicious", "title": "beaconing", "subtitle": "203.0.113.1", "payload": {}}]}
    return {"q": "203.0.113.1", "qualifiers": {}, "groups": groups}


def test_search_global_flag_renders_groups(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "global_search",
        lambda q, limit=10: _search_response({"findings": 2, "iocs": 1}),
    )
    result = runner.invoke(app, ["search", "203.0.113.1", "--global"])
    assert result.exit_code == 0
    assert "findings · 2 match(es)" in result.output
    assert "iocs · 1 match(es)" in result.output
    assert "beaconing" in result.output
    # Groups with zero matches are hidden.
    assert "campaigns" not in result.output


def test_search_global_no_matches(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "global_search",
        lambda q, limit=10: _search_response({}),
    )
    result = runner.invoke(app, ["search", "zzz", "--global"])
    assert result.exit_code == 0
    assert "No matches for" in result.output


def test_hosts_timeline_renders_feed(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "host_timeline",
        lambda host_id, kind=None, event_type=None, q=None, limit=50, offset=0: {
            "host_id": host_id, "platform": "linux", "last_heartbeat": None,
            "total": 3, "limit": limit, "offset": offset,
            "timeline": [
                {"kind": "finding", "timestamp": "2026-08-17T10:00:00Z", "id": "7", "title": "C2-style beaconing", "subtitle": "malicious · open · run1", "payload": {}},
                {"kind": "session", "timestamp": "2026-08-17T09:00:00Z", "id": "run1", "title": "p08-sample.bin", "subtitle": "analysis_job · linux · completed", "payload": {}},
                {"kind": "ioc", "timestamp": "2026-08-17T08:00:00Z", "id": "ioc1", "title": "203.0.113.1", "subtitle": "ip · candidate", "payload": {}},
            ],
        },
    )
    result = runner.invoke(app, ["hosts", "timeline", "archlinux"])
    assert result.exit_code == 0
    assert "archlinux" in result.output
    assert "3 timeline entries" in result.output
    assert "C2-style beaconing" in result.output
    assert "203.0.113.1" in result.output


def test_hosts_timeline_empty(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client, "host_timeline",
        lambda host_id, kind=None, event_type=None, q=None, limit=50, offset=0: {
            "host_id": host_id, "platform": None, "last_heartbeat": None,
            "total": 0, "limit": limit, "offset": offset, "timeline": [],
        },
    )
    result = runner.invoke(app, ["hosts", "timeline", "quiet-host"])
    assert result.exit_code == 0
    assert "No activity for this host yet" in result.output


# ---------------------------------------------------------------------------
# api_client contract — the functions hit the right endpoints (terminal
# parity with frontend/src/lib/api.ts). Monkeypatch _get/_post and assert
# the exact path + params.
# ---------------------------------------------------------------------------


def test_global_search_hits_search_endpoint(monkeypatch):
    captured = {}

    def fake_get(path: str):
        captured["path"] = path
        return _search_response({})

    monkeypatch.setattr(api_client, "_get", fake_get)
    api_client.global_search("203.0.113.1", limit=5)
    assert captured["path"] == "/search?q=203.0.113.1&limit=5"


def test_host_timeline_hits_timeline_endpoint(monkeypatch):
    captured = {}

    def fake_get(path: str):
        captured["path"] = path
        return {"host_id": "h", "total": 0, "limit": 50, "offset": 0, "timeline": []}

    monkeypatch.setattr(api_client, "_get", fake_get)
    api_client.host_timeline("archlinux", kind="finding", q="beacon", limit=20, offset=40)
    assert captured["path"] == "/hosts/archlinux/timeline?kind=finding&q=beacon&limit=20&offset=40"


def test_analysis_job_functions_hit_endpoints(monkeypatch):
    captured = {}

    def fake_get(path: str):
        captured["path"] = path
        return {}

    def fake_post(path: str, body: dict | None = None):
        captured["path"] = path
        captured["body"] = body
        return {}

    monkeypatch.setattr(api_client, "_get", fake_get)
    api_client.get_analysis_job("run1")
    assert captured["path"] == "/analysis/run1"
    api_client.list_analysis_jobs(backend="static", status="completed")
    assert captured["path"] == "/analysis?backend=static&status=completed&limit=50&offset=0"

    monkeypatch.setattr(api_client, "_post", fake_post)
    api_client.create_analysis_job("watched-host", sample_name="x.bin", platform="linux")
    assert captured["path"] == "/analysis"
    assert captured["body"] == {"backend": "watched-host", "sample_name": "x.bin", "platform": "linux"}
    api_client.cancel_analysis_job("run1")
    assert captured["path"] == "/analysis/run1/cancel"


def test_upload_sample_and_run_isolated(monkeypatch, tmp_path):
    test_file = tmp_path / "implant.sh"
    test_file.write_bytes(b"#!/bin/bash\necho 'payload'\n")

    monkeypatch.setattr(
        api_client,
        "upload_sample",
        lambda data, name: {"sample_id": "spl_123", "original_name": name, "size": len(data)},
    )
    monkeypatch.setattr(
        api_client,
        "detonate_sample",
        lambda sid, timeout: {
            "run_id": "dyn_run_999",
            "sample_id": sid,
            "exit_code": 0,
            "events_count": 8,
            "alerts_count": 1,
            "risk_score": 75,
            "terminal_output": "[OutPost Dynamic Sandbox] Detonation complete.",
        },
    )
    monkeypatch.setattr(
        api_client,
        "get_run",
        lambda rid: {
            "run_id": rid,
            "sample_name": "implant.sh",
            "started_at": "2026-08-30T10:00:00Z",
            "completed_at": "2026-08-30T10:00:10Z",
            "events": [],
            "alerts": [],
            "tree": [],
            "risk_score": 75,
        },
    )

    result = runner.invoke(app, ["run", str(test_file), "--isolated", "--timeout", "10"])
    assert result.exit_code == 0
    assert "Uploading 'implant.sh' to sandbox vault" in result.output
    assert "Dynamic Detonation Completed (Run ID: dyn_run_999)" in result.output
    assert "Risk Score: 75" in result.output

