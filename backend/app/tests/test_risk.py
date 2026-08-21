"""Tests for roadmap 1.3 — run risk score + MITRE ATT&CK metadata."""

import datetime

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _proc(run_id: str, pid: int, ppid: int, name: str, cmd: str = "", ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _net(run_id: str, ip: str, port: int = 4444, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": 1, "dest_ip": ip, "dest_port": port,
        "protocol": "TCP",
    }


def test_compute_risk_score_weights_distinct_rules():
    from ..services.risk import compute_risk_score

    # masquerading 20 + lolbin 14 = 34; the duplicate lolbin must not stack.
    assert compute_risk_score(["masquerading", "lolbin-abuse", "lolbin-abuse"]) == 34
    # All eight rules — capped at 100, never above.
    all_rules = [
        "masquerading", "suspicious-parent-child", "lolbin-abuse", "beaconing",
        "registry-persistence", "autostart-persistence", "rename-burst",
        "first-seen-process",
    ]
    assert 0 < compute_risk_score(all_rules) <= 100
    # Unknown rule ids contribute 0.
    assert compute_risk_score(["future-rule"]) == 0
    assert compute_risk_score([]) == 0


def test_run_summary_includes_risk_score(client):
    run_id = make_run(client)
    # beaconing (15) + registry-persistence (16) + unusual-port (10 on :4444) = 41
    _ingest(client, run_id, [_net(run_id, "203.0.113.31", ts=i) for i in range(5, 14, 2)])
    _ingest(client, run_id, [{
        "run_id": run_id, "platform": "windows", "event_type": "registry_write",
        "timestamp": _ts(30), "pid": 1,
        "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad",
    }])

    runs = client.get("/runs", params={"include_synthetic": "true"}).json()
    me = [r for r in runs if r["run_id"] == run_id][0]
    assert me["risk_score"] == 41
    detail = client.get(f"/runs/{run_id}").json()
    assert detail["run"]["risk_score"] == 41


def test_rules_meta_endpoint(client):
    resp = client.get("/rules/meta")
    assert resp.status_code == 200
    by_id = {m["rule_id"]: m for m in resp.json()}
    assert by_id["beaconing"]["technique"] == "T1071.001"
    assert by_id["beaconing"]["tactic"] == "Command and Control"
    assert by_id["rename-burst"]["weight"] == 22
    assert all({"rule_id", "rule_name", "technique", "tactic", "weight"} <= set(m) for m in by_id.values())
