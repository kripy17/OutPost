"""Tests for detection-depth batch B — lateral movement, log-clearing, and DNS channels.

Lateral movement (T1021): PsExec/SMB-admin, WinRM/WMI, SMB share enumeration,
and RDP connection bursts. Defense evasion (T1070): logging services being
stopped and log stores purged. Command and control (T1071.004): DNS tunneling
bursts, single absurd DNS labels, and DNS on non-standard ports.
"""

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


def _proc(run_id: str, pid: int, cmd: str, platform: str = "windows", ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": platform, "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": 1, "process_name": "cmd.exe" if platform == "windows" else "bash",
        "command_line": cmd,
    }


def _net(run_id: str, ip: str, port: int, pid: int = 100, ts: int = 0, query: str | None = None) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "process_name": "evil.exe",
        "dest_ip": ip, "dest_port": port, "protocol": "TCP", "query": query,
    }


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


# -- Lateral movement ---------------------------------------------------------


def test_lateral_psexec_smb_admin_mount(client):
    run_id = make_run(client, sample_name="psexec.bat")
    _ingest(client, run_id, [
        _proc(run_id, 100, r"net use \\\\192.168.1.50\\admin$ /user:admin p@ss", ts=1),
        _proc(run_id, 101, r"psexec \\192.168.1.50 -s cmd.exe", ts=2),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lateral-psexec-smb"]
    assert len(fired) == 2  # admin$ mount + the psexec invocation itself
    assert any("admin$" in a["details"] for a in fired)
    assert any("PsExec" in a["details"] for a in fired)


def test_lateral_winrm_wmi_remote_exec(client):
    run_id = make_run(client, sample_name="winrm.ps1")
    _ingest(client, run_id, [
        _proc(run_id, 100, "powershell.exe -Command Invoke-Command -ComputerName dc01 -ScriptBlock {whoami}", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lateral-winrm-wmi"]
    assert len(fired) == 1
    assert "Invoke-Command" in fired[0]["details"]


def test_lateral_smb_share_enumeration(client):
    run_id = make_run(client, sample_name="netview.bat")
    _ingest(client, run_id, [
        _proc(run_id, 100, "net view \\\\192.168.1.50", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lateral-smb-share"]
    assert len(fired) == 1
    assert "net view" in fired[0]["details"]


def test_rdp_brute_force_burst(client):
    run_id = make_run(client, sample_name="rdp-spray.exe")
    events = [_net(run_id, "10.0.0.10", 3389, pid=100, ts=i) for i in range(4)]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "rdp-brute-force"]
    assert len(fired) == 1
    assert "3389" in fired[0]["details"]


def test_rdp_brute_force_single_connection_is_not_a_spray(client):
    run_id = make_run(client, sample_name="rdp-once.exe")
    _ingest(client, run_id, [_net(run_id, "10.0.0.10", 3389, pid=100, ts=1)])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "rdp-brute-force"]
    assert fired == []


# -- Log clearing / anti-forensics -------------------------------------------


def test_log_service_stop_auditd(client):
    run_id = make_run(client, sample_name="silence.sh", platform="linux")
    _ingest(client, run_id, [
        _proc(run_id, 100, "sudo systemctl stop auditd", platform="linux", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "log-service-stop"]
    assert len(fired) == 1
    assert "auditd" in fired[0]["details"]


def test_log_clearing_wevtutil(client):
    run_id = make_run(client, sample_name="wipe.bat")
    _ingest(client, run_id, [
        _proc(run_id, 100, "wevtutil cl Security", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "log-clearing"]
    assert len(fired) == 1
    assert "wevtutil" in fired[0]["details"]


def test_log_clearing_journal_vacuum(client):
    run_id = make_run(client, sample_name="vacuum.sh", platform="linux")
    _ingest(client, run_id, [
        _proc(run_id, 100, "journalctl --vacuum-time=1s", platform="linux", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "log-clearing"]
    assert len(fired) == 1
    assert "journal" in fired[0]["details"]


# -- DNS channels -------------------------------------------------------------


def _dns_label(n: int, base: str = "c2.example.com") -> str:
    return f"{'a' * n}.{base}"


def test_dns_tunneling_burst(client):
    run_id = make_run(client, sample_name="dns-tunnel.exe")
    events = [
        _net(run_id, "198.51.100.70", 53, pid=100, ts=i, query=_dns_label(20 + i, "tunnel.example.com"))
        for i in range(6)
    ]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "dns-tunneling"]
    assert len(fired) == 1
    assert "6 distinct" in fired[0]["details"]


def test_dns_tunneling_normal_queries_stay_quiet(client):
    run_id = make_run(client, sample_name="normal-dns.exe")
    events = [
        _net(run_id, "198.51.100.71", 53, pid=100, ts=i, query=f"www{chr(97+i)}.example.com")
        for i in range(6)
    ]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "dns-tunneling"]
    assert fired == []


def test_dns_long_label_single_query(client):
    run_id = make_run(client, sample_name="dga.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.72", 53, pid=100, ts=1, query=_dns_label(30, "dga.example.com")),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "dns-long-label"]
    assert len(fired) == 1
    assert "dga" in fired[0]["details"]


def test_dns_unusual_port(client):
    run_id = make_run(client, sample_name="doh-covert.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.73", 5353, pid=100, ts=1, query="update.example.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "dns-unusual-port"]
    assert len(fired) == 1
    assert "5353" in fired[0]["details"]


def test_dns_unusual_port_normal_port_quiet(client):
    run_id = make_run(client, sample_name="normal-dns53.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.74", 53, pid=100, ts=1, query="www.example.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "dns-unusual-port"]
    assert fired == []
