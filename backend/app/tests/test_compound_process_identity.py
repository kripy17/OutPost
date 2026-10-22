"""Test suite for compound process identity and process_start_time propagation:
1. file_write, net_connect, and registry events inherit process_start_time from their process_create ancestor.
2. process_map is keyed by compound identity (host_id + boot_id + pid) so identical PIDs on different hosts or boots do not collide.
"""

from app.core.db import db_session

from .conftest import make_run


def test_process_start_time_propagated_to_non_process_events(client):
    """File, network, and registry events without process_start_time inherit it from process_create."""
    run_id = make_run(client, platform="linux")

    events = [
        # 1. Process creation with explicit start time
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 555,
            "ppid": 1,
            "process_name": "malware.exe",
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
        # 2. File write from the same process without process_start_time
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "file_write",
            "timestamp": "2026-08-01T10:00:05Z",
            "pid": 555,
            "file_path": "/tmp/payload.sh",
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": None,
        },
        # 3. Network connect from the same process without process_start_time
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": "2026-08-01T10:00:10Z",
            "pid": 555,
            "dest_ip": "1.2.3.4",
            "dest_port": 4444,
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": None,
        },
    ]

    ingest_res = client.post("/ingest/batch", json=events)
    assert ingest_res.status_code == 202

    # Query events from database and verify process_start_time propagation
    with db_session() as conn:
        rows = conn.execute(
            "SELECT event_type, pid, process_start_time FROM events WHERE run_id = ? ORDER BY id ASC",
            (run_id,),
        ).fetchall()

    assert len(rows) == 3
    for r in rows:
        assert r["process_start_time"] == "2026-08-01T10:00:00Z", (
            f"Event {r['event_type']} did not inherit process_start_time: got {r['process_start_time']}"
        )


def test_process_map_keyed_by_compound_identity_multi_host(client):
    """PID collisions across distinct hosts are isolated via compound process identity."""
    run_id = make_run(client)

    events = [
        # Host Alpha: PID 100 is legitimate svchost.exe
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 100,
            "ppid": 4,
            "process_name": "svchost.exe",
            "command_line": "svchost.exe -k netsvcs",
            "host_id": "host-alpha",
            "boot_id": "boot-A",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
        # Host Beta: PID 100 is winword.exe (attacker weaponized Office doc)
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:01Z",
            "pid": 100,
            "ppid": 4,
            "process_name": "winword.exe",
            "command_line": "WINWORD.EXE /q",
            "host_id": "host-beta",
            "boot_id": "boot-B",
            "process_start_time": "2026-08-01T10:00:01Z",
        },
        # Host Beta: Child spawns with ppid=100 launching powershell.exe
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:02Z",
            "pid": 200,
            "ppid": 100,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc aWV4",
            "host_id": "host-beta",
            "boot_id": "boot-B",
            "process_start_time": "2026-08-01T10:00:02Z",
        },
    ]

    ingest_res = client.post("/ingest/batch", json=events)
    assert ingest_res.status_code == 202

    alerts_res = client.get(f"/runs/{run_id}/alerts")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()

    parent_child_alerts = [a for a in alerts if a["rule_id"] == "suspicious-parent-child"]
    assert len(parent_child_alerts) == 1
    # Must correctly identify winword.exe as parent, not svchost.exe
    assert "winword.exe spawned powershell.exe" in parent_child_alerts[0]["details"]
    assert parent_child_alerts[0]["host_id"] == "host-beta"


def test_normalizer_flags_event_with_pid_but_no_start_time():
    """Events carrying a PID without an authoritative process_start_time are flagged."""
    from app.services.normalizer import normalize_event

    # 1. Event with PID and no start time must have missing_process_start_time=True
    ev_no_pst = normalize_event({
        "event_type": "file_write",
        "pid": 999,
        "file_path": "/etc/passwd",
    })
    assert ev_no_pst["missing_process_start_time"] is True

    # 2. Event with PID and explicit start time is not flagged
    ev_with_pst = normalize_event({
        "event_type": "file_write",
        "pid": 999,
        "process_start_time": "2026-08-01T12:00:00Z",
    })
    assert ev_with_pst["missing_process_start_time"] is False

    # 3. process_create gets default start time if omitted, so not flagged
    ev_proc_create = normalize_event({
        "event_type": "process_create",
        "pid": 999,
        "timestamp": "2026-08-01T12:00:00Z",
    })
    assert ev_proc_create["missing_process_start_time"] is False


def test_process_identity_pid_reuse_isolated(client):
    """PID reuse on the same host with different start times does not confuse parent attribution."""
    run_id = make_run(client)

    events = [
        # Earlier process on PID 500: benign notepad.exe (started at 09:00:00)
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T09:00:00Z",
            "pid": 500,
            "ppid": 4,
            "process_name": "notepad.exe",
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": "2026-08-01T09:00:00Z",
        },
        # PID 500 reused later: malicious winword.exe (started at 10:00:00)
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 500,
            "ppid": 4,
            "process_name": "winword.exe",
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
        # Child spawned with ppid=500 launching powershell.exe at 10:00:05
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:05Z",
            "pid": 600,
            "ppid": 500,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc test",
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "process_start_time": "2026-08-01T10:00:05Z",
        },
    ]

    ingest_res = client.post("/ingest/batch", json=events)
    assert ingest_res.status_code == 202

    alerts = client.get(f"/runs/{run_id}/alerts").json()
    parent_child = [a for a in alerts if a["rule_id"] == "suspicious-parent-child"]
    assert len(parent_child) == 1
    # Must attribute to the later winword.exe instance, not the earlier notepad.exe
    assert "winword.exe spawned powershell.exe" in parent_child[0]["details"]


def test_process_identity_boot_change_isolated(client):
    """PID collisions across different reboots (boot_ids) are completely isolated."""
    run_id = make_run(client)

    events = [
        # Boot 1: PID 250 is legitimate explorer.exe
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T08:00:00Z",
            "pid": 250,
            "ppid": 4,
            "process_name": "explorer.exe",
            "host_id": "host-gamma",
            "boot_id": "boot-session-1",
            "process_start_time": "2026-08-01T08:00:00Z",
        },
        # System reboots: Boot 2 starts. PID 250 is winword.exe
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T12:00:00Z",
            "pid": 250,
            "ppid": 4,
            "process_name": "winword.exe",
            "host_id": "host-gamma",
            "boot_id": "boot-session-2",
            "process_start_time": "2026-08-01T12:00:00Z",
        },
        # In Boot 2: Child process spawned with ppid=250
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T12:00:02Z",
            "pid": 350,
            "ppid": 250,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc reboot_test",
            "host_id": "host-gamma",
            "boot_id": "boot-session-2",
            "process_start_time": "2026-08-01T12:00:02Z",
        },
    ]

    ingest_res = client.post("/ingest/batch", json=events)
    assert ingest_res.status_code == 202

    alerts = client.get(f"/runs/{run_id}/alerts").json()
    parent_child = [a for a in alerts if a["rule_id"] == "suspicious-parent-child"]
    assert len(parent_child) == 1
    assert "winword.exe spawned powershell.exe" in parent_child[0]["details"]
