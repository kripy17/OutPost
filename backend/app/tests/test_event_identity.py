"""Milestone 3 regression tests — Event and Process Identity.

Verifies:
1. Stable source event identifiers (`source_event_id`) and burst preservation:
   - Rapid bursts of identical events with distinct source_event_ids are preserved.
   - Collector retries with identical source_event_ids are deduplicated cleanly.
   - Missing source_event_ids fallback to natural key deduplication.
2. Compound process identity (`host_id + boot_id + pid + process_start_time`):
   - PID reuse across time on the same host builds separate tree nodes with correct children.
   - Host reboots (different boot_id) and multi-host fleets keep process lineage isolated.
   - Process summary endpoint queries by compound identity keys.
3. Normalization consistency:
   - Coercion of timestamps, host_id, boot_id, process_start_time, and raw records.
"""

from ..services.normalizer import normalize_event
from ..services.process_tree import build_process_tree
from .conftest import make_run


def test_normalizer_coerces_identity_and_timestamps():
    """Missing or diverse timestamp/identity representations normalize consistently."""
    # 1. Epoch float timestamp coerced to ISO string
    raw_epoch = {
        "run_id": "r1",
        "platform": "linux",
        "event_type": "process_create",
        "timestamp": 1721234567.89,
        "pid": "100",
        "ppid": "1",
        "process_name": "bash",
    }
    norm_epoch = normalize_event(raw_epoch)
    assert isinstance(norm_epoch["timestamp"], str)
    assert norm_epoch["pid"] == 100
    assert norm_epoch["host_id"] == "local"
    assert norm_epoch["boot_id"] == "default"
    assert norm_epoch["process_start_time"] == norm_epoch["timestamp"]

    # 2. Extract source_event_id from raw auditd record
    raw_audit = {
        "run_id": "r2",
        "platform": "linux",
        "event_type": "network_connection",
        "timestamp": "2026-08-01T10:00:00Z",
        "dest_ip": "1.2.3.4",
        "dest_port": "443",
        "raw_record": 'type=SYSCALL msg=audit(1721234567.123:4567): arch=c000003e syscall=42 success=yes pid=1002 comm="curl" saddr=0200115CC0A87158',
    }
    norm_audit = normalize_event(raw_audit)
    assert norm_audit["dest_port"] == 443
    assert norm_audit["source_event_id"] == "auditd:1721234567.123:4567"

    # 3. Explicit compound fields preserved
    raw_explicit = {
        "run_id": "r3",
        "platform": "windows",
        "event_type": "process_create",
        "timestamp": "2026-08-01T10:00:00Z",
        "pid": 500,
        "host_id": "workstation-01",
        "boot_id": "boot-uuid-abc",
        "process_start_time": "2026-08-01T09:59:58Z",
        "source_event_id": "sysmon:1:12345",
    }
    norm_explicit = normalize_event(raw_explicit)
    assert norm_explicit["host_id"] == "workstation-01"
    assert norm_explicit["boot_id"] == "boot-uuid-abc"
    assert norm_explicit["process_start_time"] == "2026-08-01T09:59:58Z"
    assert norm_explicit["source_event_id"] == "sysmon:1:12345"


def test_ingest_preserves_bursts_with_distinct_source_event_ids(client):
    """Rapid bursts of identical events with distinct source_event_ids are preserved,
    while retries with the same source_event_ids are deduplicated."""
    run_id = make_run(client)
    ts = "2026-08-01T12:00:00Z"

    # 3 identical beacon events within the same timestamp, but with unique source_event_ids
    burst = [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": ts,
            "pid": 4000,
            "dest_ip": "198.51.100.188",
            "dest_port": 443,
            "protocol": "TCP",
            "source_event_id": f"burst-beacon-{i}",
        }
        for i in range(3)
    ]

    # Ingest batch: all 3 must be accepted because source_event_ids are distinct
    resp = client.post("/ingest/batch", json=burst)
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 3

    # Re-shipping the exact same batch (e.g. shipper network retry) must drop duplicates
    retry_resp = client.post("/ingest/batch", json=burst)
    assert retry_resp.status_code == 202
    assert retry_resp.json()["accepted"] == 0

    # Verify run details has 3 events
    run_detail = client.get(f"/runs/{run_id}").json()
    assert len(run_detail["timeline"]) == 3


def test_process_tree_pid_reuse_disambiguation():
    """PID reuse across time produces separate ProcessNode instances and correctly
    attaches children to their respective parent invocation."""
    events = [
        # Process invocation 1: PID 100 started at 10:00:00
        {
            "host_id": "host-1",
            "boot_id": "boot-1",
            "pid": 100,
            "ppid": None,
            "process_name": "worker.exe",
            "command_line": "worker.exe --task 1",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
        # Child spawned by PID 100 (invocation 1) at 10:01:00
        {
            "host_id": "host-1",
            "boot_id": "boot-1",
            "pid": 200,
            "ppid": 100,
            "process_name": "helper1.exe",
            "command_line": "helper1.exe",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:01:00Z",
        },
        # PID 100 is reused 10 minutes later (invocation 2) at 10:10:00
        {
            "host_id": "host-1",
            "boot_id": "boot-1",
            "pid": 100,
            "ppid": None,
            "process_name": "cleanup.exe",
            "command_line": "cleanup.exe --all",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:10:00Z",
        },
        # Child spawned by PID 100 (invocation 2) at 10:11:00
        {
            "host_id": "host-1",
            "boot_id": "boot-1",
            "pid": 300,
            "ppid": 100,
            "process_name": "helper2.exe",
            "command_line": "helper2.exe",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:11:00Z",
        },
    ]

    roots = build_process_tree(events)
    # Both worker.exe and cleanup.exe are roots because ppid is None
    assert len(roots) == 2
    root_names = {r.process_name for r in roots}
    assert root_names == {"worker.exe", "cleanup.exe"}

    worker = next(r for r in roots if r.process_name == "worker.exe")
    cleanup = next(r for r in roots if r.process_name == "cleanup.exe")

    # Invocation 1 parented helper1.exe
    assert len(worker.children) == 1
    assert worker.children[0].process_name == "helper1.exe"
    assert worker.children[0].pid == 200

    # Invocation 2 parented helper2.exe
    assert len(cleanup.children) == 1
    assert cleanup.children[0].process_name == "helper2.exe"
    assert cleanup.children[0].pid == 300


def test_process_tree_multi_host_and_reboot_isolation():
    """Identical PIDs across different hosts or boots do not collapse or link across boundaries."""
    events = [
        # Host A process
        {
            "host_id": "host-alpha",
            "boot_id": "boot-1",
            "pid": 42,
            "ppid": None,
            "process_name": "alpha_daemon",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
        # Host B process with same PID 42
        {
            "host_id": "host-beta",
            "boot_id": "boot-1",
            "pid": 42,
            "ppid": None,
            "process_name": "beta_daemon",
            "event_type": "process_create",
            "process_start_time": "2026-08-01T10:00:00Z",
        },
    ]
    roots = build_process_tree(events)
    assert len(roots) == 2
    assert {r.process_name for r in roots} == {"alpha_daemon", "beta_daemon"}
    assert {r.host_id for r in roots} == {"host-alpha", "host-beta"}


def test_process_summary_compound_identity_endpoint(client):
    """GET /events/process-summary disambiguates with compound identity parameters."""
    run_id = make_run(client)
    t1 = "2026-08-01T10:00:00Z"
    t2 = "2026-08-01T12:00:00Z"

    ev1 = {
        "run_id": run_id,
        "platform": "linux",
        "event_type": "process_create",
        "timestamp": t1,
        "pid": 999,
        "process_name": "proc_alpha",
        "command_line": "proc_alpha --run1",
        "host_id": "host-test",
        "boot_id": "boot-A",
        "process_start_time": t1,
    }
    ev2 = {
        "run_id": run_id,
        "platform": "linux",
        "event_type": "process_create",
        "timestamp": t2,
        "pid": 999,
        "process_name": "proc_beta",
        "command_line": "proc_beta --run2",
        "host_id": "host-test",
        "boot_id": "boot-B",
        "process_start_time": t2,
    }

    client.post("/ingest/batch", json=[ev1, ev2])

    # Query with boot-A
    resp1 = client.get(
        "/events/process-summary",
        params={"pid": 999, "host_id": "host-test", "boot_id": "boot-A", "process_start_time": t1},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["process_name"] == "proc_alpha"
    assert data1["boot_id"] == "boot-A"
    assert data1["compound_key"] == "host-test:boot-A:999:2026-08-01T10:00:00Z"

    # Query with boot-B
    resp2 = client.get(
        "/events/process-summary",
        params={"pid": 999, "host_id": "host-test", "boot_id": "boot-B", "process_start_time": t2},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["process_name"] == "proc_beta"
    assert data2["boot_id"] == "boot-B"
    assert data2["compound_key"] == "host-test:boot-B:999:2026-08-01T12:00:00Z"


def test_extended_telemetry_schema_storage_and_retrieval(client):
    """Extended telemetry fidelity fields (user, parent_image, parent_command_line,
    hashes, integrity_level, session_id, connection_status, process_guid) store and round-trip."""
    run_id = make_run(client, sample_name="ext-telemetry")
    ts = "2026-08-01T14:00:00Z"

    event_payload = {
        "run_id": run_id,
        "platform": "windows",
        "event_type": "process_create",
        "timestamp": ts,
        "pid": 4444,
        "ppid": 1111,
        "process_name": "mimikatz.exe",
        "exe_path": "C:\\Tools\\mimikatz.exe",
        "command_line": "mimikatz.exe privilege::debug",
        "user": "CORP\\admin",
        "parent_image": "C:\\Windows\\cmd.exe",
        "parent_command_line": "cmd.exe /c start",
        "hashes": "SHA256=abcdef1234567890abcdef1234567890",
        "integrity_level": "High",
        "session_id": "0x1a2b",
        "connection_status": "established",
        "process_guid": "{DEADBEEF-CAFE-BABE-0123-456789ABCDEF}",
        "host_id": "endpoint-win-01",
        "boot_id": "boot-uuid-1",
        "source_event_id": "sysmon:1:999",
    }

    ingest_resp = client.post("/ingest/batch", json=[event_payload])
    assert ingest_resp.status_code == 202

    run_resp = client.get(f"/runs/{run_id}")
    assert run_resp.status_code == 200
    timeline = run_resp.json()["timeline"]
    assert len(timeline) == 1
    ev = timeline[0]

    assert ev["user"] == "CORP\\admin"
    assert ev["parent_image"] == "C:\\Windows\\cmd.exe"
    assert ev["parent_command_line"] == "cmd.exe /c start"
    assert ev["hashes"] == "SHA256=abcdef1234567890abcdef1234567890"
    assert ev["integrity_level"] == "High"
    assert ev["session_id"] == "0x1a2b"
    assert ev["connection_status"] == "established"
    assert ev["process_guid"] == "{DEADBEEF-CAFE-BABE-0123-456789ABCDEF}"
