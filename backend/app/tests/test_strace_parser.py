"""Tests for Strace Parser, Process Lifecycle Attributor, and Timeline Sequencer.

Test oracle: The source code and README.md ground-truth tables of the harmless probes
(tests/probes/c_probe/README.md, tests/probes/shell_probe/README.md, tests/probes/python_probe/README.md),
NOT parser output!
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.core.db import (
    DESTRUCTIVE_MIGRATIONS,
    ORDERED_MIGRATIONS,
    SCHEMA,
)
from app.services.strace_parser import StraceParser, parse_and_persist_strace_log

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures"


@pytest.fixture
def memory_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)

    # Insert a dummy run for foreign key validity
    conn.execute(
        """
        INSERT INTO runs (run_id, sample_name, platform, started_at)
        VALUES ('run_test_probe', 'probe_test', 'linux', '2026-10-27T00:00:00Z')
        """
    )
    conn.commit()
    yield conn
    conn.close()


def test_destructive_migration_registered():
    """Verify migration 35 is registered in DESTRUCTIVE_MIGRATIONS and ORDERED_MIGRATIONS."""
    assert 35 in DESTRUCTIVE_MIGRATIONS
    migration_names = [name for ver, name, _, _ in ORDERED_MIGRATIONS if ver == 35]
    assert migration_names == ["analysis_telemetry_schema"]


def test_c_probe_trace_matches_ground_truth_readme(memory_db: sqlite3.Connection):
    """Verify C probe telemetry matches the exact source-derived actions in tests/probes/c_probe/README.md.

    Oracle assertions:
      1. Exactly 14 events are observed (no extra, unexpected file/net/dns events).
      2. Exactly 2 processes: root (ns_pid 2, host_ppid 11432, ns_ppid 1) and child (ns_pid 3, host_ppid 11433, ns_ppid 2).
      3. Strict ordered sequence: create -> write (34 B) -> chmod (0600) -> rename -> delete -> fork -> child exit (0) -> DNS -> connect (ENETUNREACH) -> root exit (0).
    """
    log_file = FIXTURES_DIR / "c_probe_strace.log"
    assert log_file.exists(), f"Missing fixture {log_file}"

    stats = parse_and_persist_strace_log("run_test_probe", log_file, memory_db)
    assert stats["total_events"] == 14
    assert stats["is_truncated"] is False

    # 1. Verify processes in consistent PID spaces
    procs = memory_db.execute(
        "SELECT host_pid, ns_pid, host_ppid, ns_ppid, initial_ppid, process_name, status, exit_code FROM analysis_processes WHERE run_id = 'run_test_probe' ORDER BY host_pid ASC"
    ).fetchall()

    assert len(procs) == 2
    root_proc = procs[0]
    child_proc = procs[1]

    # Root process
    assert root_proc["host_pid"] == 11433
    assert root_proc["ns_pid"] == 2
    assert root_proc["host_ppid"] == 11432
    assert root_proc["ns_ppid"] == 1
    assert root_proc["initial_ppid"] == 11432
    assert root_proc["exit_code"] == 0

    # Child process
    assert child_proc["host_pid"] == 11434
    assert child_proc["ns_pid"] == 3
    assert child_proc["host_ppid"] == 11433
    assert child_proc["ns_ppid"] == 2
    assert child_proc["initial_ppid"] == 11433
    assert child_proc["exit_code"] == 0

    # 2. Verify events: exact count and ordered sequence
    events = memory_db.execute(
        "SELECT seq, category, event_type, action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' ORDER BY seq ASC"
    ).fetchall()

    assert len(events) == 14  # Strictly 14 events — negative check against extra noise
    seqs = [r["seq"] for r in events]
    assert seqs == list(range(14))

    # Event 0: Root process launch
    assert events[0]["category"] == "process" and events[0]["event_type"] == "process_create" and events[0]["action"] == "create"
    assert "probe_elf" in str(events[0]["target_path"])

    # Event 1: File create
    assert events[1]["category"] == "file" and events[1]["event_type"] == "file_create" and events[1]["action"] == "create"
    assert events[1]["target_path"] == "probe_c.tmp"

    # Event 2: File write (34 bytes payload)
    assert events[2]["category"] == "file" and events[2]["event_type"] == "file_modify" and events[2]["action"] == "write"
    det_w = json.loads(events[2]["details"])
    assert det_w["bytes_written"] == 34
    assert "probe_c.tmp" in str(events[2]["target_path"])

    # Event 3: Chmod to 0600
    assert events[3]["category"] == "file" and events[3]["event_type"] == "file_perm_change" and events[3]["action"] == "chmod"
    det_chmod = json.loads(events[3]["details"])
    assert det_chmod["mode"] == "0600"
    assert "probe_c.tmp" in str(events[3]["target_path"])

    # Event 4: File rename
    assert events[4]["category"] == "file" and events[4]["event_type"] == "file_rename" and events[4]["action"] == "rename"
    det_ren = json.loads(events[4]["details"])
    assert det_ren["old_path"] == "probe_c.tmp"
    assert det_ren["new_path"] == "probe_c_renamed.tmp"

    # Event 5: File delete
    assert events[5]["category"] == "file" and events[5]["event_type"] == "file_delete" and events[5]["action"] == "delete"
    assert events[5]["target_path"] == "probe_c_renamed.tmp"

    # Event 6: Child spawn (fork)
    assert events[6]["category"] == "process" and events[6]["event_type"] == "process_create" and events[6]["action"] == "fork"
    det_fork = json.loads(events[6]["details"])
    assert det_fork["child_host_pid"] == 11434
    assert det_fork["child_ns_pid"] == 3

    # Event 7: Child exit
    assert events[7]["category"] == "process" and events[7]["event_type"] == "process_terminate" and events[7]["action"] == "exit"
    det_cexit = json.loads(events[7]["details"])
    assert det_cexit["exit_code"] == 0

    # Events 8-11: DNS query attempts and failures (strictly probe-c.test.invalid, Type A)
    assert events[8]["category"] == "dns" and events[8]["action"] == "query" and events[8]["target_path"] == "probe-c.test.invalid"
    assert json.loads(events[8]["details"])["qtype"] == "A"
    assert json.loads(events[8]["details"])["status"] == "attempted"

    assert events[9]["category"] == "dns" and events[9]["action"] == "query_failed" and events[9]["target_path"] == "probe-c.test.invalid"
    assert json.loads(events[9]["details"])["qtype"] == "A"
    assert json.loads(events[9]["details"])["status"] == "failed"

    assert events[10]["category"] == "dns" and events[10]["action"] == "query" and events[10]["target_path"] == "probe-c.test.invalid"
    assert json.loads(events[10]["details"])["qtype"] == "A"
    assert json.loads(events[10]["details"])["status"] == "attempted"

    assert events[11]["category"] == "dns" and events[11]["action"] == "query_failed" and events[11]["target_path"] == "probe-c.test.invalid"
    assert json.loads(events[11]["details"])["qtype"] == "A"
    assert json.loads(events[11]["details"])["status"] == "failed"

    # Event 12: TCP connect attempt to 192.0.2.1:80
    assert events[12]["category"] == "network" and events[12]["event_type"] == "network_connect" and events[12]["action"] == "connect"
    assert events[12]["target_path"] == "192.0.2.1:80"
    det_net = json.loads(events[12]["details"])
    assert det_net["dest_ip"] == "192.0.2.1"
    assert det_net["dest_port"] == 80
    assert det_net["status"] == "failed"
    assert det_net.get("error_code") == "ENETUNREACH"

    # Event 13: Root process exit
    assert events[13]["category"] == "process" and events[13]["event_type"] == "process_terminate" and events[13]["action"] == "exit"
    det_rexit = json.loads(events[13]["details"])
    assert det_rexit["exit_code"] == 0


def test_shell_probe_trace_matches_ground_truth_readme(memory_db: sqlite3.Connection):
    """Verify Shell probe telemetry matches the actions in tests/probes/shell_probe/README.md."""
    log_file = FIXTURES_DIR / "shell_probe_strace.log"
    assert log_file.exists(), f"Missing fixture {log_file}"

    stats = parse_and_persist_strace_log("run_test_probe", log_file, memory_db)
    assert stats["total_events"] == 37

    # Verify shell processes in consistent PID spaces
    procs = memory_db.execute(
        "SELECT host_pid, ns_pid, host_ppid, ns_ppid, process_name, command_line FROM analysis_processes WHERE run_id = 'run_test_probe' ORDER BY host_pid ASC"
    ).fetchall()
    assert len(procs) == 8
    root_sh = procs[0]
    assert root_sh["host_pid"] == 11521 and root_sh["ns_pid"] == 2 and root_sh["ns_ppid"] == 1

    # Verify file mutations in exact order
    file_events = memory_db.execute(
        "SELECT seq, action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'file' ORDER BY seq ASC"
    ).fetchall()
    assert len(file_events) == 5
    actions = [f["action"] for f in file_events]
    assert actions == ["create", "write", "chmod", "rename", "delete"]
    assert "probe_shell.tmp" in file_events[0]["target_path"]
    assert json.loads(file_events[1]["details"])["bytes_written"] == 33
    assert json.loads(file_events[2]["details"])["mode"] == "0600"
    assert json.loads(file_events[3]["details"])["new_path"] == "probe_shell_renamed.tmp"
    assert file_events[4]["target_path"] == "probe_shell_renamed.tmp"

    # Verify DNS events: exactly 8 events (4 queries + 4 failures, paired A/AAAA)
    dns_events = memory_db.execute(
        "SELECT seq, action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'dns' ORDER BY seq ASC"
    ).fetchall()
    assert len(dns_events) == 8
    expected_dns = [
        ("query", "A", "attempted"),
        ("query_failed", "A", "failed"),
        ("query", "AAAA", "attempted"),
        ("query_failed", "AAAA", "failed"),
        ("query", "A", "attempted"),
        ("query_failed", "A", "failed"),
        ("query", "AAAA", "attempted"),
        ("query_failed", "AAAA", "failed"),
    ]
    for ev, (exp_action, exp_qtype, exp_status) in zip(dns_events, expected_dns):
        assert ev["action"] == exp_action
        assert ev["target_path"] == "probe-sh.test.invalid"
        dtl = json.loads(ev["details"])
        assert dtl["qtype"] == exp_qtype
        assert dtl["status"] == exp_status
        assert dtl["domain"] == "probe-sh.test.invalid"


def test_python_probe_trace_matches_ground_truth_readme(memory_db: sqlite3.Connection):
    """Verify Python probe telemetry matches actions in tests/probes/python_probe/README.md."""
    log_file = FIXTURES_DIR / "python_probe_strace.log"
    assert log_file.exists(), f"Missing fixture {log_file}"

    stats = parse_and_persist_strace_log("run_test_probe", log_file, memory_db)
    assert stats["total_events"] == 15  # Exactly 15 events, noise suppressed

    # Verify processes in consistent PID spaces
    procs = memory_db.execute(
        "SELECT host_pid, ns_pid, host_ppid, ns_ppid, process_name, command_line, exit_code FROM analysis_processes WHERE run_id = 'run_test_probe' ORDER BY host_pid ASC"
    ).fetchall()
    assert len(procs) == 2
    root_py = procs[0]
    child_py = procs[1]

    assert root_py["host_pid"] == 11613 and root_py["ns_pid"] == 2 and root_py["ns_ppid"] == 1
    assert child_py["host_pid"] == 11616 and child_py["ns_pid"] == 3 and child_py["ns_ppid"] == 2
    assert "-c" in child_py["command_line"]
    assert "Python Probe Child Process Executing" in child_py["command_line"]
    assert child_py["exit_code"] == 0

    # Verify file mutations in exact order
    file_events = memory_db.execute(
        "SELECT seq, action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'file' ORDER BY seq ASC"
    ).fetchall()
    assert len(file_events) == 5
    actions = [f["action"] for f in file_events]
    assert actions == ["create", "write", "chmod", "rename", "delete"]
    assert "probe_py.tmp" in file_events[0]["target_path"]
    assert json.loads(file_events[1]["details"])["bytes_written"] == 34
    assert json.loads(file_events[2]["details"])["mode"] == "0600"
    assert json.loads(file_events[3]["details"])["new_path"] == "probe_py_renamed.tmp"
    assert file_events[4]["target_path"] == "probe_py_renamed.tmp"

    # Verify DNS events: exactly 4 events (2 queries + 2 failures, Type A)
    dns_events = memory_db.execute(
        "SELECT seq, action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'dns' ORDER BY seq ASC"
    ).fetchall()
    assert len(dns_events) == 4
    expected_dns = [
        ("query", "A", "attempted"),
        ("query_failed", "A", "failed"),
        ("query", "A", "attempted"),
        ("query_failed", "A", "failed"),
    ]
    for ev, (exp_action, exp_qtype, exp_status) in zip(dns_events, expected_dns):
        assert ev["action"] == exp_action
        assert ev["target_path"] == "probe-py.test.invalid"
        dtl = json.loads(ev["details"])
        assert dtl["qtype"] == exp_qtype
        assert dtl["status"] == exp_status
        assert dtl["domain"] == "probe-py.test.invalid"


def test_site_packages_pth_creation_retained(memory_db: sqlite3.Connection):
    """Verify that creating or writing to a .pth file or file under site-packages/ is NEVER suppressed."""
    trace_lines = [
        '100 1793087029.200000 execve("/sandbox/sample", ["/sandbox/sample"], 0x0) = 0',
        '100 1793087029.210000 openat(AT_FDCWD, "/workspace/OutPost/.venv/lib/python3.14/site-packages/evil.pth", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 10',
        '100 1793087029.220000 write(10, "import os; os.system(\'malicious\')", 33) = 33',
        '100 1793087029.230000 close(10) = 0',
        '100 1793087029.240000 exit_group(0) = ?',
        '100 1793087029.241000 +++ exited with 0 +++',
    ]
    parser = StraceParser("run_test_probe")
    for line in trace_lines:
        parser.parse_line(line)
    parser.commit_to_db(memory_db)

    file_events = memory_db.execute(
        "SELECT action, target_path, details FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'file' ORDER BY seq ASC"
    ).fetchall()

    actions = [f["action"] for f in file_events]
    assert "create" in actions
    assert "write" in actions
    assert parser.suppressed_system_reads == 0

    write_ev = [f for f in file_events if f["action"] == "write"][0]
    assert "evil.pth" in write_ev["target_path"]
    assert json.loads(write_ev["details"])["bytes_written"] == 33


def test_double_fork_orphaned_child_tracked_by_ancestry(memory_db: sqlite3.Connection):
    """Verify that an orphaned grandchild process (double-fork) remains tracked via ancestry.

    Scenario:
      - Host PID 100: sample root
      - Host PID 100 forks child Host PID 200
      - Host PID 200 forks grandchild Host PID 300
      - Host PID 200 exits immediately (Host PID 300 is orphaned and reparented to init)
      - Host PID 300 performs file operations
      - Host PID 999 (bwrap supervisor) closes files
    Expected:
      - Host PID 300's actions ARE tracked.
      - Host PID 999's actions are NOT tracked.
    """
    trace_lines = [
        # Supervisor bwrap lines
        '999 1793087029.100000 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0',
        # Sample start seam (PID 100)
        '100 1793087029.200000 execve("/sandbox/sample", ["/sandbox/sample"], 0x0) = 0',
        # PID 100 forks child 200
        '100 1793087029.210000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 3 /* 200 in strace\'s PID NS */',
        # Child 200 forks grandchild 300
        '200 1793087029.220000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 4 /* 300 in strace\'s PID NS */',
        # Child 200 exits (grandchild 300 is now orphaned)
        '200 1793087029.230000 exit_group(0) = ?',
        '200 1793087029.231000 +++ exited with 0 +++',
        # Supervisor 999 does internal activity (must be ignored)
        '999 1793087029.240000 openat(AT_FDCWD, "/tmp/supervisor_secret.txt", O_WRONLY|O_CREAT, 0644) = 10',
        # Orphaned grandchild 300 performs file operations (MUST be tracked)
        '300 1793087029.250000 openat(AT_FDCWD, "/tmp/orphan_payload.txt", O_WRONLY|O_CREAT, 0644) = 10',
        '300 1793087029.260000 write(10, "orphan data", 11) = 11',
        '300 1793087029.270000 exit_group(0) = ?',
        '300 1793087029.271000 +++ exited with 0 +++',
        # Sample root exits
        '100 1793087029.280000 exit_group(0) = ?',
        '100 1793087029.281000 +++ exited with 0 +++',
    ]

    parser = StraceParser("run_test_probe")
    for line in trace_lines:
        parser.parse_line(line)
    parser.commit_to_db(memory_db)

    # 1. Grandchild PID 300 must be in analysis_processes
    proc_pids = [
        r["host_pid"]
        for r in memory_db.execute("SELECT host_pid FROM analysis_processes WHERE run_id = 'run_test_probe'").fetchall()
    ]
    assert 100 in proc_pids
    assert 200 in proc_pids
    assert 300 in proc_pids
    assert 999 not in proc_pids  # Supervisor excluded!

    # 2. Grandchild's file event must be tracked, supervisor's file event must be absent
    file_events = memory_db.execute(
        "SELECT target_path FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'file'"
    ).fetchall()
    file_targets = [r["target_path"] for r in file_events]
    assert "/tmp/orphan_payload.txt" in file_targets
    assert "/tmp/supervisor_secret.txt" not in file_targets


def test_udp_connect_not_recorded_as_network_success(memory_db: sqlite3.Connection):
    """Verify connect() on UDP port 53 returning 0 is NOT recorded as a successful network connection."""
    trace_lines = [
        '100 1793087029.200000 execve("/sandbox/sample", ["/sandbox/sample"], 0x0) = 0',
        '100 1793087029.210000 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 10',
        '100 1793087029.220000 connect(10, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        '100 1793087029.230000 exit_group(0) = ?',
        '100 1793087029.231000 +++ exited with 0 +++',
    ]
    parser = StraceParser("run_test_probe")
    for line in trace_lines:
        parser.parse_line(line)
    parser.commit_to_db(memory_db)

    # Zero network_connect events should exist (UDP connect on 53 is internal binding)
    net_events = memory_db.execute(
        "SELECT * FROM analysis_events WHERE run_id = 'run_test_probe' AND category = 'network'"
    ).fetchall()
    assert len(net_events) == 0


def test_quota_cap_and_truncation_marker(memory_db: sqlite3.Connection):
    """Verify that exceeding quota caps triggers trace_truncated event."""
    from app.services.strace_parser import MAX_FILE_EVENTS

    parser = StraceParser("run_test_probe")
    # Sample start
    parser.parse_line('100 1793087029.200000 execve("/sandbox/sample", ["/sandbox/sample"], 0x0) = 0')

    # Emit file events exceeding limit
    for i in range(MAX_FILE_EVENTS + 50):
        ts = 1793087029.200000 + (i * 0.0001)
        parser.parse_line(f'100 {ts:.6f} openat(AT_FDCWD, "/tmp/file_{i}.tmp", O_WRONLY|O_CREAT, 0644) = 10')

    parser.commit_to_db(memory_db)

    stats = memory_db.execute("SELECT * FROM run_analysis_stats WHERE run_id = 'run_test_probe'").fetchone()
    assert stats["is_truncated"] == 1
    assert "file_quota_exceeded" in stats["truncation_reason"]


def test_end_to_end_from_real_log_to_report(client):
    """End-to-end integration test: parses real C probe strace telemetry,

    persists entities, queries API endpoints (/runs/{id}/report, /analysis-events,
    /analysis-processes, /analysis-stats), and verifies that the generated report
    matches the probe's ground-truth actions.
    """
    from app.core.db import db_session

    run_id = "run_e2e_c_probe"
    log_file = FIXTURES_DIR / "c_probe_strace.log"
    assert log_file.exists()

    with db_session() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO runs (run_id, sample_name, platform, started_at)
            VALUES (?, 'probe_elf', 'linux', '2026-10-27T00:00:00Z')
            """,
            (run_id,),
        )
        parse_and_persist_strace_log(run_id, log_file, conn)

    # 1. Test /runs/{id}/analysis-stats
    resp_stats = client.get(f"/runs/{run_id}/analysis-stats")
    assert resp_stats.status_code == 200, resp_stats.text
    stats_data = resp_stats.json()
    assert stats_data["total_events"] > 0
    assert stats_data["process_count"] == 2
    assert stats_data["file_events_count"] == 5
    assert stats_data["network_events_count"] == 1
    assert stats_data["is_truncated"] == 0

    # 2. Test /runs/{id}/analysis-processes
    resp_procs = client.get(f"/runs/{run_id}/analysis-processes")
    assert resp_procs.status_code == 200
    procs_data = resp_procs.json()
    assert len(procs_data) == 2
    ns_pids = {p["ns_pid"] for p in procs_data}
    assert ns_pids == {2, 3}

    # 3. Test /runs/{id}/analysis-events
    resp_ev = client.get(f"/runs/{run_id}/analysis-events")
    assert resp_ev.status_code == 200
    events_data = resp_ev.json()
    seqs = [e["seq"] for e in events_data]
    assert seqs == list(range(len(events_data)))
    actions = [e["action"] for e in events_data]
    # Ground-truth actions present
    assert "create" in actions
    assert "write" in actions
    assert "chmod" in actions
    assert "rename" in actions
    assert "delete" in actions
    assert "connect" in actions

    # 4. Test /runs/{id} (Full run detail & process tree integration)
    resp_rep = client.get(f"/runs/{run_id}")
    assert resp_rep.status_code == 200
    rep_data = resp_rep.json()
    assert "process_tree" in rep_data
    assert len(rep_data["process_tree"]) >= 1
    root_node = rep_data["process_tree"][0]
    assert root_node["pid"] == 11433
    # Child process node attached
    assert len(root_node["children"]) >= 1
    assert root_node["children"][0]["pid"] == 11434
