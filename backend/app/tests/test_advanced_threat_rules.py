"""Tests for advanced behavioral threat detection rules:
- anonymous-rwx-memory: Unbacked RWX memory allocations (fileless shellcode staging)
- fileless-unlinked-binary: Execution from deleted inodes or anonymous memfd descriptors
- gtfobins-suid-execution: Privilege escalation via setuid breakout utilities
"""

import datetime
from .conftest import make_run
from ..services.risk import RULE_META, RULE_NAMES


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def test_rule_metadata_registered():
    """Verify rules are properly registered with ATT&CK taxonomy and human descriptions."""
    for rid in ("anonymous-rwx-memory", "fileless-unlinked-binary", "gtfobins-suid-execution"):
        assert rid in RULE_META, f"{rid} missing from RULE_META"
        assert rid in RULE_NAMES, f"{rid} missing from RULE_NAMES"
        meta = RULE_META[rid]
        assert meta["severity"] == "malicious"
        assert meta["weight"] >= 18
        assert meta["technique"].startswith("T")
        assert meta["tactic"] in ("Defense Evasion", "Privilege Escalation")


def test_anonymous_rwx_memory_detection(client):
    """Verify detection fires on unbacked RWX memory allocation."""
    run_id = make_run(client, sample_name="injector.bin", platform="linux")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": _ts(1),
            "pid": 2048,
            "ppid": 1000,
            "process_name": "implant",
            "command_line": "./implant --inject-shellcode 7f4a1000-7f4b1000 rwxp [anon]",
            "raw_record": "PID 2048 mapped RWX memory page without backing file: 7f4a1000-7f4b1000 rwxp 00000000 00:00 0 [anon]",
        }
    ])

    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "anonymous-rwx-memory"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "RWX" in fired[0]["details"] or "rwx" in fired[0]["details"]


def test_fileless_unlinked_binary_detection(client):
    """Verify detection fires on process executing from unlinked on-disk inode or memfd."""
    run_id = make_run(client, sample_name="stealth_loader", platform="linux")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": _ts(1),
            "pid": 3110,
            "ppid": 1000,
            "process_name": "payload",
            "command_line": "/tmp/drop.elf (deleted)",
            "exe_path": "/proc/3110/exe -> /tmp/drop.elf (deleted)",
            "details": "PID 3110 holds open descriptor to unlinked file: /tmp/drop.elf (deleted)",
        }
    ])

    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "fileless-unlinked-binary"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "unlinked" in fired[0]["details"] or "deleted" in fired[0]["details"]


def test_gtfobins_suid_execution_detection(client):
    """Verify detection fires on privilege escalation breakout command."""
    run_id = make_run(client, sample_name="privesc.sh", platform="linux")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": _ts(1),
            "pid": 4096,
            "ppid": 1000,
            "process_name": "find",
            "command_line": "find . -exec /bin/sh -p \\; -quit",
            "exe_path": "/usr/bin/find",
        }
    ])

    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "gtfobins-suid-execution"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "breakout" in fired[0]["details"].lower() or "privilege" in fired[0]["details"].lower()
