"""Volatility3 memory forensics (docs/08 #7) — parsing, cross-reference, scan
pipeline, and API surface. The vol binary is exercised through a real
executable script (shebang + exec bit) so the explicit-path config path and
argument wiring are pinned; uninstalled/failed paths must degrade honestly.
"""

import json
import os
import stat
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from ..core import config
from ..models import event as event_store
from ..models import samples as samples_store
from ..services import memory_forensics as mf

PSLIST_JSON = json.dumps(
    {
        "config": {"scanning": False},
        "exceptions": [],
        "sections": [
            {
                "name": "windows.pslist.PsList",
                "rows": [
                    {
                        "N": 0,
                        "PID": 4,
                        "PPID": 0,
                        "ImageFileName": "System",
                        "Threads": 168,
                        "CreateTime": "2026-08-01 10:00:00.000000 UTC",
                    },
                    {"N": 1, "PID": 4820, "PPID": 640, "ImageFileName": "mimikatz.exe", "CreateTime": None},
                    {"N": 2, "PID": 912, "PPID": 4820, "ImageFileName": "notepad.exe"},
                ],
            }
        ],
    }
)

NETSCAN_JSON = json.dumps(
    {
        "sections": [
            {
                "name": "windows.netscan.NetScan",
                "rows": [
                    {
                        "Offset": "0x1f0a2c40",
                        "Proto": "TCPv4",
                        "LocalAddr": "TCPv4 10.0.2.15:49152",
                        "ForeignAddr": "185.199.108.153:443",
                        "State": "ESTABLISHED",
                        "Owner": "mimikatz.exe",
                    },
                    {"Offset": "0x1f0b0040", "Proto": "UDPv4", "LocalAddr": "10.0.2.15:138", "ForeignAddr": "-"},
                ],
            }
        ]
    }
)


@pytest.fixture(autouse=True)
def _vol_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VOLATILITY_PATH", "")
    monkeypatch.setattr(config, "SAMPLES_DIR", tmp_path / "vault")
    yield


def _fake_vol_script(tmp_path) -> str:
    """A real executable that plays the vol CLI: canned JSON per plugin."""
    script = tmp_path / "fake-vol"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"PSLIST = {repr(PSLIST_JSON)}\n"
        f"NETSCAN = {repr(NETSCAN_JSON)}\n"
        "if any('pslist' in a for a in sys.argv):\n"
        "    print(PSLIST)\n"
        "elif any('netscan' in a for a in sys.argv):\n"
        "    print(NETSCAN)\n"
        "else:\n"
        "    sys.exit(3)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_vol_status_uninstalled_is_honest(monkeypatch):
    monkeypatch.setattr(mf.shutil, "which", lambda name: None)
    report = mf.vol_status()
    assert report["configured"] is False
    assert report["available"] is False
    assert "OUTPOST_VOLATILITY_PATH" in report["error"]
    assert mf._vol_binary() is None


def test_vol_status_explicit_missing_path(monkeypatch):
    monkeypatch.setattr(config, "VOLATILITY_PATH", "/nonexistent/vol-xyz")
    report = mf.vol_status()
    assert report["configured"] is True
    assert report["available"] is False
    assert "/nonexistent/vol-xyz" in report["error"]


def test_parse_processes_modern_shape():
    processes = mf.parse_vol_processes(json.loads(PSLIST_JSON))
    by_name = {p["name"]: p for p in processes}
    assert set(by_name) == {"System", "mimikatz.exe", "notepad.exe"}
    assert by_name["System"]["pid"] == 4
    assert by_name["System"]["ppid"] == 0
    assert by_name["mimikatz.exe"]["pid"] == 4820
    assert by_name["notepad.exe"]["create_time"] is None


def test_parse_processes_garbage_safe():
    for payload in (None, {}, {"sections": 42}, {"sections": [{"rows": [1, "x", {}]}]}, [], "nope"):
        assert mf.parse_vol_processes(payload) == []


def test_parse_processes_legacy_rows_and_bare_list():
    legacy_rows = {"rows": [{"PID": "77", "ImageFileName": "legacy.exe"}]}
    assert mf.parse_vol_processes(legacy_rows)[0]["pid"] == 77
    bare = [{"ProcessName": "alt.exe", "pid": "5"}]
    parsed = mf.parse_vol_processes(bare)
    assert parsed[0]["name"] == "alt.exe" and parsed[0]["pid"] == 5


def test_parse_connections_splits_composite_addresses():
    connections = mf.parse_vol_connections(json.loads(NETSCAN_JSON))
    assert connections[0]["proto"] == "TCPv4"
    assert connections[0]["local_addr"] == "10.0.2.15:49152"
    assert connections[0]["foreign_addr"] == "185.199.108.153:443"
    assert connections[0]["state"] == "ESTABLISHED"
    assert connections[1]["foreign_addr"] is None


def test_cross_reference_flags_unseen_processes(conn):
    events = [
        {"event_type": "process_create", "process_name": "MIMIKATZ.EXE"},
        {"event_type": "process_create", "process_name": "cmd.exe"},
        {"event_type": "file_create", "process_name": "ignored-not-a-process-event"},
    ]
    processes = [
        {"pid": 4820, "name": "mimikatz.exe"},
        {"pid": 912, "name": "Notepad.exe"},
        {"pid": 700, "name": "svchost.exe"},
    ]
    xref = mf.cross_reference(processes, events)
    assert xref["telemetry_processes"] == ["cmd.exe", "mimikatz.exe"]
    assert xref["matched_count"] == 1
    assert xref["hidden_processes"] == [
        {"pid": 912, "name": "Notepad.exe"},
        {"pid": 700, "name": "svchost.exe"},
    ]


_REAL_NTF = tempfile.NamedTemporaryFile


class _SpyTemp:
    def __init__(self):
        self.paths = []

    def NamedTemporaryFile(self, **kwargs):
        real = _REAL_NTF(**kwargs)
        self.paths.append(real.name)
        return real


def test_run_memory_scan_success_and_cleanup(monkeypatch):
    spy = _SpyTemp()
    monkeypatch.setattr(mf.tempfile, "NamedTemporaryFile", spy.NamedTemporaryFile)
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if any("pslist" in a for a in argv):
            return SimpleNamespace(returncode=0, stdout=PSLIST_JSON, stderr="")
        return SimpleNamespace(returncode=0, stdout=NETSCAN_JSON, stderr="")

    monkeypatch.setattr(mf.shutil, "which", lambda name: "/usr/bin/fake-vol")
    monkeypatch.setattr(mf.subprocess, "run", fake_run)

    result = mf.run_memory_scan(b"MZdump")
    assert result["available"] is True
    assert len(result["processes"]) == 3
    assert result["connections"][0]["foreign_addr"] == "185.199.108.153:443"
    assert [c[-1] for c in calls] == ["windows.pslist", "windows.netscan"]
    for argv in calls:
        assert argv[:3] == ["/usr/bin/fake-vol", "-r", "json"]
        argv[argv.index("-f") + 1]
    assert all(not os.path.exists(p) for p in spy.paths)


def test_run_memory_scan_pslist_failure_is_honest(monkeypatch):
    monkeypatch.setattr(mf.shutil, "which", lambda name: "/usr/bin/fake-vol")
    monkeypatch.setattr(
        mf.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=1, stdout="", stderr="unsatisfied requirements"),
    )
    result = mf.run_memory_scan(b"bad")
    assert result["available"] is True
    assert "windows.pslist exited 1" in result["error"]
    assert "unsatisfied requirements" in result["error"]
    assert result["processes"] == []
    assert result["connections"] == []


def test_run_memory_scan_netscan_failure_is_tolerated(monkeypatch):
    procs = [SimpleNamespace(returncode=0, stdout=PSLIST_JSON, stderr="")]

    def fake_run(argv, **kw):
        if any("netscan" in a for a in argv):
            return SimpleNamespace(returncode=2, stdout="", stderr="boom")
        return procs.pop()

    monkeypatch.setattr(mf.shutil, "which", lambda name: "/usr/bin/fake-vol")
    monkeypatch.setattr(mf.subprocess, "run", fake_run)
    result = mf.run_memory_scan(b"dmp")
    assert len(result["processes"]) == 3
    assert result["connections"] == []
    assert "windows.netscan exited 2" in result["netscan_error"]


def test_run_memory_scan_timeout_is_honest(monkeypatch):
    def raise_timeout(argv, **kw):
        raise subprocess.TimeoutExpired(cmd="vol", timeout=config.VOLATILITY_TIMEOUT)

    monkeypatch.setattr(mf.shutil, "which", lambda name: "/usr/bin/fake-vol")
    monkeypatch.setattr(mf.subprocess, "run", raise_timeout)
    result = mf.run_memory_scan(b"slow")
    assert result["available"] is True
    assert f"timed out after {config.VOLATILITY_TIMEOUT}s" in result["error"]
    assert result["processes"] == []


def test_run_memory_scan_bad_json_is_honest(monkeypatch):
    monkeypatch.setattr(mf.shutil, "which", lambda name: "/usr/bin/fake-vol")
    monkeypatch.setattr(
        mf.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=0, stdout="<html>not json</html>", stderr=""),
    )
    result = mf.run_memory_scan(b"dmp")
    assert result["available"] is True
    assert "pslist output was not valid JSON" in result["error"]
    assert result["processes"] == []


# -- API surface ---------------------------------------------------------------


def _seed_dump(client, conn, sample_id: str, process_names: list[str]) -> str:
    resp = client.post("/runs", json={"sample_name": "memtest.bin", "platform": "windows"})
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]
    samples_store.add_sample(conn, sample_id, "memdump.raw", "a" * 64, "windows", 4)
    config.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    (config.SAMPLES_DIR / f"{sample_id}.bin").write_bytes(b"MZDUMP")
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    for i, name in enumerate(process_names):
        event_store.insert_event(
            conn,
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "process_create",
                "timestamp": ts,
                "pid": 100 + i,
                "process_name": name,
            },
        )
    conn.commit()
    return run_id


def _cleanup(client_run_ids, sample_ids, conn):
    conn.execute("DELETE FROM audit_log WHERE target_type = 'run'")
    for rid in client_run_ids:
        conn.execute("DELETE FROM events WHERE run_id = ?", (rid,))
        conn.execute("DELETE FROM runs WHERE run_id = ?", (rid,))
    for sid in sample_ids:
        conn.execute("DELETE FROM samples WHERE sample_id = ?", (sid,))
    conn.commit()


def test_api_memory_scan_full_pipeline(client, conn, tmp_path, monkeypatch):
    run_id = _seed_dump(client, conn, "dumpsess1", ["mimikatz.exe"])
    try:
        monkeypatch.setattr(config, "VOLATILITY_PATH", _fake_vol_script(tmp_path))

        resp = client.post("/runs/%s/memory-scan" % run_id, json={"dump_sample_id": "dumpsess1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert body["tools"]["available"] is True
        assert len(body["processes"]) == 3
        xref = body["cross_reference"]
        assert xref["matched_count"] == 1
        hidden = {h["name"].lower() for h in xref["hidden_processes"]}
        assert {"system", "notepad.exe"} <= hidden
    finally:
        _cleanup([run_id], ["dumpsess1"], conn)


def test_api_memory_scan_404_paths(client, conn):
    resp = client.post("/runs/no-such-run/memory-scan", json={"dump_sample_id": "x"})
    assert resp.status_code == 404

    run_id = _seed_dump(client, conn, "dumpmiss", [])
    try:
        resp = client.post(f"/runs/{run_id}/memory-scan", json={"dump_sample_id": "never-uploaded"})
        assert resp.status_code == 404
        assert "Unknown sample" in resp.json()["detail"]
    finally:
        _cleanup([run_id], ["dumpmiss"], conn)


def test_api_memory_scan_501_when_vol_missing(client, conn):
    run_id = _seed_dump(client, conn, "dump501", ["cmd.exe"])
    try:
        resp = client.post(f"/runs/{run_id}/memory-scan", json={"dump_sample_id": "dump501"})
        assert resp.status_code == 501
        assert "volatility3" in resp.json()["detail"]
    finally:
        _cleanup([run_id], ["dump501"], conn)


def test_api_memory_scan_501_when_explicit_path_missing(client, conn, monkeypatch):
    monkeypatch.setattr(config, "VOLATILITY_PATH", "/nonexistent/vol-xyz")
    run_id = _seed_dump(client, conn, "dumpbadpath", [])
    try:
        resp = client.post(f"/runs/{run_id}/memory-scan", json={"dump_sample_id": "dumpbadpath"})
        assert resp.status_code == 501
        assert "/nonexistent/vol-xyz" in resp.json()["detail"]
    finally:
        _cleanup([run_id], ["dumpbadpath"], conn)
