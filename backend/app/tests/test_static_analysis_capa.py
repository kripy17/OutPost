"""CAPA (Mandiant) subprocess integration in static analysis.

`run_capa` shells out to the `capa` CLI when present and must degrade
honestly when it isn't. These tests pin the parsing, merge, and every
failure path with monkeypatched `shutil.which` / `subprocess.run`.
"""

import json
import subprocess

import pytest

from ..services import static_analysis as sa


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


CAPA_REPORT = {
    "meta": {"sample": {"sha256": "a" * 64}},
    "rules": {
        "create TCP socket": {
            "meta": {
                "namespace": "communication/socket/tcp",
                "attack": [{"id": "T1095", "name": "Non-Application Layer Protocol"}],
                "mbc": [{"id": "C0001", "object": "communication", "behavior": "socket"}],
            }
        },
        "persist via registry run key": {
            "meta": {
                "namespace": "persistence/registry",
                "attack": [{"id": "T1060", "name": "Registry Run Keys / Startup Folder"}],
            }
        },
    },
}


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    yield
    monkeypatch.undo()


def test_heuristic_capabilities_are_sourced():
    data = b"VirtualAllocEx WriteProcessMemory socket connect"
    caps = sa.detect_capabilities(data, [])
    assert caps, "expected at least one heuristic hit"
    assert all(c["source"] == "heuristic" for c in caps)


def test_parse_capa_rules_modern_mapping():
    entries = sa.parse_capa_rules(CAPA_REPORT)
    names = {e["category"] for e in entries}
    assert names == {"create TCP socket", "persist via registry run key"}
    sock = next(e for e in entries if e["category"] == "create TCP socket")
    assert sock["source"] == "capa"
    assert sock["confidence"] == "high"
    assert sock["namespace"] == "communication/socket/tcp"
    assert sock["attack"] == ["Non-Application Layer Protocol (T1095)"]
    assert sock["mbc"] == ["communication::socket [C0001]"]
    assert "Non-Application Layer Protocol (T1095)" in sock["matched"]
    assert "communication::socket [C0001]" in sock["matched"]


def test_parse_capa_rules_legacy_list_shape():
    legacy = {
        "rules": [
            {"rule": "old style match", "meta": {"attack": [{"id": "T1003", "name": "OS Credential Dumping"}]}},
            {"nope": True},
        ]
    }
    entries = sa.parse_capa_rules(legacy)
    assert [e["category"] for e in entries] == ["old style match"]
    assert entries[0]["attack"] == ["OS Credential Dumping (T1003)"]


def test_parse_capa_rules_garbage():
    assert sa.parse_capa_rules(None) == []
    assert sa.parse_capa_rules({}) == []
    assert sa.parse_capa_rules({"rules": 42}) == []
    # malformed rule bodies still yield an entry, just without refs
    entries = sa.parse_capa_rules({"rules": {"bare rule": {"meta": "junk"}}})
    assert len(entries) == 1
    assert entries[0]["category"] == "bare rule"
    assert entries[0]["matched"] == []


def test_run_capa_unavailable_when_not_installed(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: None)
    report = sa.run_capa(b"MZ")
    assert report == {"available": False, "error": "capa not installed", "capabilities": []}


def test_run_capa_success_parses_rules(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: "/usr/bin/capa")
    seen_cmds: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        seen_cmds.append(list(cmd))
        return FakeProc(returncode=0, stdout=json.dumps(CAPA_REPORT))

    monkeypatch.setattr(sa.subprocess, "run", fake_run)
    report = sa.run_capa(b"MZ-fake-pe")
    assert report["available"] is True
    assert "error" not in report
    assert {e["source"] for e in report["capabilities"]} == {"capa"}
    assert len(report["capabilities"]) == 2
    assert seen_cmds and seen_cmds[0][0] == "/usr/bin/capa" and "--json" in seen_cmds[0]


def test_run_capa_nonzero_exit_is_reported(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr(
        sa.subprocess,
        "run",
        lambda cmd, **kw: FakeProc(returncode=3, stdout="", stderr="boom"),
    )
    report = sa.run_capa(b"MZ")
    assert report["available"] is True
    assert "exited 3" in report["error"]
    assert report["capabilities"] == []


def test_run_capa_timeout_degrades(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: "/usr/bin/capa")

    def raise_timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(sa.subprocess, "run", raise_timeout)
    report = sa.run_capa(b"MZ")
    assert report["available"] is True
    assert "timed out" in report["error"]


def test_run_capa_bad_json_degrades(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr(sa.subprocess, "run", lambda cmd, **kw: FakeProc(stdout="not json"))
    report = sa.run_capa(b"MZ")
    assert report["available"] is True
    assert "not valid JSON" in report["error"]


def test_run_capa_cleans_temp_file(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: "/usr/bin/capa")
    written: list[str] = []

    import os
    import tempfile as _tempfile

    real_ntf = _tempfile.NamedTemporaryFile

    def spy_ntf(*args, **kwargs):
        handle = real_ntf(*args, **kwargs)
        written.append(handle.name)
        return handle

    monkeypatch.setattr(sa.tempfile, "NamedTemporaryFile", spy_ntf)
    monkeypatch.setattr(sa.os, "unlink", os.unlink)
    monkeypatch.setattr(sa.subprocess, "run", lambda cmd, **kw: FakeProc(stdout="{}"))

    sa.run_capa(b"data")
    assert written, "temp sample file should be written"
    assert not any(os.path.exists(p) for p in written), "temp file must be removed"


def test_analyze_sample_merges_capa_and_reports_availability(monkeypatch):
    fixed = {
        "available": True,
        "capabilities": [
            {"category": "create TCP socket", "matched": [], "confidence": "high", "source": "capa"}
        ],
    }
    monkeypatch.setattr(sa, "run_capa", lambda data: fixed)
    result = sa.analyze_sample(b"VirtualAllocEx WriteProcessMemory")
    sources = {c["source"] for c in result["capabilities"]}
    assert "heuristic" in sources and "capa" in sources
    assert result["capa"]["available"] is True


def test_analyze_sample_without_capa_still_honest(monkeypatch):
    monkeypatch.setattr(sa.shutil, "which", lambda name: None)
    result = sa.analyze_sample(b"plain text nothing here")
    assert result["capabilities"] == []
    assert result["capa"]["available"] is False
