"""Detonation screenshot capture (docs/10 #4) — service + API surface.

The capture command is exercised end-to-end through a real subprocess writer
script so template substitution ({output}), PNG validation, the interval loop,
and artifact serving are all pinned. Unconfigured/missing-binary paths must
report honestly rather than fake artifacts.
"""

import json
import sys
import time

import pytest

from ..core import config
from ..services import screenshots as ss

PNG = b"\x89PNG\r\n\x1a\n" + b"fakepngdata"


@pytest.fixture
def writer_cmd(tmp_path, monkeypatch):
    """A real capture command: a tiny python script that writes a fake PNG."""
    script = tmp_path / "capture_writer.py"
    script.write_text(
        "import sys, pathlib\n"
        "pathlib.Path(sys.argv[1]).write_bytes(" + repr(PNG) + ")\n"
    )
    cmd = f"{sys.executable} {script} {{output}}"
    monkeypatch.setattr(config, "SCREENSHOT_CMD", cmd)
    return cmd


@pytest.fixture(autouse=True)
def _artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ARTIFACTS_DIR", tmp_path / "artifacts")
    yield


def test_status_unconfigured_is_honest(monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOT_CMD", "")
    report = ss.status()
    assert report["configured"] is False
    assert report["available"] is False
    assert "OUTPOST_SCREENSHOT_CMD" in report["error"]


def test_status_missing_binary_reports_error(monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOT_CMD", "/nonexistent-binary-xyz {output}")
    report = ss.status()
    assert report["configured"] is True
    assert report["available"] is False
    assert "/nonexistent-binary-xyz" in report["error"]
    assert ss.capture_available() is False


def test_capture_to_writes_png(writer_cmd):
    out = config.ARTIFACTS_DIR / "manual.png"
    assert ss.capture_to(out) is True
    assert out.read_bytes() == PNG


def test_capture_to_failing_command_returns_false(monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOT_CMD", "false {output}")
    out = config.ARTIFACTS_DIR / "nope.png"
    assert ss.capture_to(out) is False


def test_session_captures_on_interval_and_manifests(writer_cmd):
    session = ss.ScreenshotSession("runscreens1", interval=0.05)
    session.start()
    time.sleep(0.35)
    shots = session.stop()
    assert len(shots) >= 2
    manifest = json.loads((session.dir / "manifest.json").read_text())
    assert manifest["run_id"] == "runscreens1"
    assert manifest["count"] == len(shots)
    assert [s["file"] for s in manifest["shots"]] == sorted(s["file"] for s in manifest["shots"])
    for shot in manifest["shots"]:
        assert (session.dir / shot["file"]).read_bytes() == PNG
        assert shot["captured_at"]


def test_session_without_capture_never_starts(monkeypatch):
    monkeypatch.setattr(config, "SCREENSHOT_CMD", "")
    session = ss.ScreenshotSession("nosess")
    session.start()
    assert session.stop() == []
    assert not session.dir.exists()


def test_list_shots_reads_disk_plus_manifest(writer_cmd):
    session = ss.ScreenshotSession("listsess", interval=0.05)
    session.start()
    time.sleep(0.25)
    session.stop()

    listing = ss.list_shots("listsess")
    assert listing["run_id"] == "listsess"
    assert listing["available"] is True
    assert listing["count"] == listing["shots"].__len__() >= 1
    assert listing["shots"][0]["captured_at"]
    assert listing["shots"][0]["size"] == len(PNG)
    assert listing["capture_status"]["available"] is True


def test_list_shots_empty_run_is_honest():
    listing = ss.list_shots("never-ran")
    assert listing["available"] is False
    assert listing["count"] == 0
    assert listing["shots"] == []


def test_read_shot_validates_name_and_magic(writer_cmd):
    d = ss.run_artifacts_dir("readsess")
    d.mkdir(parents=True)
    (d / "shot_0001.png").write_bytes(PNG)
    (d / "shot_0002.png").write_bytes(b"not a png")

    assert ss.read_shot("readsess", "shot_0001.png") == PNG
    assert ss.read_shot("readsess", "shot_0002.png") is None
    for bad in ("../evil.png", "sub/shot_0001.png", "manifest.json", "..\\shot.png", "shot_0003.png"):
        assert ss.read_shot("readsess", bad) is None


def test_screenshot_api_list_and_serve(client):
    d = ss.run_artifacts_dir("apisess")
    d.mkdir(parents=True)
    (d / "shot_0001.png").write_bytes(PNG)

    resp = client.get("/sandbox/detonate/apisess/screenshots")
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is True and body["count"] == 1
    assert body["shots"][0]["file"] == "shot_0001.png"

    png_resp = client.get("/sandbox/detonate/apisess/screenshots/shot_0001.png")
    assert png_resp.status_code == 200
    assert png_resp.headers["content-type"] == "image/png"
    assert png_resp.content == PNG

    missing = client.get("/sandbox/detonate/apisess/screenshots/shot_9999.png")
    assert missing.status_code == 404
