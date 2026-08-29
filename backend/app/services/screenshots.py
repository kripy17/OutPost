"""Detonation screenshot capture (docs/10-STANDOUT-FEATURES.md #4).

Periodically captures screen images while a dynamic detonation runs and stores
them as run artifacts under ``ARTIFACTS_DIR/<run_id>/`` (``shot_NNNN.png`` +
``manifest.json``). Capture is driven by a user-supplied command template
(VBoxManage / grim / scrot ...) — when none is configured the session reports
honestly that capture is unavailable; nothing is faked.
"""

import datetime
import json
import shlex
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

from ..core import config

_CAPTURE_TIMEOUT = 15.0

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _command_parts() -> list[str] | None:
    """Resolve the configured capture template into argv."""
    if not config.SCREENSHOT_CMD:
        return None
    try:
        parts = shlex.split(config.SCREENSHOT_CMD)
    except ValueError:
        return None
    return [p for p in parts if p] or None


def capture_available() -> bool:
    """True when a capture command is configured AND its binary resolves."""
    parts = _command_parts()
    return bool(parts) and shutil.which(parts[0]) is not None


def status() -> dict[str, Any]:
    """Honest capability report for API/UI badges."""
    parts = _command_parts()
    report: dict[str, Any] = {
        "configured": bool(parts),
        "available": capture_available(),
        "interval_seconds": config.SCREENSHOT_INTERVAL,
    }
    if parts and not report["available"]:
        report["error"] = f"capture binary not found: {parts[0]}"
    elif not parts:
        report["error"] = "no capture command configured (set OUTPOST_SCREENSHOT_CMD)"
    return report


def capture_to(path: Path) -> bool:
    """One-shot capture into ``path`` via the configured command. Never raises."""
    parts = _command_parts()
    if not parts:
        return False
    argv = [str(path) if p == "{output}" else p for p in parts]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(argv, capture_output=True, timeout=_CAPTURE_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    try:
        return path.exists() and path.stat().st_size > 0
    except OSError:
        return False


def run_artifacts_dir(run_id: str) -> Path:
    return Path(config.ARTIFACTS_DIR) / run_id


class ScreenshotSession:
    """Interval capture loop for one detonation run (daemon thread)."""

    def __init__(self, run_id: str, interval: float | None = None):
        self.run_id = run_id
        self.interval = max(0.05, float(interval or config.SCREENSHOT_INTERVAL))
        self.dir = run_artifacts_dir(run_id)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.shots: list[dict[str, Any]] = []

    def start(self) -> None:
        if not capture_available():
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> list[dict[str, Any]]:
        """Stop the loop, persist manifest.json, return captured shot metadata."""
        self._stop.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=self.interval + _CAPTURE_TIMEOUT + 5)
        self._write_manifest()
        return self.shots

    @property
    def started(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _next_path(self) -> Path:
        return self.dir / f"shot_{len(self.shots) + 1:04d}.png"

    def _loop(self) -> None:
        while not self._stop.is_set():
            path = self._next_path()
            captured_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if capture_to(path):
                self.shots.append({"file": path.name, "captured_at": captured_at})
            elif path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
            self._stop.wait(self.interval)

    def _write_manifest(self) -> None:
        if not self.shots and not self.dir.exists():
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            (self.dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "run_id": self.run_id,
                        "count": len(self.shots),
                        "shots": self.shots,
                    },
                    indent=2,
                )
            )
        except OSError:
            pass


def list_shots(run_id: str) -> dict[str, Any]:
    """Artifact listing for one run — shots on disk plus honest capture status."""
    directory = run_artifacts_dir(run_id)
    manifest: dict[str, Any] = {}
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
    except (OSError, ValueError):
        pass
    times = {s.get("file"): s.get("captured_at") for s in manifest.get("shots") or []}
    shots: list[dict[str, Any]] = []
    if directory.exists():
        for entry in sorted(directory.glob("shot_*.png")):
            try:
                st = entry.stat()
            except OSError:
                continue
            shots.append(
                {
                    "file": entry.name,
                    "size": st.st_size,
                    "captured_at": times.get(entry.name),
                }
            )
    return {
        "run_id": run_id,
        "available": bool(shots),
        "capture_status": status(),
        "count": len(shots),
        "shots": shots,
    }


def read_shot(run_id: str, filename: str) -> bytes | None:
    """PNG bytes for one artifact; strict name allowlist blocks path traversal."""
    if (
        "/" in filename
        or "\\" in filename
        or ".." in filename
        or not filename.startswith("shot_")
        or not filename.endswith(".png")
    ):
        return None
    try:
        data = (run_artifacts_dir(run_id) / filename).read_bytes()
    except OSError:
        return None
    if data[:8] != _PNG_MAGIC:
        return None
    return data
