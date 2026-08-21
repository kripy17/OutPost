"""Start/stop the local collector process and track session state.

The CLI starts the platform's collector as a subprocess and talks to the
backend; it never embeds collection logic (AGENTS.md rule 2 — collectors
stay dumb, and the CLI stays a thin client).
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
COLLECTORS = REPO_ROOT / "collectors"


def detect_platform() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    raise RuntimeError(f"Unsupported platform: {system} — OutPost collectors support Windows and Linux")


def collector_script(platform_name: str) -> Path:
    if platform_name == "windows":
        return COLLECTORS / "windows" / "collector_win.py"
    return COLLECTORS / "linux" / "collector_linux.py"


def start_local_collector(run_id: str, mode: str = "analysis", timeout: int = 240) -> subprocess.Popen:
    platform_name = detect_platform()
    script = collector_script(platform_name)
    cmd = [
        sys.executable,
        str(script),
        "--run-id", run_id,
        "--backend-url", os.getenv("OUTPOST_API_URL", "http://localhost:8000"),
        "--mode", mode,
    ]
    if mode == "analysis":
        cmd += ["--timeout", str(timeout)]
    return subprocess.Popen(cmd)


def stop_local_collector(proc: subprocess.Popen) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
