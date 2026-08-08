"""GET /health — liveness; GET /platform — host-OS auto-detection."""

import platform as _platform
import sys

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/platform")
def platform_info() -> dict:
    """Report the OS the backend runs on.

    The webapp has no OS picker: it reads this once on load and targets every
    live session and detonation at the detected host OS (Windows/Linux focus;
    macOS hosts resolve to macos but the UI only surfaces win/linux icons).
    """
    system = _platform.system().lower()  # "windows" | "linux" | "darwin"
    os_name = "macos" if system == "darwin" else ("windows" if system == "windows" else "linux")
    collector = {"windows": "sysmon", "linux": "auditd", "macos": "unified-logs"}[os_name]
    return {
        "os": os_name,
        "name": _platform.system(),
        "release": _platform.release(),
        "machine": _platform.machine(),
        "python": sys.version.split()[0],
        "collector": collector,
    }
