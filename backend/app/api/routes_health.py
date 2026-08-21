"""GET /health — liveness; GET /platform — host-OS auto-detection."""

import platform as _platform
import socket
import sys

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/meta")
def meta() -> dict:
    """App metadata — the demo-mode flag, version, and first-run state.

    The seed scripts (seed_demo / seed_campaign) flip `demo_mode` in the
    settings table so the webapp can label seeded data honestly instead of
    letting it masquerade as real host telemetry. The Overview renders a
    dismissible banner when it's set.

    `first_run` is true only while the operator hasn't made the onboarding
    choice AND no sessions exist yet — a fresh install never silently shows
    demo data as real. `onboarding` records which choice was made
    ("demo" | "empty"), or null before the welcome screen is resolved.
    """
    from ..core.db import db_session
    from ..models.run import SYNTHETIC_SOURCES

    with db_session() as conn:
        demo = conn.execute("SELECT value FROM settings WHERE key = 'demo_mode'").fetchone()
        onboarding = conn.execute("SELECT value FROM settings WHERE key = 'onboarding'").fetchone()
        run_count = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
        marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
        real_run_count = conn.execute(
            f"SELECT COUNT(*) AS n FROM runs WHERE source NOT IN ({marks})",
            SYNTHETIC_SOURCES,
        ).fetchone()["n"]
    onboarding_value = onboarding["value"] if onboarding else None
    return {
        "demo_mode": bool(demo and demo["value"] == "1"),
        "version": "1.0",
        "first_run": onboarding_value is None and run_count == 0,
        "onboarding": onboarding_value,
        "real_run_count": real_run_count,
    }


@router.get("/platform")
def platform_info() -> dict:
    """Report the OS the backend runs on.

    The webapp has no OS picker: it reads this once on load and targets every
    live session and detonation at the detected host OS (Windows/Linux focus;
    macOS hosts resolve to macos but the UI only surfaces win/linux icons).
    """
    system = _platform.system().lower()  # "windows" | "linux" | "darwin"
    os_name = "macos" if system == "darwin" else ("windows" if system == "windows" else "linux")
    # Focus is Windows/Linux (the two shipped collectors). macOS hosts are
    # honest: no collector ships for them yet — "unsupported", not a fake one.
    collector = {"windows": "sysmon", "linux": "auditd", "macos": "unsupported"}[os_name]
    return {
        "os": os_name,
        "name": _platform.system(),
        "release": _platform.release(),
        "machine": _platform.machine(),
        "python": sys.version.split()[0],
        "collector": collector,
        # The backend host's identity — the webapp compares it against the
        # fleet so the Overview can answer "is THIS host monitored?" and lead
        # with an install-agent CTA when it isn't (auto-OS front door).
        "hostname": socket.gethostname(),
    }
