"""HTTP shipping for collector events — buffer + batch POST.

Per docs/03-COLLECTOR-SPEC.md:
- Buffer locally and batch-POST every N events or T seconds, whichever first
- On backend unreachable: retry with backoff, spool to a local fallback file
  so no data is lost if the backend restarts mid-run
"""

import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import quote

import requests

# Shipped with every heartbeat so the fleet view can tell agent versions apart.
COLLECTOR_VERSION = "outpost-collector/1.0"

log = logging.getLogger("outpost.shipper")


def _auth_headers() -> dict:
    """Authorization for the shared agent credential (OUTPOST_AGENT_TOKEN).

    When set, every request carries it so the collector works under
    fail-closed auth (OUTPOST_AUTH_REQUIRED=1) — heartbeats, event shipping,
    and session claims all authenticate as the host. Empty when unset.
    """
    tok = os.environ.get("OUTPOST_AGENT_TOKEN", "").strip()
    return {"Authorization": f"Bearer {tok}"} if tok else {}


def _default_host_id() -> str:
    """A stable-enough host label for fleet attribution: hostname, lowercased.
    Override with OUTPOST_HOST_ID for multi-host fleets where hostnames could
    collide (then the fleet view shows the operator-chosen label)."""
    import socket

    return os.getenv("OUTPOST_HOST_ID", "").strip() or socket.gethostname().lower()


def claim_active_live_run(backend_url: str) -> str:
    """Claim the newest open live session the webapp started.

    GET /runs/active-live and return its run_id — the collector then streams
    real host events into exactly the run the Live Monitor is showing.
    Raises RuntimeError with a human message when nothing is open.
    """
    try:
        resp = requests.get(f"{backend_url.rstrip('/')}/runs/active-live", headers=_auth_headers(), timeout=5)
    except requests.RequestException:
        raise RuntimeError(
            f"Backend not reachable at {backend_url} — is it running? "
            "(set OUTPOST_API_URL if it isn't the default)"
        )
    if resp.status_code == 404:
        raise RuntimeError(
            "No active live session to stream into — open the Live Monitor in the "
            "webapp and click 'Start live monitoring' first."
        )
    if not resp.ok:
        raise RuntimeError(f"Claim failed: GET /runs/active-live -> {resp.status_code}")
    return resp.json()["run_id"]


def agent_run_name(host_id: str, when=None) -> str:
    """One agent session per host per day — `agent-<host>-<YYYY-MM-DD>`.

    The daily-summary tool and the systemd service both rely on this naming:
    a crash-restart of the service reuses *today's* open run (the daily
    measurement stays one session), and `outpost agent summary --days N`
    selects exactly the agent's own sessions by the `agent-` prefix.
    """
    import datetime as _dt

    d = (when or _dt.datetime.now(_dt.timezone.utc)).strftime("%Y-%m-%d")
    return f"agent-{host_id}-{d}"


def resolve_live_run_id(backend_url: str, platform: str) -> str:
    """Standalone session resolution for live monitoring (systemd service).

    1. Claim the webapp's open live session (Live Monitor parity — a user
       watching the browser gets the host's real events).
    2. Otherwise reuse today's open agent run (crash-safe: one session/day).
    3. Otherwise create one (POST /runs, session_type=live, source=agent).

    So the agent service is self-sufficient — no webapp session needs to be
    open for telemetry to flow.
    """
    try:
        return claim_active_live_run(backend_url)
    except RuntimeError:
        pass  # nothing open — fall through to the agent's own sessions

    base = backend_url.rstrip("/")
    host = _default_host_id()
    name = agent_run_name(host)
    # Reuse today's open agent run if the service restarted mid-day.
    try:
        resp = requests.get(f"{base}/runs", headers=_auth_headers(), timeout=5)
        if resp.ok:
            for r in resp.json():
                if (
                    r.get("sample_name") == name
                    and not r.get("completed_at")
                    and r.get("session_type") == "live"
                ):
                    return r["run_id"]
    except requests.RequestException:
        pass
    # Fresh session for today.
    payload = {
        "sample_name": name,
        "platform": platform,
        "session_type": "live",
        "source": "agent",
    }
    resp = requests.post(f"{base}/runs", json=payload, headers=_auth_headers(), timeout=5)
    resp.raise_for_status()
    return resp.json()["run_id"]


class Shipper:
    def __init__(
        self,
        backend_url: str,
        run_id: str,
        batch_size: int = 20,
        flush_interval: float = 2.0,
        spool_path: str | None = None,
        max_retries: int = 3,
        host_id: str | None = None,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.run_id = run_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.host_id = host_id or _default_host_id()
        self.buffer: list[dict] = []
        self.last_flush = time.time()
        self.spool_path = spool_path or str(Path.cwd() / f"outpost-spool-{run_id}.jsonl")

    def add(self, event: dict) -> None:
        """Queue one normalized event dict; flush when thresholds are hit.

        Every event is stamped with this shipper's host identity (fleet
        attribution — the backend's /agents view groups by it). An event that
        already names a host keeps its own.

        The exact log channel comes from the collectors themselves (they
        stamp auditd/sysmon on every event they build); this platform-based
        fallback covers events built elsewhere, so no collector-shipped event
        can ever land unstamped."""
        event["run_id"] = self.run_id
        event.setdefault("host_id", self.host_id)
        plat = (event.get("platform") or "").lower()
        if plat == "linux":
            event.setdefault("log_source", "auditd")
        elif plat == "windows":
            event.setdefault("log_source", "sysmon")
        self.buffer.append(event)
        if len(self.buffer) >= self.batch_size or time.time() - self.last_flush > self.flush_interval:
            self.flush()

    def maybe_heartbeat(self, platform: str | None = None, interval: float = 60.0) -> None:
        """Ping /agents/{host}/heartbeat when `interval` elapsed since the last
        ping — liveness independent of event volume, so the fleet view can
        flag hosts that went silent. Best-effort like snapshots: a down
        backend just logs and retries next tick."""
        if time.time() - getattr(self, "_last_heartbeat", 0.0) < interval:
            return
        self._last_heartbeat = time.time()
        try:
            resp = requests.post(
                f"{self.backend_url}/agents/{quote(self.host_id, safe='')}/heartbeat",
                json={"platform": platform, "version": COLLECTOR_VERSION},
                headers=_auth_headers(),
                timeout=5,
            )
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001 — heartbeat is best-effort
            log.warning("Heartbeat failed: %s", exc)

    def ship_snapshot(self, platform: str | None = None) -> dict | None:
        """POST the live system snapshot (processes + listening ports) for this
        host. Best-effort: a failure just logs — the event stream must never
        die because the snapshot couldn't ship."""
        try:
            from . import snapshot as snapshot_mod  # package import (collectors.common)
        except ImportError:
            import snapshot as snapshot_mod  # top-level module (test sys.path)

        try:
            payload = snapshot_mod.collect_snapshot(self.host_id, platform)
            resp = requests.post(
                f"{self.backend_url}/ingest/snapshot",
                json=payload,
                headers=_auth_headers(),
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001 — snapshot is best-effort
            log.warning("Snapshot ship failed: %s", exc)
            return None

    def flush(self) -> None:
        batch = self.buffer
        self.buffer = []

        if batch:
            for attempt in range(self.max_retries):
                try:
                    resp = requests.post(f"{self.backend_url}/ingest/batch", json=batch, headers=_auth_headers(), timeout=5)
                    resp.raise_for_status()
                    self._replay_spool()
                    self.last_flush = time.time()
                    return
                except requests.RequestException:
                    if attempt < self.max_retries - 1:
                        time.sleep(0.5 * (2**attempt))
                    else:
                        self._spool(batch)
                        log.warning("Backend unreachable — spooled %d events to %s", len(batch), self.spool_path)
            self.last_flush = time.time()
        else:
            # Empty flush still attempts spool replay — without this, a
            # collector with no new events would never push buffered events
            # back after the backend recovers (the buffer check used to
            # early-return and skip replay entirely).
            self._replay_spool()

    # -- fallback spooling ---------------------------------------------------
    def _spool(self, batch: list[dict]) -> None:
        with open(self.spool_path, "a", encoding="utf-8") as fh:
            for ev in batch:
                fh.write(json.dumps(ev) + "\n")

    def _replay_spool(self) -> None:
        """Push any spooled events to the backend now that it's reachable."""
        if not os.path.exists(self.spool_path):
            return
        try:
            with open(self.spool_path, "r", encoding="utf-8") as fh:
                events = [json.loads(line) for line in fh if line.strip()]
            if events:
                requests.post(f"{self.backend_url}/ingest/batch", json=events, headers=_auth_headers(), timeout=5).raise_for_status()
            os.remove(self.spool_path)
        except Exception:
            log.warning("Spool replay failed — will retry on next successful flush")
