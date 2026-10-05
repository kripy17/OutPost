"""HTTP shipping for collector events — buffer + batch POST.

Per docs/03-COLLECTOR-SPEC.md:
- Buffer locally and batch-POST every N events or T seconds, whichever first
- On backend unreachable: retry with backoff, spool to a local fallback file
  so no data is lost if the backend restarts mid-run
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import quote

import requests

# Shipped with every heartbeat so the fleet view can tell agent versions apart.
COLLECTOR_VERSION = "outpost-collector/1.0"

log = logging.getLogger("outpost.shipper")


def compute_hmac_headers(agent_id: str, agent_secret: str, method: str = "GET", path: str = "/") -> dict:
    """Compute HMAC-SHA256 signature headers for an enrolled agent."""
    ts = str(int(time.time()))
    method_clean = (method or "GET").upper()
    path_clean = path or "/"
    canonical = f"{agent_id}:{ts}:{method_clean}:{path_clean}"
    sig = hmac.new(agent_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-OutPost-Agent-Id": agent_id,
        "X-OutPost-Timestamp": ts,
        "X-OutPost-Signature": sig,
    }


def _auth_headers(
    method: str = "GET",
    path: str = "/",
    agent_id: str | None = None,
    agent_secret: str | None = None,
) -> dict:
    """Authorization for the agent: HMAC signature if enrolled, or Bearer token fallback.

    When set, every request carries it so the collector works under
    fail-closed auth (OUTPOST_AUTH_REQUIRED=1) — heartbeats, event shipping,
    and session claims all authenticate as the host. Empty when unset.
    """
    aid = agent_id or os.environ.get("OUTPOST_AGENT_ID", "").strip()
    asec = agent_secret or os.environ.get("OUTPOST_AGENT_SECRET", "").strip()
    if aid and asec:
        return compute_hmac_headers(aid, asec, method, path)
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


class SQLiteSpool:
    """Thread-safe, crash-resilient local event spool buffer using SQLite WAL mode."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_spool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def spool(self, events: list[dict]) -> None:
        if not events:
            return
        now = time.time()
        rows = [(now, json.dumps(ev)) for ev in events]
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany("INSERT INTO event_spool (created_at, payload) VALUES (?, ?)", rows)
            conn.commit()

    def count(self) -> int:
        if not os.path.exists(self.db_path):
            return 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute("SELECT COUNT(*) FROM event_spool").fetchone()
                return row[0] if row else 0
        except Exception:
            return 0

    def peek(self, limit: int = 100) -> list[tuple[int, dict]]:
        if not os.path.exists(self.db_path):
            return []
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id, payload FROM event_spool ORDER BY id ASC LIMIT ?", (limit,)
                ).fetchall()
                out = []
                for row_id, raw in rows:
                    try:
                        out.append((row_id, json.loads(raw)))
                    except Exception:
                        pass
                return out
        except Exception:
            return []

    def remove(self, ids: list[int]) -> None:
        if not ids or not os.path.exists(self.db_path):
            return
        try:
            with sqlite3.connect(self.db_path) as conn:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM event_spool WHERE id IN ({placeholders})", ids)
                conn.commit()
        except Exception:
            pass


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
        compress: bool = False,
        agent_id: str | None = None,
        agent_secret: str | None = None,
        **kwargs,
    ):
        self.backend_url = backend_url.rstrip("/")
        self.run_id = run_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.host_id = host_id or _default_host_id()
        self.compress = compress
        self.agent_id = agent_id or os.environ.get("OUTPOST_AGENT_ID", "").strip() or None
        self.agent_secret = agent_secret or os.environ.get("OUTPOST_AGENT_SECRET", "").strip() or None
        self.buffer: list[dict] = []
        self.last_flush = time.time()
        self._start_time = time.time()
        self._last_heartbeat = 0.0
        self._hb_running = False
        self._hb_thread: threading.Thread | None = None

        if spool_path is None:
            self.spool_path = str(Path.cwd() / f"outpost-spool-{run_id}.db")
            self._use_sqlite_spool = True
        elif spool_path.endswith(".jsonl"):
            self.spool_path = spool_path
            self._use_sqlite_spool = False
        else:
            self.spool_path = spool_path
            self._use_sqlite_spool = True

        if self._use_sqlite_spool:
            self._sqlite_spool = SQLiteSpool(self.spool_path)
        else:
            self._sqlite_spool = None

    def get_auth_headers(self, method: str = "GET", path: str = "/") -> dict:
        """Resolve current authorization headers (HMAC signature or Bearer token)."""
        return _auth_headers(method, path, self.agent_id, self.agent_secret)

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

    ship = add

    def get_system_metrics(self) -> dict:
        """Collect live host system telemetry (CPU %, memory %, queue backlog, uptime)."""
        cpu_pct = 0.0
        mem_pct = 0.0
        mem_used_mb = 0
        mem_total_mb = 0

        try:
            import psutil
            cpu_pct = float(psutil.cpu_percent(interval=None))
            vmem = psutil.virtual_memory()
            mem_pct = float(vmem.percent)
            mem_used_mb = int(vmem.used / (1024 * 1024))
            mem_total_mb = int(vmem.total / (1024 * 1024))
        except (ImportError, Exception):
            try:
                if os.path.exists("/proc/loadavg"):
                    with open("/proc/loadavg", "r") as fh:
                        load1 = float(fh.read().split()[0])
                    cpu_count = os.cpu_count() or 1
                    cpu_pct = round(min(100.0, (load1 / cpu_count) * 100.0), 1)
                if os.path.exists("/proc/meminfo"):
                    mem_data = {}
                    with open("/proc/meminfo", "r") as fh:
                        for line in fh:
                            parts = line.split(":")
                            if len(parts) == 2:
                                k = parts[0].strip()
                                v = parts[1].strip().split()[0]
                                if v.isdigit():
                                    mem_data[k] = int(v)
                    total_kb = mem_data.get("MemTotal", 0)
                    avail_kb = mem_data.get("MemAvailable", mem_data.get("MemFree", 0))
                    if total_kb > 0:
                        used_kb = max(0, total_kb - avail_kb)
                        mem_total_mb = int(total_kb / 1024)
                        mem_used_mb = int(used_kb / 1024)
                        mem_pct = round((used_kb / total_kb) * 100.0, 1)
            except Exception:
                pass

        backlog = len(self.buffer)
        if getattr(self, "_use_sqlite_spool", False) and getattr(self, "_sqlite_spool", None):
            backlog += self._sqlite_spool.count()

        uptime_sec = int(time.time() - getattr(self, "_start_time", time.time()))

        return {
            "cpu_percent": round(cpu_pct, 1),
            "memory_percent": round(mem_pct, 1),
            "memory_used_mb": mem_used_mb,
            "memory_total_mb": mem_total_mb,
            "queue_backlog": backlog,
            "uptime_seconds": uptime_sec,
        }

    def start_heartbeat_daemon(self, interval: float = 30.0, platform: str | None = None) -> None:
        """Start a background daemon thread that periodically ships heartbeats."""
        if getattr(self, "_hb_running", False):
            return
        self._hb_running = True
        self._hb_thread = threading.Thread(
            target=self._heartbeat_worker,
            args=(interval, platform),
            daemon=True,
            name="outpost-heartbeat-daemon",
        )
        self._hb_thread.start()

    def stop_heartbeat_daemon(self) -> None:
        self._hb_running = False

    def _heartbeat_worker(self, interval: float, platform: str | None) -> None:
        while getattr(self, "_hb_running", False):
            try:
                self.maybe_heartbeat(platform=platform, interval=0.0)
            except Exception as e:
                log.debug("Heartbeat daemon error: %s", e)
            time.sleep(interval)

    def maybe_heartbeat(
        self,
        platform: str | None = None,
        interval: float = 60.0,
        metrics: dict | None = None,
        channel: str | None = None,
    ) -> None:
        """Ping /agents/{host}/heartbeat when `interval` elapsed since the last
        ping — liveness independent of event volume, so the fleet view can
        flag hosts that went silent. Best-effort like snapshots: a down
        backend just logs and retries next tick."""
        if time.time() - getattr(self, "_last_heartbeat", 0.0) < interval:
            return
        self._last_heartbeat = time.time()
        path = f"/agents/{quote(self.host_id, safe='')}/heartbeat"
        try:
            payload = {
                "platform": platform,
                "version": COLLECTOR_VERSION,
            }
            if metrics is not None:
                payload["metrics"] = metrics
            else:
                payload["metrics"] = self.get_system_metrics()
            if self.agent_id:
                payload["agent_id"] = self.agent_id

            resp = requests.post(
                f"{self.backend_url}{path}",
                json=payload,
                headers=self.get_auth_headers("POST", path),
                timeout=5,
            )
            resp.raise_for_status()
            try:
                data = resp.json() if hasattr(resp, "json") and callable(resp.json) else {}
                isolated = bool(data.get("isolated", False))
                try:
                    from . import containment
                except ImportError:
                    import containment
                containment.apply_containment_state(isolated, self.backend_url)

                pending_actions = data.get("pending_actions") or []
                if pending_actions:
                    self._execute_pending_actions(pending_actions)
            except Exception as e_cont:
                log.warning("Containment evaluation error: %s", e_cont)
        except Exception as exc:
            log.warning("Heartbeat failed: %s", exc)

    heartbeat = maybe_heartbeat

    def _execute_pending_actions(self, actions: list[dict]) -> None:
        """Execute queued remediation actions (e.g. process termination) and acknowledge completion."""
        import signal
        executed_ids = []
        for act in actions:
            action_type = act.get("action")
            action_id = act.get("action_id")
            if action_type == "kill_process":
                pid = act.get("pid")
                proc_name = act.get("process_name", "")
                if pid:
                    try:
                        pid_int = int(pid)
                        if pid_int > 1 and pid_int != os.getpid():
                            try:
                                os.kill(pid_int, signal.SIGTERM)
                            except AttributeError:
                                import subprocess
                                subprocess.run(["taskkill", "/F", "/PID", str(pid_int)], capture_output=True, timeout=5)
                            log.info("Terminated process PID %d (%s) as instructed by OutPost controller", pid_int, proc_name)
                    except (ProcessLookupError, OSError) as err:
                        log.debug("Process PID %s could not be terminated: %s", pid, err)
                    except Exception as err:
                        log.warning("Failed executing kill_process on PID %s: %s", pid, err)
            if action_id:
                executed_ids.append(action_id)

        if executed_ids:
            try:
                ack_path = f"/agents/{quote(self.host_id, safe='')}/actions/ack"
                ack_resp = requests.post(
                    f"{self.backend_url}{ack_path}",
                    json={"action_ids": executed_ids},
                    headers=self.get_auth_headers("POST", ack_path),
                    timeout=5,
                )
                ack_resp.raise_for_status()
            except Exception as ack_err:
                log.warning("Failed to acknowledge agent actions %s: %s", executed_ids, ack_err)

    def ship_snapshot(self, platform: str | None = None) -> dict | None:
        """POST the live system snapshot (processes + listening ports) for this
        host. Best-effort: a failure just logs — the event stream must never
        die because the snapshot couldn't ship."""
        try:
            from . import snapshot as snapshot_mod
        except ImportError:
            import snapshot as snapshot_mod

        try:
            payload = snapshot_mod.collect_snapshot(self.host_id, platform)
            path = "/ingest/snapshot"
            resp = requests.post(
                f"{self.backend_url}{path}",
                json=payload,
                headers=self.get_auth_headers("POST", path),
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            log.warning("Snapshot ship failed: %s", exc)
            return None

    def flush(self) -> None:
        batch = self.buffer
        self.buffer = []

        if batch:
            headers = self.get_auth_headers("POST", "/ingest/batch")
            for attempt in range(self.max_retries):
                try:
                    if self.compress:
                        import gzip as _gzip
                        raw = json.dumps(batch).encode("utf-8")
                        payload = _gzip.compress(raw)
                        headers_comp = {**headers, "Content-Encoding": "gzip", "Content-Type": "application/json"}
                        resp = requests.post(f"{self.backend_url}/ingest/batch", data=payload, headers=headers_comp, timeout=5)
                    else:
                        resp = requests.post(f"{self.backend_url}/ingest/batch", json=batch, headers=headers, timeout=5)
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
            self._replay_spool()

    def _spool(self, batch: list[dict]) -> None:
        if getattr(self, "_use_sqlite_spool", False) and getattr(self, "_sqlite_spool", None):
            try:
                self._sqlite_spool.spool(batch)
            except Exception as err:
                log.warning("Failed to write to SQLite spool: %s", err)
            return

        try:
            if os.path.exists(self.spool_path) and os.path.getsize(self.spool_path) > 25 * 1024 * 1024:
                log.warning("Spool file exceeds 25MB safety cap (%s)", self.spool_path)
            with open(self.spool_path, "a", encoding="utf-8") as fh:
                fh.writelines(json.dumps(ev) + "\n" for ev in batch)
        except OSError as err:
            log.warning("Failed to write to spool: %s", err)

    def _replay_spool(self) -> None:
        """Push any spooled events to the backend now that it's reachable."""
        if getattr(self, "_use_sqlite_spool", False) and getattr(self, "_sqlite_spool", None):
            try:
                chunk_size = 100
                headers = self.get_auth_headers("POST", "/ingest/batch")
                while True:
                    items = self._sqlite_spool.peek(chunk_size)
                    if not items:
                        break
                    batch = [it[1] for it in items]
                    ids = [it[0] for it in items]
                    resp = requests.post(f"{self.backend_url}/ingest/batch", json=batch, headers=headers, timeout=5)
                    resp.raise_for_status()
                    self._sqlite_spool.remove(ids)
            except Exception:
                log.warning("SQLite spool replay failed — will retry on next successful flush")
            return

        if not os.path.exists(self.spool_path):
            return
        try:
            with open(self.spool_path, "r", encoding="utf-8") as fh:
                events = [json.loads(line) for line in fh if line.strip()]
            if events:
                chunk_size = 100
                headers = self.get_auth_headers("POST", "/ingest/batch")
                for i in range(0, len(events), chunk_size):
                    chunk = events[i : i + chunk_size]
                    requests.post(f"{self.backend_url}/ingest/batch", json=chunk, headers=headers, timeout=5).raise_for_status()
            os.remove(self.spool_path)
        except Exception:
            log.warning("Spool replay failed — will retry on next successful flush")
