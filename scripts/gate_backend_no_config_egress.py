#!/usr/bin/env python3
"""gate_backend_no_config_egress.py — "gate the gating", the runtime proof.

The static egress gate (gate_backend_egress.py) proves WHERE httpx may
live. This gate proves WHEN it may fire: with a fresh DB (no keys) and the
operator's env keys cleared, the routine BACKGROUND flows must make ZERO
outbound requests. The httpx client itself is patched to record any
non-loopback URL (and fail that request), so even an ungated call site is
caught with the URL and the endpoint that triggered it.

Exercised flows (all through the real API, in-process via TestClient):
  run create → ingest batch (detections fire) → run complete (triggers
  enrichment) → run detail (re-enrichment) → sample upload → sandbox demo
  detonation → sandbox with an unconfigured provider (must 422, no egress).

Negative control (proves the patch bites AND that keyed paths really would
egress): set a dummy AbuseIPDB key, force-refresh one destination IP — the
patch MUST observe the provider URL. Both directions are thereby locked:
no-config → silent; keyed → egress attempted and caught.

Exit 0 = contract holds; 1 = violation; 2 = scan error.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

# 1. Zero-config precondition: clear every key env var BEFORE config imports.
for var in (
    "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY",
    "ANYRUN_API_KEY", "TRIAGE_API_KEY", "JOE_API_KEY",
):
    os.environ.pop(var, None)

# 2. Isolated temp DB + samples dir, then import the app fresh.
os.environ["DATABASE_PATH"] = tempfile.mktemp(suffix=".db")
os.environ["SAMPLES_DIR"] = tempfile.mkdtemp(prefix="no-config-egress-samples-")

from fastapi.testclient import TestClient  # noqa: E402
import httpx  # noqa: E402

from app.core import config  # noqa: E402
from app.core.db import init_db  # noqa: E402
from app.core import api_keys  # noqa: E402
from app.main import app  # noqa: E402


class EgressProbe:
    """Records any non-loopback URL an httpx client tries to reach."""

    def __init__(self) -> None:
        self.recorded: list[tuple[str, str]] = []

    def _check(self, url: object) -> None:
        try:
            from urllib.parse import urlparse
            host = urlparse(str(url)).hostname or ""
        except Exception:
            host = ""
        # testserver = TestClient's in-process ASGI transport host.
        if host not in ("127.0.0.1", "::1", "localhost", "testserver"):
            self.recorded.append((host, str(url)[:120]))
            raise ConnectionError(f"no-config egress gate: blocked {url}")

    def __enter__(self) -> "EgressProbe":
        self._real_async = httpx.AsyncClient.request
        self._real_sync = httpx.Client.request

        async def guard_async(self_, method, url, *args, **kwargs):
            self._check(url)
            return await self._real_async(self_, method, url, *args, **kwargs)

        def guard_sync(self_, method, url, *args, **kwargs):
            self._check(url)
            return self._real_sync(self_, method, url, *args, **kwargs)

        httpx.AsyncClient.request = guard_async
        httpx.Client.request = guard_sync
        return self

    def __exit__(self, *exc) -> None:
        httpx.AsyncClient.request = self._real_async
        httpx.Client.request = self._real_sync
        return False


def main() -> int:
    init_db()
    client = TestClient(app)

    failures: list[str] = []
    db_path = os.environ["DATABASE_PATH"]
    samples_dir = os.environ["SAMPLES_DIR"]
    run_id = None
    sample_id = None

    try:
        with EgressProbe() as probe:
            # --- background flow: create → ingest → complete → detail ---
            r = client.post("/runs", json={
                "sample_name": "no-config-probe.exe",
                "platform": "windows",
                "session_type": "analysis",
            })
            if r.status_code not in (200, 201):
                failures.append(f"POST /runs -> {r.status_code}: {r.text[:120]}")
            else:
                run_id = r.json()["run_id"]

            events = [
                {"run_id": run_id, "platform": "windows", "event_type": "process_create",
                 "timestamp": "2026-08-14T08:00:00Z", "pid": 4242, "ppid": 1,
                 "process_name": "no-config-probe.exe", "command_line": "probe.exe --scan"},
                {"run_id": run_id, "platform": "windows", "event_type": "network_connection",
                 "timestamp": "2026-08-14T08:00:01Z", "pid": 4242, "ppid": 1,
                 "process_name": "no-config-probe.exe", "dest_ip": "203.0.113.88", "dest_port": 4444},
                {"run_id": run_id, "platform": "windows", "event_type": "file_write",
                 "timestamp": "2026-08-14T08:00:02Z", "pid": 4242, "ppid": 1,
                 "process_name": "no-config-probe.exe", "file_path": "C:\\Users\\x\\AppData\\Roaming\\x.exe"},
            ]
            r = client.post("/ingest/batch", json=events)
            if r.status_code not in (200, 202):
                failures.append(f"POST /ingest/batch -> {r.status_code}: {r.text[:120]}")

            r = client.post(f"/runs/{run_id}/complete")
            if r.status_code != 200:
                failures.append(f"POST /runs/{run_id}/complete -> {r.status_code}")

            r = client.get(f"/runs/{run_id}")
            if r.status_code != 200:
                failures.append(f"GET /runs/{run_id} -> {r.status_code}")

            # --- sample upload + sandbox demo detonation (no provider key) ---
            r = client.post("/samples?name=no-config-probe.exe", content=b"MZ\x90\x00\x03\x00\x00\x00" * 32)
            if r.status_code != 201:
                failures.append(f"POST /samples -> {r.status_code}")
            else:
                sample_id = r.json()["sample_id"]

            if sample_id:
                r = client.post("/sandbox/detonate", json={
                    "sample_id": sample_id, "provider": "demo", "platform": "windows",
                })
                if r.status_code not in (200, 202):
                    failures.append(f"POST /sandbox/detonate demo -> {r.status_code}")

                # A REAL provider without a key must refuse — and never egress.
                r = client.post("/sandbox/detonate", json={
                    "sample_id": sample_id, "provider": "anyrun", "platform": "windows",
                })
                if r.status_code != 422:
                    failures.append(
                        f"POST /sandbox/detonate anyrun (unconfigured) -> {r.status_code} (expected 422)")

        if probe.recorded:
            for host, url in sorted(set(probe.recorded)):
                failures.append(f"background flow reached external {host}: {url}")

        # --- negative control: a configured key MUST make the provider reachable ---
        if run_id:
            from app.core.db import db_session
            with db_session() as conn:
                api_keys.set_api_key(conn, "abuseipdb", "dummy-key-for-gate")
            control_recorded: list[tuple[str, str]] = []
            with EgressProbe() as control:
                try:
                    client.post(f"/runs/{run_id}/enrichment/refresh?ip=203.0.113.88")
                except Exception:
                    pass  # the probe raises inside the handler — recorded is what matters
                control_recorded = control.recorded
            if not any(host == "api.abuseipdb.com" for host, _ in control_recorded):
                hosts = sorted({h for h, _ in control_recorded}) or ["<none>"]
                failures.append(
                    "negative control FAILED: a keyed refresh made no provider "
                    f"contact (observed: {', '.join(hosts)}) — the probe may not bite")
    finally:
        import shutil
        for p in (db_path,):
            try:
                os.unlink(p)
            except OSError:
                pass
        shutil.rmtree(samples_dir, ignore_errors=True)

    if failures:
        print(f"✗ Backend no-config egress gate: {len(failures)} violation(s)")
        for f in failures:
            print(f"    {f}")
        return 1
    print("✓ Backend no-config egress gate: background flows silent with zero config "
          "(create/ingest/complete/detail/upload/demo-detonate), keyed refresh caught by probe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
