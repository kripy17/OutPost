#!/usr/bin/env python3
"""Self-test for validate_sandbox_provider.py's fix hints.

The sandbox-provider gate validates a REAL provider end to end (upload →
detonate → poll → run assertions), but its failure diagnostics used to stop
at a bare `FAIL — …` line. Every failure path now ends with an actionable
`→ fix:` line. This self-test pins that behavior WITHOUT a real provider or
backend: it spins up a tiny fake HTTP backend (stdlib http.server) that
serves the exact endpoints the gate calls — /sandbox/providers, /samples,
/sandbox/detonate, /sandbox/tasks/{id}, /runs/{id} — with per-scenario
state, then runs the REAL gate script against it as a subprocess.

For every drift direction it asserts the gate exits 1 AND prints the
`→ fix:` line, then flips the fake backend to the "fixed" state and asserts
the gate exits 0 (the hint actually repairs). The detonate response carries
the FINAL status (completed/error) so the gate's 15s poll sleep is never
entered — the whole test runs in seconds.

Directions covered:
  backend unreachable / unknown provider / provider not configured /
  upload failure / detonate failure / task error / timeout /
  zero events / run source wrong — plus the clean-skip and happy paths.

Exit 0 only when all assertions pass.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from hint_coverage_map import gate_for

GATE = ROOT / "scripts" / gate_for(Path(__file__).name)

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


# -- fake backend -----------------------------------------------------------


class _State:
    def __init__(self) -> None:
        self.providers = {"anyrun": False, "triage": False, "joe": False}
        self.upload_fail = False
        self.detonate_fail = False
        self.task_status = "completed"  # completed | error | running
        self.task_error = None
        self.events = 5
        self.alerts = 1
        self.run_completed = True
        self.run_source = "sandbox:demo"


STATE = _State()


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)

    def do_GET(self) -> None:  # noqa: N802
        p = self.path
        if p == "/sandbox/providers":
            self._send(200, {
                "providers": [{"id": k, "configured": v} for k, v in STATE.providers.items()],
                "active": "demo",
            })
        elif p.startswith("/sandbox/tasks/"):
            if STATE.task_status == "completed":
                self._send(200, {"task_id": "t1", "run_id": "r1", "status": "completed",
                                 "events": STATE.events, "alerts": STATE.alerts,
                                 "risk_score": 80, "highest_severity": "suspicious"})
            elif STATE.task_status == "error":
                self._send(200, {"task_id": "t1", "run_id": "r1", "status": "error",
                                 "error": STATE.task_error or "provider rejected sample",
                                 "events": 0, "alerts": 0})
            else:
                self._send(200, {"task_id": "t1", "run_id": "r1", "status": "running",
                                 "events": 0, "alerts": 0})
        elif p.startswith("/runs/"):
            self._send(200, {"run": {"run_id": "r1",
                                     "completed_at": "2026-01-01T00:00:00Z" if STATE.run_completed else None,
                                     "source": STATE.run_source}})
        else:
            self._send(404, {"detail": "no such endpoint"})

    def do_POST(self) -> None:  # noqa: N802
        self._drain()
        if self.path.startswith("/samples"):
            if STATE.upload_fail:
                self._send(500, {"detail": "upload boom"})
            else:
                self._send(200, {"sample_id": "s1", "detected_platform": "windows", "size": 64})
        elif self.path.startswith("/sandbox/detonate"):
            if STATE.detonate_fail:
                self._send(500, {"detail": "detonate boom"})
            else:
                # The real backend resolves the demo provider INLINE, so the
                # detonate response is already the full completed task (the
                # gate reads last['events']/risk/severity straight from it).
                done = STATE.task_status == "completed"
                self._send(200, {"task_id": "t1", "run_id": "r1", "sample_id": "s1",
                                 "provider": "demo", "status": STATE.task_status,
                                 "events": STATE.events if done else 0,
                                 "alerts": STATE.alerts if done else 0,
                                 "risk_score": 80 if done else 0,
                                 "highest_severity": "suspicious" if done else None})
        else:
            self._send(404, {"detail": "no such endpoint"})

    def log_message(self, *args) -> None:  # keep the test output clean
        pass


def start_server() -> int:
    global STATE
    STATE = _State()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return port


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_fixture(tmp: Path) -> Path:
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(GATE, tmp / "scripts/validate_sandbox_provider.py")
    return tmp / "scripts/validate_sandbox_provider.py"


def run_gate(gate: Path, port: int, *extra: str) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(gate), "--backend", f"http://127.0.0.1:{port}", *extra],
        capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def expect_drift(name: str, hint_needle: str, rc: int, out: str) -> None:
    ok = rc == 1 and hint_needle in out
    check(name, ok, f"rc={rc}, hint={hint_needle!r} in output" if not ok else f"rc={rc}, hint present")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sandbox-hints-") as td:
        gate = build_fixture(Path(td))
        port = start_server()

        # 0a. Happy path (labeled demo) — passes with no hint line.
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("happy path passes", rc == 0 and "PASS" in out and "→ fix:" not in out, f"rc={rc}")

        # 0b. auto + none configured — the clean SKIP, no hint line.
        rc, out = run_gate(gate, port)
        check("no keys + auto → clean skip", rc == 0 and "SKIP" in out and "→ fix:" not in out, f"rc={rc}")

        # 1. Backend unreachable — the hint names the fix (start / point it).
        dead = closed_port()
        rc, out = run_gate(gate, dead, "--provider", "demo")
        expect_drift("backend unreachable", "→ fix: start the backend first", rc, out)
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("backend unreachable → repair green", rc == 0, f"rc={rc}")

        # 2. Unknown provider — the hint lists the valid choices.
        rc, out = run_gate(gate, port, "--provider", "nope")
        expect_drift("unknown provider", "→ fix: pass --provider anyrun", rc, out)
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("unknown provider → repair green", rc == 0, f"rc={rc}")

        # 3. Requested provider not configured — the hint names the key + fallback.
        rc, out = run_gate(gate, port, "--provider", "anyrun")
        expect_drift("provider requested but not configured", "→ fix: set ANYRUN_API_KEY", rc, out)
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("provider requested but not configured → repair green", rc == 0, f"rc={rc}")

        # 4. Sample upload failure.
        STATE.upload_fail = True
        rc, out = run_gate(gate, port, "--provider", "demo")
        expect_drift("sample upload failure", "→ fix: confirm the backend is up", rc, out)
        STATE.upload_fail = False
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("sample upload failure → repair green", rc == 0, f"rc={rc}")

        # 5. Detonation failure.
        STATE.detonate_fail = True
        rc, out = run_gate(gate, port, "--provider", "demo")
        expect_drift("detonate failure", "→ fix: check the provider key", rc, out)
        STATE.detonate_fail = False
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("detonate failure → repair green", rc == 0, f"rc={rc}")

        # 6. Task error status.
        STATE.task_status = "error"
        STATE.task_error = "sample type not supported"
        rc, out = run_gate(gate, port, "--provider", "demo")
        expect_drift("task error", "→ fix: inspect the provider's task error", rc, out)
        STATE.task_status = "completed"
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("task error → repair green", rc == 0, f"rc={rc}")

        # 7. Timeout — max-wait 0 skips the poll loop entirely (no 15s sleep).
        STATE.task_status = "running"
        rc, out = run_gate(gate, port, "--provider", "demo", "--max-wait", "0")
        expect_drift("did not complete (timeout)", "→ fix: raise --max-wait", rc, out)
        STATE.task_status = "completed"
        rc, out = run_gate(gate, port, "--provider", "demo", "--max-wait", "30")
        check("did not complete (timeout) → repair green", rc == 0, f"rc={rc}")

        # 8. Task completed with zero events.
        STATE.events = 0
        rc, out = run_gate(gate, port, "--provider", "demo")
        expect_drift("zero events", "→ fix: confirm the sample type", rc, out)
        STATE.events = 5
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("zero events → repair green", rc == 0, f"rc={rc}")

        # 9. Run source not sandbox:<provider>.
        STATE.run_source = "webapp"
        rc, out = run_gate(gate, port, "--provider", "demo")
        expect_drift("run source wrong", "→ fix: the run must be created by the sandbox detonation path", rc, out)
        STATE.run_source = "sandbox:demo"
        rc, out = run_gate(gate, port, "--provider", "demo")
        check("run source wrong → repair green", rc == 0, f"rc={rc}")

    print(f"Sandbox-provider hint self-test: {len(FAILURES)} failed" if FAILURES else "Sandbox-provider hint self-test: every failure path prints a repair hint")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
