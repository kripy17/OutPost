"""Post-deploy checklist walk — repeatable CI gate (verify.sh step).

Recreates the production shape WITHOUT Docker: a fail-closed backend
(OUTPOST_AUTH_REQUIRED=1, admin password, agent token) behind a self-signed
TLS reverse proxy that mirrors deploy/Caddyfile semantics (`/api/*` strips
the prefix and forwards to the backend), then asserts the four checks from
deploy/README.md's post-deploy checklist live:

  1. TLS    — `curl -k https://host/health` → {"status":"ok"}
  2. Auth   — /api/runs without a token → 401; with an admin token → 200
  3. Login  — POST /auth/login → token; /auth/me → enabled:true
  4. Agent  — heartbeat without credential → 401; with OUTPOST_AGENT_TOKEN
              → 200 and the host appears online on /agents; the agent
              credential is refused outside telemetry (/campaigns → 403)

Exit 0 only when every assertion passes. Runs entirely on spare loopback
ports and cleans up (backend process, proxy, temp DB/cert) on the way out.
"""

import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib3
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
ADMIN_PASSWORD = "walk-admin-pass"
AGENT_TOKEN = "walk-agent-tok"

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_cert(tmp: Path) -> tuple[Path, Path]:
    key = tmp / "key.pem"
    cert = tmp / "cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", "/CN=outpost.local",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


# -- TLS reverse proxy (in-process stand-in for deploy/Caddyfile) --------------

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        path = self.path
        if path.startswith("/api"):
            path = path[len("/api"):] or "/"
        elif path == "/health":
            pass
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        conn = http.client.HTTPConnection(self.server.backend_host, self.server.backend_port, timeout=15)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)) or None
        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "connection", "accept-encoding")
        }
        headers["Host"] = f"{self.server.backend_host}:{self.server.backend_port}"
        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
        finally:
            conn.close()

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_DELETE = _forward
    do_PATCH = _forward

    def log_message(self, *args):
        pass  # keep the walk's output clean


def start_proxy(backend_port: int, cert: Path, key: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    proxy_port = free_port()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", proxy_port), ProxyHandler)
    server.backend_host = "127.0.0.1"
    server.backend_port = backend_port
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, proxy_port


def _walk_real_collector(base: str, admin: str, audit_log: Path, collector_log: Path) -> None:
    """Section 5 — drive the real Linux collector in live mode."""
    admin_h = {"Authorization": f"Bearer {admin}"}

    # The collector claims/creates its live agent run (`agent-<host>-<date>`;
    # live sessions normalize to source=live by design — host telemetry).
    # Wait for it to appear.
    run_id = None
    for _ in range(40):
        runs = requests.get(f"{base}/api/runs", headers=admin_h, verify=False, timeout=5).json()
        for r in runs:
            if (
                (r.get("sample_name") or "").startswith("agent-")
                and r.get("session_type") == "live"
                and not r.get("completed_at")
            ):
                run_id = r["run_id"]
                break
        if run_id:
            break
        time.sleep(0.5)
    check("5 · collector claims a live agent run", run_id is not None, f"run={run_id}")
    if run_id is None:
        print(f"    collector log:\n{(collector_log.read_text() if collector_log.exists() else '')[:800]}")
        return

    # Feed the audit log real auditd-format records (execve + connect). PIDs
    # are real processes on this host so the collector's /proc reads populate
    # process_name/command_line — nothing is patched in the collector itself.
    now = time.time()
    lines = [
        f"type=SYSCALL msg=audit({now:.3f}:101): arch=c000003e syscall=59 success=yes exit=0 pid={os.getpid()} comm=\"outpost-walk\"",
        f"type=SYSCALL msg=audit({now + 0.2:.3f}:102): arch=c000003e syscall=59 success=yes exit=0 pid=1 comm=\"systemd\"",
        f"type=SYSCALL msg=audit({now + 0.4:.3f}:103): syscall=42 success=yes exit=0 pid={os.getpid()} saddr=02000050C0A8010A",
        f"type=SYSCALL msg=audit({now + 0.6:.3f}:104): syscall=42 success=yes exit=0 pid=1 saddr=02001BBD7F000001",
    ]
    with open(audit_log, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    # The events must land in the claimed run (flush interval is 2s).
    timeline_len = 0
    events = []
    for _ in range(50):  # up to ~25s
        detail = requests.get(f"{base}/api/runs/{run_id}", headers=admin_h, verify=False, timeout=5).json()
        events = detail.get("timeline", [])
        if len(events) >= 4:
            break
        time.sleep(0.5)
    check("5 · shipped events land in the run", len(events) >= 4, f"timeline={len(events)}")

    kinds = sorted({e.get("event_type") for e in events})
    check(
        "5 · process_create + network_connection present",
        "process_create" in kinds and "network_connection" in kinds,
        f"kinds={kinds}",
    )
    check(
        "5 · events attributed to host + auditd channel",
        all(e.get("host_id") == "walk-collector" and e.get("log_source") == "auditd" for e in events),
        f"hosts={sorted({e.get('host_id') for e in events})} channels={sorted({e.get('log_source') for e in events})}",
    )

    # The heartbeat (2s interval) makes the collector host read online — and
    # because the backend is fail-closed, that heartbeat authenticates with
    # the agent credential, so the fleet must record the auth context:
    # identity=collector (only the real shipper heartbeats), last_auth_role=
    # 'agent', the collector version, and the auditd channel from its events.
    host_row = None
    for _ in range(20):
        agents = requests.get(f"{base}/api/agents", headers=admin_h, verify=False, timeout=5).json()
        host_row = next((a for a in agents.get("agents", []) if a.get("host_id") == "walk-collector"), None)
        if host_row and host_row.get("online"):
            break
        time.sleep(0.5)
    check("5 · walk-collector online on /agents", bool(host_row and host_row.get("online")))
    check(
        "5 · fleet auth context: collector + agent role",
        bool(host_row)
        and host_row.get("identity") == "collector"
        and host_row.get("last_auth_role") == "agent"
        and bool(host_row.get("last_auth_at")),
        (
            f"identity={host_row.get('identity') if host_row else None} "
            f"auth_role={host_row.get('last_auth_role') if host_row else None}"
        ),
    )
    check(
        "5 · fleet collector version + auditd channel",
        bool(host_row)
        and (host_row.get("heartbeat_version") or "").startswith("outpost-collector/")
        and "auditd" in (host_row.get("channels") or []),
        f"version={host_row.get('heartbeat_version') if host_row else None} "
        f"channels={host_row.get('channels') if host_row else None}",
    )

    # The run's verdict is computed from real events — a live session created
    # by the collector reads as host-telemetry provenance (source=live).
    detail = requests.get(f"{base}/api/runs/{run_id}", headers=admin_h, verify=False, timeout=5).json()
    run_meta = detail.get("run") or {}
    check(
        "5 · run summary real (live host-telemetry provenance)",
        run_meta.get("source") == "live" and run_meta.get("session_type") == "live",
        f"source={run_meta.get('source')} type={run_meta.get('session_type')}",
    )


def main() -> int:
    if shutil.which("openssl") is None:
        print("  FAIL — openssl not found; cannot generate the TLS cert for the walk")
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="outpost-walk-"))
    backend = None
    proxy = None
    collector = None
    try:
        backend_port = free_port()
        cert, key = make_cert(tmp)
        proxy, proxy_port = start_proxy(backend_port, cert, key)
        base = f"https://127.0.0.1:{proxy_port}"

        # Fail-closed backend, exactly as deploy/docker-compose.prod.yml configures it.
        backend = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(backend_port)],
            cwd=ROOT / "backend",
            env={
                **os.environ,
                "DATABASE_PATH": str(tmp / "walk.db"),
                "OUTPOST_AUTH_REQUIRED": "1",
                "OUTPOST_ADMIN_PASSWORD": ADMIN_PASSWORD,
                "OUTPOST_AGENT_TOKEN": AGENT_TOKEN,
                "CORS_ORIGINS": json.dumps([f"https://127.0.0.1:{proxy_port}"]),
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for the proxy + backend to answer over TLS.
        healthy = False
        for _ in range(40):
            if backend.poll() is not None:
                print(f"  FAIL — backend exited early with code {backend.returncode}")
                return 1
            try:
                if requests.get(f"{base}/health", verify=False, timeout=2).status_code == 200:
                    healthy = True
                    break
            except requests.RequestException:
                pass
            time.sleep(0.5)
        if not healthy:
            print("  FAIL — backend never became healthy over TLS")
            return 1

        # 1. TLS — health through the TLS proxy (the Caddy equivalent).
        health = requests.get(f"{base}/health", verify=False, timeout=5).json()
        check("1 · TLS /health → ok", health.get("status") == "ok", f"status={health.get('status')}")

        # 2. Auth — 401 without a token, 200 with an admin token.
        no_token = requests.get(f"{base}/api/runs", verify=False, timeout=5)
        check("2 · /api/runs no token → 401", no_token.status_code == 401, f"HTTP {no_token.status_code}")
        login = requests.post(
            f"{base}/api/auth/login",
            json={"password": ADMIN_PASSWORD},
            verify=False,
            timeout=5,
        ).json()
        admin = login["token"]
        with_token = requests.get(f"{base}/api/runs", headers={"Authorization": f"Bearer {admin}"}, verify=False, timeout=5)
        check("2 · /api/runs with admin token → 200", with_token.status_code == 200, f"HTTP {with_token.status_code}")

        # 3. Login — /auth/me reports enabled.
        me = requests.get(f"{base}/api/auth/me", headers={"Authorization": f"Bearer {admin}"}, verify=False, timeout=5).json()
        check(
            "3 · login → /auth/me enabled",
            me.get("enabled") is True and me.get("role") == "admin",
            f"enabled={me.get('enabled')} role={me.get('role')}",
        )

        # 4. Agent — the OUTPOST_AGENT_TOKEN flow (was 401-broken before the fix).
        heartbeat_bare = requests.post(f"{base}/api/agents/walk-host/heartbeat", json={"platform": "linux"}, verify=False, timeout=5)
        check("4 · heartbeat without credential → 401", heartbeat_bare.status_code == 401, f"HTTP {heartbeat_bare.status_code}")
        agent = {"Authorization": f"Bearer {AGENT_TOKEN}"}
        heartbeat = requests.post(f"{base}/api/agents/walk-host/heartbeat", json={"platform": "linux", "version": "outpost-collector/1.0"}, headers=agent, verify=False, timeout=5)
        check("4 · heartbeat with agent token → 200", heartbeat.status_code == 200, f"HTTP {heartbeat.status_code}")
        agents = requests.get(f"{base}/api/agents", headers={"Authorization": f"Bearer {admin}"}, verify=False, timeout=5).json()
        host_online = any(a.get("host_id") == "walk-host" and a.get("online") for a in agents.get("agents", []))
        check("4 · walk-host online on /agents", host_online, f"hosts={len(agents.get('agents', []))}")
        scoped = requests.get(f"{base}/api/campaigns", headers=agent, verify=False, timeout=5)
        check("4 · agent token refused outside telemetry → 403", scoped.status_code == 403, f"HTTP {scoped.status_code}")
        admin_still = requests.get(f"{base}/api/campaigns", headers={"Authorization": f"Bearer {admin}"}, verify=False, timeout=5)
        check("4 · admin unaffected → 200", admin_still.status_code == 200, f"HTTP {admin_still.status_code}")

        # 5. Real collector — the actual Linux collector in live mode against
        # the fail-closed backend. It claims/creates its agent run (with the
        # OUTPOST_AGENT_TOKEN), tails a temp audit log, and ships real
        # normalized events; those events must land in the run, attributed to
        # the host with the auditd channel, and the heartbeat must make the
        # host show online. This is the full agent→backend auth path.
        audit_log = tmp / "audit.log"
        audit_log.write_text("")
        collector_log = tmp / "collector.log"
        collector = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "collectors" / "linux" / "collector_linux.py"),
                "--backend-url", f"http://127.0.0.1:{backend_port}",
                "--mode", "live",
            ],
            env={
                **os.environ,
                "AUDIT_LOG": str(audit_log),
                "OUTPOST_AGENT_TOKEN": AGENT_TOKEN,
                "OUTPOST_HOST_ID": "walk-collector",
                "HEARTBEAT_INTERVAL": "2",
                "SNAPSHOT_INTERVAL": "9999",
            },
            stdout=open(collector_log, "w"),
            stderr=subprocess.STDOUT,
        )
        try:
            _walk_real_collector(base, admin, audit_log, collector_log)
        finally:
            collector.terminate()
            try:
                collector.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector.kill()
            collector = None

        print(f"\nPost-deploy walk: {len(PASSED)} passed, {len(FAILED)} failed")
        return 0 if not FAILED else 1
    finally:
        if collector is not None:
            collector.kill()
        if backend is not None:
            backend.terminate()
            try:
                backend.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend.kill()
        if proxy is not None:
            proxy.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
