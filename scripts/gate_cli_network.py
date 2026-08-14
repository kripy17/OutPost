#!/usr/bin/env python3
"""Gate: the CLI's network surface is loopback-only (air-gap parity).

The frontend e2e gates already fail on any non-localhost HTTP request — this
extends the same proof to the terminal. Two layers:

1. Static AST scan — HTTP-client primitives (`requests`, `urllib.request`,
   `httpx`, `http.client`, `urlopen`, `urlretrieve`) may only live in the
   sanctioned api seam (lib/api_client.py, commands/auth.py, commands/
   export.py), every `requests.<verb>` URL must be built from the env-driven
   `BASE_URL`/`base` variable, and raw client sockets (`.connect(` /
   `create_connection`) are forbidden everywhere. `socket.gethostname()` for
   host identity stays allowed.

2. Runtime proof — boots an isolated backend, seeds it through its own API,
   installs a loopback-only socket patch (every connect to a non-loopback
   address raises), then runs a representative CLI command matrix in-process.
   Any command that reaches outside loopback fails the gate with the
   offending address. A negative control (a command pointed at an external
   base URL) must FAIL under the patch — so the gate can never go vacuously
   green.

Run:  .venv/bin/python scripts/gate_cli_network.py [--port 8014]
Exit: 0 = clean, 1 = a static violation or a runtime external reach.
"""

import argparse
import ast
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / "bin" / "python"
CLI_DIR = ROOT / "cli"
OUTPOST = CLI_DIR / "outpost"

# The sanctioned seam: files that may speak HTTP at all, always at the
# env-configured base URL.
HTTP_FILES = {"lib/api_client.py", "commands/auth.py", "commands/export.py"}
# URL variables that derive from OUTPOST_API_URL (api_client's BASE_URL, the
# typer options backed by the same env in auth/admin/agent).
URL_VARS = {"BASE_URL", "base", "backend_url"}

# Imports that open a network channel. urllib.parse is URL *quoting* only.
FORBIDDEN_IMPORTS = {
    "requests": "use lib/api_client.py (the env-configured seam)",
    "urllib.request": "use lib/api_client.py",
    "httpx": "use lib/api_client.py",
    "http.client": "use lib/api_client.py",
    "urlopen": "use lib/api_client.py",
    "urlretrieve": "use lib/api_client.py",
    "socket.socket": "raw sockets are banned; socket.gethostname() is fine",
}
ALLOWED_URLLIB_PARSE = {"lib/api_client.py"}


def _rel(path: Path) -> str:
    return str(path.relative_to(OUTPOST))


def _has_url_var(node: ast.AST) -> bool:
    """The expression builds its URL from BASE_URL/base/backend_url."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in URL_VARS:
            return True
    return False


def static_scan() -> list[str]:
    problems: list[str] = []
    for path in sorted(OUTPOST.rglob("*.py")):
        rel = _rel(path)
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError as exc:  # pragma: no cover
            problems.append(f"{rel}: syntax error: {exc}")
            continue

        for node in ast.walk(tree):
            # Forbidden imports (requests outside the seam, raw clients).
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FORBIDDEN_IMPORTS:
                        if alias.name == "requests" and rel in HTTP_FILES:
                            continue
                        problems.append(
                            f"{rel}:{node.lineno} import {alias.name} — {FORBIDDEN_IMPORTS[alias.name]}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module == "requests" and rel not in HTTP_FILES:
                    problems.append(
                        f"{rel}:{node.lineno} from requests import — use lib/api_client.py"
                    )
                if node.module in ("urllib.request", "httpx", "http.client"):
                    problems.append(f"{rel}:{node.lineno} import {node.module} is banned")
                if node.module == "urllib.parse" and rel not in ALLOWED_URLLIB_PARSE:
                    problems.append(f"{rel}:{node.lineno} urllib.parse outside api_client.py")

            # requests.<verb>(url) — URL must come from the env seam. Only
            # calls whose base is literally `requests` count (dict.get() and
            # friends are not network).
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "connect" or node.func.attr == "create_connection":
                    problems.append(
                        f"{rel}:{node.lineno} raw socket {node.func.attr}() is banned — "
                        "use lib/api_client.py"
                    )
                if (
                    node.func.attr in ("get", "post", "put", "delete", "patch", "head")
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "requests"
                ):
                    if rel not in HTTP_FILES:
                        problems.append(
                            f"{rel}:{node.lineno} requests.{node.func.attr}() outside the "
                            f"api seam ({', '.join(sorted(HTTP_FILES))})"
                        )
                    elif node.args and not _has_url_var(node.args[0]):
                        problems.append(
                            f"{rel}:{node.lineno} requests.{node.func.attr}() URL is not "
                            "built from the OUTPOST_API_URL seam (BASE_URL/base)"
                        )
    return problems


# ── Layer 2: runtime loopback-only proof ──────────────────────────────────

def _wait_healthy(port: int, pid: int) -> None:
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/meta", timeout=1):
                return
        except Exception:
            if pid.poll() is not None:
                raise RuntimeError(f"isolated backend on :{port} exited early")
            time.sleep(0.5)
    raise RuntimeError(f"isolated backend on :{port} never answered")


def _api(port: int, method: str, path: str, body: dict | None = None) -> dict:
    import json
    import urllib.error
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"} if body else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"seed {method} {path} failed: {exc.code} {exc.read().decode()[:200]}") from exc


def _seed(port: int) -> str:
    """Create a run + a couple of events through the backend's own API so the
    CLI read commands have real data to fetch."""
    run = _api(port, "POST", "/runs", {"sample_name": "gate-cli-probe.exe", "platform": "windows", "session_type": "analysis"})
    run_id = run["run_id"]
    events = [
        {"run_id": run_id, "platform": "windows", "event_type": "process_create",
         "timestamp": "2026-08-13T12:00:00Z", "pid": 4242, "ppid": 1,
         "process_name": "gate-cli-probe.exe", "command_line": "probe.exe --scan"},
        {"run_id": run_id, "platform": "windows", "event_type": "network_connection",
         "timestamp": "2026-08-13T12:00:01Z", "pid": 4242, "ppid": 1,
         "process_name": "gate-cli-probe.exe", "dest_ip": "8.8.8.8", "dest_port": 53},
    ]
    _api(port, "POST", "/ingest/batch", events)
    return run_id


class LoopbackOnly:
    """Blocks every TCP connect to a non-loopback destination."""

    def __init__(self) -> None:
        self.blocked: list[tuple[str, int]] = []
        self._real_connect = socket.socket.connect
        self._real_create = socket.create_connection
        try:  # urllib3 keeps its own create_connection (handles socket_options
        # itself, which 3.14 removed from socket.create_connection)
            from urllib3.util import connection as uc
            self._real_uc_create = uc.create_connection
        except Exception:
            self._real_uc_create = None

    def _check(self, address) -> None:
        host = address[0] if isinstance(address, tuple) else str(address)
        port = address[1] if isinstance(address, tuple) else 0
        if host not in ("127.0.0.1", "::1", "localhost"):
            self.blocked.append((host, port))
            raise ConnectionError(f"air-gap gate: blocked external connect to {host}:{port}")

    def __enter__(self) -> "LoopbackOnly":
        def guard(self_, *args):
            self._check(args[0] if args else ("?", 0))
            return self._real_connect(self_, *args)

        def guard_create(address, *args, **kwargs):
            self._check(address)
            return self._real_create(address, *args, **kwargs)

        socket.socket.connect = guard
        socket.create_connection = guard_create
        if self._real_uc_create is not None:
            from urllib3.util import connection as uc

            def guard_uc(address, *args, **kwargs):
                self._check(address)
                return self._real_uc_create(address, *args, **kwargs)

            uc.create_connection = guard_uc
        return self

    def __exit__(self, *exc) -> None:
        socket.socket.connect = self._real_connect
        socket.create_connection = self._real_create
        if self._real_uc_create is not None:
            from urllib3.util import connection as uc
            uc.create_connection = self._real_uc_create
        return False


def runtime_proof(port: int) -> tuple[int, list[str]]:
    """Run the CLI matrix against the isolated backend under the patch."""
    os.environ["OUTPOST_API_URL"] = f"http://127.0.0.1:{port}"
    sys.path.insert(0, str(CLI_DIR))
    from typer.testing import CliRunner
    from outpost.main import app

    run_id = _seed(port)
    runner = CliRunner()
    matrix: list[tuple[str, list[str]]] = [
        ("list runs", ["list"]),
        ("run detail", ["show", run_id]),
        ("IOC search", ["search", "8.8.8.8"]),
        ("rules knobs", ["rules", "knobs"]),
        ("rules log-patterns", ["rules", "log-patterns"]),
        ("agent status", ["agent", "status"]),
        ("watchlist add", ["watchlist", "add", "8.8.8.8", "--label", "gate-probe"]),
        ("watchlist list", ["watchlist", "list"]),
        ("watchlist remove", ["watchlist", "remove", "8.8.8.8"]),
    ]

    failures: list[str] = []

    # The matrix itself: any blocked connect is a real violation.
    with LoopbackOnly() as guard:
        for label, args in matrix:
            try:
                result = runner.invoke(app, args)
            except Exception as exc:  # the patch raises ConnectionError through requests
                failures.append(f"{label} crashed under the loopback patch: {exc}")
                continue
            if result.exit_code != 0:
                failures.append(
                    f"{label} (`outpost {' '.join(args)}`) failed: exit {result.exit_code} — "
                    f"{result.output.strip()[-240:]}"
                )
    if guard.blocked:
        seen = sorted(set(guard.blocked))
        failures.append("CLI reached " + ", ".join(f"{h}:{p}" for h, p in seen))

    # Negative control (its own patch context): a command aimed at an external
    # base URL MUST be blocked — proves the patch bites and the matrix isn't
    # vacuously green. BASE_URL is read at import time, so point the module
    # attribute at an external host directly; example.com resolves to a real
    # external IP, so the connect is stopped by the patch, not by a DNS miss.
    import outpost.lib.api_client as api_client_mod
    old_base = api_client_mod.BASE_URL
    api_client_mod.BASE_URL = "http://example.com:8080"
    try:
        with LoopbackOnly() as control_guard:
            control = runner.invoke(app, ["list"])
        blocked_control = sorted(set(control_guard.blocked))
        if control.exit_code == 0:
            failures.append("negative control FAILED: an external-base command succeeded — "
                            "the loopback patch is not effective")
        elif not any(h == "example.com" for h, _ in blocked_control):
            failures.append(
                "negative control FAILED: no connect to example.com was observed — "
                "the command failed for a different reason than the patch "
                f"(blocked={blocked_control or 'none'})"
            )
    finally:
        api_client_mod.BASE_URL = old_base

    return 0 if not failures else 1, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8014)
    parser.add_argument("--static-only", action="store_true", help="skip the runtime proof")
    args = parser.parse_args()

    problems = static_scan()
    if problems:
        print(f"✗ CLI network gate (static): {len(problems)} problem(s)")
        for p in problems:
            print(f"  {p}")
        return 1
    print("✓ CLI network gate (static): HTTP only via the api seam, no raw sockets")

    if args.static_only:
        return 0

    db_path = tempfile.mktemp(suffix=".db")
    samples_dir = tempfile.mkdtemp(prefix="gate-cli-samples-")
    log_path = tempfile.mktemp(suffix=".log")
    pid = None
    try:
        env = dict(os.environ, DATABASE_PATH=db_path, SAMPLES_DIR=samples_dir)
        with open(log_path, "w") as lf:
            pid = subprocess.Popen(
                [str(PYTHON), "-m", "uvicorn", "app.main:app",
                 "--host", "127.0.0.1", "--port", str(args.port)],
                cwd=str(ROOT / "backend"), env=env, stdout=lf, stderr=subprocess.STDOUT,
            )
        _wait_healthy(args.port, pid)
        rc, failures = runtime_proof(args.port)
        if failures:
            print("✗ CLI network gate (runtime): external reach detected")
            for f in failures:
                print(f"  {f}")
            return 1
        print("✓ CLI network gate (runtime): 9-command matrix + negative control, loopback-only")
        return 0
    finally:
        if pid is not None:
            pid.terminate()
            try:
                pid.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pid.kill()
        for p in (db_path, log_path):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            import shutil
            shutil.rmtree(samples_dir, ignore_errors=True)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
