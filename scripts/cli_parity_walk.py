"""CLI parity walk — repeatable CI gate (verify.sh step).

Proves the terminal-mirror surfaces that the webapp's run-detail triage panel
and queue sweep have — but that the CLI only covered with unit tests until
now — LIVE, against a real seeded backend:

  1. Allowlist — `outpost allowlist add` (run-scoped ip) → appears in
     `outpost allowlist list` → `remove` → gone (relaxed 200/204 DELETE).
  2. Suppressions — `outpost rules suppressions add` (value-scoped) →
     appears in `list` → `remove` → gone.
  3. Bulk triage — pick two open alerts, `outpost triage acknowledged <a> <b>`
     → both leave the open queue → `outpost triage open <a> <b>` → both are
     back (state restored).

Booting an isolated backend on a spare port with a throwaway DB, seeding it
with the campaign pair (real detection-engine alerts), and cleaning up the
backend process + temp dir on the way out. Exit 0 only when every assertion
holds — same shape as post_deploy_walk.py.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv" / "bin" / "python"
OUTPOST = ROOT / ".venv" / "bin" / "outpost"

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


def cli(*args: str, env: dict) -> subprocess.CompletedProcess:
    """Run a real `outpost` command against the walk backend."""
    return subprocess.run(
        [str(OUTPOST), *args],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, **env},
        check=False,  # the walk inspects returncodes itself
    )


def queue_ids(base: str) -> set[int]:
    """The id set of the open-alert queue (wrapped under `alerts`)."""
    body = requests.get(f"{base}/alerts/queue?status=open&limit=10", timeout=5).json()
    items = body.get("alerts") or body.get("items") or []
    return {x["id"] for x in items}


def main() -> int:
    backend = None
    tmp = tempfile.mkdtemp(prefix="outpost-cli-walk-")
    try:
        port = free_port()
        backend = subprocess.Popen(
            [str(PY), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT / "backend",
            env={
                **os.environ,
                "DATABASE_PATH": str(Path(tmp) / "walk.db"),
                "OUTPOST_AUTH_REQUIRED": "0",
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        healthy = False
        for _ in range(40):
            if backend.poll() is not None:
                print(f"  FAIL — backend exited early with code {backend.returncode}")
                return 1
            try:
                if requests.get(f"{base}/health", timeout=2).status_code == 200:
                    healthy = True
                    break
            except requests.RequestException:
                pass
            time.sleep(0.5)
        if not healthy:
            print("  FAIL — backend never became healthy")
            return 1

        # Seed the campaign pair so there are runs + real detection alerts.
        subprocess.run(
            [str(PY), "-m", "app.seed_campaign"],
            cwd=ROOT / "backend",
            env={**os.environ, "DATABASE_PATH": str(Path(tmp) / "walk.db")},
            capture_output=True,
            timeout=120,
            check=False,  # failure surfaces as the empty-runs assertion below
        )

        # -- 1. Allowlist round-trip (run-scoped) ----------------------------
        # Seeded runs are source=seed — hidden by default; opt in so the walk
        # drives the real campaign pair.
        runs = requests.get(f"{base}/runs?include_synthetic=true", timeout=5).json()
        run_id = runs[0]["run_id"]
        env = {"OUTPOST_API_URL": base}

        r = cli("allowlist", "add", run_id, "ip", "203.0.113.88", "--note", "cli parity walk", env=env)
        check("1a · allowlist add → exit 0 + echo", r.returncode == 0 and "Allowlisted ip 203.0.113.88" in r.stdout, r.stdout.strip().splitlines()[0] if r.stdout else f"rc={r.returncode}")

        r = cli("allowlist", "list", run_id, env=env)
        check("1b · allowlist list shows the entry", r.returncode == 0 and "203.0.113.88" in r.stdout and "cli parity walk" in r.stdout)

        entries = requests.get(f"{base}/runs/{run_id}/allowlist", timeout=5).json()
        entry_id = entries[0]["id"]
        r = cli("allowlist", "remove", run_id, str(entry_id), env=env)
        check("1c · allowlist remove → gone", r.returncode == 0 and f"Removed allowlist entry {entry_id}" in r.stdout and requests.get(f"{base}/runs/{run_id}/allowlist", timeout=5).json() == [])

        # -- 2. Suppressions round-trip (value-scoped) -----------------------
        r = cli("rules", "suppressions", "add", "beaconing", "--value", "203.0.113.88", "--reason", "cli parity walk", env=env)
        check("2a · suppressions add → exit 0 + echo", r.returncode == 0 and "Suppressed beaconing (value 203.0.113.88)" in r.stdout, r.stdout.strip().splitlines()[0] if r.stdout else f"rc={r.returncode}")

        r = cli("rules", "suppressions", "list", env=env)
        check("2b · suppressions list shows the scope", r.returncode == 0 and "value 203.0.113.88" in r.stdout and "cli parity walk" in r.stdout)

        supps = requests.get(f"{base}/rules/suppressions", timeout=5).json()
        supp_id = [s["id"] for s in supps if s.get("value") == "203.0.113.88"][0]
        r = cli("rules", "suppressions", "remove", str(supp_id), env=env)
        gone = all(s["id"] != supp_id for s in requests.get(f"{base}/rules/suppressions", timeout=5).json())
        check("2c · suppressions remove → gone", r.returncode == 0 and f"Removed suppression {supp_id}" in r.stdout and gone)

        # -- 3. Bulk triage round-trip (open → acked → open) -----------------
        before_open = queue_ids(base)
        a, b = min(before_open), min(before_open - {min(before_open)})

        r = cli("triage", "acknowledged", str(a), str(b), "--comment", "cli parity walk", env=env)
        check("3a · bulk ack → exit 0 + count echo", r.returncode == 0 and "2 alert(s) → acknowledged" in r.stdout, r.stdout.strip().splitlines()[0] if r.stdout else f"rc={r.returncode}")

        still_open = queue_ids(base)
        check("3b · both left the open queue", a not in still_open and b not in still_open, f"open={sorted(still_open)[:3]}")

        r = cli("triage", "open", str(a), str(b), env=env)
        restored = queue_ids(base)
        check("3c · bulk reopen → both back in the open queue", r.returncode == 0 and "2 alert(s) → open" in r.stdout and a in restored and b in restored)

        print(f"\nCLI parity walk: {len(PASSED)} passed, {len(FAILED)} failed")
        return 0 if not FAILED else 1
    finally:
        if backend is not None and backend.poll() is None:
            backend.terminate()
            try:
                backend.wait(timeout=10)
            except subprocess.TimeoutExpired:
                backend.kill()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
