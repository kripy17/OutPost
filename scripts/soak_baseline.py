#!/usr/bin/env python3
"""Cross-platform collector soak baseline — one table, both platforms.

Runs the Windows (Sysmon) and Linux (auditd) collector soaks with `--gate`
against a single isolated backend and prints the FP/detection baseline as a
compact table, so every verify.sh sweep shows both platforms' numbers at a
glance instead of two separate blocks.

Both soaks exercise the REAL collector parsers + Shipper over HTTP and the
production detection pipeline (only the log tails and /proc reads are
simulated). Each soak's own gate assertions are preserved: a benign-baseline
FP or a missed core detection fails the step.

Run:  .venv/bin/python scripts/soak_baseline.py [--port 8013]
"""

import argparse
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = ROOT / ".venv" / "bin" / "python"

SOAKS = [
    ("Windows", "soak_windows_collector.py"),
    ("Linux", "soak_linux_collector.py"),
]

_FP_RE = re.compile(r"FP candidates \(fired on the modeled benign baseline\): (.+)")
_DET_RE = re.compile(r"Detection(?:-only)? rules \(malicious story\): (.+)")


def _wait_healthy(port: int, pid: int) -> None:
    for _ in range(30):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/meta", timeout=1):
                return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"isolated backend on :{port} never answered")


def _run_soak(name: str, script: str, backend: str, host: str) -> tuple[int, str, list[str]]:
    proc = subprocess.run(
        [str(PYTHON), str(ROOT / "scripts" / script), "--backend", backend, "--host", host, "--gate"],
        capture_output=True, text=True, timeout=240,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    fp = _FP_RE.search(out)
    det = _DET_RE.search(out)
    fp_rules = fp.group(1).strip() if fp else "?"
    det_rules = det.group(1).strip() if det else "?"
    return proc.returncode, fp_rules, det_rules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8013)
    parser.add_argument("--host", default=None, help="host_id stamped on the shipped events (default: this hostname)")
    args = parser.parse_args()
    host = args.host or __import__("socket").gethostname()

    import tempfile
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path, db.name = db.name, db.name
    db.close()
    import os
    samples_dir = tempfile.mkdtemp(prefix="soak-samples-")
    log_path = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name

    backend = f"http://127.0.0.1:{args.port}"
    pid = None
    try:
        env = dict(os.environ, DATABASE_PATH=db_path, SAMPLES_DIR=samples_dir)
        with open(log_path, "w") as lf:
            pid = subprocess.Popen(
                [str(PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.port)],
                cwd=str(ROOT / "backend"), env=env, stdout=lf, stderr=subprocess.STDOUT,
            )
        _wait_healthy(args.port, pid.pid)

        results = []
        for name, script in SOAKS:
            rc, fp_rules, det_rules = _run_soak(name, script, backend, host)
            results.append((name, rc, fp_rules, det_rules))

        print()
        print("Cross-platform collector soak baseline (real parser/shipper, isolated backend)")
        print(f"{'Platform':<10} {'Benign FPs':<14} {'Detections on evil story':<44} Gate")
        print("-" * 90)
        any_fail = 0
        for name, rc, fp_rules, det_rules in results:
            gate = "PASS" if rc == 0 else "FAIL"
            if rc != 0:
                any_fail = 1
            print(f"{name:<10} {fp_rules:<14} {det_rules:<44} {gate}")
        print()
        if any_fail:
            print("Soak baseline: FAILED (see the failing soak's output above)")
            return 1
        print("Soak baseline: PASS — zero FPs on both benign baselines, all core detections fired")
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
            shutil.rmtree(samples_dir)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
