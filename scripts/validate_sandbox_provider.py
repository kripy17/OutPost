#!/usr/bin/env python3
"""Live sandbox-provider validation — the missing real-provider check.

The webapp's sandbox detonation adapter (backend/app/services/sandbox.py)
supports Any.Run / Hatching Triage / Joe Sandbox, but those live adapters have
never been validated end to end against a real provider — the test suite only
covers the report *normalizers* (pure functions) and the labeled demo path.
This harness closes that gap the same way the collector soaks close the
collector gap: drive the REAL API surface and assert the pipeline holds.

Flow (against a running backend):
  1. GET /sandbox/providers — is any live provider configured?
     None configured → clean SKIP (exit 0): stock installs and CI without a
     provider key must not fail; the webapp falls back to the labeled demo.
     An explicitly requested provider that is NOT configured → FAIL (exit 1):
     the operator asked for a real detonation and the key is missing.
  2. Upload a tiny PE sample (POST /samples?name=... body bytes).
  3. POST /sandbox/detonate {sample_id, provider} → task + run ids.
  4. Poll GET /sandbox/tasks/{task_id} until completed / error / timeout.
  5. Assert the run completed with events ingested through the REAL
     pipeline: task.events > 0 and GET /runs/{id} shows the completed run
     under source=sandbox:<provider>.

Run:  .venv/bin/python scripts/validate_sandbox_provider.py \
          [--backend http://127.0.0.1:8001] [--provider auto] [--max-wait 900]
"""

import argparse
import json
import sys
import time
import urllib.request
import uuid

BASE = "http://127.0.0.1:8001"
# A minimal MZ header (mirrors the test fixtures) — enough for the sandbox to
# accept a Windows PE and for magic-sniffing to report windows.
MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(f"{base}{path}", timeout=30) as resp:
        return json.loads(resp.read())


def _post_json(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _upload(base: str, name: str, body: bytes) -> dict:
    req = urllib.request.Request(f"{base}/samples?name={name}", data=body, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", default=BASE, help="Backend base URL (default: %(default)s)")
    ap.add_argument("--provider", default="auto", help="anyrun | triage | joe | auto (default: %(default)s)")
    ap.add_argument("--max-wait", type=int, default=900, help="Seconds to poll for completion (default: %(default)s)")
    args = ap.parse_args()
    base = args.backend.rstrip("/")

    try:
        registry = _get(base, "/sandbox/providers")
    except Exception as exc:  # backend down — the gate must fail, not skip
        print(f"FAIL — cannot reach backend at {base}: {exc}", file=sys.stderr)
        print("  → fix: start the backend first (e.g. bash scripts/dev.sh) or pass --backend <url>, then re-run this gate", file=sys.stderr)
        return 1

    providers = {p["id"]: p for p in registry["providers"]}
    configured = [pid for pid in ("anyrun", "triage", "joe") if providers.get(pid, {}).get("configured")]
    requested = args.provider.strip().lower()

    if requested not in ("auto", "demo", "anyrun", "triage", "joe"):
        print(f"FAIL — unknown provider '{requested}' (expected anyrun | triage | joe | auto | demo)", file=sys.stderr)
        print("  → fix: pass --provider anyrun | triage | joe | auto | demo (auto = the configured provider, demo = the labeled pipeline)", file=sys.stderr)
        return 1

    if requested in ("anyrun", "triage", "joe") and requested not in configured:
        print(
            f"FAIL — provider '{requested}' requested but NOT configured "
            f"(set the {requested.upper()}_API_KEY env var and restart the backend)",
            file=sys.stderr,
        )
        print(
            f"  → fix: set {requested.upper()}_API_KEY and restart the backend, "
            "or pass --provider demo to validate the labeled pipeline instead",
            file=sys.stderr,
        )
        return 1

    if not configured:
        if requested != "demo":
            print("SKIP — no live sandbox provider key configured (mode: demo).")
            print("  Configure ANYRUN_API_KEY / TRIAGE_API_KEY / JOE_API_KEY to enable this gate.")
            return 0
        print("NOTE — provider=demo requested; validating the labeled demo pipeline instead.")
        provider = "demo"
    else:
        provider = requested if requested in ("anyrun", "triage", "joe") else registry["active"] or configured[0]

    # -- 1. Upload a real sample through the vault ---------------------------------
    name = f"validate-{uuid.uuid4().hex[:8]}.exe"
    try:
        sample = _upload(base, name, MZ)
    except Exception as exc:
        print(f"FAIL — sample upload to {base} failed: {exc}", file=sys.stderr)
        print("  → fix: confirm the backend is up and the samples vault is writable, then re-run this gate", file=sys.stderr)
        return 1
    print(f"uploaded {name} → {sample['sample_id']} ({sample['detected_platform']}, {sample['size']} B)")

    # -- 2. Detonate against the live provider -------------------------------------
    try:
        task = _post_json(base, "/sandbox/detonate", {"sample_id": sample["sample_id"], "provider": provider, "platform": "windows"})
    except Exception as exc:
        print(f"FAIL — /sandbox/detonate failed: {exc}", file=sys.stderr)
        print("  → fix: check the provider key is set and the sandbox service is reachable, then re-run this gate", file=sys.stderr)
        return 1
    task_id = task["task_id"]
    run_id = task["run_id"]
    print(f"detonation task {task_id} (run {run_id}, provider={provider}, status={task['status']})")

    # -- 3. Poll until completion ---------------------------------------------------
    deadline = time.time() + args.max_wait
    last = task
    while time.time() < deadline and last["status"] not in ("completed", "error"):
        time.sleep(15)
        try:
            last = _get(base, f"/sandbox/tasks/{task_id}")
        except Exception as exc:
            print(f"WARN — task poll failed (retrying): {exc}", file=sys.stderr)
            time.sleep(5)
            continue
        print(f"  … {last['status']} (events={last['events']}, alerts={last['alerts']})")

    if last["status"] == "error":
        print(f"FAIL — detonation errored: {last.get('error')}", file=sys.stderr)
        print("  → fix: inspect the provider's task error above and confirm the sample's platform matches the provider, then re-run", file=sys.stderr)
        return 1
    if last["status"] != "completed":
        print(f"FAIL — detonation did not complete within {args.max_wait}s (status={last['status']})", file=sys.stderr)
        print("  → fix: raise --max-wait for slow provider queues, or check the provider's job status, then re-run", file=sys.stderr)
        return 1

    # -- 4. Assert the pipeline landed the events -----------------------------------
    if last["events"] <= 0:
        print("FAIL — task completed with zero events (normalizer produced nothing)", file=sys.stderr)
        print("  → fix: confirm the sample type is in the provider's supported set and check the report normalizer, then re-run", file=sys.stderr)
        return 1
    try:
        run = _get(base, f"/runs/{run_id}")
    except Exception as exc:
        print(f"FAIL — cannot read the completed run: {exc}", file=sys.stderr)
        print("  → fix: confirm the backend's /runs endpoint responds, then re-run this gate", file=sys.stderr)
        return 1
    summary = run.get("run", run)
    if not summary.get("completed_at"):
        print("FAIL — run never completed", file=sys.stderr)
        print("  → fix: wait for the run to finish (or check the provider task) and re-run", file=sys.stderr)
        return 1
    if not str(summary.get("source", "")).startswith("sandbox:"):
        print(f"FAIL — run source '{summary.get('source')}' is not sandbox:<provider>", file=sys.stderr)
        print("  → fix: the run must be created by the sandbox detonation path — restart the backend and re-detonate", file=sys.stderr)
        return 1

    print("PASS — live sandbox detonation validated end to end:")
    print(f"  provider={provider} run={run_id} events={last['events']} alerts={last['alerts']} "
          f"risk={last['risk_score']} severity={last['highest_severity']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
