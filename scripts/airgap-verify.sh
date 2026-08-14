#!/usr/bin/env bash
# airgap-verify.sh — one-shot air-gap verification bundle.
#
# Runs the four air-gap gates in sequence:
#   1. frontend artifacts  (scripts/gate_airgap_artifacts.py — shipped build)
#   2. CLI network        (scripts/gate_cli_network.py — loopback-only)
#   3. backend egress     (scripts/gate_backend_egress.py — key-gated httpx)
#   4. backend no-config  (scripts/gate_backend_no_config_egress.py — runtime:
#      background flows make zero httpx calls with zero config, keyed paths
#      caught by a probe)
#
# Then, when a webapp is reachable, measures the cold-start latency with the
# Playwright harness and FAILS if the worst-case interactive render exceeds
# the budget (default 1000ms — the measured value is ~300ms, so a regression
# past 1s means something external or pathological crept into the load path).
#
# Usage:
#   bash scripts/airgap-verify.sh                    # gates + timing vs localhost:5174
#   bash scripts/airgap-verify.sh --web http://<host>:5174 --max 1500
#   bash scripts/airgap-verify.sh --gates-only       # skip the timing harness
#
# Env: OUTPOST_ITERS  (timing iterations, default 3)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
WEB=""
MAX=1000
GATES_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --web) WEB="$2"; shift 2 ;;
    --max) MAX="$2"; shift 2 ;;
    --gates-only) GATES_ONLY=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "── 1 · Frontend artifact gate (shipped build) ──"
if [ ! -d "$ROOT/frontend/dist" ]; then
  echo "dist missing — building (cd frontend && npm run build)…"
  (cd "$ROOT/frontend" && npm run build)
fi
"$PY" "$ROOT/scripts/gate_airgap_artifacts.py" --dist "$ROOT/frontend/dist"

echo "── 2 · CLI network gate (loopback-only) ──"
"$PY" "$ROOT/scripts/gate_cli_network.py"

echo "── 3 · Backend egress gate (key/config-gated httpx) ──"
"$PY" "$ROOT/scripts/gate_backend_egress.py"

echo "── 4 · Backend no-config egress (runtime, zero-config silent) ──"
"$PY" "$ROOT/scripts/gate_backend_no_config_egress.py"

if [ "$GATES_ONLY" = 1 ] || [ -z "$WEB" ]; then
  echo
  echo "gates-only: all four air-gap gates passed."
  exit 0
fi

echo "── 5 · Cold-start latency (web=${WEB}, budget ${MAX}ms) ──"
node "$ROOT/demo/measure-airgap-load.mjs" --web "$WEB" --iters "${OUTPOST_ITERS:-3}" \
  --max-interactive "$MAX"
