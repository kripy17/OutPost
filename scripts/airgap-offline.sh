#!/usr/bin/env bash
# airgap-offline.sh — the full air-gap verification inside a container whose
# network namespace is EMPTY (`docker run --network none`). Only loopback
# exists, so any attempt to reach an external host fails at the OS level —
# regardless of library or technique. This is the strongest proof: the
# in-process probes (httpx patch, socket patch, resolver rules) simulate
# blocking; here it is real.
#
# Runs (all on loopback):
#   1. boot the backend  (uvicorn, temp DB)       127.0.0.1:8001
#   2. seed campaign + a live-sourced run
#   3. boot the frontend preview (production build)  localhost:5174
#   4. the four-gate bundle + cold-start latency budget
#   5. both Playwright e2e gates (alert lifecycle + live monitor)
#
# Usage: bash scripts/airgap-offline.sh     (inside the airgap-ci image)
# Env:  OUTPOST_OFFLINE_PORT (default 8001), OUTPOST_OFFLINE_WEB (default
# 5174), OUTPOST_ITERS (default 3). Names are prefix-scoped on purpose —
# generic PORT/WEB collide with tooling that exports PORT=0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
PORT="${OUTPOST_OFFLINE_PORT:-8001}"
WEB="${OUTPOST_OFFLINE_WEB:-5174}"

DB="$(mktemp -u).db"
SAMPLES="$(mktemp -d)"
BACK_LOG="$(mktemp)"
WEB_LOG="$(mktemp)"
BACK_PID=""
WEB_PID=""

cleanup() {
  [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null || true
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  rm -f "$DB" "$BACK_LOG" "$WEB_LOG"
  rm -rf "$SAMPLES"
}
trap cleanup EXIT

echo "── 1 · boot backend (loopback :$PORT) ──"
# CORS_ORIGINS must match the frontend origin: the production build baked
# VITE_API_URL=http://127.0.0.1:$PORT, and the browser at localhost:$WEB is
# a DIFFERENT origin — without this the API blocks every fetch (the same
# reason verify.sh's layout step sets it).
(cd "$ROOT/backend" && DATABASE_PATH="$DB" SAMPLES_DIR="$SAMPLES" \
  CORS_ORIGINS="http://localhost:$WEB" \
  "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" >"$BACK_LOG" 2>&1) &
BACK_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PORT/meta" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PORT/meta" >/dev/null || {
  echo "ERROR: backend never answered"; cat "$BACK_LOG"; exit 1; }

echo "── 2 · seed campaign + live-sourced run ──"
(cd "$ROOT/backend" && DATABASE_PATH="$DB" "$PY" -m app.seed_campaign >/dev/null 2>&1)
"$PY" "$ROOT/scripts/seed_sweep_live.py" --api "http://127.0.0.1:$PORT" >/dev/null

echo "── 3 · boot frontend preview (production build, :$WEB) ──"
(cd "$ROOT/frontend" && npx vite preview --port "$WEB" --strictPort >"$WEB_LOG" 2>&1) &
WEB_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://localhost:$WEB" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://localhost:$WEB" >/dev/null || {
  echo "ERROR: preview never answered"; cat "$WEB_LOG"; exit 1; }

echo "── 4 · four-gate bundle + cold-start latency budget ──"
OUTPOST_ITERS="${OUTPOST_ITERS:-3}" \
  bash "$ROOT/scripts/airgap-verify.sh" --web "http://localhost:$WEB" --max 1000

echo "── 5 · e2e gates (real browser, loopback API) ──"
(cd "$ROOT/demo" && node e2e-alert-lifecycle.mjs \
  --web "http://localhost:$WEB" --api "http://127.0.0.1:$PORT")
(cd "$ROOT/demo" && node e2e-live-monitor.mjs \
  --web "http://localhost:$WEB" --api "http://127.0.0.1:$PORT")

echo
echo "✓ air-gap offline: all gates + e2es passed with the network namespace empty"
