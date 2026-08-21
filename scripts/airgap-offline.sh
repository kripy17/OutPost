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
#
# Volume mode (production-volume proof): the default run proves the guarantee
# on a tiny seeded store. OUTPOST_OFFLINE_VOLUME=1 seeds a deterministic
# ~11k-event synthetic store (scripts/seed_volume.py) and runs the whole
# bundle against it; OUTPOST_OFFLINE_DB=<path> boots against a COPY of any
# given DB (e.g. the real soak store) — the original is never touched. The
# e2e gates always create their own fresh runs through the API on top.
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
VOLUME_SRC="${OUTPOST_OFFLINE_DB:-}"
if [ "${OUTPOST_OFFLINE_VOLUME:-0}" = "1" ] && [ -z "$VOLUME_SRC" ]; then
  VOLUME_SRC="$(mktemp -u).db"
  DATABASE_PATH="$VOLUME_SRC" "$PY" "$ROOT/scripts/seed_volume.py" >/dev/null
fi

cleanup() {
  [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null || true
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  rm -f "$DB" "$BACK_LOG" "$WEB_LOG"
  rm -rf "$SAMPLES"
}
trap cleanup EXIT

# Dependency-free health check — node slim images ship no curl.
health() { "$PY" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)' "$1" 2>/dev/null; }

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
  health "http://127.0.0.1:$PORT/meta" && break
  sleep 1
done
health "http://127.0.0.1:$PORT/meta" || {
  echo "ERROR: backend never answered"; cat "$BACK_LOG"; exit 1; }

if [ -n "$VOLUME_SRC" ]; then
  # Copy — the supplied DB is never opened in place.
  cp "$VOLUME_SRC" "$DB"
  VOL="$("$PY" -c '
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
for t in ("events", "runs", "alerts"):
    print(t, db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
' "$DB")"
  echo "── 2 · volume DB loaded (real-soak/production scale) ──"
  echo "     $VOL" | tr '\n' ' '
  echo
else
  echo "── 2 · seed campaign + live-sourced run ──"
  (cd "$ROOT/backend" && DATABASE_PATH="$DB" "$PY" -m app.seed_campaign >/dev/null 2>&1)
fi
"$PY" "$ROOT/scripts/seed_sweep_live.py" --api "http://127.0.0.1:$PORT" >/dev/null

echo "── 3 · boot frontend preview (production build, :$WEB) ──"
(cd "$ROOT/frontend" && npx vite preview --port "$WEB" --strictPort >"$WEB_LOG" 2>&1) &
WEB_PID=$!
for _ in $(seq 1 30); do
  health "http://localhost:$WEB" && break
  sleep 1
done
health "http://localhost:$WEB" || {
  echo "ERROR: preview never answered"; cat "$WEB_LOG"; exit 1; }

echo "── 4 · four-gate bundle + cold-start latency budget ──"
# Small-store runs stay on the 1000ms budget (they measure ~300ms). At
# production volume a cold store + fresh browser legitimately takes longer
# on the first hit — the documented deployment budget (1500ms, see
# airgap-verify.sh) is the honest limit there, and it is now actually
# ENFORCED (airgap-verify.sh passes --max-interactive to the harness).
MAX_BUDGET=1000
[ -n "$VOLUME_SRC" ] && MAX_BUDGET=1500
OUTPOST_ITERS="${OUTPOST_ITERS:-3}" \
  bash "$ROOT/scripts/airgap-verify.sh" --web "http://localhost:$WEB" --max "$MAX_BUDGET"

echo "── 5 · e2e gates (real browser, loopback API) ──"
(cd "$ROOT/demo" && node e2e-alert-lifecycle.mjs \
  --web "http://localhost:$WEB" --api "http://127.0.0.1:$PORT")
(cd "$ROOT/demo" && node e2e-live-monitor.mjs \
  --web "http://localhost:$WEB" --api "http://127.0.0.1:$PORT")

echo
echo "✓ air-gap offline: all gates + e2es passed with the network namespace empty"
if [ -n "$VOLUME_SRC" ]; then
  echo "  production-volume proof: bundle ran against $(echo "$VOL" | tr '\n' ' ')"
fi
