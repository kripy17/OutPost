#!/usr/bin/env bash
# OutPost — Fast Playwright End-to-End Verification Runner
#
# Runs headless Playwright browser verification against isolated local backend and frontend instances.
# Verifies all web pages, live telemetry feeds, dynamic detonation, triage lifecycle, and air-gap network isolation.
#
# Usage:
#   ./test_ui.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -d "$ROOT/demo/node_modules/playwright" ]; then
  echo "[*] Installing Playwright dependencies in demo/..."
  (cd "$ROOT/demo" && npm install)
fi

PYTHON="$ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "[-] Python virtual environment (.venv) not found. Run ./setup.sh first."
  exit 1
fi

TEMP_DB=$(mktemp --suffix=.db)
TEMP_SAMPLES=$(mktemp -d)
BACKEND_PORT=8091
FRONTEND_PORT=5194
BACKEND_LOG=$(mktemp --suffix=.log)
FRONTEND_LOG=$(mktemp --suffix=.log)

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo -e "\n[*] Cleaning up test services..."
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  rm -f "$TEMP_DB" "$BACKEND_LOG" "$FRONTEND_LOG"
  rm -rf "$TEMP_SAMPLES"
}
trap cleanup EXIT INT TERM

echo "[*] Starting isolated test backend on port $BACKEND_PORT..."
DATABASE_PATH="$TEMP_DB" SAMPLES_DIR="$TEMP_SAMPLES" CORS_ORIGINS="http://localhost:$FRONTEND_PORT" \
  "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$BACKEND_PORT" --app-dir "$ROOT/backend" >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$BACKEND_PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sf "http://127.0.0.1:$BACKEND_PORT/health" >/dev/null 2>&1; then
  echo "[-] Failed to start backend test server. Log:"
  cat "$BACKEND_LOG"
  exit 1
fi

echo "[*] Starting isolated test frontend on port $FRONTEND_PORT..."
(cd "$ROOT/frontend" && VITE_API_URL="http://127.0.0.1:$BACKEND_PORT" \
  npm run dev -- --port "$FRONTEND_PORT" --strictPort >"$FRONTEND_LOG" 2>&1) &
FRONTEND_PID=$!

for _ in $(seq 1 40); do
  if curl -sf "http://localhost:$FRONTEND_PORT" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -sf "http://localhost:$FRONTEND_PORT" >/dev/null 2>&1; then
  echo "[-] Failed to start frontend test server. Log:"
  cat "$FRONTEND_LOG"
  exit 1
fi

echo "[*] Launching Playwright E2E Route & Layout Suite..."
node "$ROOT/demo/full-e2e.mjs" --web "http://localhost:$FRONTEND_PORT" --api "http://127.0.0.1:$BACKEND_PORT"

echo "[*] Launching Playwright Telemetry Authenticity & Live Detonation Test..."
node "$ROOT/demo/test-telemetry-authenticity.mjs" --web "http://localhost:$FRONTEND_PORT" --api "http://127.0.0.1:$BACKEND_PORT"

echo -e "\x1b[32m[✓] All Playwright End-to-End checks passed successfully!\x1b[0m\n"
