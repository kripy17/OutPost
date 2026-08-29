#!/usr/bin/env bash
# OutPost — Universal Startup Script (Linux / macOS)
#
# Launches the FastAPI backend AND the Frontend Web Console together, wires the
# frontend's API target + CORS to whatever ports are chosen, waits for real
# health checks (and says so loudly if they never come up), then opens the UI
# in a browser. Cleanly shuts everything down on Ctrl+C.
#
# Usage: ./start.sh [--with-agent]
# Env:
#   OUTPOST_PORT       backend port          (default 8001)
#   OUTPOST_FE_PORT    frontend port         (default 5174)
#   OUTPOST_RELOAD     set to 1 for uvicorn auto-reload during development
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -d ".venv" ]; then
  echo "[-] Virtual environment not found. Running ./setup.sh first..."
  ./setup.sh
fi

# shellcheck disable=SC1091
source .venv/bin/activate

BACKEND_PORT="${OUTPOST_PORT:-8001}"
FRONTEND_PORT="${OUTPOST_FE_PORT:-5174}"
BACKEND_URL="http://localhost:${BACKEND_PORT}"

# The web console must talk to THIS backend instance. An inline env var beats
# any stale frontend/.env.local, and a missing node_modules is fatal otherwise.
export VITE_API_URL="$BACKEND_URL"

# CORS: allow the exact origin vite will serve. Merge with any operator-provided
# CORS_ORIGINS so custom setups don't silently lose their extra origins.
DEFAULT_ORIGIN="http://localhost:${FRONTEND_PORT}"
if [ -n "${CORS_ORIGINS:-}" ]; then
  case ",${CORS_ORIGINS}," in
    *",${DEFAULT_ORIGIN},"*) : ;;                      # already listed
    *) export CORS_ORIGINS="${CORS_ORIGINS},${DEFAULT_ORIGIN}" ;;
  esac
else
  export CORS_ORIGINS="http://localhost:5173,http://localhost:5174,http://localhost:5175,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:5175,${DEFAULT_ORIGIN}"
fi

echo "=========================================="
echo "      OutPost Security Monitor"
echo "=========================================="
echo "[*] Backend API:  ${BACKEND_URL}"
echo "[*] Web Console:  http://localhost:${FRONTEND_PORT}"
echo "=========================================="

BACKEND_PID=""
FRONTEND_PID=""
AGENT_PID=""

cleanup() {
  echo
  echo "[*] Shutting down OutPost services..."
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  # uvicorn --reload forks a reloader child; kill the whole tree, not just $!.
  if [ -n "$BACKEND_PID" ]; then
    pkill -P "$BACKEND_PID" 2>/dev/null || true
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  # Last resort: anything of ours still bound to the chosen ports.
  for port in "$BACKEND_PORT" "$FRONTEND_PORT"; do
    fuser -k "${port}/tcp" 2>/dev/null || true
  done
  echo "[✓] All services stopped."
}

trap cleanup INT TERM EXIT

port_busy() { curl -sf -m 1 "http://127.0.0.1:$1/health" >/dev/null 2>&1 \
           || curl -sf -m 1 "http://127.0.0.1:$1" >/dev/null 2>&1; }

if port_busy "$BACKEND_PORT"; then
  echo "[-] Port ${BACKEND_PORT} is already serving something."
  echo "    Stop it (or pick another port via OUTPOST_PORT=<n>) and retry."
  exit 1
fi
if port_busy "$FRONTEND_PORT"; then
  echo "[-] Port ${FRONTEND_PORT} is already serving something."
  echo "    Stop it (or pick another port via OUTPOST_FE_PORT=<n>) and retry."
  exit 1
fi

if [ ! -d "frontend/node_modules" ]; then
  echo "[*] Installing frontend dependencies..."
  (cd frontend && npm install --no-fund --no-audit)
fi

echo "[*] Initializing database & demo telemetry..."
(cd backend && python -m app.seed_demo >/dev/null 2>&1 || true)

UVICORN_ARGS=(--host 127.0.0.1 --port "$BACKEND_PORT" --log-level warning)
if [ "${OUTPOST_RELOAD:-0}" = "1" ]; then
  UVICORN_ARGS+=(--reload --reload-dir app)
fi

echo "[*] Starting FastAPI Backend on port ${BACKEND_PORT}..."
(cd backend && exec python -m uvicorn app.main:app "${UVICORN_ARGS[@]}") &
BACKEND_PID=$!

BACKEND_UP=0
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1; then
    BACKEND_UP=1
    break
  fi
  sleep 0.5
done
if [ "$BACKEND_UP" != "1" ]; then
  echo "[-] Backend failed to become healthy on port ${BACKEND_PORT}."
  echo "    Check backend logs / try OUTPOST_PORT=<other port>."
  exit 1
fi
echo "[+] Backend healthy."

echo "[*] Starting Frontend Web Console on port ${FRONTEND_PORT}..."
(cd frontend && exec npm run dev -- --port "$FRONTEND_PORT" --strictPort) &
FRONTEND_PID=$!

FRONTEND_UP=0
for _ in $(seq 1 60); do
  if curl -sf "http://localhost:${FRONTEND_PORT}" >/dev/null 2>&1; then
    FRONTEND_UP=1
    break
  fi
  sleep 0.5
done
if [ "$FRONTEND_UP" != "1" ]; then
  echo "[-] Frontend dev server failed to start on port ${FRONTEND_PORT}."
  exit 1
fi
echo "[+] Frontend up — pointing at ${BACKEND_URL}."

if [[ "${1:-}" == "--with-agent" ]]; then
  echo "[*] Starting Live Local Collector Agent..."
  (python -m collectors.common.collector_local --backend "$BACKEND_URL") &
  AGENT_PID=$!
fi

echo "[*] Launching browser at http://localhost:${FRONTEND_PORT}..."
python -m webbrowser "http://localhost:${FRONTEND_PORT}" 2>/dev/null \
  || xdg-open "http://localhost:${FRONTEND_PORT}" 2>/dev/null \
  || open "http://localhost:${FRONTEND_PORT}" 2>/dev/null || true

echo
echo "=========================================="
echo " [✓] OutPost is running live!"
echo " Web Console: http://localhost:${FRONTEND_PORT}"
echo " API Docs:    ${BACKEND_URL}/docs"
echo " Press Ctrl+C in this terminal to stop."
echo "=========================================="
echo

wait
