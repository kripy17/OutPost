#!/usr/bin/env bash
# OutPost — Universal Startup Script (Linux / macOS)
#
# Launches the FastAPI backend (port 8001) and Frontend Web Console (port 5174),
# automatically opens the web browser, and cleanly shuts down on Ctrl+C.
#
# Usage: ./start.sh [--with-agent]

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

echo "=========================================="
echo "      OutPost Security Monitor"
echo "=========================================="
echo "[*] Backend API:  http://localhost:${BACKEND_PORT}"
echo "[*] Web Console:  http://localhost:${FRONTEND_PORT}"
echo "=========================================="

BACKEND_PID=""
FRONTEND_PID=""
AGENT_PID=""

cleanup() {
  echo
  echo "[*] Shutting down OutPost services..."
  if [ -n "$FRONTEND_PID" ]; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  if [ -n "$BACKEND_PID" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [ -n "$AGENT_PID" ]; then
    kill "$AGENT_PID" 2>/dev/null || true
  fi
  echo "[✓] All services stopped."
}

trap cleanup INT TERM EXIT

if [[ "${1:-}" == "--demo" || "${2:-}" == "--demo" ]]; then
  echo "[*] Initializing database with demo telemetry..."
  (cd backend && python -m app.seed_demo >/dev/null 2>&1 || true)
else
  echo "[*] Initializing clean database schema (zero demo data)..."
  (cd backend && python -c "from app.core.db import init_db, db_session; init_db(); conn = db_session().__enter__(); conn.execute(\"INSERT OR REPLACE INTO settings (key, value) VALUES ('onboarding', 'empty'), ('demo_mode', '0')\"); conn.commit()" >/dev/null 2>&1 || true)
fi

echo "[*] Starting FastAPI Backend on port ${BACKEND_PORT}..."
(cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port "$BACKEND_PORT" --reload --reload-dir app --log-level warning) &
BACKEND_PID=$!

# Wait for backend health check
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${BACKEND_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "[*] Starting Frontend Web Console on port ${FRONTEND_PORT}..."
(cd frontend && npm run dev -- --port "$FRONTEND_PORT") &
FRONTEND_PID=$!

# Wait for frontend server
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${FRONTEND_PORT}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if [[ "${1:-}" == "--with-agent" ]]; then
  echo "[*] Starting Live Local Collector Agent..."
  (python -m collectors.common.collector_local --backend "http://localhost:${BACKEND_PORT}") &
  AGENT_PID=$!
fi

echo "[*] Launching browser at http://localhost:${FRONTEND_PORT}..."
python -m webbrowser "http://localhost:${FRONTEND_PORT}" 2>/dev/null || xdg-open "http://localhost:${FRONTEND_PORT}" 2>/dev/null || open "http://localhost:${FRONTEND_PORT}" 2>/dev/null || true

echo
echo "=========================================="
echo " [✓] OutPost is running live!"
echo " Web Console: http://localhost:${FRONTEND_PORT}"
echo " API Docs:    http://localhost:${BACKEND_PORT}/docs"
echo " Press Ctrl+C in this terminal to stop."
echo "=========================================="
echo

wait
