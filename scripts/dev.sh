#!/usr/bin/env bash
# OutPost — start / stop / status for the webapp stack.
#
#   start   Launch backend (:8001) + frontend (:5174) detached, log to
#           .freebuff/*.log, and wait for both to answer. PIDs are recorded
#           in .freebuff/*.pid so `stop` can find them.
#   stop    Stop both servers (kills the recorded PIDs and anything holding
#           the API port).
#   status  Print whether each server is answering.
#   logs    Tail the server logs.
#
# Usage:   bash scripts/dev.sh [start|stop|status|logs]
# Overrides:  API_PORT=8001  WEB_PORT=5174
set -euo pipefail

cd "$(dirname "$0")/.."          # project root
ROOT="$(pwd)"
VENV="$ROOT/.venv"
LOG_DIR="$ROOT/.freebuff"
API_PORT="${API_PORT:-8001}"
WEB_PORT="${WEB_PORT:-5174}"
API_URL="http://127.0.0.1:$API_PORT"
WEB_URL="http://localhost:$WEB_PORT"

API_LOG="$LOG_DIR/backend.log"
WEB_LOG="$LOG_DIR/frontend.log"
API_PID="$LOG_DIR/backend.pid"
WEB_PID="$LOG_DIR/frontend.pid"

C_GREEN=$'\033[1;32m'; C_RED=$'\033[1;31m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
say()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
err()  { printf '%s==>%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }

mkdir -p "$LOG_DIR"

api_healthy() { curl -sf "$API_URL/health" >/dev/null 2>&1; }
web_healthy() { curl -sf "$WEB_URL" >/dev/null 2>&1; }

wait_healthy() { # wait_healthy <label> <seconds> <fn>
  local label="$1" secs="$2" fn="$3" i
  for ((i = 0; i < secs; i++)); do
    if "$fn"; then return 0; fi
    sleep 1
  done
  return 1
}

cmd="${1:-start}"
case "$cmd" in

  start)
    if api_healthy || web_healthy; then
      err "Something is already running on :$API_PORT or :$WEB_PORT."
      echo "  $BASH_SOURCE status   # see what's up"
      exit 1
    fi

    say "Starting backend on :$API_PORT  (log: $API_LOG)"
    setsid nohup env CORS_ORIGINS="http://localhost:$WEB_PORT" \
      "$VENV/bin/uvicorn" app.main:app --host 127.0.0.1 --port "$API_PORT" \
      >"$API_LOG" 2>&1 &
    echo $! > "$API_PID"
    if ! wait_healthy "api" 30 api_healthy; then
      err "Backend did not answer within 30s — check $API_LOG"
      exit 1
    fi
    say "Backend up: $API_URL/health"

    say "Starting frontend on :$WEB_PORT  (log: $WEB_LOG)"
    setsid nohup bash -c "cd '$ROOT/frontend' && npm run dev -- --port '$WEB_PORT' --strictPort" \
      >"$WEB_LOG" 2>&1 &
    echo $! > "$WEB_PID"
    if ! wait_healthy "web" 45 web_healthy; then
      err "Frontend did not answer within 45s — check $WEB_LOG"
      exit 1
    fi
    say "Frontend up: $WEB_URL"
    echo
    echo "  Webapp:   $WEB_URL"
    echo "  API:      $API_URL"
    echo "  Stop:     $BASH_SOURCE stop"
    ;;

  stop)
    say "Stopping stack…"
    for pf in "$WEB_PID" "$API_PID"; do
      if [ -f "$pf" ]; then
        kill "$(cat "$pf")" 2>/dev/null || true
        rm -f "$pf"
      fi
    done
    # Any process still holding the API port (stale server, etc.):
    pkill -f "uvicorn app.main:a[p]p" 2>/dev/null || true
    pkill -f "vite.*--port $WEB_PORT" 2>/dev/null || true
    sleep 1
    if api_healthy || web_healthy; then err "Some servers still answering — check the logs."; exit 1; fi
    say "Stack stopped."
    ;;

  status)
    if api_healthy; then echo "  API      :$API_PORT  ${C_GREEN}up ✓${C_RESET}"; else echo "  API      :$API_PORT  ${C_RED}down${C_RESET}"; fi
    if web_healthy; then echo "  Webapp   :$WEB_PORT  ${C_GREEN}up ✓${C_RESET}"; else echo "  Webapp   :$WEB_PORT  ${C_RED}down${C_RESET}"; fi
    ;;

  logs)
    echo "── backend ($API_LOG) ──"
    tail -n 30 "$API_LOG" 2>/dev/null || echo "(no backend log yet)"
    echo
    echo "── frontend ($WEB_LOG) ──"
    tail -n 30 "$WEB_LOG" 2>/dev/null || echo "(no frontend log yet)"
    ;;

  *)
    echo "Usage: $BASH_SOURCE [start|stop|status|logs]" >&2
    exit 2
    ;;
esac
