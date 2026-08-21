#!/usr/bin/env bash
# OutPost — one-command installer.
#
#   Creates a virtual environment (required on PEP 668 distros like Arch),
#   installs the backend (+ dev tools) and CLI as editable packages, installs
#   frontend dependencies, writes frontend/.env.local, and seeds demo data.
#   Safe to re-run — existing artifacts are reused, never clobbered.
#
# Usage:   bash scripts/install.sh
# After:   bash scripts/dev.sh start        (or see the printed next steps)
#
# Overrides:  PYTHON=python3.12  NPM=pnpm  API_PORT=8001  WEB_PORT=5174  SEED=0

set -euo pipefail

cd "$(dirname "$0")/.."          # project root
ROOT="$(pwd)"

PY="${PYTHON:-python3}"
NPM_BIN="${NPM:-npm}"
API_PORT="${API_PORT:-8001}"
WEB_PORT="${WEB_PORT:-5174}"
SEED="${SEED:-1}"

C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'; C_BOLD=$'\033[1m'; C_RESET=$'\033[0m'
say()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s==>%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }

# ---- prereq checks ---------------------------------------------------------
command -v "$PY" >/dev/null 2>&1 || { echo "Error: '$PY' not found (set PYTHON=...)." >&2; exit 1; }
command -v "$NPM_BIN" >/dev/null 2>&1 || { echo "Error: '$NPM_BIN' not found (set NPM=...)." >&2; exit 1; }

# ---- virtual environment ---------------------------------------------------
if [ -d .venv ]; then
  say "Reusing existing virtual environment (.venv)"
else
  say "Creating virtual environment (.venv) with $PY"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

say "Upgrading pip"
pip install --upgrade pip

say "Installing backend (editable) + dev tools (pytest, ruff, black)"
pip install -e "./backend[dev]"

say "Installing CLI (editable) — the 'outpost' command"
pip install -e ./cli

# ---- frontend --------------------------------------------------------------
if [ -d frontend/node_modules ]; then
  say "Reusing frontend/node_modules"
else
  say "Installing frontend dependencies"
  (cd frontend && "$NPM_BIN" install)
fi

# ---- demo tooling (Playwright — the verify.sh layout-sweep gate) -----------
if [ -d demo/node_modules ]; then
  say "Reusing demo/node_modules (Playwright)"
else
  say "Installing demo dependencies (Playwright for the layout regression gate)"
  (cd demo && "$NPM_BIN" install)
  (cd demo && "$NPM_BIN" exec playwright install chromium) || warn "chromium download skipped — run 'cd demo && npx playwright install chromium' when you need the layout gate locally"
fi

# ---- frontend API target ---------------------------------------------------
if [ ! -f frontend/.env.local ]; then
  say "Writing frontend/.env.local  (VITE_API_URL=http://localhost:$API_PORT)"
  printf 'VITE_API_URL=http://localhost:%s\n' "$API_PORT" > frontend/.env.local
else
  say "frontend/.env.local already exists (left untouched)"
fi

# ---- demo data -------------------------------------------------------------
if [ "$SEED" = "1" ]; then
  say "Seeding demo data (campaign pair + demo run)"
  (cd backend && python -m app.seed_campaign) || warn "seed_campaign failed — install continues; you can re-seed later."
  (cd backend && python -m app.seed_demo) || true
else
  say "Skipping demo data (SEED=0)"
fi

# ---- summary ---------------------------------------------------------------
echo
printf '%sOutPost install complete.%s\n' "$C_BOLD" "$C_RESET"
echo
echo "  Start the stack:      bash scripts/dev.sh start"
echo "  Webapp:               http://localhost:$WEB_PORT"
echo "  API:                  http://localhost:$API_PORT"
echo
echo "  Or run pieces by hand (venv active first:  source .venv/bin/activate):"
echo "    backend:  cd backend && uvicorn app.main:app --reload --port $API_PORT"
echo "    frontend: cd frontend && npm run dev -- --port $WEB_PORT"
echo "    CLI:      outpost --help"
echo
echo "  Tip: OUTPOST_API_URL=http://localhost:$API_PORT outpost list"
