#!/usr/bin/env bash
# OutPost — one-shot development setup.
#
# Creates a virtual environment (required on PEP 668 distros like Arch),
# installs the backend (+ dev tools) and CLI as editable packages, and
# installs the frontend dependencies. Safe to re-run.
#
# Usage:  bash scripts/setup.sh
# After:  source .venv/bin/activate   (in each new shell)

set -euo pipefail

cd "$(dirname "$0")/.."          # project root

PY="${PYTHON:-python3}"

echo "==> Creating virtual environment (.venv)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Upgrading pip"
pip install --upgrade pip

echo "==> Installing backend (editable) + dev tools (pytest, ruff, black)"
pip install -e "./backend[dev]"

echo "==> Installing CLI (editable) — 'outpost' command"
pip install -e ./cli

echo "==> Installing frontend dependencies"
(cd frontend && npm install)

echo
echo "Setup complete. Next steps (venv must be active):"
echo "  source .venv/bin/activate"
echo "  cd backend && uvicorn app.main:app --reload    # API on http://localhost:8000"
echo "  cd backend && pytest                           # run the test suite"
echo "  cd backend && python -m app.seed_demo          # demo data (3 alerts)"
echo "  cd frontend && npm run dev                     # webapp on http://localhost:5173"
echo "  outpost --help                                 # CLI"
