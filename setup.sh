#!/usr/bin/env bash
# OutPost — Universal Cross-Platform Setup Script (Linux / macOS)
#
# Sets up Python virtual environment, installs backend and CLI packages,
# and installs frontend npm packages.
#
# Usage: ./setup.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=========================================="
echo "      OutPost Universal Setup"
echo "=========================================="

PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "[-] Error: Python 3 not found. Please install Python 3.10+." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[-] Error: npm not found. Please install Node.js 18+." >&2
  exit 1
fi

echo "[*] Initializing Python virtual environment (.venv)..."
if [ ! -d ".venv" ]; then
  "$PY" -m venv .venv
fi

# Activate venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Upgrading pip & installing backend + CLI packages..."
pip install --upgrade pip
pip install -e "./backend[dev]"
pip install -e "./cli"

echo "[*] Installing frontend dependencies (npm)..."
(cd frontend && npm install)

echo "[*] Setting up local frontend environment..."
if [ ! -f "frontend/.env.local" ]; then
  echo "VITE_API_URL=http://localhost:8001" > frontend/.env.local
fi

echo
echo "=========================================="
echo " [✓] OutPost setup completed successfully!"
echo "=========================================="
echo "To start OutPost (Backend + Web Console):"
echo "  ./start.sh"
echo
echo "To run the CLI:"
echo "  source .venv/bin/activate && outpost --help"
echo "=========================================="
