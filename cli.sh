#!/usr/bin/env bash
# OutPost — Universal CLI & SOC Terminal Launcher (Linux / macOS)
#
# Launches the OutPost Typer/Rich CLI or interactive SOC Terminal TUI.
#
# Usage:
#   ./cli.sh                   # Launch the interactive full-screen SOC Terminal (TUI)
#   ./cli.sh <command> [args]  # Run any OutPost CLI command (e.g. ./cli.sh watch, ./cli.sh alerts, ./cli.sh list)
#   ./cli.sh --help            # Show all available commands

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ ! -d ".venv" ] || [ ! -x ".venv/bin/python" ]; then
  echo "[-] Virtual environment (.venv) not found or incomplete. Running ./setup.sh first..."
  ./setup.sh
fi

export OUTPOST_API_URL="${OUTPOST_API_URL:-http://127.0.0.1:8001}"
exec "$ROOT/.venv/bin/python" -m outpost.main "$@"
