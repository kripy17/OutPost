#!/usr/bin/env bash
# OutPost — Universal Application & CLI Launcher
#
# Usage:
#   ./outpost.sh                   # Launch the interactive full-screen SOC Terminal (TUI)
#   ./outpost.sh <command> [args]  # Run any OutPost command (e.g. ./outpost.sh watch, ./outpost.sh alerts)
#   ./outpost.sh --help            # Show all available commands

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/cli.sh" "$@"
