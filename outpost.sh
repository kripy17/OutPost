#!/usr/bin/env bash
# OutPost — Universal Application & CLI Control Center
#
# Usage:
#   ./outpost.sh                      # Launch the interactive full-screen SOC Terminal (TUI)
#   ./outpost.sh start [--demo]       # Start the OutPost stack (Backend API + Web Console) in background
#   ./outpost.sh stop                 # Stop all OutPost services and release ports
#   ./outpost.sh restart              # Restart all OutPost services
#   ./outpost.sh status               # View real-time platform, service, and database health
#   ./outpost.sh logs                 # View or tail service logs (.freebuff/)
#   ./outpost.sh web                  # Open the Web Console in your default browser
#   ./outpost.sh doctor               # Run comprehensive environment diagnostic checks
#   ./outpost.sh <command> [args]     # Run any SOC CLI command (e.g. ./outpost.sh list, alerts, intel)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Terminal formatting
C_CYAN=$'\033[1;36m'
C_GREEN=$'\033[1;32m'
C_YELLOW=$'\033[1;33m'
C_RED=$'\033[1;31m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_RESET=$'\033[0m'

ensure_venv() {
  if [ ! -d ".venv" ] || [ ! -x ".venv/bin/python" ]; then
    echo "${C_YELLOW}[-] Virtual environment (.venv) not found. Running ./setup.sh first...${C_RESET}"
    ./setup.sh
  fi
}

show_help() {
  cat << EOF
${C_BOLD}OutPost${C_RESET} — Cross-Platform Behavioral Security Workstation & EDR Platform

${C_CYAN}USAGE:${C_RESET}
  ./outpost.sh [COMMAND] [OPTIONS]

${C_CYAN}SERVICE STACK OPERATIONS:${C_RESET}
  ${C_GREEN}start${C_RESET} [--demo] [--with-agent] [--foreground|-f]
                   Start the OutPost stack (FastAPI :8001 + Web Console :5174) in the background
  ${C_GREEN}stop${C_RESET}            Stop all running OutPost services and release ports
  ${C_GREEN}restart${C_RESET}         Restart the OutPost backend and frontend services
  ${C_GREEN}status${C_RESET}          Display real-time health for Backend API, Web Console, SQLite, and Agents
  ${C_GREEN}logs${C_RESET} [-f|--follow]  View or tail live application server logs
  ${C_GREEN}web${C_RESET}             Open the OutPost Web Console in the default browser (starts stack if needed)
  ${C_GREEN}doctor${C_RESET}          Run diagnostic checks (Python, Node, Ports, SQLite, Directories)

${C_CYAN}INTERACTIVE TERMINAL:${C_RESET}
  ${C_GREEN}tui${C_RESET}, ${C_GREEN}console${C_RESET}     Launch the full-screen interactive SOC Terminal User Interface
  ${C_DIM}(Running ./outpost.sh with no arguments in a terminal launches the TUI automatically)${C_RESET}

${C_CYAN}THREAT HUNTING & DFIR COMMANDS:${C_RESET}
  ${C_GREEN}list${C_RESET}            View past execution and live monitoring sessions
  ${C_GREEN}alerts${C_RESET}          List, filter, or tail live security alerts (--follow)
  ${C_GREEN}triage${C_RESET}          Move alerts through triage lifecycle (open -> acknowledged -> resolved)
  ${C_GREEN}watch${C_RESET}           Start an interactive real-time live behavioral monitoring session
  ${C_GREEN}run${C_RESET} <sample>    Detonate or analyze a sample under monitored sandbox
  ${C_GREEN}samples${C_RESET}         Inspect sample vault, upload binaries (--upload), or launch analysis
  ${C_GREEN}rules${C_RESET}           Inspect detection rules, tuning knobs, anti-forensics patterns, Sigma
  ${C_GREEN}playbooks${C_RESET}       Execute automated IR playbooks and containment workflows
  ${C_GREEN}forensics${C_RESET}       Deep Host Forensics — process causality, network threat matrix, triage packs
  ${C_GREEN}intel${C_RESET}           Threat-intel feeds, IOC fleet compromise hunting, and IOC extraction
  ${C_GREEN}yara${C_RESET}            YARA rule catalog and local directory/file scanner
  ${C_GREEN}coverage${C_RESET}        View Enterprise MITRE ATT&CK coverage matrix
  ${C_GREEN}campaigns${C_RESET}       Correlate multi-session threat campaigns across fleet
  ${C_GREEN}search${C_RESET} <ioc>    Search historical indicators across all sessions or fleet resources
  ${C_GREEN}hosts${C_RESET}           Aggregate per-host behavioral timeline and anomaly metrics
  ${C_GREEN}watchlist${C_RESET}       Manage monitored IOC indicators (IPs, domains, hashes)
  ${C_GREEN}allowlist${C_RESET}       Configure false-positive rule suppressions
  ${C_GREEN}agent${C_RESET}           Bootstrap, run, or install OS collector agent (Linux, Windows, macOS)
  ${C_GREEN}export${C_RESET}          Export STIX 2.1 bundles, forensic packs, or investigation dossiers
  ${C_GREEN}seed${C_RESET}            Seed realistic labeled demo telemetry, campaigns, and cases into SQLite

${C_CYAN}GLOBAL OPTIONS:${C_RESET}
  -v, --version    Show OutPost platform version and architecture
  -h, --help       Show this help manual and command reference

EOF
}

open_browser() {
  local url="${1:-http://localhost:5174}"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
  else
    ensure_venv
    "$ROOT/.venv/bin/python" -m webbrowser "$url" >/dev/null 2>&1 || true
  fi
}

cmd="${1:-}"

case "$cmd" in
  "" )
    # No arguments provided
    if [ -t 0 ]; then
      # Running interactively in a real terminal: launch TUI
      ensure_venv
      exec "$ROOT/cli.sh" tui
    else
      # Running non-interactively (pipe / script / CI): show help
      show_help
      exit 0
    fi
    ;;

  -h|--help|help)
    show_help
    exit 0
    ;;

  -v|--version|version)
    ensure_venv
    exec "$ROOT/cli.sh" --version
    ;;

  start|up)
    ensure_venv
    shift || true

    # Check for foreground flag
    FOREGROUND=false
    ARGS=()
    for arg in "$@"; do
      if [[ "$arg" == "--foreground" || "$arg" == "-f" ]]; then
        FOREGROUND=true
      else
        ARGS+=("$arg")
      fi
    done

    if [ "$FOREGROUND" = true ]; then
      exec "$ROOT/start.sh" "${ARGS[@]}"
    fi

    # Background launch via scripts/dev.sh
    echo "${C_CYAN}[*] Starting OutPost stack in background...${C_RESET}"
    bash "$ROOT/scripts/dev.sh" start
    echo "${C_GREEN}[✓] OutPost stack is active!${C_RESET}"
    echo "  Web Console: ${C_CYAN}http://localhost:5174${C_RESET}"
    echo "  API Docs:    ${C_CYAN}http://127.0.0.1:8001/docs${C_RESET}"
    echo "  Stop Stack:  ${C_BOLD}./outpost.sh stop${C_RESET}"
    echo "  View Logs:   ${C_BOLD}./outpost.sh logs${C_RESET}"
    ;;

  stop|down)
    echo "${C_CYAN}[*] Stopping OutPost services...${C_RESET}"
    bash "$ROOT/scripts/dev.sh" stop
    # Clean any dangling agent collectors
    pkill -f "collectors.common.collector_local" 2>/dev/null || true
    echo "${C_GREEN}[✓] All OutPost services stopped successfully.${C_RESET}"
    ;;

  restart)
    echo "${C_CYAN}[*] Restarting OutPost services...${C_RESET}"
    bash "$ROOT/scripts/dev.sh" stop || true
    sleep 1
    bash "$ROOT/scripts/dev.sh" start
    echo "${C_GREEN}[✓] OutPost services restarted successfully.${C_RESET}"
    ;;

  status)
    ensure_venv
    exec "$ROOT/cli.sh" status
    ;;

  doctor)
    ensure_venv
    exec "$ROOT/cli.sh" doctor
    ;;

  logs)
    shift || true
    if [[ "${1:-}" == "-f" || "${1:-}" == "--follow" ]]; then
      echo "${C_CYAN}[*] Tailing live OutPost logs (Ctrl+C to stop)...${C_RESET}"
      tail -f "$ROOT/.freebuff/backend.log" "$ROOT/.freebuff/frontend.log" 2>/dev/null
    else
      bash "$ROOT/scripts/dev.sh" logs
    fi
    ;;

  web|ui|open|browse)
    # Check if frontend is active
    if ! curl -sf http://localhost:5174 >/dev/null 2>&1; then
      echo "${C_YELLOW}[*] Web Console is not currently running. Starting services first...${C_RESET}"
      bash "$ROOT/scripts/dev.sh" start
    fi
    echo "${C_GREEN}[*] Opening OutPost Web Console at http://localhost:5174...${C_RESET}"
    open_browser "http://localhost:5174"
    ;;

  tui|console)
    ensure_venv
    exec "$ROOT/cli.sh" tui
    ;;

  seed)
    ensure_venv
    exec "$ROOT/cli.sh" seed
    ;;

  *)
    # All other CLI subcommands: forward directly to cli.sh
    ensure_venv
    exec "$ROOT/cli.sh" "$@"
    ;;
esac
