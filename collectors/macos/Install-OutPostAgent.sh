#!/usr/bin/env bash
# OutPost macOS EndpointSecurity Agent Automated Installer
# Usage: sudo bash Install-OutPostAgent.sh [--backend-url <URL>] [--agent-token <TOKEN>]

set -euo pipefail

BACKEND_URL="${1:-http://127.0.0.1:8000}"
AGENT_TOKEN="${OUTPOST_AGENT_TOKEN:-}"

# Parse optional CLI flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backend-url)
            BACKEND_URL="$2"
            shift 2
            ;;
        --agent-token)
            AGENT_TOKEN="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

C_GREEN=$'\033[1;32m'
C_YELLOW=$'\033[1;33m'
C_RED=$'\033[1;31m'
C_CYAN=$'\033[1;36m'
C_BOLD=$'\033[1m'
C_RESET=$'\033[0m'

say()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s==>%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s==>%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }

echo
printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s  OutPost macOS EndpointSecurity Agent — Automated Deployment Setup     %s\n' "$C_BOLD" "$C_RESET"
printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# 1. Check Root / Sudo
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        say "Administrative privileges (sudo) required for EndpointSecurity daemon. Authenticating..."
        sudo -v
        SUDO_CMD="sudo"
    else
        err "This script requires administrative (root or sudo) privileges."
        exit 1
    fi
fi

# 2. Diagnostics
MISSING=()
HAS_PY="no"
PY_VER=""
HAS_ESLOGGER="no"
HAS_BREW="no"

if command -v python3 >/dev/null 2>&1; then
    HAS_PY="yes"
    PY="python3"
    PY_VER="$(python3 --version 2>&1 | head -n 1)"
else
    MISSING+=("python3")
fi

if command -v eslogger >/dev/null 2>&1; then
    HAS_ESLOGGER="yes"
fi

if command -v brew >/dev/null 2>&1; then
    HAS_BREW="yes"
fi

# Diagnostics Table
printf '  %-24s %-16s %s\n' "COMPONENT" "STATUS" "DETAILS"
printf '  %-24s %-16s %s\n' "------------------------" "----------------" "----------------------------------"

if [ "$HAS_PY" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Python 3 Runtime" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$PY_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Python 3 Runtime" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for collector agent"
fi

if [ "$HAS_ESLOGGER" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Apple eslogger (ESF)" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "macOS EndpointSecurity Framework"
else
    printf '  %-24s %s%-16s%s %s\n' "Apple eslogger (ESF)" "$C_CYAN" "[○ OPTIONAL]" "$C_RESET" "Native EndpointSecurity CLI (macOS 13+)"
fi

if [ "$HAS_BREW" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Homebrew" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "Package Manager"
fi

printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# 3. Install missing python if needed
if [ "$HAS_PY" != "yes" ]; then
    if [ "$HAS_BREW" = "yes" ]; then
        say "Installing python via Homebrew..."
        brew install python
        PY="python3"
    else
        err "Python 3 is missing. Please install Python 3 or Homebrew and re-run."
        exit 1
    fi
fi

# Ensure Python requirements
say "Configuring Python packages (requests, psutil)..."
$PY -m pip install --quiet --upgrade pip 2>/dev/null || true
$PY -m pip install --quiet requests psutil 2>/dev/null || true

# 4. Deploy Agent Files
INSTALL_DIR="/Library/Application Support/OutPost"
$SUDO_CMD mkdir -p "$INSTALL_DIR"
$SUDO_CMD cp -r "$(dirname "$0")/.." "$INSTALL_DIR/collectors" 2>/dev/null || true

cat << LAUNCHER | $SUDO_CMD tee "$INSTALL_DIR/start-agent.sh" >/dev/null
#!/usr/bin/env bash
export OUTPOST_API_URL="${BACKEND_URL}"
export OUTPOST_AGENT_TOKEN="${AGENT_TOKEN}"
exec "${PY}" -m collectors.macos.collector_macos --backend "${BACKEND_URL}" --mode live
LAUNCHER
$SUDO_CMD chmod +x "$INSTALL_DIR/start-agent.sh"

# 5. Create launchd daemon
PLIST_PATH="/Library/LaunchDaemons/com.outpost.agent.plist"
cat << PLIST | $SUDO_CMD tee "$PLIST_PATH" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.outpost.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${INSTALL_DIR}/start-agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/outpost-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/outpost-agent.err</string>
</dict>
</plist>
PLIST

$SUDO_CMD launchctl load -w "$PLIST_PATH" 2>/dev/null || true

echo
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
printf '%s  ✔ OutPost macOS Sensor Agent Successfully Deployed!                   %s\n' "$C_BOLD" "$C_RESET"
printf '%s  Telemetry Source: Apple EndpointSecurity (eslogger / psutil)          %s\n' "$C_RESET"
printf '%s  Target Backend:   %s                                                 %s\n' "$C_RESET" "$BACKEND_URL" "$C_RESET"
printf '%s  Daemon:           %s                         %s\n' "$C_RESET" "$PLIST_PATH" "$C_RESET"
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
echo
echo "Note: If prompted, grant Full Disk Access to Terminal / Python in:"
echo "  System Settings -> Privacy & Security -> Full Disk Access"
echo
