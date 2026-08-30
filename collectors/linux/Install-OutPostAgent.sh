#!/usr/bin/env bash
# OutPost Linux Sensor Agent & Auditd Automated Installer
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
printf '%s  OutPost Linux Security Sensor Agent — Automated Deployment Setup      %s\n' "$C_BOLD" "$C_RESET"
printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# 1. Check Root / Sudo
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        say "Administrative privileges (sudo) required for kernel audit configuration. Authenticating..."
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
HAS_AUDITD="no"
AUDITD_STATUS="Not installed"
HAS_CURL="no"

if command -v python3 >/dev/null 2>&1; then
    HAS_PY="yes"
    PY="python3"
    PY_VER="$(python3 --version 2>&1 | head -n 1)"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; exit(0 if sys.version_info[0]>=3 else 1)' 2>/dev/null; then
    HAS_PY="yes"
    PY="python"
    PY_VER="$(python --version 2>&1 | head -n 1)"
else
    MISSING+=("python3")
fi

if command -v auditd >/dev/null 2>&1 || command -v auditctl >/dev/null 2>&1; then
    HAS_AUDITD="yes"
    if systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd >/dev/null 2>&1; then
        AUDITD_STATUS="Active & Running"
    else
        AUDITD_STATUS="Installed (Inactive)"
    fi
else
    MISSING+=("auditd")
fi

if command -v curl >/dev/null 2>&1; then
    HAS_CURL="yes"
fi

# Diagnostics Table
printf '  %-24s %-16s %s\n' "COMPONENT" "STATUS" "DETAILS"
printf '  %-24s %-16s %s\n' "------------------------" "----------------" "----------------------------------"

if [ "$HAS_PY" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Python 3 Runtime" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$PY_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Python 3 Runtime" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for collector agent"
fi

if [ "$HAS_AUDITD" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Linux Auditd (auditd)" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$AUDITD_STATUS"
else
    printf '  %-24s %s%-16s%s %s\n' "Linux Auditd (auditd)" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for kernel syscall event streaming"
fi

if [ "$HAS_CURL" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "curl utility" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "Ready"
else
    printf '  %-24s %s%-16s%s %s\n' "curl utility" "$C_CYAN" "[○ OPTIONAL]" "$C_RESET" "HTTP utility"
fi

printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# 3. Auto-installation if needed
if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Installing missing components: ${MISSING[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO_CMD apt-get update -y
        $SUDO_CMD apt-get install -y python3 python3-pip auditd curl
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO_CMD dnf install -y python3 python3-pip audit curl
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO_CMD pacman -Sy --noconfirm python python-pip audit curl
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO_CMD zypper install -y python3 python3-pip audit curl
    elif command -v apk >/dev/null 2>&1; then
        $SUDO_CMD apk add python3 py3-pip audit curl
    fi
    PY="python3"
fi

# Ensure Python requirements for collector
say "Configuring Python packages (requests, psutil)..."
$PY -m pip install --quiet --upgrade pip 2>/dev/null || true
$PY -m pip install --quiet requests psutil 2>/dev/null || true

# 4. Install & Load Audit Rules
say "Deploying OutPost Linux kernel audit rules..."
RULES_SRC="$(dirname "$0")/audit.rules"
if [ -f "$RULES_SRC" ]; then
    if [ -d /etc/audit/rules.d ]; then
        $SUDO_CMD cp "$RULES_SRC" /etc/audit/rules.d/outpost.rules
    fi
    $SUDO_CMD auditctl -R "$RULES_SRC" 2>/dev/null || true
fi

# Enable and start auditd
if command -v systemctl >/dev/null 2>&1; then
    $SUDO_CMD systemctl enable --now auditd 2>/dev/null || true
fi

# 5. Create Agent Launcher & Service
INSTALL_DIR="/opt/outpost-agent"
$SUDO_CMD mkdir -p "$INSTALL_DIR"
$SUDO_CMD cp -r "$(dirname "$0")/.." "$INSTALL_DIR/collectors" 2>/dev/null || true

cat << LAUNCHER | $SUDO_CMD tee "$INSTALL_DIR/start-agent.sh" >/dev/null
#!/usr/bin/env bash
export OUTPOST_API_URL="${BACKEND_URL}"
export OUTPOST_AGENT_TOKEN="${AGENT_TOKEN}"
exec "${PY}" -m collectors.linux.collector_linux --backend-url "\$OUTPOST_API_URL" --mode live
LAUNCHER
$SUDO_CMD chmod +x "$INSTALL_DIR/start-agent.sh"

echo
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
printf '%s  ✔ OutPost Linux Sensor Agent Successfully Configured!                 %s\n' "$C_BOLD" "$C_RESET"
printf '%s  Telemetry Source: Linux Kernel Audit (auditd / auditctl)             %s\n' "$C_RESET"
printf '%s  Target Backend:   %s                                                 %s\n' "$C_RESET" "$BACKEND_URL" "$C_RESET"
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
echo
echo "To start live event streaming immediately, run:"
echo "  sudo bash $INSTALL_DIR/start-agent.sh"
echo
