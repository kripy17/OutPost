#!/usr/bin/env bash
# OutPost — one-command installer & dependency manager.
#
#   1. Inspects system dependencies (Python 3, venv, pip, Node.js, npm, git, curl).
#   2. Displays an interactive Installed vs Missing Diagnostics Table.
#   3. If dependencies are missing, requests permission and installs them automatically
#      via the system package manager (apt, dnf, pacman, zypper, apk, brew).
#   4. Creates an isolated virtual environment (.venv).
#   5. Installs backend (+ dev tools) and CLI as editable packages.
#   6. Installs frontend dependencies and demo tools.
#   7. Configures frontend/.env.local and seeds initial demo data.
#
# Usage:   bash scripts/install.sh
# Overrides: PYTHON=python3.12 NPM=pnpm API_PORT=8001 WEB_PORT=5174 SEED=1 NON_INTERACTIVE=0

set -euo pipefail

cd "$(dirname "$0")/.."          # project root
ROOT="$(pwd)"

PY="${PYTHON:-python3}"
NPM_BIN="${NPM:-npm}"
API_PORT="${API_PORT:-8001}"
WEB_PORT="${WEB_PORT:-5174}"
SEED="${SEED:-1}"
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"

# Colors & Formatting
C_GREEN=$'\033[1;32m'
C_YELLOW=$'\033[1;33m'
C_RED=$'\033[1;31m'
C_CYAN=$'\033[1;36m'
C_BOLD=$'\033[1m'
C_RESET=$'\033[0m'

say()  { printf '%s==>%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s==>%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()  { printf '%s==>%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
info() { printf '%s==>%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }

echo
printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
printf '%s  OutPost — System Diagnostics & Automated Environment Setup          %s\n' "$C_BOLD" "$C_RESET"
printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# -----------------------------------------------------------------------------
# 1. Dependency Diagnostics
# -----------------------------------------------------------------------------
MISSING_DEPS=()
MISSING_PKGS=()

HAS_PY="no"
PY_VER=""
HAS_VENV="no"
HAS_PIP="no"
PIP_VER=""
HAS_NODE="no"
NODE_VER=""
HAS_NPM="no"
NPM_VER=""
HAS_GIT="no"
GIT_VER=""
HAS_CURL="no"
CURL_VER=""

# Check Python 3
if command -v "$PY" >/dev/null 2>&1; then
    HAS_PY="yes"
    PY_VER="$("$PY" --version 2>&1 | head -n 1)"
elif command -v python >/dev/null 2>&1 && python -c 'import sys; exit(0 if sys.version_info[0]>=3 else 1)' 2>/dev/null; then
    HAS_PY="yes"
    PY="python"
    PY_VER="$(python --version 2>&1 | head -n 1)"
else
    MISSING_DEPS+=("Python 3 (>=3.10)")
    MISSING_PKGS+=("python3")
fi

# Check Python venv
if [ "$HAS_PY" = "yes" ]; then
    if "$PY" -m venv --help >/dev/null 2>&1; then
        HAS_VENV="yes"
    else
        MISSING_DEPS+=("python3-venv module")
        MISSING_PKGS+=("python3-venv")
    fi
fi

# Check Python pip
if [ "$HAS_PY" = "yes" ]; then
    if "$PY" -m pip --version >/dev/null 2>&1; then
        HAS_PIP="yes"
        PIP_VER="$("$PY" -m pip --version | awk '{print $1, $2}')"
    elif [ -f .venv/bin/pip ] && .venv/bin/pip --version >/dev/null 2>&1; then
        HAS_PIP="yes"
        PIP_VER="$(.venv/bin/pip --version | awk '{print $1, $2}') (.venv)"
    elif "$PY" -c 'import ensurepip' >/dev/null 2>&1; then
        HAS_PIP="yes"
        PIP_VER="Available via ensurepip"
    else
        MISSING_DEPS+=("python3-pip")
        MISSING_PKGS+=("python3-pip")
    fi
fi

# Check Node.js
if command -v node >/dev/null 2>&1; then
    HAS_NODE="yes"
    NODE_VER="$(node -v 2>&1)"
else
    MISSING_DEPS+=("Node.js (>=18)")
    MISSING_PKGS+=("nodejs")
fi

# Check npm
if command -v "$NPM_BIN" >/dev/null 2>&1; then
    HAS_NPM="yes"
    NPM_VER="$("$NPM_BIN" -v 2>&1)"
else
    MISSING_DEPS+=("npm package manager")
    MISSING_PKGS+=("npm")
fi

# Check Git
if command -v git >/dev/null 2>&1; then
    HAS_GIT="yes"
    GIT_VER="$(git --version 2>&1 | head -n 1)"
else
    MISSING_DEPS+=("git")
    MISSING_PKGS+=("git")
fi

# Check curl
if command -v curl >/dev/null 2>&1; then
    HAS_CURL="yes"
    CURL_VER="$(curl --version 2>&1 | head -n 1 | awk '{print $1, $2}')"
else
    MISSING_DEPS+=("curl")
    MISSING_PKGS+=("curl")
fi

# Check Linux Auditd (Optional / Recommended for Host Telemetry)
HAS_AUDITD="no"
AUDITD_STATUS="Not installed"
if command -v auditd >/dev/null 2>&1 || command -v auditctl >/dev/null 2>&1; then
    HAS_AUDITD="yes"
    if systemctl is-active --quiet auditd 2>/dev/null || pgrep -x auditd >/dev/null 2>&1; then
        AUDITD_STATUS="Active & Running"
    else
        AUDITD_STATUS="Installed (Inactive)"
    fi
fi

# -----------------------------------------------------------------------------
# 2. Render Diagnostic Matrix
# -----------------------------------------------------------------------------
printf '  %-24s %-16s %s\n' "COMPONENT" "STATUS" "DETAILS"
printf '  %-24s %-16s %s\n' "------------------------" "----------------" "----------------------------------"

if [ "$HAS_PY" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Python 3" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$PY_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Python 3" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for OutPost backend & CLI"
fi

if [ "$HAS_VENV" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Python venv module" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "Standard library module"
else
    printf '  %-24s %s%-16s%s %s\n' "Python venv module" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for isolated sandbox environment"
fi

if [ "$HAS_PIP" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Python pip" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$PIP_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Python pip" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for package installations"
fi

if [ "$HAS_NODE" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Node.js" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$NODE_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Node.js" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for OutPost React webapp"
fi

if [ "$HAS_NPM" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "npm package manager" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "v$NPM_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "npm package manager" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for frontend bundling"
fi

if [ "$HAS_GIT" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Git" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$GIT_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "Git" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for repository management"
fi

if [ "$HAS_CURL" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "curl" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$CURL_VER"
else
    printf '  %-24s %s%-16s%s %s\n' "curl" "$C_RED" "[✖ MISSING]" "$C_RESET" "Required for threat intel feeds & updates"
fi

if [ "$HAS_AUDITD" = "yes" ]; then
    printf '  %-24s %s%-16s%s %s\n' "Linux Auditd (auditd)" "$C_GREEN" "[✔ INSTALLED]" "$C_RESET" "$AUDITD_STATUS"
else
    printf '  %-24s %s%-16s%s %s\n' "Linux Auditd (auditd)" "$C_CYAN" "[○ OPTIONAL]" "$C_RESET" "Recommended for kernel syscall telemetry"
fi

printf '%s========================================================================%s\n' "$C_CYAN" "$C_RESET"
echo

# -----------------------------------------------------------------------------
# 3. Automated Package Installation on Missing Dependencies
# -----------------------------------------------------------------------------
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    warn "Missing ${#MISSING_DEPS[@]} required dependencies on this system."
    echo

    DO_INSTALL="yes"
    if [ "$NON_INTERACTIVE" != "1" ] && [ -t 0 ]; then
        printf '%s==>%s Would you like OutPost to install missing packages automatically? [Y/n]: ' "$C_BOLD" "$C_RESET"
        read -r choice
        case "$choice" in
            [nN][oO]|[nN])
                DO_INSTALL="no"
                ;;
            *)
                DO_INSTALL="yes"
                ;;
        esac
    fi

    if [ "$DO_INSTALL" != "yes" ]; then
        err "Installation aborted by user. Please install the missing dependencies manually and re-run scripts/install.sh."
        exit 1
    fi

    # Detect package manager
    info "Detecting system package manager..."
    SUDO_CMD=""
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            say "Administrative privileges (sudo) required to install packages. Authenticating..."
            sudo -v
            SUDO_CMD="sudo"
        else
            err "'sudo' not found and script is not running as root. Please run as root or install sudo."
            exit 1
        fi
    fi

    if command -v apt-get >/dev/null 2>&1; then
        say "Installing packages via apt-get (Debian / Ubuntu / Kali / Mint)..."
        $SUDO_CMD apt-get update -y
        $SUDO_CMD apt-get install -y python3 python3-venv python3-pip nodejs npm git curl
    elif command -v dnf >/dev/null 2>&1; then
        say "Installing packages via dnf (Fedora / RHEL / Alma / Rocky)..."
        $SUDO_CMD dnf install -y python3 python3-pip nodejs npm git curl
    elif command -v pacman >/dev/null 2>&1; then
        say "Installing packages via pacman (Arch Linux / Manjaro)..."
        $SUDO_CMD pacman -Sy --noconfirm python python-pip nodejs npm git curl
    elif command -v zypper >/dev/null 2>&1; then
        say "Installing packages via zypper (openSUSE / SLES)..."
        $SUDO_CMD zypper install -y python3 python3-pip nodejs npm git curl
    elif command -v apk >/dev/null 2>&1; then
        say "Installing packages via apk (Alpine Linux)..."
        $SUDO_CMD apk add python3 py3-pip nodejs npm git curl
    elif command -v brew >/dev/null 2>&1; then
        say "Installing packages via Homebrew (macOS)..."
        brew install python node git curl
    else
        err "Could not identify a supported package manager (apt, dnf, pacman, zypper, apk, brew)."
        err "Please install Python 3, python3-venv, Node.js, npm, and git manually."
        exit 1
    fi

    say "Package installation completed. Re-evaluating environment..."
    PY="${PYTHON:-python3}"
fi

# -----------------------------------------------------------------------------
# 4. Virtual Environment Setup
# -----------------------------------------------------------------------------
if [ -d .venv ]; then
    say "Reusing existing virtual environment (.venv)"
else
    say "Creating virtual environment (.venv) with $PY"
    "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

say "Upgrading pip & setuptools"
pip install --upgrade pip setuptools

say "Installing OutPost backend (editable) + dev tools (pytest, ruff, black)"
pip install -e "./backend[dev]"

say "Installing OutPost CLI (editable) — the 'outpost' command"
pip install -e ./cli

# -----------------------------------------------------------------------------
# 5. Frontend Dependencies
# -----------------------------------------------------------------------------
if [ -d frontend/node_modules ]; then
    say "Reusing frontend/node_modules"
else
    say "Installing frontend dependencies with $NPM_BIN"
    (cd frontend && "$NPM_BIN" install)
fi

# -----------------------------------------------------------------------------
# 6. Demo Tooling (Playwright Regression Gate)
# -----------------------------------------------------------------------------
if [ -d demo/node_modules ]; then
    say "Reusing demo/node_modules (Playwright)"
else
    say "Installing demo dependencies"
    (cd demo && "$NPM_BIN" install)
    (cd demo && "$NPM_BIN" exec playwright install chromium) || warn "chromium download skipped — run 'cd demo && npx playwright install chromium' when you need the layout gate locally"
fi

# -----------------------------------------------------------------------------
# 7. Frontend API Configuration
# -----------------------------------------------------------------------------
if [ ! -f frontend/.env.local ]; then
    say "Writing frontend/.env.local (VITE_API_URL=http://localhost:$API_PORT)"
    printf 'VITE_API_URL=http://localhost:%s\n' "$API_PORT" > frontend/.env.local
else
    say "frontend/.env.local already exists (left untouched)"
fi

# -----------------------------------------------------------------------------
# 8. Initial Demo Seed
# -----------------------------------------------------------------------------
if [ "$SEED" = "1" ]; then
    say "Seeding demo data (campaign pair + demo run)"
    (cd backend && python -m app.seed_campaign) || warn "seed_campaign failed — install continues; you can re-seed later."
    (cd backend && python -m app.seed_demo) || true
else
    say "Skipping demo data (SEED=0)"
fi

# -----------------------------------------------------------------------------
# 9. Optional Linux Auditd Rules Setup
# -----------------------------------------------------------------------------
INSTALL_AUDIT_RULES="${INSTALL_AUDIT_RULES:-0}"
if [ "$HAS_AUDITD" = "yes" ] && [ -f collectors/linux/audit.rules ]; then
    DO_AUDIT_RULES="no"
    if [ "$INSTALL_AUDIT_RULES" = "1" ]; then
        DO_AUDIT_RULES="yes"
    elif [ "$NON_INTERACTIVE" != "1" ] && [ -t 0 ]; then
        printf '%s==>%s Would you like OutPost to load Linux audit rules (execve, connect, file watches)? [Y/n]: ' "$C_BOLD" "$C_RESET"
        read -r choice
        case "$choice" in
            [nN][oO]|[nN]) DO_AUDIT_RULES="no" ;;
            *) DO_AUDIT_RULES="yes" ;;
        esac
    fi

    if [ "$DO_AUDIT_RULES" = "yes" ]; then
        say "Applying OutPost audit rules into Linux kernel..."
        if [ "$(id -u)" -ne 0 ]; then
            sudo auditctl -R collectors/linux/audit.rules 2>/dev/null || warn "Could not load auditctl rules directly."
        else
            auditctl -R collectors/linux/audit.rules 2>/dev/null || warn "Could not load auditctl rules directly."
        fi
        say "✔ OutPost Linux audit rules active."
    fi
fi

# -----------------------------------------------------------------------------
# 10. Installation Summary & Next Steps
# -----------------------------------------------------------------------------
echo
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
printf '%s  ✔ OutPost Installation Complete!                                      %s\n' "$C_BOLD" "$C_RESET"
printf '%s========================================================================%s\n' "$C_GREEN" "$C_RESET"
echo
echo "  Start the full stack:   bash scripts/dev.sh start"
echo "  Webapp interface:       http://localhost:$WEB_PORT"
echo "  Backend API:            http://localhost:$API_PORT"
echo
echo "  To activate environment manually:"
echo "    source .venv/bin/activate"
echo "    outpost --help"
echo
