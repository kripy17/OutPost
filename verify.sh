#!/usr/bin/env bash
# verify.sh — OutPost full verification sweep in one command.
#
#   backend pytest  →  coverage gate (14/14 ATT&CK)  →  collector pytest
#   →  CLI pytest  →  frontend build (tsc --noEmit + vite)
#
# Prints a colored pass/fail summary per step and exits non-zero if any step
# fails. Environment overrides:
#   PYTEST   path to pytest        (default: $ROOT/.venv/bin/pytest)
#   NPM      npm binary            (default: npm)
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTEST="${PYTEST:-$ROOT/.venv/bin/pytest}"
NPM="${NPM:-npm}"

C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'
C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'

PASS=0
FAIL=0
FAILED_NAMES=()

step() { # step <name> <command...>
  local name="$1"; shift
  echo
  echo "${C_BOLD}── $name ──${C_RESET}"
  if "$@"; then
    echo "${C_GREEN}✓ $name passed${C_RESET}"
    PASS=$((PASS + 1))
  else
    echo "${C_RED}✗ $name FAILED (exit $?)${C_RESET}"
    FAIL=$((FAIL + 1))
    FAILED_NAMES+=("$name")
  fi
}

if [ ! -x "$PYTEST" ]; then
  echo "${C_RED}Error: $PYTEST not found.${C_RESET}" >&2
  echo "  Create the venv first (see .freebuff/run.md):" >&2
  echo "    cd '$ROOT' && python3 -m venv .venv" >&2
  echo "    source .venv/bin/activate && pip install -e './backend[dev]' -e ./cli" >&2
  exit 2
fi

echo "${C_DIM}OutPost verification sweep — root: $ROOT${C_RESET}"

step "Backend pytest  (backend/app/tests)" \
  bash -c "cd '$ROOT/backend' && '$PYTEST' -q"

# Coverage gate — the Navigator layer (and therefore RULE_META) must touch all
# 14 canonical ATT&CK Enterprise tactics. A new rule that forgets its RULE_META
# entry, or a tactic renamed off the canonical list, fails here — CI enforces
# the coverage story instead of the Coverage page merely telling it.
step "Coverage gate   (14/14 ATT&CK tactics)" \
  bash -c "cd '$ROOT/backend' && '$PYTEST' -q app/tests/test_exports.py -k covers_all_14"

step "Collector pytest (collectors/tests)" \
  bash -c "cd '$ROOT/collectors' && '$PYTEST' -q"

step "CLI pytest      (cli/tests)" \
  bash -c "cd '$ROOT/cli' && '$PYTEST' -q"

step "Frontend lint   (eslint)" \
  bash -c "cd '$ROOT/frontend' && '$NPM' run lint"

step "Frontend tests  (vitest)" \
  bash -c "cd '$ROOT/frontend' && '$NPM' run test"

step "Frontend build  (tsc --noEmit && vite build)" \
  bash -c "cd '$ROOT/frontend' && '$NPM' run build"

echo
echo "${C_BOLD}══════════════════════════════════════${C_RESET}"
if [ "$FAIL" -eq 0 ]; then
  echo "${C_GREEN}${C_BOLD}All $PASS step(s) passed. ✓${C_RESET}"
  exit 0
else
  echo "${C_RED}${C_BOLD}$FAIL of $((PASS + FAIL)) step(s) failed:${C_RESET}"
  for n in "${FAILED_NAMES[@]}"; do echo "${C_RED}  ✗ $n${C_RESET}"; done
  exit 1
fi
