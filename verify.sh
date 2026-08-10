#!/usr/bin/env bash
# verify.sh — OutPost full verification sweep in one command.
#
#   backend pytest  →  coverage gate (14/14 ATT&CK)  →  collector pytest
#   →  CLI pytest  →  frontend lint/tests/build  →  collector soak gates
#   →  doc-count gate (stale numeric references in shipped docs)
#
# Prints a colored pass/fail summary per step and exits non-zero if any step
# fails. Environment overrides:
#   PYTEST   path to pytest        (default: $ROOT/.venv/bin/pytest)
#   NPM      npm binary            (default: npm)
#
# Steps 8/9 (collector soak gates) boot an ISOLATED backend (temp DB, spare
# ports 8011/8012) and assert the modeled benign Sysmon/auditd baselines fire
# ZERO alerts while the known-malicious stories still land their core
# detections — the collector FP baselines are part of CI, not just local
# measurements.
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

# Windows collector soak gate — the real parser + Shipper over HTTP into an
# isolated backend (temp DB, spare port), so the benign-baseline FP budget is
# checked on every push, not just locally. Fails when Phase A fires any alert
# or the malicious story misses its core detections (over-exemption guard).
step "Windows soak    (Sysmon FP baseline gate)" \
  env ROOT="$ROOT" PYTHON="$ROOT/.venv/bin/python" bash -c '
    set -e
    SOAK_DB=$(mktemp --suffix=.db)
    SOAK_SAMPLES=$(mktemp -d)
    SOAK_PORT=8011
    SOAK_LOG=$(mktemp --suffix=.log)
    SOAK_PID=""
    cleanup() {
      [ -n "$SOAK_PID" ] && kill "$SOAK_PID" 2>/dev/null || true
      rm -f "$SOAK_DB" "$SOAK_LOG"
      rm -rf "$SOAK_SAMPLES"
    }
    trap cleanup EXIT
    DATABASE_PATH="$SOAK_DB" SAMPLES_DIR="$SOAK_SAMPLES" \
      "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$SOAK_PORT" >"$SOAK_LOG" 2>&1 &
    SOAK_PID=$!
    for _ in $(seq 1 30); do
      curl -sf "http://127.0.0.1:$SOAK_PORT/meta" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://127.0.0.1:$SOAK_PORT/meta" >/dev/null
    cd "$ROOT"
    "$PYTHON" scripts/soak_windows_collector.py \
      --backend "http://127.0.0.1:$SOAK_PORT" --host "$(hostname)" --gate
  '

# Linux collector soak gate — the auditd parser + real Shipper over HTTP into
# an isolated backend, so the Linux benign-baseline FP budget is gated too.
# Same semantics as the Windows gate: zero FPs on the modeled baseline, core
# detections (lolbin-abuse / unusual-port / enumeration-burst) on the evil
# story. (The soak's only simulations: the audit log tail + the /proc reads.)
step "Linux soak     (auditd FP baseline gate)" \
  env ROOT="$ROOT" PYTHON="$ROOT/.venv/bin/python" bash -c '
    set -e
    SOAK_DB=$(mktemp --suffix=.db)
    SOAK_SAMPLES=$(mktemp -d)
    SOAK_PORT=8012
    SOAK_LOG=$(mktemp --suffix=.log)
    SOAK_PID=""
    cleanup() {
      [ -n "$SOAK_PID" ] && kill "$SOAK_PID" 2>/dev/null || true
      rm -f "$SOAK_DB" "$SOAK_LOG"
      rm -rf "$SOAK_SAMPLES"
    }
    trap cleanup EXIT
    DATABASE_PATH="$SOAK_DB" SAMPLES_DIR="$SOAK_SAMPLES" \
      "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$SOAK_PORT" >"$SOAK_LOG" 2>&1 &
    SOAK_PID=$!
    for _ in $(seq 1 30); do
      curl -sf "http://127.0.0.1:$SOAK_PORT/meta" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://127.0.0.1:$SOAK_PORT/meta" >/dev/null
    cd "$ROOT"
    "$PYTHON" scripts/soak_linux_collector.py \
      --backend "http://127.0.0.1:$SOAK_PORT" --host "$(hostname)" --gate
  '

# Doc-count gate — the shipped READMEs must not drift from the code they
# describe. Two checks: (1) known-stale numeric patterns (old test counts,
# the pre-trim "2-minute/4 acts" demo copy) never reappear; (2) every claimed
# count — the README badge total and the per-suite numbers in the Testing
# table — matches what pytest / vitest actually collect, so a count change
# can't silently go stale again.
step "Doc counts     (stale-reference gate)" \
  env ROOT="$ROOT" PYTEST="$PYTEST" NPM="$NPM" bash -c '
    set -e
    DOCS=()
    for f in README.md demo/README.md collectors/README.md cli/README.md; do
      [ -f "$ROOT/$f" ] && DOCS+=("$ROOT/$f")
    done

    # 1) Known-stale patterns must not reappear in shipped docs — including
    #    any hardcoded shields tests badge (the count is dynamic now, served
    #    from badges/tests.json).
    stale=$(grep -nE "\b(tests-478|2-minute|2 min|4 acts|12 tests|13 commands|~2\.5 min|shields\.io/badge/tests-[0-9]+)\b" "${DOCS[@]}" 2>/dev/null || true)
    if [ -n "$stale" ]; then
      echo "Stale numeric references in shipped docs:" >&2
      echo "$stale" >&2
      exit 1
    fi

    # 2) Actual counts: pytest collect-only (fast) + vitest list (collect-only).
    cd "$ROOT/backend"
    BE=$( "$PYTEST" --collect-only -q 2>/dev/null | grep -oE "[0-9]+ tests collected" | grep -oE "^[0-9]+" )
    cd "$ROOT/collectors"
    COL=$( "$PYTEST" --collect-only -q 2>/dev/null | grep -oE "[0-9]+ tests collected" | grep -oE "^[0-9]+" )
    cd "$ROOT/cli"
    CLI=$( "$PYTEST" --collect-only -q 2>/dev/null | grep -oE "[0-9]+ tests collected" | grep -oE "^[0-9]+" )
    cd "$ROOT/frontend"
    FE=$( "$NPM" exec -- vitest list 2>/dev/null | wc -l | tr -d " " )

    # Claims: the dynamic badge payload (badges/tests.json) + the per-suite
    # numbers in the README Testing table.
    BADGE=$(grep -oE "\"message\": *\"[0-9]+ passing\"" "$ROOT/badges/tests.json" | grep -oE "[0-9]+")
    BE_CLAIM=$(grep -oE "Backend pytest \| \*\*[0-9]+\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")
    COL_CLAIM=$(grep -oE "Collector pytest \| \*\*[0-9]+\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")
    CLI_CLAIM=$(grep -oE "CLI pytest \| \*\*[0-9]+\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")

    sum=$((BE + COL + CLI + FE))
    ok=1
    [ "$BADGE" = "$sum" ] || { echo "  badges/tests.json claims $BADGE, actual $sum (be=$BE col=$COL cli=$CLI fe=$FE)" >&2; ok=0; }
    [ "$BE_CLAIM" = "$BE" ] || { echo "  README backend claim $BE_CLAIM, actual $BE" >&2; ok=0; }
    [ "$COL_CLAIM" = "$COL" ] || { echo "  README collector claim $COL_CLAIM, actual $COL" >&2; ok=0; }
    [ "$CLI_CLAIM" = "$CLI" ] || { echo "  README CLI claim $CLI_CLAIM, actual $CLI" >&2; ok=0; }

    # Rules + commands — the other two dynamic badges: RULE_META and the Typer
    # registry, validated against badges/*.json and the README Highlights table.
    cd "$ROOT/backend"
    RULES_ACT=$( "$ROOT/.venv/bin/python" -c "from app.services.risk import RULE_META; print(len(RULE_META))" )
    cd "$ROOT"
    CMDS_ACT=$( "$ROOT/.venv/bin/python" -c "from outpost.main import app; print(len(app.registered_commands) + len(app.registered_groups))" )
    RULES_BADGE=$(grep -oE "\"message\": *\"[0-9]+\"" "$ROOT/badges/rules.json" | grep -oE "[0-9]+")
    CMDS_BADGE=$(grep -oE "\"message\": *\"[0-9]+\"" "$ROOT/badges/commands.json" | grep -oE "[0-9]+")
    RULES_CLAIM=$(grep -oE "\*\*[0-9]+ rules\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")
    CMDS_CLAIM=$(grep -oE "\*\*[0-9]+ commands\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")

    [ "$RULES_BADGE" = "$RULES_ACT" ] || { echo "  badges/rules.json claims $RULES_BADGE, actual $RULES_ACT" >&2; ok=0; }
    [ "$CMDS_BADGE" = "$CMDS_ACT" ] || { echo "  badges/commands.json claims $CMDS_BADGE, actual $CMDS_ACT" >&2; ok=0; }
    [ "$RULES_CLAIM" = "$RULES_ACT" ] || { echo "  README claims $RULES_CLAIM rules, actual $RULES_ACT" >&2; ok=0; }
    [ "$CMDS_CLAIM" = "$CMDS_ACT" ] || { echo "  README claims $CMDS_CLAIM commands, actual $CMDS_ACT" >&2; ok=0; }
    [ "$ok" = 1 ] || exit 1
    echo "  badge=$sum (be=$BE + col=$COL + cli=$CLI + fe=$FE), rules=$RULES_ACT, commands=$CMDS_ACT — badge payloads + README claims match"
  '

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
