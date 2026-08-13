#!/usr/bin/env bash
# verify.sh — OutPost full verification sweep in one command.
#
#   backend pytest  →  coverage gate (14/14 ATT&CK)  →  collector pytest
#   →  CLI pytest  →  frontend lint/tests/build  →  doc-count gate (fails
#     FAST on stale badge/README claims — before the slow collector gates)
#   →  collector soak baseline (cross-platform FP table)  →  collector
#     live-claim gate  →  sandbox provider gate (skips cleanly without a
#     provider key)  →  layout sweep (Playwright overflow gate)
#   →  post-deploy walk (fail-closed auth + TLS + agent heartbeat)
#   →  badge refresh (dry-run; PUBLISH_BADGES=1 also publishes)
#
# Prints a colored pass/fail summary per step and exits non-zero if any step
# fails. Environment overrides:
#   PYTEST   path to pytest        (default: $ROOT/.venv/bin/pytest)
#   NPM      npm binary            (default: npm)
#
# The soak baseline step boots an ISOLATED backend (temp DB, spare port
# 8013) and runs BOTH collector soaks (Windows Sysmon + Linux auditd) with
# --gate, asserting the modeled benign baselines fire ZERO alerts while the
# known-malicious stories still land their core detections — the collector
# FP baselines are part of CI, not just local measurements, and the table
# shows both platforms at a glance.
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

# Process-identity gate — no event-level process_name read may exist without
# an exe_path resolution (AST scan of detection/process_tree/baseline). Locks
# the identity-fallback invariant so a future rule can't silently regress to
# name-only matching that skips nameless rows.
step "Identity gate   (process_name → exe_path resolution)" \
  bash -c "'$ROOT/.venv/bin/python' '$ROOT/scripts/gate_proc_identity.py'"

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

# Doc-count gate — the shipped READMEs must not drift from the code they
# describe. Two checks: (1) known-stale numeric patterns (old test counts,
# the pre-trim "2-minute/4 acts" demo copy) never reappear; (2) every claimed
# count — the README badge total and the per-suite numbers in the Testing
# table — matches what pytest / vitest actually collect, so a count change
# can't silently go stale again. Positioned here (before the collector soak
# gates, layout sweep, and walk) so a stale badge/README claim fails the
# sweep FAST instead of after the ~3 min of slow gates — the same fast-fail
# the CI job's "Fast-fail on stale badges" step gives the push-run.
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
    FE_CLAIM=$(grep -oE "^\| Frontend \| \*\*[0-9]+\*\*" "$ROOT/README.md" | grep -oE "[0-9]+")

    sum=$((BE + COL + CLI + FE))
    ok=1
    [ "$BADGE" = "$sum" ] || { echo "  badges/tests.json claims $BADGE, actual $sum (be=$BE col=$COL cli=$CLI fe=$FE)" >&2; ok=0; }
    [ "$BE_CLAIM" = "$BE" ] || { echo "  README backend claim $BE_CLAIM, actual $BE" >&2; ok=0; }
    [ "$COL_CLAIM" = "$COL" ] || { echo "  README collector claim $COL_CLAIM, actual $COL" >&2; ok=0; }
    [ "$CLI_CLAIM" = "$CLI" ] || { echo "  README CLI claim $CLI_CLAIM, actual $CLI" >&2; ok=0; }
    [ "$FE_CLAIM" = "$FE" ] || { echo "  README frontend claim $FE_CLAIM, actual $FE" >&2; ok=0; }

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

    # Tactics — the fourth badge, fed from the Navigator layer output
    # (tactic_coverage reads the built layer, not RULE_META directly).
    COV_ACT=$( "$ROOT/.venv/bin/python" -c "from app.services.navigator import tactic_coverage; c, t = tactic_coverage(); print(f\"{c} {t}\")" )
    COV_C=${COV_ACT% *}
    COV_T=${COV_ACT#* }
    COV_BADGE=$(grep -oE "\"message\": *\"[0-9]+/[0-9]+\"" "$ROOT/badges/coverage.json" | grep -oE "[0-9]+/[0-9]+")
    COV_CLAIM=$(grep -oE "all [0-9]+ MITRE tactics" "$ROOT/README.md" | grep -oE "[0-9]+")

    [ "$RULES_BADGE" = "$RULES_ACT" ] || { echo "  badges/rules.json claims $RULES_BADGE, actual $RULES_ACT" >&2; ok=0; }
    [ "$CMDS_BADGE" = "$CMDS_ACT" ] || { echo "  badges/commands.json claims $CMDS_BADGE, actual $CMDS_ACT" >&2; ok=0; }
    [ "$RULES_CLAIM" = "$RULES_ACT" ] || { echo "  README claims $RULES_CLAIM rules, actual $RULES_ACT" >&2; ok=0; }
    [ "$CMDS_CLAIM" = "$CMDS_ACT" ] || { echo "  README claims $CMDS_CLAIM commands, actual $CMDS_ACT" >&2; ok=0; }
    [ "$COV_BADGE" = "$COV_C/$COV_T" ] || { echo "  badges/coverage.json claims $COV_BADGE, actual $COV_C/$COV_T" >&2; ok=0; }
    [ "$COV_CLAIM" = "$COV_C" ] || { echo "  README claims all $COV_CLAIM MITRE tactics, actual $COV_C" >&2; ok=0; }
    [ "$ok" = 1 ] || exit 1
    echo "  badge=$sum (be=$BE + col=$COL + cli=$CLI + fe=$FE), rules=$RULES_ACT, tactics=$COV_C/$COV_T, commands=$CMDS_ACT — badge payloads + README claims match"
  '

# Cross-platform collector soak baseline — the Windows (Sysmon) and Linux
# (auditd) soaks run with --gate against ONE isolated backend (temp DB,
# spare port) and print the FP/detection baseline as a compact table, so
# every sweep shows both platforms' numbers at a glance. Each soak's own
# gate assertions are preserved: a benign-baseline FP or a missed core
# detection fails the step (over-exemption guard).
step "Soak baseline   (cross-platform FP table)" \
  bash -c "'$ROOT/.venv/bin/python' '$ROOT/scripts/soak_baseline.py'"

# Collector live-claim gate — the one-line `--mode live` collector flow, end
# to end. Boots an isolated backend and runs the REAL collector_linux.py with
# no --run-id against a temp AUDIT_LOG feed (the documented root-less path):
# with an open webapp live session it must CLAIM it and stream real events
# into it (recon actors firing through the collector path, no rogue agent
# run), and with NO session open it must create its own agent-<host>-<date>
# run. The heartbeat must surface the host online as identity=collector with
# the auditd channel, and no unstamped collector event may survive.
step "Live-claim gate (collector live session claim)" \
  env ROOT="$ROOT" PYTHON="$ROOT/.venv/bin/python" bash -c '
    set -e
    LC_DB=$(mktemp --suffix=.db)
    LC_SAMPLES=$(mktemp -d)
    LC_PORT=8015
    LC_LOG=$(mktemp --suffix=.log)
    LC_PID=""
    cleanup() {
      [ -n "$LC_PID" ] && kill "$LC_PID" 2>/dev/null || true
      rm -f "$LC_DB" "$LC_LOG"
      rm -rf "$LC_SAMPLES"
    }
    trap cleanup EXIT
    DATABASE_PATH="$LC_DB" SAMPLES_DIR="$LC_SAMPLES" \
      "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$LC_PORT" >"$LC_LOG" 2>&1 &
    LC_PID=$!
    for _ in $(seq 1 30); do
      curl -sf "http://127.0.0.1:$LC_PORT/meta" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://127.0.0.1:$LC_PORT/meta" >/dev/null
    cd "$ROOT"
    "$PYTHON" scripts/gate_live_claim.py \
      --backend "http://127.0.0.1:$LC_PORT" --host "gate-host" --db "$LC_DB"
  '

# Sandbox provider gate — end-to-end validation of the live detonation
# adapter (Any.Run / Triage / Joe) against an isolated backend. With no
# provider key configured (stock installs, CI) the script SKIPs cleanly and
# the step passes in seconds; with a key set it runs a REAL detonation —
# upload → detonate → poll → assert events landed — taking up to --max-wait.
step "Sandbox provider (live detonation gate)" \
  env ROOT="$ROOT" PYTHON="$ROOT/.venv/bin/python" bash -c '
    set -e
    SBX_DB=$(mktemp --suffix=.db)
    SBX_SAMPLES=$(mktemp -d)
    SBX_PORT=8014
    SBX_LOG=$(mktemp --suffix=.log)
    SBX_PID=""
    cleanup() {
      [ -n "$SBX_PID" ] && kill "$SBX_PID" 2>/dev/null || true
      rm -f "$SBX_DB" "$SBX_LOG"
      rm -rf "$SBX_SAMPLES"
    }
    trap cleanup EXIT
    DATABASE_PATH="$SBX_DB" SAMPLES_DIR="$SBX_SAMPLES" \
      "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$SBX_PORT" >"$SBX_LOG" 2>&1 &
    SBX_PID=$!
    for _ in $(seq 1 30); do
      curl -sf "http://127.0.0.1:$SBX_PORT/meta" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://127.0.0.1:$SBX_PORT/meta" >/dev/null
    cd "$ROOT"
    "$PYTHON" scripts/validate_sandbox_provider.py --backend "http://127.0.0.1:$SBX_PORT"
  '

# Layout regression gate — the min-width bug class (a grid/flex item that
# refuses to shrink pushes the page wider than the viewport) caught by a real
# browser before it ships. Boots an ISOLATED backend (temp DB, spare ports
# 8013/5176), seeds the campaign pair so the data-heavy pages (run detail,
# History charts, campaigns) actually render, then drives every route at
# several desktop widths with Playwright and fails on any horizontal overflow
# or page that fails to render content. Skips with a note when Playwright
# isn't installed locally (CI installs it — see .github/workflows/ci.yml).
step "Layout sweep    (Playwright UI gates: overflow + triage + live monitor)" \
  env ROOT="$ROOT" PYTHON="$ROOT/.venv/bin/python" NPM="$NPM" bash -c '
    set -e
    if [ ! -d "$ROOT/demo/node_modules/playwright" ]; then
      echo "  Playwright not installed (cd demo && npm i) — SKIPPING layout sweep; CI enforces it" >&2
      exit 0
    fi
    SWEEP_DB=$(mktemp --suffix=.db)
    SWEEP_SAMPLES=$(mktemp -d)
    SWEEP_PORT=8013
    SWEEP_WEB=5176
    SWEEP_LOG=$(mktemp --suffix=.log)
    SWEEP_WEBLOG=$(mktemp --suffix=.log)
    SWEEP_PID=""
    WEB_PID=""
    cleanup() {
      [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
      [ -n "$SWEEP_PID" ] && kill "$SWEEP_PID" 2>/dev/null || true
      rm -f "$SWEEP_DB" "$SWEEP_LOG" "$SWEEP_WEBLOG"
      rm -rf "$SWEEP_SAMPLES"
    }
    trap cleanup EXIT
    DATABASE_PATH="$SWEEP_DB" SAMPLES_DIR="$SWEEP_SAMPLES" \
      CORS_ORIGINS="http://localhost:$SWEEP_WEB" \
      "$PYTHON" -m uvicorn app.main:app --host 127.0.0.1 --port "$SWEEP_PORT" >"$SWEEP_LOG" 2>&1 &
    SWEEP_PID=$!
    for _ in $(seq 1 30); do
      curl -sf "http://127.0.0.1:$SWEEP_PORT/meta" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://127.0.0.1:$SWEEP_PORT/meta" >/dev/null
    # Seed the campaign pair (real detection alerts) so every data-heavy page
    # renders with content — an empty page can never overflow. The campaign
    # runs are source='seed' (synthetic, hidden by default), so also stream a
    # live-sourced run through the real API: default views (History charts,
    # Findings, Event Log) then lay out real data.
    cd "$ROOT/backend"
    DATABASE_PATH="$SWEEP_DB" "$PYTHON" -m app.seed_campaign >/dev/null 2>&1
    "$PYTHON" "$ROOT/scripts/seed_sweep_live.py" --api "http://127.0.0.1:$SWEEP_PORT" >/dev/null
    # Frontend dev server pointed at the isolated backend (VITE_API_URL env
    # beats .env.local per Vite precedence).
    cd "$ROOT/frontend"
    VITE_API_URL="http://127.0.0.1:$SWEEP_PORT" \
      "$NPM" run dev -- --port "$SWEEP_WEB" --strictPort >"$SWEEP_WEBLOG" 2>&1 &
    WEB_PID=$!
    for _ in $(seq 1 45); do
      curl -sf "http://localhost:$SWEEP_WEB" >/dev/null 2>&1 && break
      sleep 1
    done
    curl -sf "http://localhost:$SWEEP_WEB" >/dev/null
    cd "$ROOT/demo"
    node layout-sweep.mjs --web "http://localhost:$SWEEP_WEB" --api "http://127.0.0.1:$SWEEP_PORT"
    # Behavioral gate on the SAME stack: the alert-triage state machine
    # (open→acked→resolved→open + bulk) driven in a real browser against the
    # seeded backend — closes the "no browser test for the lifecycle" gap.
    node e2e-alert-lifecycle.mjs --web "http://localhost:$SWEEP_WEB" --api "http://127.0.0.1:$SWEEP_PORT"
    # Live-monitor gate on the SAME stack: the auto-detected-host detonation
    # flow with SSE-driven live toasts — proves live monitoring in a real
    # browser on every push, not just in the demo footage.
    node e2e-live-monitor.mjs --web "http://localhost:$SWEEP_WEB" --api "http://127.0.0.1:$SWEEP_PORT"
  '

# Post-deploy checklist walk — fail-closed auth + TLS + the four
# deploy/README.md assertions, live and without Docker. Boots an isolated
# fail-closed backend (OUTPOST_AUTH_REQUIRED=1, admin + agent token) behind
# a self-signed TLS proxy mirroring the Caddyfile, then asserts: TLS /health,
# 401-without-token / 200-with-token, login → /auth/me, and the
# OUTPOST_AGENT_TOKEN heartbeat flow (401 bare → 200 with token → host
# online → 403 outside telemetry). Catches regressions in the exact
# production shape compose deploys.
step "Post-deploy walk (fail-closed auth + TLS)" \
  bash -c "cd '$ROOT' && '$ROOT/.venv/bin/python' scripts/post_deploy_walk.py"

# Badge refresh — recompute the dynamic badge payloads with the shared
# refresh-badges.sh. Default is --check: the sweep FAILS if any badge is
# stale (counts moved but badges/*.json didn't), gating without committing.
# PUBLISH_BADGES=1 bash verify.sh instead commits + pushes them (needs a git
# checkout with push rights — CI does this automatically after the sweep).
step "Badge refresh   (refresh-badges.sh)" \
  env ROOT="$ROOT" PUBLISH="${PUBLISH_BADGES:-0}" bash -c '
    cd "$ROOT"
    if [ "$PUBLISH" = "1" ]; then
      if [ ! -d "$ROOT/.git" ]; then
        echo "PUBLISH_BADGES=1 needs a git checkout (this tree has no .git) — running --check instead" >&2
        bash scripts/refresh-badges.sh --check
      else
        bash scripts/refresh-badges.sh --commit
      fi
    else
      bash scripts/refresh-badges.sh --check
    fi
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
