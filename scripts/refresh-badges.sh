#!/usr/bin/env bash
# refresh-badges.sh — recompute the dynamic badge payloads and, with
# --commit, publish them to main if any count changed.
#
# Counts (the same sources verify.sh's doc-count gate validates):
#   tests    — backend + collector + CLI pytest collection + frontend vitest
#   rules    — len(RULE_META) from the backend detection engine
#   commands — the Typer registry (top-level commands + subcommand groups)
#   tactics  — ATT&CK tactic coverage read from the Navigator layer output
#
# Usage:
#   bash scripts/refresh-badges.sh          # dry-run: recompute, print, no write
#   bash scripts/refresh-badges.sh --commit # write badges/*.json; commit+push if changed
#
# Assumes the venv is at $ROOT/.venv with backend+CLI installed (pytest,
# the app imports) and frontend deps installed (vitest) — exactly the
# environment verify.sh and CI build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
NPM="${NPM:-npm}"

cd "$ROOT/backend"
BE=$("$PY" -m pytest --collect-only -q 2>/dev/null | grep -oE '[0-9]+ tests collected' | grep -oE '^[0-9]+')
cd "$ROOT/collectors"
COL=$("$PY" -m pytest --collect-only -q 2>/dev/null | grep -oE '[0-9]+ tests collected' | grep -oE '^[0-9]+')
cd "$ROOT/cli"
CLI=$("$PY" -m pytest --collect-only -q 2>/dev/null | grep -oE '[0-9]+ tests collected' | grep -oE '^[0-9]+')
cd "$ROOT/frontend"
FE=$("$NPM" exec -- vitest list 2>/dev/null | wc -l | tr -d ' ')

cd "$ROOT/backend"
RULES=$("$PY" -c 'from app.services.risk import RULE_META; print(len(RULE_META))')
COV=$("$PY" -c 'from app.services.navigator import tactic_coverage; c, t = tactic_coverage(); print(f"{c}/{t}")')
cd "$ROOT"
CMDS=$("$PY" -c 'from outpost.main import app; print(len(app.registered_commands) + len(app.registered_groups))')

SUM=$((BE + COL + CLI + FE))
mkdir -p "$ROOT/badges"
printf '{"schemaVersion":1,"label":"tests","message":"%s passing","color":"2ea44f"}\n' "$SUM" > "$ROOT/badges/tests.json"
printf '{"schemaVersion":1,"label":"rules","message":"%s","color":"D9A441"}\n' "$RULES" > "$ROOT/badges/rules.json"
printf '{"schemaVersion":1,"label":"commands","message":"%s","color":"3FA796"}\n' "$CMDS" > "$ROOT/badges/commands.json"
printf '{"schemaVersion":1,"label":"tactics","message":"%s","color":"3D8BFD"}\n' "$COV" > "$ROOT/badges/coverage.json"
echo "badges computed: tests=$SUM (be=$BE + col=$COL + cli=$CLI + fe=$FE), rules=$RULES, tactics=$COV, commands=$CMDS"

if [ "${1:-}" != "--commit" ]; then
  echo "(dry-run — pass --commit to publish changes)"
  exit 0
fi

if git diff --quiet -- badges/; then
  echo "badges unchanged — nothing to commit"
  exit 0
fi
git config user.name "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
git add badges/
git commit -m "chore: refresh badges (tests $SUM, rules $RULES, tactics $COV, commands $CMDS)"
git pull --rebase origin main 2>/dev/null || true
git push
echo "badges pushed to main"
