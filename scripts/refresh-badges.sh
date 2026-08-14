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
#   bash scripts/refresh-badges.sh --check  # gate: exit 1 if any badge is stale
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
T_BADGE=$(printf '{"schemaVersion":1,"label":"tests","message":"%s passing","color":"2ea44f"}' "$SUM")
R_BADGE=$(printf '{"schemaVersion":1,"label":"rules","message":"%s","color":"D9A441"}' "$RULES")
CM_BADGE=$(printf '{"schemaVersion":1,"label":"commands","message":"%s","color":"3FA796"}' "$CMDS")
CV_BADGE=$(printf '{"schemaVersion":1,"label":"tactics","message":"%s","color":"3D8BFD"}' "$COV")
echo "badges computed: tests=$SUM (be=$BE + col=$COL + cli=$CLI + fe=$FE), rules=$RULES, tactics=$COV, commands=$CMDS"

# -- Image sizes (the docs/17 baseline stamp) -------------------------------
# Measured from the shipped images when docker + the :measure images exist
# (the weekly refresh job builds them before this script runs). Skipped
# gracefully otherwise — the --check gate still enforces docs/17-vs-JSON
# consistency from committed files, no docker needed.
SIZE_JSON="$ROOT/badges/image-sizes.json"
DOCS_STAMP="$ROOT/docs/17-CI-GATES.md"
WEB_MB=""
BACKEND_MB=""
if command -v docker >/dev/null 2>&1 \
  && docker image inspect outpost-web:measure >/dev/null 2>&1 \
  && docker image inspect outpost-backend:measure >/dev/null 2>&1; then
  WEB_MB=$(( $(docker image inspect --format '{{.Size}}' outpost-web:measure) / 1024 / 1024 ))
  BACKEND_MB=$(( $(docker image inspect --format '{{.Size}}' outpost-backend:measure) / 1024 / 1024 ))
  echo "image sizes measured: web=${WEB_MB} MB, backend=${BACKEND_MB} MB"
else
  echo "image sizes not measured (docker + :measure images unavailable)"
fi

json_get() { # json_get <file> <key>
  "$PY" -c "import json,sys; print(json.load(open('$1'))['$2'])" 2>/dev/null || true
}

size_commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
size_date="$(date -u +%Y-%m-%d)"

# Rebuild the stamp line exactly as it must appear in docs/17.
stamp_line() {
  if [[ -n "$WEB_MB" ]]; then
    echo "> **Last measured:** web ${WEB_MB} MB / backend ${BACKEND_MB} MB — badge job @ \`${size_commit}\` (${size_date})."
  else
    echo ""
  fi
}

# Rewrite the docs/17 stamp (regex-sub if present, else insert after the
# baseline table so a fresh checkout gets the stamp on the first run).
write_size_stamp() {
  [[ -n "$WEB_MB" ]] || return 0
  local stamp; stamp=$(stamp_line)
  "$PY" "$stamp" <<'PYEOF'
import re, sys
stamp = sys.argv[1]
path = "docs/17-CI-GATES.md"
text = open(path).read()
pattern = re.compile(r"^> \*\*Last measured:\*\*.*$", re.M)
if pattern.search(text):
    text = pattern.sub(lambda m: stamp, text)
else:
    anchor = "| `outpost-backend:ci` (python:3.12-slim + pip deps + app) |"
    idx = text.find(anchor)
    if idx == -1:
        sys.exit(2)
    nl = text.index("\n", idx)
    text = text[: nl + 1] + "\n" + stamp + "\n" + text[nl + 1 :]
open(path, "w").write(text)
PYEOF
}

MODE="${1:-}"
case "$MODE" in
  --check)
    stale=0
    for spec in tests:T_BADGE rules:R_BADGE commands:CM_BADGE coverage:CV_BADGE; do
      name=${spec%%:*}
      var=${spec#*:}
      want=${!var}
      file="$ROOT/badges/$name.json"
      if [ ! -f "$file" ] || [ "$(cat "$file")" != "$want" ]; then
        echo "  stale: badges/$name.json" >&2
        diff -u "$file" <(printf '%s\n' "$want") 2>&1 | sed 's/^/    /' || true
        stale=1
      fi
    done
    # Size stamp consistency: the committed image-sizes.json must match the
    # docs/17 'Last measured' stamp, and (when measurable here) the live
    # measurement must match the committed JSON — so the baseline table can't
    # silently drift from the data file or from reality.
    if [ -f "$SIZE_JSON" ]; then
      W=$(json_get "$SIZE_JSON" web_mb)
      B=$(json_get "$SIZE_JSON" backend_mb)
      grep -q '^> \*\*Last measured:\*\*' "$DOCS_STAMP" || { echo "  stale: docs/17 has no 'Last measured' stamp" >&2; stale=1; }
      if [[ -n "$W" && -n "$B" ]] && ! grep -q "web ${W} MB / backend ${B} MB" "$DOCS_STAMP"; then
        echo "  stale: docs/17 size stamp != badges/image-sizes.json (web ${W} / backend ${B})" >&2
        stale=1
      fi
      if [[ -n "$WEB_MB" ]] && { [ "$WEB_MB" != "$W" ] || [ "$BACKEND_MB" != "$B" ]; }; then
        echo "  stale: measured (web ${WEB_MB} / backend ${BACKEND_MB}) != committed image-sizes.json (web ${W} / backend ${B})" >&2
        stale=1
      fi
    else
      echo "  stale: badges/image-sizes.json missing (no size stamp data)" >&2
      stale=1
    fi
    if [ "$stale" = 1 ]; then
      echo "STALE — run 'bash scripts/refresh-badges.sh --commit' (or PUBLISH_BADGES=1 bash verify.sh) to publish" >&2
      exit 1
    fi
    echo "badges fresh — all 4 payloads + the size stamp match the committed files"
    exit 0
    ;;
  --commit) ;;
  "")
    echo "(dry-run — pass --check to gate or --commit to publish changes)"
    exit 0
    ;;
  *)
    echo "unknown mode: $MODE (use --check or --commit)" >&2
    exit 2
    ;;
esac

printf '%s\n' "$T_BADGE" > "$ROOT/badges/tests.json"
printf '%s\n' "$R_BADGE" > "$ROOT/badges/rules.json"
printf '%s\n' "$CM_BADGE" > "$ROOT/badges/commands.json"
printf '%s\n' "$CV_BADGE" > "$ROOT/badges/coverage.json"
if [[ -n "$WEB_MB" ]]; then
  printf '{"web_mb":%s,"backend_mb":%s,"commit":"%s","date":"%s"}\n' \
    "$WEB_MB" "$BACKEND_MB" "$size_commit" "$size_date" > "$SIZE_JSON"
  write_size_stamp || { echo "  could not rewrite the docs/17 size stamp (no anchor)" >&2; exit 2; }
fi

if git diff --quiet -- badges/ docs/17-CI-GATES.md; then
  echo "badges unchanged — nothing to commit"
  exit 0
fi
SIZE_NOTE=""
[[ -n "$WEB_MB" ]] && SIZE_NOTE=" — sizes web ${WEB_MB} MB / backend ${BACKEND_MB} MB"
git config user.name "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
git add badges/ docs/17-CI-GATES.md
git commit -m "chore: refresh badges (tests $SUM, rules $RULES, tactics $COV, commands $CMDS)$SIZE_NOTE"
git pull --rebase origin main 2>/dev/null || true
git push
echo "badges pushed to main"
