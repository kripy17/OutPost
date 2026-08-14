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
AIRGAP_MB=""
if command -v docker >/dev/null 2>&1 \
  && docker image inspect outpost-web:measure >/dev/null 2>&1 \
  && docker image inspect outpost-backend:measure >/dev/null 2>&1 \
  && docker image inspect outpost-airgap:measure >/dev/null 2>&1; then
  WEB_MB=$(( $(docker image inspect --format '{{.Size}}' outpost-web:measure) / 1024 / 1024 ))
  BACKEND_MB=$(( $(docker image inspect --format '{{.Size}}' outpost-backend:measure) / 1024 / 1024 ))
  AIRGAP_MB=$(( $(docker image inspect --format '{{.Size}}' outpost-airgap:measure) / 1024 / 1024 ))
  echo "image sizes measured: web=${WEB_MB} MB, backend=${BACKEND_MB} MB, airgap=${AIRGAP_MB} MB"
else
  echo "image sizes not measured (docker + :measure images unavailable)"
fi

json_get() { # json_get <file> <key>
  "$PY" -c "import json,sys; print(json.load(open('$1'))['$2'])" 2>/dev/null || true
}

size_commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
size_date="$(date -u +%Y-%m-%d)"

# Rebuild a per-image stamp line exactly as it must appear in docs/17. One
# line per image (not one combined line) so the gate can require a stamp for
# EVERY table row — a fourth image can't be documented without its trend
# data.
stamp_line() { # stamp_line <image> <measured_mb>
  echo "> **Last measured:** \`$1\` $2 MB — badge job @ \`${size_commit}\` (${size_date})."
}

# Rewrite or insert the stamp line for ONE image (regex-sub if present, else
# insert after the last stamp line — or after the baseline table on a fresh
# checkout). Images the refresh doesn't measure are left untouched, so a
# newer image's stamp survives a refresh that only measures web/backend/
# airgap.
#   `python -` reads the script from stdin (the heredoc) with args as
#   argv[1..] — `python "$stamp"` would treat the stamp as a script FILE.
ensure_size_stamp() { # ensure_size_stamp <image> <measured_mb>
  local img=$1 mb=$2
  [[ -n "$mb" ]] || return 0
  local stamp; stamp=$(stamp_line "$img" "$mb")
  "$PY" - "$img" "$stamp" <<'PYEOF'
import re, sys
img, stamp = sys.argv[1], sys.argv[2]
path = "docs/17-CI-GATES.md"
text = open(path).read()
pat = re.compile(r"^> \*\*Last measured:\*\* `" + re.escape(img) + r"`\s+\d+ MB.*$", re.M)
if pat.search(text):
    text = pat.sub(lambda m: stamp, text)
else:
    stamps = list(re.finditer(r"^> \*\*Last measured:.*$", text, re.M))
    if stamps:
        nl = text.index("\n", stamps[-1].end())
    else:
        anchor = "| `outpost-airgap-ci`"
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
    # --check is the gate tier (badge fast-fail): every drift prints the exact
    # corrected payload/stamp/JSON line so the failure is self-explaining —
    # copy-paste the "→ fix:" line and the sweep goes green.
    for spec in tests:T_BADGE rules:R_BADGE commands:CM_BADGE coverage:CV_BADGE; do
      name=${spec%%:*}
      var=${spec#*:}
      want=${!var}
      file="$ROOT/badges/$name.json"
      if [ ! -f "$file" ] || [ "$(cat "$file")" != "$want" ]; then
        echo "  stale: badges/$name.json" >&2
        echo "  → fix: write the payload below to badges/$name.json:" >&2
        echo "        $want" >&2
        stale=1
      fi
    done
    # Size stamp consistency: the committed image-sizes.json must match the
    # docs/17 'Last measured' stamp, and (when measurable here) the live
    # measurement must match the committed JSON — so the baseline table can't
    # silently drift from the data file or from reality.
    if [ -f "$SIZE_JSON" ]; then
      # Committed values (read once — the measured-vs-committed branch needs
      # all three, not just the per-image loop value).
      W=$(json_get "$SIZE_JSON" web_mb)
      B=$(json_get "$SIZE_JSON" backend_mb)
      A=$(json_get "$SIZE_JSON" airgap_mb)
      J_COMMIT=$(json_get "$SIZE_JSON" commit)
      J_DATE=$(json_get "$SIZE_JSON" date)
      # Every measured image needs its own stamp line carrying the
      # committed value (per-image lines — one combined line is no longer
      # accepted, so a table row can never be documented without trend data).
      for pair in "outpost-web:ci:web_mb" "outpost-backend:ci:backend_mb" "outpost-airgap-ci:airgap_mb"; do
        img=${pair%%:*}
        rest=${pair#*:}
        key=${rest%%:*}
        val=$(json_get "$SIZE_JSON" "$key")
        if [[ -n "$val" ]] && ! grep -q "^> \*\*Last measured:\*\* \`${img}\` ${val} MB" "$DOCS_STAMP"; then
          echo "  stale: docs/17 lacks the 'Last measured' stamp for ${img} (${val} MB)" >&2
          echo "  → fix: add the line below to docs/17-CI-GATES.md:" >&2
          echo "        > **Last measured:** \`${img}\` ${val} MB — badge job @ \`${J_COMMIT}\` (${J_DATE})." >&2
          stale=1
        fi
      done
      if [[ -n "$WEB_MB" ]] && { [ "$WEB_MB" != "$W" ] || [ "$BACKEND_MB" != "$B" ] || [ "$AIRGAP_MB" != "$A" ]; }; then
        echo "  stale: measured (web ${WEB_MB} / backend ${BACKEND_MB} / airgap ${AIRGAP_MB}) != committed image-sizes.json (web ${W} / backend ${B} / airgap ${A})" >&2
        echo "  → fix: rewrite badges/image-sizes.json with the measured values:" >&2
        echo "        {\"web_mb\":${WEB_MB},\"backend_mb\":${BACKEND_MB},\"airgap_mb\":${AIRGAP_MB},\"commit\":\"${size_commit}\",\"date\":\"${size_date}\"}" >&2
        stale=1
      fi
    else
      echo "  stale: badges/image-sizes.json missing (no size stamp data)" >&2
      echo "  → fix: restore badges/image-sizes.json (or build the :measure images and run 'bash scripts/refresh-badges.sh --commit' to regenerate it)" >&2
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
  printf '{"web_mb":%s,"backend_mb":%s,"airgap_mb":%s,"commit":"%s","date":"%s"}\n' \
    "$WEB_MB" "$BACKEND_MB" "$AIRGAP_MB" "$size_commit" "$size_date" > "$SIZE_JSON"
  ensure_size_stamp outpost-web:ci "$WEB_MB" || { echo "  could not write the docs/17 stamp for outpost-web:ci" >&2; exit 2; }
  ensure_size_stamp outpost-backend:ci "$BACKEND_MB" || { echo "  could not write the docs/17 stamp for outpost-backend:ci" >&2; exit 2; }
  ensure_size_stamp outpost-airgap-ci "$AIRGAP_MB" || { echo "  could not write the docs/17 stamp for outpost-airgap-ci" >&2; exit 2; }
fi

if git diff --quiet -- badges/ docs/17-CI-GATES.md; then
  echo "badges unchanged — nothing to commit"
  exit 0
fi
SIZE_NOTE=""
[[ -n "$WEB_MB" ]] && SIZE_NOTE=" — sizes web ${WEB_MB} MB / backend ${BACKEND_MB} MB / airgap ${AIRGAP_MB} MB"
TITLE="chore: refresh badges (tests $SUM, rules $RULES, tactics $COV, commands $CMDS)$SIZE_NOTE"
git config user.name "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"

# main is branch-protected: the three required status checks must pass on
# anything that lands there, so a locally-created bot commit can never push
# directly (GH006 — proven by the dispatch run). Land via a PR with
# auto-merge armed — the documented mechanism for main — so badges/docs
# changes get the same gate as everything else.
BRANCH="chore/badges-$(date -u +%Y%m%d-%H%M%S)"
git checkout -b "$BRANCH"
git add badges/ docs/17-CI-GATES.md
git commit -m "$TITLE"
git pull --rebase origin main 2>/dev/null || true
if ! git push -u origin "$BRANCH"; then
  echo "  push failed — branch protection blocks direct main pushes; this must go via PR" >&2
  exit 1
fi
if command -v gh >/dev/null 2>&1; then
  if ! gh pr create --base main --head "$BRANCH" --title "$TITLE" \
      --body "Auto-generated by the refresh-badges job (weekly schedule / workflow_dispatch). Merges itself once the required checks pass." \
      >/dev/null; then
    echo "  gh pr create failed — the repo setting 'Allow GitHub Actions to create" >&2
    echo "  and approve pull requests' (Settings → Actions → General → Workflow" >&2
    echo "  permissions) must be ON for the bot to land via PR. The branch is pushed" >&2
    echo "  at '$BRANCH' — open the PR manually, or flip the setting and re-dispatch." >&2
    exit 1
  fi
  gh pr merge --auto --squash
  echo "badges PR opened with auto-merge armed — merges when the required checks pass"
else
  echo "  gh not available — branch pushed at '$BRANCH'; open the PR manually" >&2
  exit 1
fi
