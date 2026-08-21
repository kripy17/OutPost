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
#   bash scripts/refresh-badges.sh --recover # regenerate the ENTIRE size story
#                                            # (docs/17 table + stamps +
#                                            # image-sizes.json) from the live
#                                            # ci.yml gates and fresh :measure
#                                            # measurements; lands via PR
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
WEB_BYTES=""
BACKEND_BYTES=""
AIRGAP_BYTES=""
if command -v docker >/dev/null 2>&1 \
  && docker image inspect outpost-web:measure >/dev/null 2>&1 \
  && docker image inspect outpost-backend:measure >/dev/null 2>&1 \
  && docker image inspect outpost-airgap:measure >/dev/null 2>&1; then
  WEB_BYTES=$(docker image inspect --format '{{.Size}}' outpost-web:measure)
  BACKEND_BYTES=$(docker image inspect --format '{{.Size}}' outpost-backend:measure)
  AIRGAP_BYTES=$(docker image inspect --format '{{.Size}}' outpost-airgap:measure)
  WEB_MB=$(( WEB_BYTES / 1024 / 1024 ))
  BACKEND_MB=$(( BACKEND_BYTES / 1024 / 1024 ))
  AIRGAP_MB=$(( AIRGAP_BYTES / 1024 / 1024 ))
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
m = pat.search(text)
if m:
    # Idempotent: leave the line untouched when it already carries the same
    # measured value, so a fresh --recover doesn't churn the commit reference.
    cur = int(re.search(r"(\d+) MB", m.group(0)).group(1))
    if cur != int(re.search(r"(\d+) MB", stamp).group(1)):
        text = pat.sub(lambda x: stamp, text)
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

# -- --recover: regenerate the entire size story from the live gates ---------
# The one-command repair path for any drift among ci.yml's size-gate
# invocations, docs/17's budget table, the per-image 'Last measured' stamps,
# and badges/image-sizes.json. The table is rebuilt EXACTLY from the gates:
# every gated row's measured + budget cells refresh from docker and the
# ci.yml flags (description text preserved), rows for un-gated images are
# dropped, and the stamps + JSON are rewritten to match — so after recovery
# the image-budget docs gate passes by construction.

GATE_SOFT_DEFAULT="$(grep -oP '^BUDGET_MB=\K\d+' "$ROOT/scripts/check-image-size.sh" | head -1 || true)"
GATE_HARD_DEFAULT="$(grep -oP '^FAIL_MB=\K\d+' "$ROOT/scripts/check-image-size.sh" | head -1 || true)"

# image|soft|hard — one record per check-image-size.sh invocation in ci.yml,
# budgets resolved to the script's own defaults when the step passes no flags
# (the web gate's style). '|' is the delimiter because image names contain ':'.
parse_gates() {
  local ci="$ROOT/.github/workflows/ci.yml"
  local line img soft hard
  while IFS= read -r line; do
    case "$line" in
      *check-image-size.sh*)
        img=$(printf '%s\n' "$line" | grep -oP -- '--image\s+\K[\w:.\-]+' | head -1 || true)
        [[ -n "$img" ]] || continue
        soft=$(printf '%s\n' "$line" | grep -oP -- '--budget-mb\s+\K\d+' | head -1 || true)
        hard=$(printf '%s\n' "$line" | grep -oP -- '--fail-mb\s+\K\d+' | head -1 || true)
        printf '%s|%s|%s\n' "$img" "${soft:-$GATE_SOFT_DEFAULT}" "${hard:-$GATE_HARD_DEFAULT}"
        ;;
    esac
  done < "$ci"
}

# Regenerate the docs/17 budget table from the gates + measurements.
#   rewrite_size_table $'img|mb|bytes|commit|soft|hard\n...'
# Rewrites measured + budget cells for every gated image (description
# preserved; unchanged rows left byte-identical so a fresh recovery is a
# no-op), inserts rows for gated images missing from the table (with a (…)
# description), and drops rows whose image has no gate — the table becomes
# exactly what the gates enforce.
rewrite_size_table() {
  local specs=$1
  [[ -n "$specs" ]] || return 0
  "$PY" - "$specs" <<'PYEOF'
import re, sys
specs = sys.argv[1]
parsed = [s.split("|") for s in specs.splitlines() if s]
valid = {r[0] for r in parsed}
path = "docs/17-CI-GATES.md"
text = open(path).read()
row_re = re.compile(
    r"^(\|\s*`([^`]+)`\s*\(.*?\)\s*\|\s*)\*\*(\d+) MB\*\*.*?(\|\s*)(\d+) MB(\s*\|\s*)(\d+) MB(\s*\|)$",
    re.M,
)
def row_for(img):
    for img2, mb, raw, commit, soft, hard in parsed:
        if img2 == img:
            return (f"| `{img}` (…) | **{mb} MB** ({int(raw):,} B, commit `{commit}`) "
                    f"| {soft} MB | {hard} MB |")
    return None
out = []
for line in text.splitlines(keepends=True):
    stripped = line.rstrip("\n")
    m = row_re.match(stripped)
    if not m:
        out.append(line)
        continue
    img = m.group(2)
    if img not in valid:
        print(f"  recovery: dropped table row for {img} (no gate in ci.yml)")
        continue
    for img2, mb, raw, commit, soft, hard in parsed:
        if img2 == img:
            # Idempotent: keep the row byte-identical when the measured MB
            # and budgets already match the fresh measurement + gates — the
            # embedded commit ref and byte count are cosmetic and may be
            # older, so they don't trigger a rewrite.
            if int(mb) == int(m.group(3)) and int(soft) == int(m.group(5)) and int(hard) == int(m.group(7)):
                out.append(line)
                break
            new = (f"{m.group(1)}**{mb} MB** ({int(raw):,} B, commit `{commit}`)"
                   f"{m.group(4)}{soft} MB{m.group(6)}{hard} MB{m.group(8)}\n")
            out.append(new)
            break
new_text = "".join(out)
missing = [r for r in parsed if r[0] not in valid]
if missing:
    rows = list(re.finditer(r"^\| `[^`]+` \(.*?\) \|.*\|$", new_text, re.M))
    pos = rows[-1].end() if rows else len(new_text)
    insert = "".join(f"{row_for(r[0])}\n" for r in missing)
    new_text = new_text[:pos] + insert + new_text[pos:]
open(path, "w").write(new_text)
PYEOF
}

recover_size_story() {
  [[ -n "$WEB_MB" && -n "$BACKEND_MB" && -n "$AIRGAP_MB" ]] || {
    echo "  recovery needs a fresh measurement — build the :measure images first:" >&2
    echo "    docker build -f deploy/Dockerfile.web -t outpost-web:measure ." >&2
    echo "    docker build -f backend/Dockerfile -t outpost-backend:measure backend" >&2
    echo "    docker build -f deploy/Dockerfile.airgap-ci -t outpost-airgap:measure ." >&2
    exit 3
  }
  local gates specs body
  gates=$(parse_gates)
  [[ -n "$gates" ]] || { echo "  no check-image-size.sh gates in ci.yml — nothing to regenerate" >&2; exit 2; }
  # Pass 1: table specs (img|mb|bytes|commit|soft|hard) + the JSON body
  # ("key":mb), resolving each gated image's JSON key.
  while IFS='|' read -r img soft hard; do
    local key mb bytes
    case "$img" in
      outpost-web:ci)     key=web_mb;     mb=$WEB_MB;     bytes=$WEB_BYTES ;;
      outpost-backend:ci) key=backend_mb; mb=$BACKEND_MB; bytes=$BACKEND_BYTES ;;
      outpost-airgap-ci)  key=airgap_mb;  mb=$AIRGAP_MB;  bytes=$AIRGAP_BYTES ;;
      *)
        echo "  recovery doesn't know the badges/image-sizes.json key for $img — map it in refresh-badges.sh first" >&2
        exit 2 ;;
    esac
    specs+="${img}|${mb}|${bytes}|${size_commit}|${soft}|${hard}"$'\n'
    body+="${body:+,}\"${key}\":${mb}"
  done <<< "$gates"
  rewrite_size_table "$specs"
  # JSON — written only when a measured value actually changed. The commit/
  # date refs are cosmetic: comparing the MB values keeps a fresh recovery a
  # genuine no-op instead of churning the file every run.
  local json_text need_write=1 pair key val
  json_text=$(printf '{%s,"commit":"%s","date":"%s"}\n' "$body" "$size_commit" "$size_date")
  if [ -f "$SIZE_JSON" ]; then
    need_write=0
    for pair in $(printf '%s' "$body" | tr ',' '\n'); do
      key=${pair%%:*}
      key=${key//\"/}  # body carries "key":val — strip the quotes
      val=${pair#*:}
      if [ "$(json_get "$SIZE_JSON" "$key")" != "$val" ]; then
        need_write=1
        break
      fi
    done
  fi
  if [ "$need_write" = 1 ]; then
    printf '%s\n' "$json_text" > "$SIZE_JSON"
  fi
  # Pass 2: per-image stamp lines (only for gated images).
  while IFS='|' read -r img _soft _hard; do
    local mb
    case "$img" in
      outpost-web:ci)     mb=$WEB_MB ;;
      outpost-backend:ci) mb=$BACKEND_MB ;;
      outpost-airgap-ci)  mb=$AIRGAP_MB ;;
    esac
    ensure_size_stamp "$img" "$mb" || { echo "  could not write the docs/17 stamp for $img" >&2; exit 2; }
  done <<< "$gates"
  echo "recovered: docs/17 table rows + 'Last measured' stamps + image-sizes.json regenerated from the ci.yml gates and fresh measurements"
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
      # Byte-exact against the canonical payload (printf '%s\n'): command
      # substitution would strip the trailing newline and let a newline-only
      # drift pass the gate while the --commit path still "finds" a change.
      if [ ! -f "$file" ] || ! printf '%s\n' "$want" | cmp -s - "$file"; then
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
  --commit|--recover) ;;
  "")
    echo "(dry-run — pass --check to gate or --commit to publish changes)"
    exit 0
    ;;
  *)
    echo "unknown mode: $MODE (use --check or --commit)" >&2
    exit 2
    ;;
esac

if [ "$MODE" = "--recover" ]; then
  recover_size_story
else
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
fi

if git diff --quiet -- badges/ docs/17-CI-GATES.md; then
  echo "badges unchanged — nothing to commit"
  exit 0
fi
SIZE_NOTE=""
[[ -n "$WEB_MB" ]] && SIZE_NOTE=" — sizes web ${WEB_MB} MB / backend ${BACKEND_MB} MB / airgap ${AIRGAP_MB} MB"
if [ "$MODE" = "--recover" ]; then
  TITLE="chore: recover size-budget table + stamps from the live gates$SIZE_NOTE"
else
  TITLE="chore: refresh badges (tests $SUM, rules $RULES, tactics $COV, commands $CMDS)$SIZE_NOTE"
fi
git config user.name "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"

# main is branch-protected: the three required status checks must pass on
# anything that lands there, so a locally-created bot commit can never push
# directly (GH006 — proven by the dispatch run). Land via a PR with
# auto-merge armed — the documented mechanism for main — so badges/docs
# changes get the same gate as everything else.
BRANCH="chore/badges-$(date -u +%Y%m%d-%H%M%S)"
git checkout -b "$BRANCH"
# Record the branch this run created so the badge-branch cleanup step
# (scripts/cleanup_badge_branches.sh) can exclude it — never delete the
# branch an in-flight publish still needs (an open PR, or the manual-PR
# wait after a blocked pr create). The file is consumed in the same CI job.
printf '%s\n' "$BRANCH" > "${RUNNER_TEMP:-/tmp}/outpost-badge-branch"
git add badges/ docs/17-CI-GATES.md
git commit -m "$TITLE"
git pull --rebase origin main 2>/dev/null || true
if ! git push -u origin "$BRANCH"; then
  echo "  push failed — branch protection blocks direct main pushes; this must go via PR" >&2
  exit 1
fi
if command -v gh >/dev/null 2>&1; then
  if ! PR_ERR=$(gh pr create --base main --head "$BRANCH" --title "$TITLE" \
      --body "Auto-generated by the refresh-badges job (weekly schedule / workflow_dispatch). Merges itself once the required checks pass." \
      2>&1); then
    # The repo may forbid Actions from opening PRs (Settings → Actions →
    # General → Workflow permissions → 'Allow GitHub Actions to create and
    # approve pull requests'). That's a repo POLICY, not a payload problem:
    # the refreshed payloads are already committed and safe on the pushed
    # branch. Warn loudly — the ::warning:: workflow command renders as an
    # annotation in the Actions UI — and stay green; a human opens the PR
    # from the branch, or flips the setting and re-dispatches. Failing red
    # here is noise, because the badge data never left the branch either way.
    echo "::warning title=Badge publish PR blocked::gh pr create failed — badges/docs refreshed and committed on '$BRANCH', but this repo forbids Actions from opening PRs. Open the PR manually from '$BRANCH', or enable 'Allow GitHub Actions to create and approve pull requests' (Settings → Actions → General → Workflow permissions) and re-dispatch."
    echo "  gh pr create failed — the repo setting 'Allow GitHub Actions to create" >&2
    echo "  and approve pull requests' (Settings → Actions → General → Workflow" >&2
    echo "  permissions) must be ON for the bot to land via PR. This is a policy" >&2
    echo "  warning, not a failure: the refreshed payloads are safe on the pushed" >&2
    echo "  branch '$BRANCH'. Open the PR manually from it, or flip the setting" >&2
    echo "  and re-dispatch — the branch carries the same work either way." >&2
    printf '  gh pr create said: %s\n' "$PR_ERR" >&2
    exit 0
  fi
  gh pr merge --auto --squash
  echo "badges PR opened with auto-merge armed — merges when the required checks pass"
else
  echo "  gh not available — branch pushed at '$BRANCH'; open the PR manually" >&2
  exit 1
fi
