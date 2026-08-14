#!/usr/bin/env bash
# Gate the PRODUCTION web image's size so bundle bloat surfaces in CI.
#
#   bash scripts/check-image-size.sh --image outpost-web:ci
#   bash scripts/check-image-size.sh --image outpost-web:ci --budget-mb 100 --fail-mb 150
#   bash scripts/check-image-size.sh --size-bytes 57671680   # offline (no docker)
#
# The shipped web image is deliberately tiny: a multi-stage build
# (deploy/Dockerfile.web) compiles the Vite bundle in node:20-alpine, then
# copies ONLY the dist into caddy:2-alpine — so the runtime image is the
# Caddy binary + a few MB of static assets (~50 MB class). That makes size a
# sharp bloat detector: a leaked build stage (node_modules copied in, a
# COPY . . mistake, test fixtures or docs shipped) dwarfs the base in one
# step. Two budgets:
#
#   - SOFT (default 100 MB): growth past this WARNS (exit 0) and is written
#     to the GitHub step summary so it is visible on the run page, not just
#     buried in logs. The warning is the point — bloat should surface early,
#     not fail a ship that is otherwise green.
#   - HARD (default 150 MB): growth past this FAILS the deploy job. At some
#     size the image is shipping something it should not, and a deploy that
#     would push a bloated artifact should not go through silently.
#
# Budgets are tunable knobs (--budget-mb / --fail-mb); the first CI run
# prints the measured size so they can be calibrated against reality.
set -euo pipefail

IMAGE=""
BUDGET_MB=100
FAIL_MB=150
SIZE_BYTES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --budget-mb) BUDGET_MB="$2"; shift 2 ;;
    --fail-mb) FAIL_MB="$2"; shift 2 ;;
    --size-bytes) SIZE_BYTES="$2"; shift 2 ;;
    *) echo "  unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$SIZE_BYTES" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "  docker not found — pass --size-bytes N to check offline." >&2
    exit 3
  fi
  if [[ -z "$IMAGE" ]]; then
    echo "  --image required (or --size-bytes for offline checks)" >&2
    exit 2
  fi
  SIZE_BYTES=$(docker image inspect --format '{{.Size}}' "$IMAGE" 2>/dev/null || true)
  if [[ -z "$SIZE_BYTES" || "$SIZE_BYTES" == "0" ]]; then
    echo "  FAIL: image '$IMAGE' not present or reports no size (build it first)" >&2
    exit 1
  fi
fi

SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
NAME="${IMAGE:-image}"
echo "  $NAME size: ${SIZE_MB} MB (${SIZE_BYTES} B) — soft budget ${BUDGET_MB} MB, hard ceiling ${FAIL_MB} MB"

if [[ "$SIZE_MB" -gt "$FAIL_MB" ]]; then
  echo "  ✗ HARD CEILING EXCEEDED: ${SIZE_MB} MB > ${FAIL_MB} MB — the image is shipping something it should not (leaked build stage / node_modules / test fixtures)." >&2
  exit 1
fi

if [[ "$SIZE_MB" -gt "$BUDGET_MB" ]]; then
  MSG="⚠ ${NAME} ${SIZE_MB} MB exceeds the ${BUDGET_MB} MB soft budget (+$((SIZE_MB - BUDGET_MB)) MB over). Check what the image is now carrying — the runtime image should stay close to its base + runtime deps only."
  echo "  $MSG"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## ⚠ Web image size over budget"
      echo ""
      echo "$MSG"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

echo "  ✓ $IMAGE within the ${BUDGET_MB} MB budget"
