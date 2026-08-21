#!/usr/bin/env bash
# Gate a PRODUCTION image's size so bundle bloat surfaces in CI.
#
#   bash scripts/check-image-size.sh --image outpost-web:ci
#   bash scripts/check-image-size.sh --image outpost-backend:ci --budget-mb 300 --fail-mb 400
#   bash scripts/check-image-size.sh --size-bytes 57671680   # offline (no docker)
#
# The shipped images are deliberately lean: the web image is a multi-stage
# build (deploy/Dockerfile.web) that compiles in node:20-alpine and copies
# ONLY the dist into caddy:2-alpine (~60 MB class); the backend image is
# python:3.12-slim + pip runtime deps + the app package only (~190 MB
# class). That makes size a sharp bloat detector: a leaked build stage
# (node_modules copied in, a COPY . . mistake, test fixtures or docs
# shipped) dwarfs the base in one step. Two budgets:
#
#   - SOFT (default 100 MB): growth past this WARNS (exit 0) and is written
#     to the GitHub step summary so it is visible on the run page, not just
#     buried in logs. The warning is the point — bloat should surface early,
#     not fail a ship that is otherwise green.
#   - HARD (default 150 MB): growth past this FAILS the deploy job. At some
#     size the image is shipping something it should not, and a deploy that
#     would push a bloated artifact should not go through silently. When it
#     trips, the top layers by size are dumped (`docker history`) so the
#     offending layer — a giant COPY, an npm/pip install, a leaked venv — is
#     identifiable in the CI log instead of a bare number.
#
# Budgets are tunable knobs (--budget-mb / --fail-mb); the measured size
# prints on every run so the budgets can be calibrated against reality.
# The layer dump is testable offline by pointing HISTORY_SOURCE at a
# `docker history --no-trunc --human=false --format '{{.Size}} {{.CreatedBy}}'`
# sample file (the failure path never runs on a green build).
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

# Raw layer data: docker history (real mode) or a HISTORY_SOURCE sample file
# (offline test of the failure-path dump). Emits '<size_bytes> <created_by>'
# lines, newest layer first.
layer_data() {
  if [[ -n "${HISTORY_SOURCE:-}" ]]; then
    cat "$HISTORY_SOURCE"
  elif [[ -n "$IMAGE" ]] && command -v docker >/dev/null 2>&1; then
    docker history --no-trunc --human=false --format '{{.Size}} {{.CreatedBy}}' "$IMAGE" 2>/dev/null || true
  fi
}

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
  DATA=$(layer_data)
  if [[ -n "$DATA" ]]; then
    echo "  Likely bloat source — top layers by size:" >&2
    echo "$DATA" | sort -rn -k1,1 | head -8 | awk '{printf "    %9.1f MB  %s\n", $1/1048576, substr($0, index($0, $2))}' >&2
    echo "  (the FROM base layer is expected to dominate — look for oversized COPY/install/ENV layers above it)" >&2
  else
    echo "  (offline — no layer data; rerun on a docker host to see the offending layers)" >&2
  fi
  echo "  → fix: rebuild the image lean — add a .dockerignore (node_modules, .venv, dist, *.db, tests, docs) and drop leaked build stages/COPYs, then confirm with: bash scripts/check-image-size.sh --image ${NAME}" >&2
  exit 1
fi

if [[ "$SIZE_MB" -gt "$BUDGET_MB" ]]; then
  MSG="⚠ ${NAME} ${SIZE_MB} MB exceeds the ${BUDGET_MB} MB soft budget (+$((SIZE_MB - BUDGET_MB)) MB over). Check what the image is now carrying — the runtime image should stay close to its base + runtime deps only."
  echo "  $MSG"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## ⚠ ${NAME} size over budget"
      echo ""
      echo "$MSG"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

echo "  ✓ $NAME within the ${BUDGET_MB} MB budget"
