#!/usr/bin/env bash
# sync-mirror.sh — copy the workspace (source of truth) into the git mirror
# used for commits/PRs, safely.
#
# The workspace itself is NOT a git checkout (commits go through the mirror +
# scripts/new-pr.sh). This script:
#   1. Creates the mirror at $MIRROR if it's missing (init + fetch + checkout main).
#   2. rsyncs the workspace into it — ALWAYS excluding '.git' (a `--delete`
#      sync from a non-git source wiped the mirror's git metadata once).
#   3. Verifies the mirror's git metadata survived the sync, failing loudly
#      otherwise.
#   4. Prints the resulting working-tree status so the caller can review.
#
# Usage:   bash scripts/sync-mirror.sh [--print-status]
# Env:     MIRROR=/tmp/outpost-clone  OUTPOST_REPO=kripy17/OutPost
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIRROR="${MIRROR:-/tmp/outpost-clone}"
REPO="${OUTPOST_REPO:-kripy17/OutPost}"
PRINT_STATUS="${1:---print-status}"

EXCLUDES=(--exclude='.git' --exclude='.venv' --exclude='node_modules'
  --exclude='__pycache__' --exclude='dist' --exclude='*.egg-info'
  --exclude='.freebuff' --exclude='*.db' --exclude='*.db-wal'
  --exclude='*.db-shm' --exclude='.pytest_cache' --exclude='.deck-video'
  --exclude='*.pyc')

# 1. Create the mirror if it doesn't exist.
if [ ! -d "$MIRROR/.git" ]; then
  echo "==> Mirror missing or gitless at $MIRROR — bootstrapping from origin/$REPO"
  rm -rf "$MIRROR"
  mkdir -p "$MIRROR"
  git -C "$MIRROR" init -q -b main
  git -C "$MIRROR" remote add origin "https://github.com/$REPO.git"
  git -C "$MIRROR" fetch -q origin main
  git -C "$MIRROR" checkout -q main
  git -C "$MIRROR" reset --hard -q origin/main
fi

# 2. Sync the workspace into the mirror.
rsync -a --delete "${EXCLUDES[@]}" "$ROOT"/ "$MIRROR"/

# 3. Guard: the sync must never destroy the mirror's git metadata.
if [ ! -d "$MIRROR/.git" ]; then
  echo "ERROR: sync removed $MIRROR/.git — aborting before anything git touches it." >&2
  echo "       Re-run to re-bootstrap from origin." >&2
  exit 1
fi

echo "==> Synced workspace -> $MIRROR (main @ $(git -C "$MIRROR" rev-parse --short HEAD))"
if [ "$PRINT_STATUS" = "--print-status" ]; then
  cd "$MIRROR"
  if [ -z "$(git status --short)" ]; then
    echo "    clean — workspace matches origin/main"
  else
    git status --short
  fi
fi
