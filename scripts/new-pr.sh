#!/usr/bin/env bash
# new-pr.sh — open a pull request with auto-merge armed, so a green PR
# merges itself the moment the required checks pass. The repo has
# allow_auto_merge enabled and main is protected (required checks + strict)
# — see docs/17-CI-GATES.md "Auto-merge policy".
#
# Usage:
#   bash scripts/new-pr.sh "Title"                 # from the current branch
#   bash scripts/new-pr.sh "Title" "Body text..."  # explicit body
#
# Pushes the current branch (creating the upstream if needed), opens the PR
# against the default branch, and arms `gh pr merge --auto --squash`.
# No-op guards: refuses to run from a detached HEAD or the default branch.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TITLE="${1:-}"
BODY="${2:-}"
if [ -z "$TITLE" ]; then
  echo "usage: bash scripts/new-pr.sh <title> [body]" >&2
  exit 2
fi

# The workspace (source of truth) is not a git checkout — this script runs
# from the mirror. Sync the workspace's latest edits into the mirror FIRST
# so a PR never ships stale content. Override with OUTPOST_WORKSPACE.
WORKSPACE="${OUTPOST_WORKSPACE:-/home/kripy/Projects/OutPost}"
if [ -n "$WORKSPACE" ] && [ "$WORKSPACE" != "$ROOT" ] && [ -f "$WORKSPACE/scripts/sync-mirror.sh" ]; then
  echo "==> syncing workspace ($WORKSPACE) into this mirror…"
  bash "$WORKSPACE/scripts/sync-mirror.sh" --quiet
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" = "HEAD" ]; then
  echo "detached HEAD — checkout a feature branch first" >&2
  exit 2
fi
# `git symbolic-ref --short` yields `origin/main` — strip the remote prefix
# so the comparison below is branch-name to branch-name.
DEFAULT_BRANCH="$(git symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null || echo main)"
DEFAULT_BRANCH="${DEFAULT_BRANCH#origin/}"
if [ "$BRANCH" = "$DEFAULT_BRANCH" ]; then
  echo "on the default branch ($DEFAULT_BRANCH) — create a feature branch first" >&2
  exit 2
fi

# Worktree must be clean enough to push a meaningful branch (tracked
# changes only; untracked files are the caller's call).
if ! git diff --quiet HEAD; then
  echo "uncommitted tracked changes — commit before opening a PR" >&2
  exit 2
fi

git push -u origin "$BRANCH" >/dev/null 2>&1
PR_URL="$(gh pr create --title "$TITLE" --body "${BODY:-$TITLE}")"
PR_NUM="$(basename "$PR_URL")"
gh pr merge "$PR_NUM" --auto --squash >/dev/null
echo "PR $PR_URL — auto-merge armed: merges itself once the required checks pass"
