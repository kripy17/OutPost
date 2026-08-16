#!/usr/bin/env bash
# cleanup_badge_branches.sh — CI hygiene: delete stale chore/badges-* branches.
#
# The publish step lands badge refreshes on a chore/badges-* branch and,
# when the repo allows it, opens an auto-merge PR from it. When PR creation
# is blocked (the repo forbids Actions from opening PRs — a policy warning,
# not a failure), or an old run crashed between push and PR, the branch is
# left on origin as an orphan. This step runs after a successful publish on
# main and removes every chore/badges-* branch EXCEPT the one the current
# run created — recorded in ${RUNNER_TEMP:-/tmp}/outpost-badge-branch by
# refresh-badges.sh — which may still be in flight (an open PR, or the
# manual-PR wait the warning points at).
#
# Idempotent and never a hard failure: a delete that fails is reported and
# skipped (a race with another publish job), and "nothing to delete" exits
# 0. The record file is always removed on exit so a stale branch name can
# never be treated as "current" by a later run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RECORD="${RUNNER_TEMP:-/tmp}/outpost-badge-branch"
KEEP=""
if [ -f "$RECORD" ]; then
  KEEP="$(cat "$RECORD")"
fi

BRANCHES="$(git ls-remote --heads origin 'refs/heads/chore/badges-*' | awk '{print $2}' | sed 's#^refs/heads/##' || true)"
if [ -z "$BRANCHES" ]; then
  echo "no chore/badges-* branches on origin — nothing to clean"
  rm -f "$RECORD"
  exit 0
fi

deleted=0
for b in $BRANCHES; do
  if [ -n "$KEEP" ] && [ "$b" = "$KEEP" ]; then
    echo "  keep $b (the branch this run created — may be an in-flight publish)"
    continue
  fi
  echo "  delete $b (stale badge branch)"
  if git push origin --delete "$b" >/dev/null 2>&1; then
    deleted=$((deleted + 1))
  else
    echo "  could not delete $b (skipping — a publish may be mid-flight for it)"
  fi
done
rm -f "$RECORD"
echo "badge-branch cleanup: deleted $deleted stale branch(es)"
