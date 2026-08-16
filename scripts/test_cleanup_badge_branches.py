#!/usr/bin/env python3
"""Self-test for scripts/cleanup_badge_branches.sh — the CI hygiene gate.

The cleanup step runs after a successful badge publish and deletes every
chore/badges-* branch on origin EXCEPT the branch the current run created
(recorded in ${RUNNER_TEMP:-/tmp}/outpost-badge-branch by refresh-badges.sh),
which may still be in flight — an open auto-merge PR, or the manual-PR wait
the blocked-pr-create warning points at.

The fixture mirrors the CI shape: a worktree repo with a local bare origin
seeded with main, two stale chore/badges-* branches, and one "current"
branch (recorded in a fake RUNNER_TEMP); the script is copied in so ROOT
resolves to the fixture. Asserts:

  1. stale branches are deleted from the bare origin and the recorded
     branch survives (exit 0),
  2. with no record file, every chore/badges-* branch is deleted,
  3. with nothing to delete, exit 0 with a "nothing to clean" note,
  4. the record file is removed on exit in every path.

Static + dependency-free (git + bash only), seconds.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def build_fixture(tmp: Path) -> tuple[Path, Path]:
    """Worktree repo + local bare origin; returns (repo, bare)."""
    bare = tmp / "origin.git"
    repo = tmp / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    git("init", "--bare", "-q", str(bare), cwd=tmp)
    git("-c", "init.defaultBranch=main", "init", "-q", cwd=repo)
    git("config", "user.name", "test", cwd=repo)
    git("config", "user.email", "test@test", cwd=repo)
    (repo / "f.txt").write_text("base\n")
    git("add", "-A", cwd=repo)
    git("commit", "-qm", "baseline", cwd=repo)
    git("remote", "add", "origin", str(bare), cwd=repo)
    git("push", "-q", "-u", "origin", "main", cwd=repo)
    for name in ("chore/badges-stale1", "chore/badges-stale2", "chore/badges-current"):
        git("checkout", "-q", "-b", name, cwd=repo)
        (repo / "f.txt").write_text(f"{name}\n")
        git("add", "-A", cwd=repo)
        git("commit", "-qm", name, cwd=repo)
        git("push", "-q", "-u", "origin", name, cwd=repo)
        git("checkout", "-q", "main", cwd=repo)
    (repo / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "scripts/cleanup_badge_branches.sh", repo / "scripts/cleanup_badge_branches.sh")
    return repo, bare


def list_origin(bare: Path) -> set[str]:
    out = subprocess.run(
        ["git", "-C", str(bare), "for-each-ref", "refs/heads", "--format=%(refname:short)"],
        capture_output=True, text=True, check=True,
    ).stdout
    return {line for line in out.splitlines() if line}


def run_cleanup(repo: Path, runner_temp: Path, keep: str | None) -> tuple[int, str]:
    if keep:
        (runner_temp / "outpost-badge-branch").write_text(keep + "\n")
    env = dict(os.environ)
    env["RUNNER_TEMP"] = str(runner_temp)
    p = subprocess.run(
        ["bash", "scripts/cleanup_badge_branches.sh"],
        cwd=repo, env=env, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="badge-cleanup-") as td:
        tmp = Path(td)

        # 1. Two stale branches + one recorded current branch → stale deleted,
        #    current survives, record file removed.
        repo, bare = build_fixture(tmp)
        runner_temp = tmp / "runner-temp"
        runner_temp.mkdir()
        rc, out = run_cleanup(repo, runner_temp, "chore/badges-current")
        remaining = list_origin(bare)
        check(
            "stale deleted, recorded branch kept",
            rc == 0
            and "chore/badges-current" in remaining
            and "chore/badges-stale1" not in remaining
            and "chore/badges-stale2" not in remaining
            and "main" in remaining,
            f"rc={rc}, remaining={sorted(remaining)}",
        )
        check("deleted count reported", "deleted 2 stale branch" in out, out if "deleted 2" not in out else "")
        check("record file removed", not (runner_temp / "outpost-badge-branch").exists())

        # 2. No record file → every chore/badges-* branch deleted.
        repo2, bare2 = build_fixture(tmp / "f2")
        runner_temp2 = tmp / "runner-temp2"
        runner_temp2.mkdir()
        rc, out = run_cleanup(repo2, runner_temp2, None)
        remaining = list_origin(bare2)
        check(
            "no record → all chore/badges-* deleted",
            rc == 0 and remaining == {"main"},
            f"rc={rc}, remaining={sorted(remaining)}",
        )

        # 3. Nothing to delete → exit 0 with the nothing-to-clean note.
        repo3, bare3 = build_fixture(tmp / "f3")
        git("push", "origin", "--delete", "chore/badges-stale1", cwd=repo3)
        git("push", "origin", "--delete", "chore/badges-stale2", cwd=repo3)
        git("push", "origin", "--delete", "chore/badges-current", cwd=repo3)
        runner_temp3 = tmp / "runner-temp3"
        runner_temp3.mkdir()
        rc, out = run_cleanup(repo3, runner_temp3, None)
        check(
            "nothing to clean → exit 0",
            rc == 0 and "nothing to clean" in out,
            f"rc={rc}\n{out}" if rc != 0 or "nothing to clean" not in out else "",
        )

    print(
        "Badge-branch cleanup self-test: all clear — stale branches die, the live publish branch survives"
        if not FAILURES
        else f"Badge-branch cleanup self-test: {len(FAILURES)} failed"
    )
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
