#!/usr/bin/env python3
"""The transition-comment bite drill — one command, three layers.

The alert-triage comment contract (backend `update_alert_status`: a
non-empty comment is recorded whitespace-trimmed; an empty / whitespace-only
/ omitted comment stores NULL, so a bare transition clears a prior one) is
pinned at all three layers — the backend test
(`test_alert_status_comment_semantics`), the webapp lifecycle test
(`triageLifecycle.test.tsx`), and the CLI lifecycle test
(`test_triage_lifecycle.py`). This drill proves all three tests actually
BITE: it temporarily corrupts each layer's comment handling with its own
failure mode, asserts the targeted test FAILS on the exact comment
assertion, then restores the file and asserts the same test passes again.

Why a drill, not a gate: it deliberately breaks the code under test and
runs three test suites twice — the opposite of a fast sweep gate. Run it
deliberately (e.g. after touching any of the three comment paths) to prove
the contract is still load-bearing everywhere:

    python scripts/bite_triage_comment.py

Each layer exits its half only when BOTH directions hold: the bite makes
the test fail on the expected assertion, and the restore makes it pass
again. If the code drifts so a bite no longer lands (the anchor string
moved, or the test stopped asserting the comment), the drill fails loudly
with the actual output instead of guessing. The files are restored even on
failure (per-layer try/finally plus a final self-heal sweep), so a crash
mid-drill cannot leave a bite in place.
"""

import os
import subprocess
import sys
from pathlib import Path

# OUTPOST_BITE_ROOT overrides the project root so the self-test
# (scripts/test_bite_drill.py) can point the drill at a throwaway fixture
# tree; in that mode the drill skips the real test runs (apply + restore is
# what's under test) and the venv-existence precheck.
ROOT = Path(os.environ.get("OUTPOST_BITE_ROOT") or Path(__file__).resolve().parent.parent)
VENV_PY = ROOT / ".venv" / "bin" / "python"
FIXTURE_MODE = bool(os.environ.get("OUTPOST_BITE_ROOT"))

# name, file, anchor (old), bite (new), test command, cwd, expected failure substring.
# The anchors include enough context to be EXACTLY ONE occurrence in the file.
BITES = [
    {
        "name": "backend (raw, untrimmed comment)",
        "path": ROOT / "backend" / "app" / "api" / "routes_alerts.py",
        "old": '    comment = (body.comment or "").strip() or None\n    actor = auth.role_from_request(request)',
        "new": '    comment = body.comment  # BITE-DRILL: raw untrimmed\n    actor = auth.role_from_request(request)',
        "cmd": [str(VENV_PY), "-m", "pytest", "app/tests/test_triage.py::test_alert_status_comment_semantics", "-q"],
        "cwd": ROOT / "backend",
        "expect_fail": "seen, will resolve",
    },
    {
        "name": "webapp (strip every transition)",
        "path": ROOT / "frontend" / "src" / "test" / "triageLifecycle.test.tsx",
        "old": '        // Backend: comment = (body.comment or "").strip() or None.\n        const comment = (p.comment ?? "").trim() || null;',
        "new": "        // BITE-DRILL: strip on every transition\n        const comment = null;",
        "cmd": ["npx", "vitest", "run", "src/test/triageLifecycle.test.tsx"],
        "cwd": ROOT / "frontend",
        "expect_fail": "\u201cseen, will resolve\u201d",
    },
    {
        "name": "cli (strip every transition)",
        "path": ROOT / "cli" / "tests" / "test_triage_lifecycle.py",
        # The anchor includes the following line: the same comment-strip
        # expression now also appears in _stateful_post (the bulk stub), so
        # context is required for the exactly-one uniqueness check.
        "old": '        comment = (json.get("comment") or "").strip() or None\n        row = store[alert_id]',
        "new": "        comment = None  # BITE-DRILL: strip on every transition\n        row = store[alert_id]",
        "cmd": [str(VENV_PY), "-m", "pytest", "tests/test_triage_lifecycle.py::test_triage_command_full_lifecycle", "-q"],
        "cwd": ROOT / "cli",
        "expect_fail": "comment: seen, will resolve",
    },
]

FAILURES: list[str] = []


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    # check=False is deliberate: the drill EXPECTS failures under the bite
    # and inspects returncode itself.
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300, check=False)


def _apply(path: Path, old: str, new: str) -> None:
    """Apply the bite, failing loudly if the anchor drifted (count != 1)."""
    src = path.read_text()
    count = src.count(old)
    if count != 1:
        raise RuntimeError(
            f"{path.name}: anchor found {count} time(s), expected exactly 1 — the code shape drifted, "
            "the drill can't proceed safely (re-run after the comment paths are restored to the pinned shape)"
        )
    path.write_text(src.replace(old, new))


def drill_layer(layer: dict) -> bool:
    name: str = layer["name"]
    path: Path = layer["path"]
    old: str = layer["old"]
    new: str = layer["new"]
    cmd: list[str] = layer["cmd"]
    cwd: Path = layer["cwd"]
    expect_fail: str = layer["expect_fail"]

    ok = True
    try:
        _apply(path, old, new)
    except RuntimeError as exc:
        print(f"  [FAIL] {name} — {exc}")
        return False

    if FIXTURE_MODE:
        # Self-test mode: no real test run — verify the bite applies and
        # restores cleanly (the fail-loud path above already covers drift).
        ok = new in path.read_text()
        if not ok:
            print(f"  [FAIL] {name} — fixture bite did not apply")
        path.write_text(path.read_text().replace(new, old))
        restored = old in path.read_text() and new not in path.read_text()
        if not restored:
            print(f"  [FAIL] {name} — fixture restore did not land")
            return False
        print(f"  [OK] {name} — fixture bite + restore round-trip")
        return ok

    try:
        bitten = _run(cmd, cwd)
        failed_right = bitten.returncode != 0 and expect_fail in bitten.stdout + bitten.stderr
        if failed_right:
            print(f"  [OK] {name} — bite landed, test failed on: {expect_fail!r}")
        else:
            ok = False
            print(f"  [FAIL] {name} — under the bite the test did NOT fail on {expect_fail!r} (rc={bitten.returncode})")
            tail = (bitten.stdout + bitten.stderr).strip().splitlines()
            for line in tail[-8:]:
                print(f"          {line}")
    finally:
        path.write_text(path.read_text().replace(new, old))

    if not ok:
        return False

    restored = _run(cmd, cwd)
    if restored.returncode != 0:
        print(f"  [FAIL] {name} — after restore the test did NOT pass (rc={restored.returncode})")
        tail = (restored.stdout + restored.stderr).strip().splitlines()
        for line in tail[-8:]:
            print(f"          {line}")
        return False
    print(f"  [OK] {name} — restore landed, test passes again")
    return True


def _self_heal() -> None:
    """Restore anything left bitten (e.g. a SIGKILL mid-drill). Also the
    hook the self-test calls directly to prove the safety net works."""
    for layer in BITES:
        path: Path = layer["path"]
        if layer["new"] in path.read_text():
            path.write_text(path.read_text().replace(layer["new"], layer["old"]))
            print(f"  !! {path.name} was left bitten — restored by the final sweep")


def main() -> int:
    if not FIXTURE_MODE and not VENV_PY.exists():
        print(f"  FAIL — venv python not found at {VENV_PY}", file=sys.stderr)
        return 1
    print("Transition-comment bite drill — three layers, both directions:")
    for layer in BITES:
        if not drill_layer(layer):
            FAILURES.append(layer["name"])

    _self_heal()

    if FAILURES:
        print(f"\nDrill FAILED — {len(FAILURES)} layer(s) did not bite: {', '.join(FAILURES)}")
        return 1
    print("\nDrill passed — all three layers bite on the comment contract and restore cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
