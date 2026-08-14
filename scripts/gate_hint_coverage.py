#!/usr/bin/env python3
"""Hint-coverage guard — every gate that prints a `→ fix:` hint must be tested.

The self-explaining-hint discipline (each failure prints the exact corrected
artifact, and a self-test proves that hint actually repairs the fixture)
only holds while it's enforced structurally. This guard makes the coverage
itself a gate, so the property can't silently regress:

  1. Every script under scripts/ that emits a `→ fix:` hint (a `hint(...)`
     call, an `echo "  → fix:` line, or an `→ fix:` literal) MUST appear in
     COVERAGE below, mapped to the self-test that pins it.
  2. Each mapped self-test must exist.
  3. Each mapped self-test must actually run inside verify.sh (a self-test
     nobody invokes is dead coverage — the sweep must fail if a gate grows
     hints and someone forgets to wire the test in).

Caddyfile/compose validation is excluded by construction: those steps run
third-party tools (`caddy validate`, `docker compose config`) whose output
isn't ours to hint, so no hint emission and no coverage obligation.

Exit 0 only when every hint-emitting gate is covered by a wired-in
self-test. Static + dependency-free (regex + file existence), milliseconds.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
VERIFY = ROOT / "verify.sh"

# gate (scripts/<file>) -> self-test (scripts/<file>) that pins its hints AND
# proves they repair (exit-1 + hint presence + applied-fix-goes-green).
COVERAGE = {
    "gate_image_budget_docs.py": "test_image_budget_hints.py",
    "refresh-badges.sh": "test_badge_hints.py",
}

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def main() -> int:
    if not SCRIPTS.exists() or not VERIFY.exists():
        print("  FAIL — scripts/ or verify.sh missing", file=sys.stderr)
        return 1

    # A gate EMITS a hint when it calls hint(...) or prints/echoes a '→ fix:'
    # line. Docstring/comment mentions ("prints a → fix: line") don't count.
    # Self-tests and this guard are excluded: the tests deliberately mention
    # the hints they pin, and this file describes its own job.
    emit_re = re.compile(r"hint\(|echo\s+.*→ fix:|print\(.*→ fix:")
    emitting = sorted(
        p.name for p in SCRIPTS.iterdir()
        if p.is_file()
        and p.suffix in (".py", ".sh")
        and not p.name.startswith("test_")
        and p.name != "gate_hint_coverage.py"
        and emit_re.search(p.read_text())
    )

    # 1. Every hint-emitting gate must be covered.
    for name in emitting:
        if name not in COVERAGE:
            check(f"hint-emitting gate covered: {name}", False, "prints '→ fix:' hints but has no self-test")
            continue
        test_name = COVERAGE[name]
        test_path = SCRIPTS / test_name
        check(f"hint-emitting gate covered: {name}", True, f"pinned by {test_name}")

        # 2. The mapped self-test must exist.
        check(f"self-test exists: {test_name}", test_path.exists(), "missing file" if not test_path.exists() else "")

    # 3. Every mapped self-test must be wired into verify.sh — and, for the
    #    ones found emitting, the mapping must be complete.
    verify_text = VERIFY.read_text()
    for gate, test_name in sorted(COVERAGE.items()):
        wired = test_name in verify_text
        check(
            f"self-test wired into verify.sh: {test_name}",
            wired,
            f"gate {gate} prints hints but {test_name} is not invoked by the sweep" if not wired else "",
        )
    for name in emitting:
        if name in COVERAGE and COVERAGE[name] not in verify_text:
            check(f"self-test actually invoked: {COVERAGE[name]}", False)

    print(f"Hint-coverage guard: {len(FAILURES)} failed" if FAILURES else "Hint-coverage guard: every hint-emitting gate has a wired-in repair self-test")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
