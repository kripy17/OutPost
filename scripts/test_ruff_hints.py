#!/usr/bin/env python3
"""Self-test for gate_ruff.py's fix hint.

The ruff gate must fail with an actionable `→ fix:` line on any lint drift
and go green once the fix is applied. This self-test runs the REAL gate
against a throwaway fixture tree: a deliberately-broken module (unused
import, F401) must fail the gate WITH the hint, and deleting the import must
turn it green — proving the hinted repair actually repairs, without touching
the real trees.

Exit 0 only when both assertions hold.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from hint_coverage_map import gate_for  # noqa: E402

GATE = ROOT / "scripts" / gate_for(Path(__file__).name)
RUFF_TOML = ROOT / "ruff.toml"

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def run_gate(fixture: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(GATE), "--paths", str(fixture), "--config", str(RUFF_TOML)],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ruff-hints-") as td:
        fixture = Path(td)
        pkg = fixture / "mypkg"
        pkg.mkdir()
        bad = pkg / "bad.py"

        # Drift: an unused import (F401) — the curated gate must catch it.
        bad.write_text("import os\n\ndef f() -> int:\n    return 1\n")
        rc, out = run_gate(fixture)
        check("lint drift (unused import) fails the gate", rc == 1, f"rc={rc}")
        has_hint = "→ fix: run `.venv/bin/python -m ruff check" in out
        check("drift prints the fix hint", has_hint, "hint missing from output" if not has_hint else "hint present")

        # Repair: remove the unused import — the same hint's fix goes green.
        bad.write_text("def f() -> int:\n    return 1\n")
        rc, out = run_gate(fixture)
        check("applied fix → gate green", rc == 0, f"rc={rc}")

    print(
        f"Ruff-hint self-test: {len(FAILURES)} failed"
        if FAILURES
        else "Ruff-hint self-test: drift fails with a repair hint, applied fix goes green"
    )
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
