#!/usr/bin/env python3
"""Self-test for the image-budget gate's self-explaining hints.

Runs `gate_image_budget_docs.py` against a throwaway fixture tree (the real
ci.yml / docs/17 / check-image-size.sh / image-sizes.json copied into a temp
dir so the gate's ROOT resolves there), mutates one drift direction at a
time, and asserts the gate exits 1 AND prints a `→ fix:` line that would
actually repair the drift.

Every drift direction the gate can report must be covered here, so the
self-explaining behavior can't silently regress: if a future refactor drops
a hint or a new failure path forgets one, this test fails.

Exit 0 only when all directions pass.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SRC = {
    "ci": ROOT / ".github/workflows/ci.yml",
    "docs": ROOT / "docs/17-CI-GATES.md",
    "gate": ROOT / "scripts/gate_image_budget_docs.py",
    "sizes_script": ROOT / "scripts/check-image-size.sh",
    "sizes_json": ROOT / "badges/image-sizes.json",
}

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def build_fixture(tmp: Path) -> None:
    """Copy the real sources into the fixture so the gate's ROOT = tmp."""
    (tmp / ".github/workflows").mkdir(parents=True, exist_ok=True)
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    (tmp / "docs").mkdir(parents=True, exist_ok=True)
    (tmp / "badges").mkdir(parents=True, exist_ok=True)
    for rel, src in [
        (".github/workflows/ci.yml", SRC["ci"]),
        ("docs/17-CI-GATES.md", SRC["docs"]),
        ("scripts/gate_image_budget_docs.py", SRC["gate"]),
        ("scripts/check-image-size.sh", SRC["sizes_script"]),
        ("badges/image-sizes.json", SRC["sizes_json"]),
    ]:
        shutil.copy(src, tmp / rel)


def run_gate(tmp: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(tmp / "scripts/gate_image_budget_docs.py")],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout + p.stderr


def expect_drift(tmp: Path, name: str, hint_needle: str) -> None:
    """Assert the gate fails on the fixture AND prints a fix hint."""
    rc, out = run_gate(tmp)
    ok = rc == 1 and hint_needle in out
    check(name, ok, f"rc={rc}, hint={hint_needle!r} in output" if not ok else f"rc={rc}, hint present")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="img-budget-hints-") as td:
        tmp = Path(td)

        # 0. Fresh fixture — gate passes, no hint lines.
        build_fixture(tmp)
        rc, out = run_gate(tmp)
        check("fresh fixture passes", rc == 0 and "→ fix:" not in out, f"rc={rc}")

        # 1. No size-gate steps in ci.yml.
        build_fixture(tmp)
        (tmp / ".github/workflows/ci.yml").write_text(
            re.sub(r"(?m)^.*check-image-size\.sh.*$", "", (tmp / ".github/workflows/ci.yml").read_text())
        )
        expect_drift(tmp, "no gates in ci.yml", "add a size-gate step to ci.yml")

        # 2. No budget rows in docs/17.
        build_fixture(tmp)
        docs = (tmp / "docs/17-CI-GATES.md").read_text()
        docs = re.sub(r"(?m)^\| `outpost-[^`]+` \(.*\) \| \*\*\d+ MB\*\*.*\|$", "", docs)
        (tmp / "docs/17-CI-GATES.md").write_text(docs)
        expect_drift(tmp, "no budget rows in docs/17", "add a budget row to docs/17")

        # 3. A gate with no docs row.
        build_fixture(tmp)
        with (tmp / ".github/workflows/ci.yml").open("a") as f:
            f.write("\n        run: bash scripts/check-image-size.sh --image outpost-extra-ci --budget-mb 222 --fail-mb 333\n")
        expect_drift(tmp, "gate without docs row", "add a docs/17 row like:    | `outpost-extra-ci`")

        # 4. Budget drift: docs row budgets != gate flags.
        build_fixture(tmp)
        ci = (tmp / ".github/workflows/ci.yml").read_text()
        ci = ci.replace("--image outpost-backend:ci --budget-mb 300 --fail-mb 400", "--image outpost-backend:ci --budget-mb 350 --fail-mb 450")
        (tmp / ".github/workflows/ci.yml").write_text(ci)
        expect_drift(tmp, "budget drift (docs vs gate)", "docs row should read:")

        # 5. Missing badges/image-sizes.json.
        build_fixture(tmp)
        (tmp / "badges/image-sizes.json").unlink()
        expect_drift(tmp, "missing image-sizes.json", "regenerate badges/image-sizes.json")

        # 6. Measured drift: docs measured column != image-sizes.json.
        build_fixture(tmp)
        import json
        sizes = json.loads((tmp / "badges/image-sizes.json").read_text())
        sizes["web_mb"] = 71
        (tmp / "badges/image-sizes.json").write_text(json.dumps(sizes))
        expect_drift(tmp, "measured drift (docs vs json)", "docs row should read:")

        # 7. Docs row with no gate step.
        build_fixture(tmp)
        docs = (tmp / "docs/17-CI-GATES.md").read_text()
        row = "| `outpost-ghost-ci` (phantom image) | **999 MB** (1,000,000 B, commit `deadbeef`) | 500 MB | 600 MB |\n"
        idx = docs.index("| `outpost-airgap-ci`")
        nl = docs.index("\n", idx)
        docs = docs[: nl + 1] + "\n" + row + docs[nl + 1 :]
        (tmp / "docs/17-CI-GATES.md").write_text(docs)
        expect_drift(tmp, "docs row without gate", "add the ci.yml step:  bash scripts/check-image-size.sh --image outpost-ghost-ci")

        # 8. Missing 'Last measured' stamp line for a table row.
        build_fixture(tmp)
        docs = (tmp / "docs/17-CI-GATES.md").read_text()
        docs = re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-airgap-ci`.*$\n?", "", docs)
        (tmp / "docs/17-CI-GATES.md").write_text(docs)
        expect_drift(tmp, "missing stamp line", "stamp line should read:")

        # 9. Orphan stamp: a stamp with no table row.
        build_fixture(tmp)
        with (tmp / "docs/17-CI-GATES.md").open("a") as f:
            f.write("\n> **Last measured:** `outpost-ghost-ci` 500 MB — badge job @ `deadbeef` (2026-01-01).\n")
        expect_drift(tmp, "orphan stamp line", "remove that stamp line, or add a table row + gate step")

    print(f"Image-budget hint self-test: {len(FAILURES)} failed" if FAILURES else "Image-budget hint self-test: all drift directions print a usable fix hint")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
