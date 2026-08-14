#!/usr/bin/env python3
"""Self-test for the image-budget gate's self-explaining hints.

Runs `gate_image_budget_docs.py` against a throwaway fixture tree (the real
ci.yml / docs/17 / check-image-size.sh / image-sizes.json copied into a temp
dir so the gate's ROOT resolves there), mutates one drift direction at a
time, and asserts two things for every direction:

  1. the gate exits 1 AND prints a `→ fix:` line (self-explaining), and
  2. applying the hinted fix — the corrected row/stamp/ci.yml line the
     hint points at — makes the gate exit 0 (the hint actually repairs).

Every drift direction the gate can report must be covered here, so the
self-explaining behavior can't silently regress: a refactor that drops a
hint, or a hint that no longer repairs what it claims to, fails this test.

Exit 0 only when all directions pass.
"""

import json
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


def docs_path(tmp: Path) -> Path:
    return tmp / "docs/17-CI-GATES.md"


def ci_path(tmp: Path) -> Path:
    return tmp / ".github/workflows/ci.yml"


def append_docs(tmp: Path, text: str) -> None:
    with docs_path(tmp).open("a") as f:
        f.write("\n" + text + "\n")


def append_ci(tmp: Path, text: str) -> None:
    with ci_path(tmp).open("a") as f:
        f.write("\n" + text + "\n")


def expect_drift(tmp: Path, name: str, hint_needle: str) -> None:
    """Assert the gate fails on the fixture AND prints a fix hint."""
    rc, out = run_gate(tmp)
    ok = rc == 1 and hint_needle in out
    check(name, ok, f"rc={rc}, hint={hint_needle!r} in output" if not ok else f"rc={rc}, hint present")


def expect_repair(tmp: Path, name: str, repair) -> None:
    """Assert applying the hinted fix makes the gate go green."""
    repair()
    rc, out = run_gate(tmp)
    check(f"{name} → repair green", rc == 0, f"rc={rc}\n{out}" if rc != 0 else "gate green after repair")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="img-budget-hints-") as td:
        tmp = Path(td)
        import json as _json

        # 0. Fresh fixture — gate passes, no hint lines.
        build_fixture(tmp)
        rc, out = run_gate(tmp)
        check("fresh fixture passes", rc == 0 and "→ fix:" not in out, f"rc={rc}")

        # 1. No size-gate steps in ci.yml.
        #    Repair (the hint's suggestion): re-add the gate steps.
        build_fixture(tmp)
        ci_path(tmp).write_text(
            re.sub(r"(?m)^.*check-image-size\.sh.*$", "", ci_path(tmp).read_text())
        )
        expect_drift(tmp, "no gates in ci.yml", "add a size-gate step to ci.yml")
        gate_lines = [l for l in SRC["ci"].read_text().splitlines() if "check-image-size.sh" in l]
        expect_repair(tmp, "no gates in ci.yml", lambda: append_ci(tmp, "\n".join(gate_lines)))

        # 2. No budget rows in docs/17.
        #    Repair: restore the real budget rows (the hint's suggestion).
        build_fixture(tmp)
        docs = docs_path(tmp).read_text()
        docs = re.sub(r"(?m)^\| `outpost-[^`]+` \(.*\) \| \*\*\d+ MB\*\*.*\|$", "", docs)
        docs_path(tmp).write_text(docs)
        expect_drift(tmp, "no budget rows in docs/17", "add a budget row to docs/17")
        rows = [l for l in SRC["docs"].read_text().splitlines() if re.match(r"^\| `outpost-[^`]+` \(.*\) \| \*\*\d+ MB\*\*", l)]
        expect_repair(tmp, "no budget rows in docs/17", lambda: append_docs(tmp, "\n".join(rows)))

        # 3. A gate with no docs row (real image — backend row removed).
        #    Repair: re-add the row (budgets from the gate, measured from the
        #    JSON) + its stamp line, exactly what the hints suggest.
        build_fixture(tmp)
        docs = docs_path(tmp).read_text()
        docs = re.sub(r"(?m)^\| `outpost-backend:ci` \(.*\) \|.*\|$", "", docs)
        docs = re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-backend:ci`.*$\n?", "", docs)
        docs_path(tmp).write_text(docs)
        expect_drift(tmp, "gate without docs row", "add a docs/17 row like:    | `outpost-backend:ci`")
        expect_repair(
            tmp, "gate without docs row",
            lambda: append_docs(
                tmp,
                "| `outpost-backend:ci` (…) | **191 MB** (200,772,677 B, commit `repair`) | 300 MB | 400 MB |\n"
                "> **Last measured:** `outpost-backend:ci` 191 MB — badge job @ `repair` (2026-08-14).",
            ),
        )

        # 4. Budget drift: docs row budgets != gate flags.
        #    Repair: apply the hint's corrected row (budgets from the gate).
        build_fixture(tmp)
        ci = ci_path(tmp).read_text()
        ci = ci.replace("--image outpost-backend:ci --budget-mb 300 --fail-mb 400", "--image outpost-backend:ci --budget-mb 350 --fail-mb 450")
        ci_path(tmp).write_text(ci)
        expect_drift(tmp, "budget drift (docs vs gate)", "docs row should read:")
        expect_repair(
            tmp, "budget drift (docs vs gate)",
            lambda: docs_path(tmp).write_text(
                re.sub(
                    r"(?m)^(\| `outpost-backend:ci` \(.*\) \| \*\*\d+ MB\*\*.*) \| \d+ MB \| \d+ MB \|$",
                    r"\1 | 350 MB | 450 MB |",
                    docs_path(tmp).read_text(),
                )
            ),
        )

        # 5. Missing badges/image-sizes.json.
        #    Repair: restore it (the hint points at regenerate/restore).
        build_fixture(tmp)
        (tmp / "badges/image-sizes.json").unlink()
        expect_drift(tmp, "missing image-sizes.json", "regenerate badges/image-sizes.json")
        expect_repair(tmp, "missing image-sizes.json", lambda: shutil.copy(SRC["sizes_json"], tmp / "badges/image-sizes.json"))

        # 6. Measured drift: docs measured column != image-sizes.json.
        #    Repair: fix the row AND the stamp to the JSON value (both hints).
        build_fixture(tmp)
        sizes = _json.loads((tmp / "badges/image-sizes.json").read_text())
        sizes["web_mb"] = 71
        (tmp / "badges/image-sizes.json").write_text(_json.dumps(sizes))
        expect_drift(tmp, "measured drift (docs vs json)", "docs row should read:")
        expect_repair(
            tmp, "measured drift (docs vs json)",
            lambda: docs_path(tmp).write_text(
                re.sub(
                    r"(?m)^(\| `outpost-web:ci` \(.*\) \| )\*\*\d+ MB\*\*(.* \| \d+ MB \| \d+ MB \|$)",
                    r"\1**71 MB**\2",
                    docs_path(tmp).read_text(),
                ).replace(
                    "> **Last measured:** `outpost-web:ci` 60 MB",
                    "> **Last measured:** `outpost-web:ci` 71 MB",
                )
            ),
        )

        # 7. Docs row with no gate step (real image — airgap gate removed).
        #    Repair: re-add the gate step, exactly the hint's ci_line.
        build_fixture(tmp)
        ci = ci_path(tmp).read_text()
        ci = re.sub(r"(?m)^.*check-image-size\.sh --image outpost-airgap-ci.*$", "", ci)
        ci_path(tmp).write_text(ci)
        expect_drift(tmp, "docs row without gate", "add the ci.yml step:  bash scripts/check-image-size.sh --image outpost-airgap-ci --budget-mb 2048 --fail-mb 2560")
        expect_repair(
            tmp, "docs row without gate",
            lambda: append_ci(tmp, "        run: bash scripts/check-image-size.sh --image outpost-airgap-ci --budget-mb 2048 --fail-mb 2560"),
        )

        # 8. Missing 'Last measured' stamp line for a table row.
        #    Repair: re-add the stamp line (hint prints it verbatim).
        build_fixture(tmp)
        docs = docs_path(tmp).read_text()
        docs = re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-airgap-ci`.*$\n?", "", docs)
        docs_path(tmp).write_text(docs)
        expect_drift(tmp, "missing stamp line", "stamp line should read:")
        expect_repair(
            tmp, "missing stamp line",
            lambda: append_docs(tmp, "> **Last measured:** `outpost-airgap-ci` 1724 MB — badge job @ `repair` (2026-08-14)."),
        )

        # 9. Orphan stamp: a stamp with no table row.
        #    Repair: remove the stamp line (the hint's first option).
        build_fixture(tmp)
        append_docs(tmp, "> **Last measured:** `outpost-ghost-ci` 500 MB — badge job @ `deadbeef` (2026-01-01).")
        expect_drift(tmp, "orphan stamp line", "remove that stamp line, or add a table row + gate step")
        expect_repair(
            tmp, "orphan stamp line",
            lambda: docs_path(tmp).write_text(
                re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-ghost-ci`.*$\n?", "", docs_path(tmp).read_text())
            ),
        )

    print(f"Image-budget hint self-test: {len(FAILURES)} failed" if FAILURES else "Image-budget hint self-test: all drift directions print a hint that repairs")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
