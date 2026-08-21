"""Image-budget docs gate — docs/17's size table must match reality.

Three static cross-checks so the "Image-size budgets — measured baselines"
table in docs/17 can never drift apart from the actual CI configuration:

  1. Every size-gate invocation in .github/workflows/ci.yml
     (`check-image-size.sh --image X [--budget-mb N --fail-mb M]`) must have
     a row in the docs/17 table, and the row's soft/hard budgets must equal
     the flags actually passed — resolving the script's own defaults when a
     step relies on them (the web gate passes no flags and uses the
     100/150 MB defaults from check-image-size.sh).
  2. The table's measured column must match badges/image-sizes.json (the
     committed stamp data the refresh job writes) — the third image and
     any future one included.
  3. Symmetrically, a table row with no corresponding gate step is drift
     too (budget documented but not enforced).

Parsing is regex-over-source (no yaml dependency): the gates are single
`run: bash scripts/check-image-size.sh ...` lines, and the table rows have
a fixed shape. Exit 0 only when everything matches.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github/workflows/ci.yml"
DOCS = ROOT / "docs/17-CI-GATES.md"
GATE = ROOT / "scripts/check-image-size.sh"
SIZES = ROOT / "badges/image-sizes.json"

# docs/17 image -> key in badges/image-sizes.json
JSON_KEY = {
    "outpost-web:ci": "web_mb",
    "outpost-backend:ci": "backend_mb",
    "outpost-airgap-ci": "airgap_mb",
}

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def hint(text: str) -> None:
    """Self-explaining fix suggestion, printed right after a FAIL."""
    print(f"      → fix: {text}")


def ci_line(img: str, soft: int, hard: int, defaults: tuple[int, int]) -> str:
    """The canonical check-image-size.sh invocation for the given budgets.

    Flags are omitted when they equal the script's own defaults (the web
    gate's style), so the suggested line stays minimal."""
    if (soft, hard) == defaults:
        return f"bash scripts/check-image-size.sh --image {img}"
    return f"bash scripts/check-image-size.sh --image {img} --budget-mb {soft} --fail-mb {hard}"


def script_defaults() -> tuple[int, int]:
    """The effective budgets when a gate step passes no flags."""
    text = GATE.read_text()
    soft = int(re.search(r"^BUDGET_MB=(\d+)", text, re.M).group(1))
    hard = int(re.search(r"^FAIL_MB=(\d+)", text, re.M).group(1))
    return soft, hard


def ci_budgets(defaults: tuple[int, int]) -> dict[str, tuple[int, int]]:
    """image -> (soft, hard) as actually enforced by the workflow steps."""
    result: dict[str, tuple[int, int]] = {}
    for line in CI.read_text().splitlines():
        if "check-image-size.sh" not in line:
            continue
        img = re.search(r"--image\s+([\w:.\-]+)", line)
        if not img:
            continue
        soft = re.search(r"--budget-mb\s+(\d+)", line)
        hard = re.search(r"--fail-mb\s+(\d+)", line)
        result[img.group(1)] = (
            int(soft.group(1)) if soft else defaults[0],
            int(hard.group(1)) if hard else defaults[1],
        )
    return result


def docs_table() -> dict[str, tuple[int, int, int, str]]:
    """image -> (measured_mb, soft, hard, raw_row) from the docs/17 table.

    The raw row is kept so failures can print the exact corrected line."""
    result: dict[str, tuple[int, int, int, str]] = {}
    row_re = re.compile(
        r"^\|\s*`([^`]+)`\s*\(.*?\)\s*\|\s*\*\*(\d+) MB\*\*.*?\|\s*(\d+) MB\s*\|\s*(\d+) MB\s*\|$"
    )
    for line in DOCS.read_text().splitlines():
        m = row_re.match(line)
        if m:
            result[m.group(1)] = (int(m.group(2)), int(m.group(3)), int(m.group(4)), line)
    return result


def docs_stamps() -> dict[str, int]:
    """image -> measured MB from the 'Last measured' stamp lines.

    One line per image — the trend data every table row must carry."""
    result: dict[str, int] = {}
    pat = re.compile(r"^> \*\*Last measured:\*\* `([^`]+)`\s+(\d+) MB", re.M)
    for m in pat.finditer(DOCS.read_text()):
        result[m.group(1)] = int(m.group(2))
    return result


def main() -> int:
    if not CI.exists() or not DOCS.exists():
        print("  FAIL — missing ci.yml or docs/17-CI-GATES.md", file=sys.stderr)
        return 1

    defaults = script_defaults()
    enforced = ci_budgets(defaults)
    table = docs_table()

    if not enforced:
        check("ci.yml size-gate invocations found", False, "no check-image-size.sh steps")
        hint(f"add a size-gate step to ci.yml, e.g.:  {ci_line('outpost-web:ci', defaults[0], defaults[1], defaults)}")
    if not table:
        check("docs/17 size-budget table found", False, "no budget rows parsed")
        hint(f"add a budget row to docs/17 like:  | `outpost-web:ci` (…) | **?? MB** | {defaults[0]} MB | {defaults[1]} MB |   (the measured cell fills from the first gate run)")

    # 1. Every enforced gate must be documented with the same budgets.
    for img, (soft, hard) in sorted(enforced.items()):
        if img not in table:
            check(f"docs row for {img}", False, f"gate enforces {soft}/{hard} MB but the table has no row")
            hint(f"add a docs/17 row like:    | `{img}` (…) | **?? MB** | {soft} MB | {hard} MB |   (the measured cell fills from the first gate run)")
            hint(f"and its stamp line:        > **Last measured:** `{img}` ?? MB — badge job @ `…` (…).")
            continue
        measured, d_soft, d_hard, raw = table[img]
        check(
            f"docs budgets match the gate for {img}",
            d_soft == soft and d_hard == hard,
            f"docs {d_soft}/{d_hard} MB vs gate {soft}/{hard} MB",
        )
        if d_soft != soft or d_hard != hard:
            corrected = re.sub(r"\| (\d+) MB \| (\d+) MB \|\s*$", f"| {soft} MB | {hard} MB |", raw)
            hint(f"docs row should read:  {corrected}   (matching the gate)")
            hint(f"or the ci.yml line should read:  {ci_line(img, d_soft, d_hard, defaults)}   (matching the docs)")

    # 2. The measured column must match the committed stamp data.
    if SIZES.exists():
        data = json.loads(SIZES.read_text())
        for img, (measured, _s, _h, raw) in sorted(table.items()):
            key = JSON_KEY.get(img)
            if key is None:
                check(f"stamp key for {img}", False, "no badges/image-sizes.json key mapped")
                continue
            want = data.get(key)
            ok = isinstance(want, int) and want == measured
            check(
                f"docs measured matches stamp data for {img}",
                ok,
                f"docs {measured} MB vs image-sizes.json {want} MB",
            )
            if not ok and isinstance(want, int):
                corrected = re.sub(r"\*\*\d+ MB\*\*", f"**{want} MB**", raw)
                hint(f"docs row should read:  {corrected}")
    else:
        check("badges/image-sizes.json present", False, "missing — measured column not checkable")
        hint("regenerate badges/image-sizes.json + the stamps with:  bash scripts/refresh-badges.sh --commit   (or --recover for the whole size story)")

    # 3. A documented row with no gate is drift too.
    for img in sorted(table):
        if img not in enforced:
            _m, d_soft, d_hard, _raw = table[img]
            check(f"gate step for {img}", False, "docs row has no check-image-size.sh invocation")
            hint(f"add the ci.yml step:  {ci_line(img, d_soft, d_hard, defaults)}")

    # 4. Every table row must carry its own 'Last measured' stamp line with
    #    the measured value — a fourth image can't be documented without its
    #    trend data.
    stamps = docs_stamps()
    for img, (measured, _s, _h, _raw) in sorted(table.items()):
        want = stamps.get(img)
        ok = want is not None and want == measured
        check(
            f"stamp line for {img}",
            ok,
            f"stamp {want} MB vs measured {measured} MB" if want is not None else "no 'Last measured' stamp line",
        )
        if not ok:
            hint(f"stamp line should read:  > **Last measured:** `{img}` {measured} MB — badge job @ `…` (…).")

    # 5. A stamp with no table row is drift too.
    for img in sorted(stamps):
        if img not in table:
            check(f"table row for stamped {img}", False, "stamp line has no table row")
            hint(f"remove that stamp line, or add a table row + gate step for `{img}`")

    print(f"Image-budget docs gate: {len(FAILURES)} failed" if FAILURES else "Image-budget docs gate: all tables, stamps, gates, and stamp data agree")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
