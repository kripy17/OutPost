#!/usr/bin/env python3
"""Self-test for check-image-size.sh's hard-ceiling fix hint.

The image-size gate's HARD-CEILING failure dumps the offending layers
(`docker history`) but, until this test existed, ended at the dump — no
actionable fix. The gate now prints a `→ fix:` line in BOTH sub-branches
(the docker layer-dump branch and the offline no-layer-data branch), telling
the operator what to rebuild and how to confirm.

This self-test runs the gate fully offline (`--size-bytes` + an optional
`HISTORY_SOURCE` sample file — the same offline seam the gate documents for
its own failure path) and asserts:

  1. a compliant size passes with NO `→ fix:` line (fresh, green),
  2. an over-ceiling size fails AND prints the `→ fix:` line (with the
     layer dump when layer data is available; with the offline note when
     it isn't), and
  3. applying the hint's repair — a compliant size — turns the gate green
     again (the hint actually converges).

Exit 0 only when all assertions pass.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from hint_coverage_map import gate_for

GATE = ROOT / "scripts" / gate_for(Path(__file__).name)

# A `docker history --no-trunc --human=false --format '{{.Size}} {{.CreatedBy}}'`
# sample (newest layer first) — an oversized COPY dwarfs the base.
LAYER_SAMPLE = "\n".join(
    [
        "125829120 COPY /app/node_modules /app/node_modules",
        "41943040 RUN npm ci",
        "0 ENV NODE_ENV=production",
        "57671680 FROM node:20-alpine AS build",
    ]
)

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def build_fixture(tmp: Path) -> Path:
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(GATE, tmp / "scripts/check-image-size.sh")
    return tmp / "scripts/check-image-size.sh"


def run_gate(gate: Path, args: list[str], history: str | None = None) -> tuple[int, str]:
    env = dict(os.environ)
    hist_file = None
    if history is not None:
        hist_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".history")
        hist_file.write(history)
        hist_file.close()
        env["HISTORY_SOURCE"] = hist_file.name
    else:
        env.pop("HISTORY_SOURCE", None)
    try:
        p = subprocess.run(
            ["bash", str(gate)] + args,
            capture_output=True, text=True, env=env,
        )
        return p.returncode, p.stdout + p.stderr
    finally:
        if hist_file is not None:
            os.unlink(hist_file.name)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="size-hints-") as td:
        tmp = Path(td)
        gate = build_fixture(tmp)

        OVER = ["--size-bytes", "209715200", "--budget-mb", "100", "--fail-mb", "150"]  # 200 MB > 150
        OK = ["--size-bytes", "83886080", "--budget-mb", "100", "--fail-mb", "150"]     # 80 MB <= 100

        # 0. Fresh — a compliant size passes with no hint line.
        rc, out = run_gate(gate, OK)
        check("fresh fixture passes", rc == 0 and "→ fix:" not in out, f"rc={rc}")

        # 1. Hard ceiling exceeded WITH layer data — the hint plus the dump.
        rc, out = run_gate(gate, OVER, history=LAYER_SAMPLE)
        ok = rc == 1 and "→ fix:" in out and "Likely bloat source" in out and "COPY /app/node_modules" in out
        check("ceiling exceeded (layer data) → rc=1 + fix hint + layer dump", ok, f"rc={rc}")
        check(
            "fix hint carries the confirm command",
            "bash scripts/check-image-size.sh --image " in out,
            "confirm command missing from hint",
        )
        # Repair: the hint says rebuild lean — a compliant size goes green.
        rc, out = run_gate(gate, OK, history=LAYER_SAMPLE)
        check("ceiling exceeded (layer data) → repair green", rc == 0 and "→ fix:" not in out, f"rc={rc}")

        # 2. Hard ceiling exceeded offline (no image, no layer data) — the
        #    hint still prints, with the offline note instead of a dump.
        rc, out = run_gate(gate, OVER)
        ok = rc == 1 and "→ fix:" in out and "(offline" in out and "Likely bloat source" not in out
        check("ceiling exceeded (offline) → rc=1 + fix hint + offline note", ok, f"rc={rc}")
        rc, out = run_gate(gate, OK)
        check("ceiling exceeded (offline) → repair green", rc == 0 and "→ fix:" not in out, f"rc={rc}")

    print(f"Size-gate hint self-test: {len(FAILURES)} failed" if FAILURES else "Size-gate hint self-test: hard-ceiling failure prints a repair hint (both branches)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
