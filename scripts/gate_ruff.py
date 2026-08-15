#!/usr/bin/env python3
"""Backend / CLI / collector lint gate — curated ruff.

verify.sh lints the frontend (eslint) but the Python trees had no gate, so
import hygiene and dead code could drift silently. This gate runs ruff under
the curated rule set in ruff.toml at the repo root: correctness (E/F) plus
import sorting (I), with the deck's intentional idioms excluded (Typer's
Option() defaults B008, collector env-setup imports E402, best-effort
exception swallows S110/S112/BLE001, and the nitpick/preview families).

Run:  .venv/bin/python scripts/gate_ruff.py \\
          [--paths backend/app cli/outpost collectors] [--config ruff.toml]
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv/bin/python"
RUFF_TOML = ROOT / "ruff.toml"
DEFAULT_PATHS = ["backend/app", "cli/outpost", "collectors"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", nargs="*", default=DEFAULT_PATHS)
    ap.add_argument("--config", default=str(RUFF_TOML))
    args = ap.parse_args()
    if not PY.exists():
        print("  FAIL — venv missing (run scripts/install.sh)", file=sys.stderr)
        return 1
    p = subprocess.run(
        [str(PY), "-m", "ruff", "check", *args.paths, "--config", args.config],
        capture_output=True,
        text=True,
    )
    if p.returncode == 0:
        print("ruff gate: clean under the curated rule set")
        return 0
    print(p.stdout, end="")
    print(p.stderr, end="")
    print("  FAIL — ruff found lint findings under the curated rule set (see above)")
    print(
        "  → fix: run `.venv/bin/python -m ruff check backend/app cli/outpost "
        "collectors/ --config ruff.toml --fix` to auto-fix the safe subset "
        "(import sorting, unused imports), fix the rest by hand, then re-run "
        "this gate"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
