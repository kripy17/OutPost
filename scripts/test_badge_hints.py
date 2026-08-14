#!/usr/bin/env python3
"""Self-test for the badge --check gate's self-explaining hints.

Runs `scripts/refresh-badges.sh --check` against a throwaway fixture tree
(the real backend/collectors/cli/frontend source, badges payloads,
docs/17, and the script itself copied into a temp dir so ROOT resolves
there), mutates one drift direction at a time, and asserts the gate exits 1
AND prints the `→ fix:` line carrying the exact corrected artifact.

The badge gate computes real counts (pytest --collect-only + vitest list),
so the fixture self-calibrates: it measures the real backend/collector/CLI
test counts, then generates a fake `npm` shim that emits exactly the
vitest-line count the committed tests.json total implies — the fresh run
then passes by construction, and each mutation below flips exactly one
drift direction:

  1. stale badge payload        → `→ fix: write the payload below to ...` + payload
  2. missing 'Last measured'    → `→ fix: add the line below to docs/17...` + stamp line
  3. measured != committed JSON → `→ fix: rewrite badges/image-sizes.json ...` + JSON
  4. missing image-sizes.json   → `→ fix: restore badges/image-sizes.json ...`

Every direction the gate can report must be covered, so the self-explaining
behavior can't silently regress. Exit 0 only when all pass.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / ".venv/bin/python"

SRC_DIRS = ("backend", "collectors", "cli", "frontend")
SRC_FILES = {
    "scripts/refresh-badges.sh": ROOT / "scripts/refresh-badges.sh",
    "scripts/check-image-size.sh": ROOT / "scripts/check-image-size.sh",
    "docs/17-CI-GATES.md": ROOT / "docs/17-CI-GATES.md",
}

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def build_fixture(tmp: Path) -> None:
    """Copy real sources into the fixture so the script's ROOT = tmp.

    Clears any previous fixture content first — each scenario rebuilds from
    scratch so mutations can't leak across directions."""
    for child in tmp.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    for d in SRC_DIRS:
        shutil.copytree(
            ROOT / d, tmp / d,
            ignore=shutil.ignore_patterns("__pycache__", "node_modules", ".venv", "dist", ".pytest_cache"),
        )
    for rel, src in SRC_FILES.items():
        (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, tmp / rel)
    shutil.copytree(ROOT / "badges", tmp / "badges")


def collect_count(cwd: Path) -> int:
    p = subprocess.run(
        [str(VENV_PY), "-m", "pytest", "--collect-only", "-q"],
        cwd=cwd, capture_output=True, text=True,
    )
    m = re.search(r"(\d+) tests collected", p.stdout)
    return int(m.group(1)) if m else 0


def write_fake_npm(tmp: Path, lines: int) -> Path:
    """npm shim printing `lines` lines (fake `npm exec -- vitest list`)."""
    bin_dir = tmp / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "npm").write_text(f"#!/usr/bin/env bash\nseq 1 {lines}\n")
    (bin_dir / "npm").chmod(0o755)
    return bin_dir


def write_fake_docker(tmp: Path, web_bytes: int) -> Path:
    """docker shim: inspect exists-checks pass, --format prints per-image sizes."""
    sizes = {
        "outpost-web:measure": web_bytes,
        "outpost-backend:measure": 200278016,   # 191 MB — committed value
        "outpost-airgap:measure": 1807745024,   # 1724 MB — committed value
    }
    lines = ["#!/usr/bin/env bash", 'if [[ "$*" == *--format* ]]; then', "  case \"$*\" in"]
    for img, b in sizes.items():
        lines.append(f"    *{img}) echo {b} ;;")
    lines.append("    *) exit 1 ;;")
    lines.append("  esac")
    lines.append("else")
    lines.append("  exit 0")
    lines.append("fi")
    bin_dir = tmp / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "docker").write_text("\n".join(lines) + "\n")
    (bin_dir / "docker").chmod(0o755)
    return bin_dir


def run_check(tmp: Path, fakebin: Path) -> tuple[int, str]:
    env = dict(os.environ)
    env["PATH"] = f"{fakebin}:{env['PATH']}"
    env["PYTHON"] = str(VENV_PY)
    p = subprocess.run(
        ["bash", "scripts/refresh-badges.sh", "--check"],
        cwd=tmp, env=env, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def calibrate(tmp: Path) -> Path:
    """Real backend/collector/CLI counts + committed tests.json total -> fake npm.

    FE = committed_total - be - col - cli, so the fresh --check passes by
    construction and the payload-drift hint carries the committed payload.
    Returns the fakebin dir; also returns nothing else — callers re-derive.
    """
    be = collect_count(tmp / "backend")
    col = collect_count(tmp / "collectors")
    cli = collect_count(tmp / "cli")
    total = json.loads((tmp / "badges/tests.json").read_text())["message"].split()[0]
    fe = int(total) - be - col - cli
    return write_fake_npm(tmp, fe)


def expect_drift(tmp: Path, name: str, hint_needle: str, fakebin: Path) -> None:
    rc, out = run_check(tmp, fakebin)
    ok = rc == 1 and hint_needle in out
    check(name, ok, f"rc={rc}, hint={hint_needle!r} in output" if not ok else f"rc={rc}, hint present")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="badge-hints-") as td:
        tmp = Path(td)

        # 0. Fresh fixture — gate passes, no hint lines.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        rc, out = run_check(tmp, fakebin)
        check("fresh fixture passes", rc == 0 and "→ fix:" not in out and "badges fresh" in out, f"rc={rc}")

        # 1. Stale badge payload — the hint carries the corrected payload.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        (tmp / "badges/tests.json").write_text('{"schemaVersion":1,"label":"tests","message":"0 passing","color":"2ea44f"}')
        expect_drift(tmp, "stale tests.json payload", "→ fix: write the payload below to badges/tests.json:", fakebin)
        rc, out = run_check(tmp, fakebin)
        total = json.loads((ROOT / "badges/tests.json").read_text())["message"]
        check("payload hint carries corrected payload", f'"message":"{total}' in out)

        # 2. Missing 'Last measured' stamp — the hint carries the stamp line.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        docs = (tmp / "docs/17-CI-GATES.md").read_text()
        docs = re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-airgap-ci`.*$\n?", "", docs)
        (tmp / "docs/17-CI-GATES.md").write_text(docs)
        expect_drift(tmp, "missing stamp line", "→ fix: add the line below to docs/17-CI-GATES.md:", fakebin)
        rc, out = run_check(tmp, fakebin)
        airgap = json.loads((tmp / "badges/image-sizes.json").read_text())["airgap_mb"]
        check("stamp hint carries corrected stamp", f"`outpost-airgap-ci` {airgap} MB" in out)

        # 3. Measured != committed JSON (docker present) — the hint carries the JSON.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        fakebin = write_fake_docker(tmp, 73400320)  # web 70 MB vs committed 60
        expect_drift(tmp, "measured vs committed drift", "→ fix: rewrite badges/image-sizes.json with the measured values:", fakebin)
        rc, out = run_check(tmp, fakebin)
        check("measured hint carries corrected JSON", '"web_mb":70' in out)

        # 4. Missing image-sizes.json.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        (tmp / "badges/image-sizes.json").unlink()
        expect_drift(tmp, "missing image-sizes.json", "→ fix: restore badges/image-sizes.json", fakebin)

    print(f"Badge hint self-test: {len(FAILURES)} failed" if FAILURES else "Badge hint self-test: all drift directions print the corrected payload/stamp")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
