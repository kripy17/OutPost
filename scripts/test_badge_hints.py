#!/usr/bin/env python3
"""Self-test for the badge --check gate's self-explaining hints.

Runs `scripts/refresh-badges.sh --check` against a throwaway fixture tree
(the real backend/collectors/cli/frontend source, badges payloads,
docs/17, and the script itself copied into a temp dir so ROOT resolves
there), mutates one drift direction at a time, and asserts TWO things for
every direction:

  1. the gate exits 1 AND prints the `→ fix:` line carrying the exact
     corrected artifact (self-explaining), and
  2. applying the hinted fix makes the gate exit 0 (the hint actually
     repairs). The measured-vs-committed direction proves this with the
     REAL recovery command: after the drift, `refresh-badges.sh --recover`
     is run against the fixture (real gates from ci.yml, real docs/17,
     fake-docker measurements) and must regenerate the JSON + stamp to the
     measured value, converging back to the same green state as fresh.

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
    ".github/workflows/ci.yml": ROOT / ".github/workflows/ci.yml",  # --recover parses its gates
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


def run_recover(tmp: Path, fakebin: Path) -> tuple[int, str]:
    """Run the REAL `--recover` against the fixture.

    Exits 1 at the landing tail (the fixture has no origin remote, so the
    branch push fails by design) — the regeneration itself is what the
    caller asserts, via the follow-up --check."""
    env = dict(os.environ)
    env["PATH"] = f"{fakebin}:{env['PATH']}"
    env["PYTHON"] = str(VENV_PY)
    p = subprocess.run(
        ["bash", "scripts/refresh-badges.sh", "--recover"],
        cwd=tmp, env=env, capture_output=True, text=True,
    )
    return p.returncode, p.stdout + p.stderr


def init_git(tmp: Path) -> None:
    """Make the fixture a git repo so --recover's diff/commit tail works
    (and its `git config` stays repo-local instead of touching the global
    config)."""
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@test", "commit", "-qm", "baseline"],
        cwd=tmp, check=True,
    )


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


def expect_repair(tmp: Path, name: str, repair, fakebin: Path) -> None:
    """Assert applying the hinted fix makes the gate go green."""
    repair()
    rc, out = run_check(tmp, fakebin)
    check(f"{name} → repair green", rc == 0, f"rc={rc}\n{out}" if rc != 0 else "gate green after repair")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="badge-hints-") as td:
        tmp = Path(td)

        # 0. Fresh fixture — gate passes, no hint lines.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        rc, out = run_check(tmp, fakebin)
        check("fresh fixture passes", rc == 0 and "→ fix:" not in out and "badges fresh" in out, f"rc={rc}")

        # 1. Stale badge payload — the hint carries the corrected payload.
        #    Repair: write the hinted payload back (the committed total).
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        (tmp / "badges/tests.json").write_text('{"schemaVersion":1,"label":"tests","message":"0 passing","color":"2ea44f"}')
        expect_drift(tmp, "stale tests.json payload", "→ fix: write the payload below to badges/tests.json:", fakebin)
        rc, out = run_check(tmp, fakebin)
        total = json.loads((ROOT / "badges/tests.json").read_text())["message"]
        check("payload hint carries corrected payload", f'"message":"{total}' in out)
        expect_repair(
            tmp, "stale tests.json payload",
            lambda: (tmp / "badges/tests.json").write_text(f'{{"schemaVersion":1,"label":"tests","message":"{total}","color":"2ea44f"}}'),
            fakebin,
        )

        # 2. Missing 'Last measured' stamp — the hint carries the stamp line.
        #    Repair: re-add the stamp line with the JSON's own commit/date.
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        docs = (tmp / "docs/17-CI-GATES.md").read_text()
        docs = re.sub(r"(?m)^> \*\*Last measured:\*\* `outpost-airgap-ci`.*$\n?", "", docs)
        (tmp / "docs/17-CI-GATES.md").write_text(docs)
        expect_drift(tmp, "missing stamp line", "→ fix: add the line below to docs/17-CI-GATES.md:", fakebin)
        rc, out = run_check(tmp, fakebin)
        sizes = json.loads((tmp / "badges/image-sizes.json").read_text())
        airgap = sizes["airgap_mb"]
        check("stamp hint carries corrected stamp", f"`outpost-airgap-ci` {airgap} MB" in out)
        expect_repair(
            tmp, "missing stamp line",
            lambda: (tmp / "docs/17-CI-GATES.md").write_text(
                (tmp / "docs/17-CI-GATES.md").read_text()
                + f"\n> **Last measured:** `outpost-airgap-ci` {airgap} MB — badge job @ `{sizes['commit']}` ({sizes['date']}).\n"
            ),
            fakebin,
        )

        # 3. Measured != committed JSON (docker present) — the hint carries the JSON.
        #    Repair: rewrite the JSON with the measured value AND update the
        #    matching docs stamp (the gate prints the stamp hint as the
        #    follow-on — the same cascade --recover/--commit performs).
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        fakebin = write_fake_docker(tmp, 73400320)  # web 70 MB vs committed 60
        expect_drift(tmp, "measured vs committed drift", "→ fix: rewrite badges/image-sizes.json with the measured values:", fakebin)
        rc, out = run_check(tmp, fakebin)
        check("measured hint carries corrected JSON", '"web_mb":70' in out)
        # Repair via the REAL --recover command (the hint's suggestion): it
        # must regenerate image-sizes.json + the matching stamp to the
        # measured 70 MB, and the follow-up --check must converge back to
        # green — the same state the fresh fixture was in.
        def _recover_roundtrip():
            init_git(tmp)
            rc, out = run_recover(tmp, fakebin)
            # rc=1 is the no-remote push tail; the regeneration is what
            # matters, and expect_repair's --check proves it converged.
            check("recover ran (regenerated artifacts)", "recovered:" in out, f"rc={rc}")
        expect_repair(tmp, "measured vs committed drift (via --recover)", _recover_roundtrip, fakebin)

        # 4. Missing image-sizes.json.
        #    Repair: restore the committed JSON (the hint's restore option).
        build_fixture(tmp)
        fakebin = calibrate(tmp)
        (tmp / "badges/image-sizes.json").unlink()
        expect_drift(tmp, "missing image-sizes.json", "→ fix: restore badges/image-sizes.json", fakebin)
        expect_repair(
            tmp, "missing image-sizes.json",
            lambda: shutil.copy(ROOT / "badges/image-sizes.json", tmp / "badges/image-sizes.json"),
            fakebin,
        )

    print(f"Badge hint self-test: {len(FAILURES)} failed" if FAILURES else "Badge hint self-test: all drift directions print a hint that repairs")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
