#!/usr/bin/env python3
"""Self-test for the transition-comment bite drill (bite_triage_comment.py).

The drill's job is to prove the comment contract's tests still bite — so
the drill itself needs the same proof. This pins its two safety properties
and its happy path against a throwaway fixture tree (the three real files
copied into a temp dir, with OUTPOST_BITE_ROOT pointing the drill there):

  1. FAIL-LOUD on anchor drift: if a file's shape changes so an anchor is
     no longer exactly one occurrence (here: the backend anchor duplicated
     verbatim, indentation included), the drill must exit 1 with the
     count-mismatch message and NOT edit the file — the drill never edits
     blindly.
  2. CLEAN ROUND-TRIP: with intact anchors, the drill applies and restores
     every layer's bite in fixture mode and exits 0.
  3. SELF-HEAL: a file left bitten (as if the drill were SIGKILLed between
     apply and restore) is restored by the final sweep — the safety net
     actually works.

Anchors come from the drill module itself (imported after the fixture env
is set), so this can't drift from what the drill actually searches for.
Exit 0 only when all three hold. Static + stdlib; the fixture mode skips
the real test runs, so this runs in well under a second.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRILL = ROOT / "scripts" / "bite_triage_comment.py"

# The three files the drill bites, relative to the project root.
FILES = [
    Path("backend") / "app" / "api" / "routes_alerts.py",
    Path("frontend") / "src" / "test" / "triageLifecycle.test.tsx",
    Path("cli") / "tests" / "test_triage_lifecycle.py",
]

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def build_fixture() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="bite-drill-"))
    for rel in FILES:
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
    return tmp


def run_drill(fixture: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, OUTPOST_BITE_ROOT=str(fixture))
    # check=False is deliberate: the self-test inspects the drill's exit code.
    return subprocess.run([sys.executable, str(DRILL)], env=env, capture_output=True, text=True, timeout=120, check=False)


def main() -> int:
    fixture = build_fixture()
    # Set in THIS process too — the import below resolves ROOT at import time.
    os.environ["OUTPOST_BITE_ROOT"] = str(fixture)
    sys.path.insert(0, str(ROOT / "scripts"))
    import bite_triage_comment as drill_mod  # noqa: PLC0415 — needs the env first

    try:
        # 1) Fail-loud: duplicate the FULL backend anchor block verbatim, so
        #    the drill's uniqueness check sees count == 2 and must refuse.
        backend = fixture / FILES[0]
        src = backend.read_text()
        b_old = drill_mod.BITES[0]["old"]
        assert src.count(b_old) == 1, "fixture setup: backend anchor should start as exactly one"
        backend.write_text(src.replace(b_old, b_old + "\n" + b_old))
        corrupted = backend.read_text()

        r = run_drill(fixture)
        check(
            "fail-loud: duplicated anchor exits 1 with the count message",
            r.returncode != 0 and "expected exactly 1" in (r.stdout + r.stderr),
            f"rc={r.returncode}",
        )
        check("fail-loud: the corrupted file was NOT edited", backend.read_text() == corrupted)

        # 2) Clean round-trip: restore the fixture to intact anchors.
        backend.write_text(corrupted.replace(b_old + "\n" + b_old, b_old))
        r = run_drill(fixture)
        check("clean fixture: drill exits 0", r.returncode == 0, f"rc={r.returncode}")
        if r.returncode != 0:
            print((r.stdout + r.stderr)[-2000:])

        # 3) Self-heal: simulate a SIGKILL between apply and restore (the
        #    bite marker REPLACED the anchor in place, mid-file), then run
        #    the drill's final sweep directly and confirm it restores.
        webapp = fixture / FILES[1]
        wsrc = webapp.read_text()
        w_old = drill_mod.BITES[1]["old"]
        w_new = drill_mod.BITES[1]["new"]
        assert w_old in wsrc, "fixture setup: webapp anchor should be present"
        webapp.write_text(wsrc.replace(w_old, w_new))
        drill_mod._self_heal()
        healed = webapp.read_text()
        check("self-heal: left-behind bite is restored", w_new not in healed and healed == wsrc)
    finally:
        os.environ.pop("OUTPOST_BITE_ROOT", None)
        shutil.rmtree(fixture, ignore_errors=True)

    if FAILURES:
        print(f"\nDrill self-test FAILED — {len(FAILURES)}: {', '.join(FAILURES)}")
        return 1
    print("\nDrill self-test passed — fail-loud, clean round-trip, and self-heal all hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
