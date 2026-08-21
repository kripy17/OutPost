#!/usr/bin/env python3
"""Code-level dead-reference sweep.

Three checks against the frontend and backend tests:

  1. Routes — every src/routes/*.tsx must be referenced (imported/lazy) from
     somewhere in src (the router lives in src/main.tsx).
  2. api.ts exports — every exported function/const must have at least one
     caller outside src/lib/api.ts. Reports two tiers: DEAD (zero references
     anywhere) and TESTS-ONLY (referenced only by test files).
  3. Test helpers — backend conftest fixtures with zero references in the
     test files, and exported helpers in frontend test-helper modules with
     zero importers.

Usage: .venv/bin/python scripts/dead_refs.py
Exit 0 always (reporting tool); findings are printed for triage.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "frontend", "src")
TESTS = os.path.join(ROOT, "backend", "app", "tests")


def walk(path: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "node_modules")]
        for f in filenames:
            if f.endswith((".ts", ".tsx", ".py")):
                out.append(os.path.join(dirpath, f))
    return out


def find_uses(name: str, files: list[str], exclude: set[str]) -> int:
    """Count files (not occurrences) containing `name` as a whole word."""
    pat = re.compile(rf"\b{re.escape(name)}\b")
    n = 0
    for f in files:
        if f in exclude:
            continue
        try:
            text = open(f, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if pat.search(text):
            n += 1
    return n


def main() -> None:
    findings: list[tuple[str, str]] = []

    # -- 1. Routes ---------------------------------------------------------
    route_dir = os.path.join(SRC, "routes")
    src_files = walk(SRC)
    src_set = {os.path.normpath(f) for f in src_files}
    for f in sorted(os.listdir(route_dir)):
        if not f.endswith(".tsx"):
            continue
        base = f[: -len(".tsx")]
        ref = f"routes/{base}"
        used = find_uses(ref, src_files, set())
        if used == 0:
            findings.append(("route", f"{f} — never imported/linked in src"))

    # -- 2. api.ts exports -------------------------------------------------
    api = os.path.join(SRC, "lib", "api.ts")
    if os.path.exists(api):
        text = open(api, encoding="utf-8").read()
        # exports: `export function name`, `export async function name`,
        # `export const name = ...` (skip types — type exports live in types/)
        exports = re.findall(
            r"^export (?:async )?(?:function|const) ([A-Za-z0-9_]+)", text, re.M
        )
        api_files = [f for f in src_files if f != api]
        for name in sorted(set(exports)):
            if name in ("BASE_URL", "DEFAULT_LIMIT"):  # internal constants
                continue
            uses = find_uses(name, api_files, set())
            if uses == 0:
                findings.append(("api-dead", f"{name}() — zero callers in src"))
            else:
                tests_only = find_uses(
                    name,
                    [f for f in api_files if "/test/" in f.replace("\\", "/")],
                    set(),
                )
                non_test = find_uses(
                    name,
                    [f for f in api_files if "/test/" not in f.replace("\\", "/")],
                    set(),
                )
                if non_test == 0 and tests_only > 0:
                    findings.append(("api-tests-only", f"{name}() — called only by tests"))

    # -- 3a. Backend conftest fixtures -------------------------------------
    for cf in ("conftest.py",):
        cf_path = os.path.join(TESTS, cf)
        if not os.path.exists(cf_path):
            continue
        lines = open(cf_path, encoding="utf-8").read().splitlines()
        test_files = walk(TESTS)
        for i, line in enumerate(lines):
            m = re.match(r"^def ([a-z0-9_]+)\(", line)
            if not m:
                continue
            name = m.group(1)
            # Decorators immediately above the def.
            decorators = []
            j = i - 1
            while j >= 0 and lines[j].strip().startswith("@"):
                decorators.append(lines[j])
                j -= 1
            # Autouse fixtures apply to every test implicitly — zero explicit
            # references is expected, not dead code.
            if any("autouse=True" in d for d in decorators):
                continue
            uses = find_uses(name, test_files, {cf_path})
            if uses == 0:
                findings.append(("fixture", f"{name} — conftest fixture never used"))

    # -- 3b. Frontend test-helper exports ----------------------------------
    helper_dir = os.path.join(SRC, "test")
    if os.path.isdir(helper_dir):
        for f in sorted(os.listdir(helper_dir)):
            if not f.endswith((".ts", ".tsx")):
                continue
            path = os.path.join(helper_dir, f)
            text = open(path, encoding="utf-8", errors="ignore").read()
            # Only treat files that export helpers as helper modules.
            if "export" not in text:
                continue
            exports = re.findall(r"^export (?:function|const) ([A-Za-z0-9_]+)", text, re.M)
            others = [p for p in src_files if p != path]
            for name in sorted(set(exports)):
                uses = find_uses(name, others, set())
                if uses == 0:
                    findings.append(("test-helper", f"{f}: {name} — exported, never imported"))

    # -- Report ------------------------------------------------------------
    if not findings:
        print("No dead references found.")
        return
    by_kind: dict[str, list[str]] = {}
    for kind, msg in findings:
        by_kind.setdefault(kind, []).append(msg)
    for kind, msgs in sorted(by_kind.items()):
        print(f"\n== {kind} ({len(msgs)}) ==")
        for m in msgs:
            print(f"  {m}")


if __name__ == "__main__":
    sys.exit(main())
