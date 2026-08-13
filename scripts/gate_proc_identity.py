"""Gate: no event-level `process_name` identity read may exist without an
`exe_path` resolution nearby.

The identity-fallback pass made every process-identity read resolve through
`_proc_name` (process_name → exe_path basename) so nameless rows still match.
This gate locks that invariant so a future rule can't regress to
name-only reads that silently skip nameless rows.

AST-based: for each file, every direct `get("process_name")` call must live in
a function that ALSO resolves exe_path — either a literal `get("exe_path")` in
its body, or a call to a known identity helper (_proc_name / _node_name) which
implements the fallback. The helpers themselves must contain the literal
exe_path read (the fallback is the whole point of them).

Run:  python scripts/gate_proc_identity.py
Exit: 0 = clean, 1 = a read without exe_path resolution was found.
"""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FILES = [
    ROOT / "backend/app/services/detection.py",
    ROOT / "backend/app/services/process_tree.py",
    ROOT / "backend/app/services/baseline.py",
    # CLI parity: terminal_views proc_label() and the campaigns detail row
    # must keep the same process_name → exe_path fallback.
    ROOT / "cli/outpost/rendering/terminal_views.py",
    ROOT / "cli/outpost/commands/campaigns.py",
]

# Helpers whose job IS the process_name → exe_path fallback. A call to one of
# these satisfies the "resolves exe_path" requirement for the caller.
HELPERS = {"_proc_name", "_node_name", "_kinds", "proc_label"}


def _reads_exe_path(node: ast.AST) -> bool:
    """Literal get("exe_path") anywhere in the subtree, or a call to a helper."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if (
                sub.func.attr == "get"
                and sub.args
                and isinstance(sub.args[0], ast.Constant)
                and sub.args[0].value == "exe_path"
            ):
                return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id in HELPERS:
                return True
    return False


def _process_name_reads(func: ast.FunctionDef) -> list[ast.Call]:
    out = []
    for sub in ast.walk(func):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if (
                sub.func.attr == "get"
                and sub.args
                and isinstance(sub.args[0], ast.Constant)
                and sub.args[0].value == "process_name"
            ):
                out.append(sub)
    return out


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError as exc:  # pragma: no cover
        return [f"{path}: syntax error: {exc}"]
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        reads = _process_name_reads(node)
        if not reads:
            continue
        if node.name in HELPERS and not _reads_exe_path(node):
            problems.append(
                f"{path}:{node.lineno} helper {node.name} reads process_name "
                "but never resolves exe_path — the fallback is its whole job"
            )
        elif node.name not in HELPERS and not _reads_exe_path(node):
            for r in reads:
                problems.append(
                    f"{path}:{r.lineno} process_name read in {node.name} with no "
                    "exe_path resolution nearby (use _proc_name or pair with exe_path)"
                )
    return problems


def main() -> int:
    problems: list[str] = []
    for path in FILES:
        if path.exists():
            problems.extend(check_file(path))
    if problems:
        print(f"✗ process-identity gate: {len(problems)} problem(s)")
        for p in problems:
            print(f"  {p}")
        return 1
    print("✓ process-identity gate: every process_name read resolves exe_path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
