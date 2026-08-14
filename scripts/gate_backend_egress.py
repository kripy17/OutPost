#!/usr/bin/env python3
"""gate_backend_egress.py — the backend/collector half of the air-gap story.

The frontend (gate_airgap_artifacts.py) and CLI (gate_cli_network.py) are
proven network-minimal. The backend is *not* zero-egress by design — it
enriches IPs/hashes (AbuseIPDB / VirusTotal / abuse.ch), detonates in real
sandboxes (Any.Run / Triage / Joe), resolves passive DNS (crt.sh / RDAP),
and delivers webhook/email notifications. Every one of those is an OPT-IN:
it fires only when an operator configures a key, a feed URL, or a webhook
target, and without config the stack runs in pure local mode.

This gate locks that contract statically:

  Backend (backend/app, excluding tests):
    - the ONLY permitted HTTP client library is `httpx`
      (forbidden: requests, aiohttp, urllib.request, http.client)
    - `httpx` may appear ONLY in the sanctioned modules below — a new module
      importing it forces a conscious decision + this allowlist update
    - raw client sockets are forbidden (`socket.socket(`, `from socket
      import socket`) — the app never opens its own connections

  Collectors (collectors, excluding tests):
    - `requests` may appear ONLY in common/shipper.py (the single seam that
      targets the env-configured OUTPOST_API_URL)
    - no other HTTP client (httpx / urllib.request / aiohttp) anywhere

Usage: python scripts/gate_backend_egress.py [--root backend/app]
Exit 0 = contract holds; 1 = a violation was found; 2 = scan error.
"""

import argparse
import ast
import sys
from pathlib import Path

BACKEND_HTTPX_SANCTIONED = {
    "api/routes_runs.py",
    "api/routes_intel.py",
    "api/routes_keys.py",
    "api/routes_samples.py",
    "services/enrichment.py",
    "services/footprint.py",  # crt.sh passive DNS + RDAP — operator-invoked lookups
    "services/sandbox.py",
    "services/notifications.py",
}

FORBIDDEN_CLIENTS = ("requests", "aiohttp", "urllib.request", "http.client")


def iter_py_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if "/tests/" in rel or rel.startswith("tests/"):
            continue
        if "__pycache__" in rel:
            continue
        files.append(path)
    return sorted(files)


def module_imports(tree: ast.AST, mod: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == mod or alias.name.startswith(mod + "."):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == mod or node.module.startswith(mod + ".")):
                return True
    return False


def uses_socket_socket(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "socket" and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "socket":
                    return True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "socket":  # from socket import socket; socket(...)
                # only flag when socket was imported from the socket module
                for imp in ast.walk(tree):
                    if isinstance(imp, ast.ImportFrom) and imp.module == "socket":
                        for a in imp.names:
                            if a.name == "socket":
                                return True
    return False


def scan_backend(root: Path) -> list[str]:
    hits = []
    for path in iter_py_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as e:
            hits.append(f"{rel}: syntax error ({e}) — cannot audit")
            continue
        for mod in FORBIDDEN_CLIENTS:
            if module_imports(tree, mod):
                hits.append(f"{rel}: forbidden HTTP client `{mod}` (use httpx, key/config-gated)")
        if module_imports(tree, "httpx") and rel not in BACKEND_HTTPX_SANCTIONED:
            hits.append(f"{rel}: httpx outside the sanctioned egress modules ({rel})")
        if uses_socket_socket(tree):
            hits.append(f"{rel}: raw socket.socket client usage")
    return hits


def scan_collectors(root: Path) -> list[str]:
    hits = []
    for path in iter_py_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as e:
            hits.append(f"{rel}: syntax error ({e}) — cannot audit")
            continue
        for mod in FORBIDDEN_CLIENTS + ("httpx",):
            if module_imports(tree, mod):
                if rel == "common/shipper.py" and mod == "requests":
                    continue  # the sanctioned shipper seam
                hits.append(f"{rel}: HTTP client `{mod}` outside the shipper seam")
        if uses_socket_socket(tree):
            hits.append(f"{rel}: raw socket.socket client usage")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=None, help="path to backend/app (default <root>/backend/app)")
    ap.add_argument("--collectors", default=None, help="path to collectors (default <root>/collectors)")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    backend = Path(args.backend) if args.backend else root / "backend" / "app"
    collectors = Path(args.collectors) if args.collectors else root / "collectors"

    if not backend.is_dir():
        print(f"ERROR: backend dir not found at {backend}", file=sys.stderr)
        return 2
    if not collectors.is_dir():
        print(f"ERROR: collectors dir not found at {collectors}", file=sys.stderr)
        return 2

    hits = scan_backend(backend) + scan_collectors(collectors)
    if hits:
        print(f"✗ BACKEND/COLLECTOR EGRESS VIOLATION ({len(hits)}):")
        for h in hits:
            print(f"    {h}")
        return 1

    n_be = len(iter_py_files(backend))
    n_co = len(iter_py_files(collectors))
    print(
        f"✓ Backend/collector egress gate: clean "
        f"({n_be} backend files, {n_co} collector files — httpx only in "
        f"{len(BACKEND_HTTPX_SANCTIONED)} sanctioned modules, requests only in shipper.py)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
