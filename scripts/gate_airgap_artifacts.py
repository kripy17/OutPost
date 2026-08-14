#!/usr/bin/env python3
"""gate_airgap_artifacts.py — static air-gap gate on the shipped frontend build.

The README's air-gap guarantee ("zero external HTTP requests") is proven at
runtime by the Playwright e2e gates — but only for the flows those two scripts
drive. This gate covers what the e2e can't: the HTML/CSS entry and EVERY
lazy-loaded JS chunk, statically, without a browser, in milliseconds.

It deliberately matches *dependency syntax*, not raw URL strings, so
display/docs/demo literals cannot false-positive:
  - SVG namespace URIs (http://www.w3.org/...)
  - demo C2 IPs (http://203.0.113.88 — TEST-NET-3, display-only)
  - webhook example URLs (hooks.slack.com / hooks.example.com)
  - doc links (react.dev, reactrouter.com, github.com, tailwindcss.com comment)

Scanned patterns:
  index.html  — any external origin in src= / href= / srcset= / url() /
                @import / @font-face (this is where the fonts.gstatic.com CDN
                link lived before the fonts were self-hosted).
  *.css       — url(<external>) and @import of an external origin.
  *.js        — fetch( / EventSource( / WebSocket( / XMLHttpRequest.open( /
                import( followed by a quoted external http(s)/wss literal.

Usage: python scripts/gate_airgap_artifacts.py [--dist frontend/dist]
Exit 0 = clean; 1 = an external dependency reference was found.
"""

import argparse
import re
import sys
from pathlib import Path

LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def external_url(url: str) -> bool:
    """True if url is an external (non-loopback) http(s) or protocol-relative ref."""
    url = url.strip().strip("\"'").strip()
    if not url:
        return False
    if url.startswith("//"):  # protocol-relative
        host = url[2:].split("/", 1)[0].split(":", 1)[0].lower()
        return host not in LOOPBACK
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", url)
    if not m:
        return False  # relative or non-URL (data:, #hash, /asset)
    scheme = m.group(1).lower()
    if scheme not in ("http", "https", "wss", "ws"):
        return False  # data:, mailto:, blob: etc. are not external fetches
    host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    return host not in LOOPBACK


def scan_html(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    hits = []
    # src=/href=/srcset= attribute values (external origins only).
    for m in re.finditer(r'\b(?:src|href)="([^"]+)"', text):
        if external_url(m.group(1)):
            hits.append(f"{path.name}: attr {m.group(1)}")
    # url(...) and @import targets anywhere in the HTML.
    for m in re.finditer(r"url\(\s*([^)]+)\)", text):
        if external_url(m.group(1)):
            hits.append(f"{path.name}: url({m.group(1).strip()})")
    for m in re.finditer(r"@import\s+([^;]+)", text):
        if external_url(m.group(1)):
            hits.append(f"{path.name}: @import {m.group(1).strip()}")
    return hits


def scan_css(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    hits = []
    for m in re.finditer(r"url\(\s*([^)]+)\)", text):
        if external_url(m.group(1)):
            hits.append(f"{path.name}: url({m.group(1).strip()})")
    for m in re.finditer(r"@import\s+([^;]+)", text):
        if external_url(m.group(1)):
            hits.append(f"{path.name}: @import {m.group(1).strip()}")
    return hits


def scan_js(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    hits = []
    # fetch("https://...") / EventSource / WebSocket / import("https://...")
    for m in re.finditer(
        r"\b(fetch|EventSource|WebSocket|import)\s*\(\s*([\"'])([a-zA-Z][a-zA-Z0-9+.-]*://[^\"']+)\2",
        text,
    ):
        if external_url(m.group(3)):
            hits.append(f"{path.name}: {m.group(1)}({m.group(3)[:64]})")
    # XMLHttpRequest .open("GET", "https://...")
    for m in re.finditer(
        r"\.open\(\s*[\"'][A-Za-z]+[\"']\s*,\s*([\"'])([a-zA-Z][a-zA-Z0-9+.-]*://[^\"']+)\1",
        text,
    ):
        if external_url(m.group(2)):
            hits.append(f"{path.name}: xhr.open({m.group(2)[:64]})")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default=None, help="path to the built frontend/dist directory")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    dist = Path(args.dist) if args.dist else root / "frontend" / "dist"
    if not dist.is_dir():
        print(f"ERROR: build output not found at {dist} — run the frontend build first.", file=sys.stderr)
        return 2

    index_html = dist / "index.html"
    if not index_html.is_file():
        print(f"ERROR: {index_html} missing — not a Vite build output.", file=sys.stderr)
        return 2

    hits: list[str] = []
    hits += scan_html(index_html)
    for css in sorted(dist.glob("assets/*.css")):
        hits += scan_css(css)
    for js in sorted(dist.glob("assets/*.js")):
        hits += scan_js(js)

    if hits:
        print(f"✗ AIR-GAP VIOLATION — external dependency references in the shipped build ({len(hits)}):")
        for h in hits:
            print(f"    {h}")
        return 1

    n_css = len(list(dist.glob("assets/*.css")))
    n_js = len(list(dist.glob("assets/*.js")))
    print(f"✓ Air-gap artifact gate: clean ({n_js} JS chunks, {n_css} CSS files, index.html)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
