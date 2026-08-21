#!/usr/bin/env python3
"""Build a small looping GIF preview of the deck demo.

A full 128s GIF at a watchable resolution would be 20+ MB, so this extracts a
~25s highlights reel — one window per act of deck-demo-trimmed.webm — at
480px wide / 10 fps with ffmpeg's two-pass palette (no gifsicle needed).
Loops forever; renders in any browser/git host without a video player.

Highlight windows are in the TRIMMED timeline (see trim-demo.py for the
segment map; 2026-08-14 re-record, 150.3s trimmed):
  Act 1  Overview       13.5-17.4s  detection-volume chart (the bright one)
  Act 2  Vault          44.7-47.2s  library table pan
  Act 3  Monitor        61.4-64.9s  live analysis streaming
  Act 4  Run detail     83.3-85.6s  process tree with risk halos
  Act 5  Findings       104.6-109.3s triage lifecycle + live tab badges
  Act 6  Quality gates  114.1-121.9s layout sweep width, shown clean
  Act 7  The gates run  138.0-139.6s verify.sh Playwright gates, 3/3 green
  Act 8  Air-gap story  142.9-149.9s four gates + measured cold start

Usage: .venv/bin/python demo/make-gif-preview.py [--out demo/deck-demo-preview.gif]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

SRC = os.path.join(os.path.dirname(__file__), "deck-demo-trimmed.webm")

WINDOWS: list[tuple[float, float]] = [
    (13.5, 17.4),   # Act 1 — Overview, detection volume
    (44.7, 47.2),   # Act 2 — Vault, table pan
    (61.4, 64.9),   # Act 3 — Monitor, live analysis
    (83.3, 85.6),   # Act 4 — Run detail, process tree
    (104.6, 109.3), # Act 5 — Findings, triage + live tab badges
    (114.1, 121.9), # Act 6 — Quality gates, layout-sweep width clean
    (138.0, 139.6), # Act 7 — the verify.sh gates run, 3/3 green panel
    (142.9, 149.9), # Act 8 — the air-gap story: four gates + cold start
]

# README hero presets: two scenes each, 2x the preview width.
HERO_OVERVIEW_WINDOWS: list[tuple[float, float]] = [
    (13.5, 16.4),   # detection-volume chart
    (24.5, 29.1),   # live findings feed
]
HERO_LIVE_WINDOWS: list[tuple[float, float]] = [
    (61.4, 63.5),   # Monitor — live analysis streaming
    (83.3, 86.9),   # Run detail — process tree with halos + network
]

WIDTH = 480
FPS = 10

# preset name -> (windows, width, output file)
PRESETS: dict[str, tuple[list[tuple[float, float]], int, str]] = {
    "preview": (WINDOWS, 480, "deck-demo-preview.gif"),
    "hero": (HERO_OVERVIEW_WINDOWS, 960, "deck-demo-hero.gif"),
    "hero2": (HERO_LIVE_WINDOWS, 960, "deck-demo-hero2.gif"),
}


def build_filter(windows: list[tuple[float, float]], width: int) -> str:
    parts: list[str] = []
    for i, (start, end) in enumerate(windows):
        parts.append(f"[0:v]trim=start={start}:end={end},setpts=PTS-STARTPTS[v{i}]")
    inputs = "".join(f"[v{i}]" for i in range(len(windows)))
    parts.append(
        f"{inputs}concat=n={len(windows)}:v=1:a=0[seq];"
        f"[seq]fps={FPS},scale={width}:-1:flags=lanczos,split[s0][s1];"
        f"[s0]palettegen=stats_mode=diff[p];[s1][p]paletteuse[out]"
    )
    return ";".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", help="output path (overrides the preset default)")
    parser.add_argument("--preset", choices=sorted(PRESETS), default="preview",
                        help="which GIF to build (default: preview)")
    # Keep --hero / --hero2 as convenient aliases.
    parser.add_argument("--hero", action="store_true",
                        help="alias for --preset hero (Overview chart + findings)")
    parser.add_argument("--hero2", action="store_true",
                        help="alias for --preset hero2 (Monitor live + run detail)")
    args = parser.parse_args()

    if args.hero:
        args.preset = "hero"
    if args.hero2:
        args.preset = "hero2"
    windows, width, default_out = PRESETS[args.preset]
    out = args.out or os.path.join(os.path.dirname(__file__), default_out)

    total = sum(end - start for start, end in windows)
    print(f"{args.preset}: {len(windows)} windows, {total:.1f}s @ {FPS}fps, {width}px wide -> {out}")

    subprocess.run(
        [
            "ffmpeg", "-y", "-v", "error", "-i", SRC,
            "-filter_complex", build_filter(windows, width),
            "-map", "[out]", "-loop", "0", out,
        ],
        check=True,
    )
    print(f"wrote {out} ({os.path.getsize(out) / 1024:.0f} KB)")


if __name__ == "__main__":
    sys.exit(main())
