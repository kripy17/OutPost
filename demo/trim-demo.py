#!/usr/bin/env python3
"""Tighten deck-demo.webm: cut dead time, keep every shot, speed pans 1.3x.

The recording is 146.7s of which ~30s is the detonation wait and another
~20s is hold pauses (map-demo-pacing.py measures these as long low-motion
runs). This trims to ~95s: each screenshot hold stays on screen ~2s at 1x,
the cursor pans run at 1.3x, the mid-pan jump at t=24-25 is cut, and the
detonation wait collapses to the live-analysis glimpse + completion.

Segments are (start, end, speed). Boundaries were chosen against the pacing
map (demo/map-demo-pacing.py) and the script's own shot timing
(demo/deck-demo.mjs) so no screenshot moment is lost.

Usage: .venv/bin/python demo/trim-demo.py [--out demo/deck-demo-trimmed.webm]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

SRC = os.path.join(os.path.dirname(__file__), "deck-demo.webm")

# (start, end, speed) — keep windows in the original timeline.
SEGMENTS: list[tuple[float, float, float]] = [
    # Act 1 — Overview (shots 01-06)
    (0.0, 6.0, 1.0),     # intro + stat-strip pan
    (6.0, 8.0, 1.0),     # shot 01 hold
    (8.0, 13.0, 1.3),    # risk-timeline pan
    (13.0, 15.0, 1.0),   # shot 02 hold
    (15.0, 19.0, 1.3),   # svg pan
    (19.0, 24.0, 1.0),   # detection-volume chart (shot 03)
    (25.0, 27.0, 1.0),   # chart hold tail   [t=24-25 mid-pan CUT]
    (30.0, 41.0, 1.3),   # findings + bottom + quick actions (shots 04-06)
    # Act 2 — Vault (shots 07-10)
    (41.0, 43.0, 1.0),   # vault load
    (43.0, 45.0, 1.0),   # shot 07 hold      [t=45-48 CUT]
    (48.0, 56.0, 1.3),   # table pan (shot 08)
    (56.0, 60.0, 1.0),   # filter typing + result (shot 09)  [t=60-65 CUT]
    (65.0, 67.0, 1.0),   # detail pan
    (67.0, 68.0, 1.0),   # shot 10 hold      [t=68-69 CUT]
    (69.0, 72.0, 1.3),   # detail pans tail
    # Act 3 — Monitor (shots 11-12)
    (72.0, 77.0, 1.3),   # load + auto-detect pan + detonate click
    (77.0, 84.0, 1.0),   # live analysis streaming (shot 11)
    # [t=84-104 detonation wait CUT]
    (104.0, 107.0, 1.0), # analysis complete (shot 12)
    # Act 4 — Run detail (shots 13-19)
    (107.0, 117.0, 1.3), # load + shot 13 + killchain + tree pans
    (117.0, 119.0, 1.0), # tree hold (shot 15)   [t=119-120 CUT]
    (120.0, 129.0, 1.3), # network + timeline + notes typing (shots 16-18)
    (129.0, 132.0, 1.0), # notes + rules gen     [t=132-133 CUT]
    (133.0, 135.0, 1.0), # rules result (shot 19)
    # Act 5 — Findings (shots 20-25)
    (135.0, 143.0, 1.0), # triage lifecycle      [t=145-146.7 tail CUT]
    (143.0, 145.0, 1.0), # resolved final hold
]


def _fmt(n: int) -> str:
    return f"[v{n}]"


def build_filter() -> str:
    parts: list[str] = []
    for i, (start, end, speed) in enumerate(SEGMENTS):
        parts.append(
            f"[0:v]trim=start={start}:end={end},setpts=(PTS-STARTPTS)/{speed}{_fmt(i)}"
        )
    inputs = "".join(_fmt(i) for i in range(len(SEGMENTS)))
    parts.append(f"{inputs}concat=n={len(SEGMENTS)}:v=1:a=0[outv]")
    return ";".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                                                      "deck-demo-trimmed.webm"))
    args = parser.parse_args()

    total = sum((end - start) / speed for start, end, speed in SEGMENTS)
    print(f"segments: {len(SEGMENTS)}   expected duration: {total:.1f}s "
          f"(from {sum(e - s for s, e, _ in SEGMENTS):.1f}s of source)")

    cmd = [
        "ffmpeg", "-y", "-v", "error", "-i", SRC,
        "-filter_complex", build_filter(),
        "-map", "[outv]",
        "-c:v", "libvpx", "-crf", "12", "-b:v", "0",
        "-deadline", "good", "-cpu-used", "2", "-pix_fmt", "yuv420p",
        args.out,
    ]
    subprocess.run(cmd, check=True)
    print(f"wrote {args.out} ({os.path.getsize(args.out) / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    sys.exit(main())
