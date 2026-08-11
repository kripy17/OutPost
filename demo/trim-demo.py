#!/usr/bin/env python3
"""Tighten deck-demo.webm: cut dead time, keep every shot, speed pans 1.3x.

The recording is 181.5s of which ~25s is the detonation wait and another
~30s is hold pauses (map-demo-pacing.py measures these as long low-motion
runs). This trims to ~128s: each screenshot hold stays on screen ~2s at 1x,
the cursor pans run at 1.3-1.4x, and the detonation wait collapses to the
live-analysis glimpse (shot 11) + completion (shot 12).

Segments are (start, end, speed). Boundaries were chosen against the pacing
map (demo/map-demo-pacing.py) — transition spikes mark the act changes, and
each shot() moment falls inside a kept window — and the script's own shot
timing (demo/deck-demo.mjs), so no screenshot moment is lost.

Usage: .venv/bin/python demo/trim-demo.py [--out demo/deck-demo-trimmed.webm]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

SRC = os.path.join(os.path.dirname(__file__), "deck-demo.webm")

# (start, end, speed) — keep windows in the original timeline.
SEGMENTS: list[tuple[float, float, float]] = [
    # Act 1 — Overview (shots 01-06)
    (0.0, 5.0, 1.0),     # intro + stat-strip pan
    (5.0, 7.0, 1.0),     # shot 01 hold
    (7.0, 12.0, 1.4),    # risk-timeline pan
    (12.0, 14.0, 1.0),   # shot 02 hold
    (14.0, 18.0, 1.4),   # detection-volume svg pan
    (18.0, 22.0, 1.0),   # shot 03 chart
    (22.0, 26.0, 1.4),   # scroll to findings
    (26.0, 32.0, 1.4),   # findings + bottom (shots 04-05)
    (32.0, 37.0, 1.4),   # quick actions (shot 06)
    # Act 2 — Vault (shots 07-10)
    (37.0, 39.0, 1.0),   # vault load
    (39.0, 41.0, 1.0),   # shot 07 hold
    (41.0, 48.0, 1.4),   # table pan (shot 08)
    (48.0, 52.0, 1.0),   # filter typing + result (shot 09)
    (52.0, 56.0, 1.4),   # detail pan
    (56.0, 58.0, 1.0),   # shot 10 hold
    (58.0, 68.0, 1.4),   # detail pans tail
    # Act 3 — Monitor (shots 11-12)
    (68.0, 72.0, 1.0),   # vault tail → monitor
    (72.0, 80.0, 1.4),   # monitor load + auto-detect pan + detonate click
    (80.0, 88.0, 1.0),   # live analysis streaming (shot 11)
    # [t=88-113 detonation wait CUT]
    (113.0, 118.0, 1.0), # analysis complete (shot 12)
    # Act 4 — Run detail (shots 13-19)
    (118.0, 127.0, 1.4), # load + shot 13 + killchain (shot 14)
    (127.0, 129.0, 1.0), # process tree hold (shot 15)
    (129.0, 133.0, 1.4), # network + timeline (shots 16-17)
    (133.0, 136.0, 1.0), # notes typing + shot 18
    (136.0, 141.0, 1.4), # rules gen (shot 19)
    # Act 5 — Findings (shots 20-26)
    (141.0, 144.0, 1.0), # load + search (shot 20)
    (144.0, 146.0, 1.0), # select (shot 21)
    (146.0, 149.0, 1.0), # ack (shot 22)
    (149.0, 151.0, 1.0), # live badges (shot 23)
    (151.0, 153.0, 1.0), # acknowledged tab (shot 24)
    (153.0, 156.0, 1.0), # resolve (shot 25)
    (156.0, 158.0, 1.0), # resolved tab (shot 26)
    (158.0, 163.0, 1.4), # findings tail
    # Act 6 — Quality gates (shots 27-28)
    (163.0, 165.0, 1.0), # history @1280 load
    (165.0, 167.0, 1.0), # shot 27 hold
    (167.0, 170.0, 1.4), # pan
    (170.0, 172.0, 1.0), # run detail @1280 load
    (172.0, 174.0, 1.0), # shot 28 hold
    (174.0, 177.0, 1.4), # end
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
