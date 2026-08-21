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

# (start, end, speed) — keep windows in the original timeline (2026-08-14
# re-record, 269.4s: same acts, faster gate executions, Act 8 added).
SEGMENTS: list[tuple[float, float, float]] = [
    # Act 1 — Overview (shots 01-06)
    (0.0, 4.0, 1.0),     # intro + stat-strip pan
    (4.0, 6.0, 1.0),     # shot 01 hold
    (6.0, 10.0, 1.4),    # risk-timeline pan
    (10.0, 12.0, 1.0),   # shot 02 hold
    (12.0, 15.0, 1.4),   # detection-volume pan
    (15.0, 18.0, 1.0),   # shot 03 hold
    (18.0, 21.0, 1.4),   # scroll to findings
    (21.0, 24.0, 1.0),   # findings pan (shot 04)
    (24.0, 30.0, 1.4),   # bottom (shot 05) + quick actions
    (30.0, 36.0, 1.4),   # quick actions (shot 06) + tail
    (36.0, 46.0, 1.4),   # act tail
    # Act 2 — Vault (shots 07-10)
    (46.0, 49.0, 1.0),   # vault load + subtitle
    (49.0, 51.0, 1.0),   # shot 07 hold
    (51.0, 54.5, 1.4),   # stats pan tail
    (54.5, 58.5, 1.4),   # table pan (shot 08)
    (58.5, 61.5, 1.4),   # table tail
    (61.5, 66.5, 1.0),   # filter typing + result (shot 09)
    (66.5, 70.0, 1.4),   # detail nav (shot 10)
    # Act 3 — Monitor (shots 11-12)
    (70.0, 74.0, 1.0),   # monitor load + auto-detect pan + detonate click
    (74.0, 78.0, 1.0),   # live analysis streaming (shot 11)
    # [t=78-103 detonation wait CUT]
    (103.0, 105.0, 1.0), # analysis complete (shot 12)
    # Act 4 — Run detail (shots 13-19)
    (105.0, 110.0, 1.4), # load + shot 13 + risk pan
    (110.0, 117.0, 1.4), # killchain pan (shot 14)
    (117.0, 121.5, 1.4), # killchain tail
    (121.5, 127.25, 1.4),# scroll to process tree
    (127.25, 131.25, 1.4),# process tree (shot 15)
    (131.25, 136.0, 1.4),# network (shot 16)
    (136.0, 141.0, 1.4), # timeline (shot 17)
    (141.0, 146.0, 1.0), # notes typing (shot 18)
    (146.0, 147.75, 1.4),# rules gen (shot 19)
    # Act 5 — Findings (shots 20-26)
    (147.75, 151.5, 1.0),# load + search (shot 20)
    (151.5, 153.5, 1.0), # select (shot 21)
    (153.5, 158.25, 1.0),# ack (shot 22) + live badges (shot 23)
    (158.25, 159.25, 1.0),# acknowledged tab (shot 24)
    (159.25, 162.75, 1.0),# resolve (shot 25) + resolved tab (shot 26)
    # Act 6 — Quality gates (shots 27-28)
    (162.75, 166.5, 1.0),# history @1280 load (shot 27)
    (166.5, 174.25, 1.4),# charts pan
    (174.25, 179.5, 1.0),# run detail @1280 load
    (179.5, 189.75, 1.4),# pan tail (shot 28)
    # Act 7 — the gates run (shot 29). The three gate scripts execute while
    # the page sits static on /history (t~194-250, health-pulse twitches
    # only) — CUT; keep the subtitle bridge and the results panel.
    (189.75, 194.0, 2.0), # gates act subtitle bridge
    (250.0, 252.5, 1.0),  # act-7 results panel + shot 29 hold
    # Act 8 — the air-gap story (shot 30). The four gates + cold-start
    # harness execute while the Overview sits static (t~256-261) — CUT;
    # keep the subtitle bridge and the verdict panel.
    (252.5, 256.25, 2.0), # overview goto + subtitle bridge
    (261.25, 269.4, 1.0), # air-gap panel + shot 30 hold
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
