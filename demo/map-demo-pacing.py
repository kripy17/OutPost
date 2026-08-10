#!/usr/bin/env python3
"""Map static (dead) runs in deck-demo.webm via consecutive-frame diffing.

Extracts 1 fps frames to a temp dir, computes the mean per-pixel channel
difference between neighbours, and prints the long low-motion runs (candidate
dead time: pauses, waits, subtitle clears) plus fast-change spikes (page
transitions, the mid-pan flicker) with timestamps.

Usage: .venv/bin/python demo/map-demo-pacing.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

WEBM = os.path.join(os.path.dirname(__file__), "deck-demo.webm")
FPS = 1.0
# Mean per-pixel diff below this = "static" (same content, no movement).
STATIC_THRESH = 1.2
# A run of N+ consecutive static frames is candidate dead time.
MIN_DEAD_RUN = 3


def main() -> None:
    from PIL import Image

    with tempfile.TemporaryDirectory(prefix="deck-pace-") as td:
        frames = os.path.join(td, "f-%03d.png")
        subprocess.run(
            ["ffmpeg", "-v", "error", "-i", WEBM, "-vf", f"fps={FPS}", "-vsync", "0", frames],
            check=True,
        )
        paths = sorted(os.listdir(td))
        print(f"{len(paths)} frames @ 1fps")

        def _sig(img: Image.Image) -> bytes:
            return img.convert("RGB").resize((160, 90)).tobytes()

        prev = _sig(Image.open(os.path.join(td, paths[0])))
        diffs: list[tuple[int, float]] = []  # (t, diff)
        for i, name in enumerate(paths[1:], start=1):
            cur = _sig(Image.open(os.path.join(td, name)))
            diff = sum(abs(a - b) for a, b in zip(prev, cur)) / (160 * 90 * 3)
            diffs.append((i, diff))
            prev = cur

        # Long static runs.
        print("\n=== candidate dead time (>=3s static) ===")
        run_start = None
        for i, d in diffs:
            if d < STATIC_THRESH:
                if run_start is None:
                    run_start = i
            else:
                if run_start is not None and i - run_start >= MIN_DEAD_RUN:
                    print(f"  t={run_start:3d}s..{i - 1:3d}s  static {i - run_start}s")
                run_start = None
        if run_start is not None and len(diffs) - run_start >= MIN_DEAD_RUN:
            print(f"  t={run_start:3d}s..{len(diffs):3d}s  static {len(diffs) - run_start}s")

        # Fast-change spikes (transitions).
        print("\n=== transition spikes (diff > 30) ===")
        for i, d in diffs:
            if d > 30:
                print(f"  t={i}s  diff={d:.1f}")

        # Summary stats.
        all_diffs = [d for _, d in diffs]
        print(f"\nmean diff: {sum(all_diffs) / len(all_diffs):.1f}   "
              f"median: {sorted(all_diffs)[len(all_diffs) // 2]:.1f}")


if __name__ == "__main__":
    sys.exit(main())
