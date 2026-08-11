#!/usr/bin/env python3
"""Build a labeled contact sheet of the deck-demo screenshots.

Usage: .venv/bin/python demo/make-contact-sheet.py [--out demo/screenshots/contact-sheet.png]

Renders all 25 demo frames in a 5x5 grid on the deck's dark base, each cell
letterboxed to a fixed aspect with its filename below — one image to review
the whole UI at a glance. Reproducible: re-run after re-recording footage.
"""

from __future__ import annotations

import argparse
import glob
import os

from PIL import Image, ImageDraw, ImageFont

# Deck palette (frontend/src/index.css).
BG_BASE = (20, 23, 28)      # #14171C
BG_SURFACE = (28, 32, 40)   # #1C2028
TEXT_PRIMARY = (228, 231, 235)  # #E4E7EB
TEXT_MUTED = (122, 130, 144)    # #7A8290
ACCENT = (217, 164, 65)         # #D9A441

CELL_W = 420      # thumbnail box width
CELL_H = 300      # thumbnail box height
PAD = 18          # gutter between cells
LABEL_H = 30      # label strip under each thumbnail
MARGIN = 28

def _grid(n: int) -> tuple[int, int]:
    """(cols, rows) — the widest grid that fits n cells with fewest empties.
    28 frames → 7x4 exactly; odd counts pad the last row with empties."""
    import math
    cols = math.ceil(math.sqrt(n))
    while cols * math.ceil(n / cols) < n:
        cols += 1
    rows = math.ceil(n / cols)
    return cols, rows


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for name in ("DejaVuSansMono.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                                                      "screenshots", "contact-sheet.png"))
    parser.add_argument("--src", default=os.path.join(os.path.dirname(__file__),
                                                      "screenshots", "deck"))
    args = parser.parse_args()

    paths = sorted(glob.glob(os.path.join(args.src, "*.png")))
    GRID_COLS, GRID_ROWS = _grid(len(paths))

    title_font = _font(26)
    label_font = _font(13)

    cell_w = CELL_W + 2 * PAD
    cell_h = CELL_H + LABEL_H + 2 * PAD
    sheet_w = MARGIN * 2 + GRID_COLS * cell_w
    sheet_h = MARGIN * 2 + 56 + GRID_ROWS * cell_h  # header band for the title

    sheet = Image.new("RGB", (sheet_w, sheet_h), BG_BASE)
    draw = ImageDraw.Draw(sheet)
    draw.text((MARGIN, MARGIN + 6), f"OutPost — deck demo · all {len(paths)} frames",
              font=title_font, fill=TEXT_PRIMARY)
    draw.text((MARGIN, MARGIN + 38), "Overview → vault → monitor detonation → run detail → findings triage → quality gates",
              font=label_font, fill=TEXT_MUTED)

    for i, path in enumerate(paths):
        col, row = i % GRID_COLS, i // GRID_COLS
        x0 = MARGIN + col * cell_w
        y0 = MARGIN + 62 + row * cell_h

        img = Image.open(path).convert("RGB")
        # Fit into the cell box, letterboxed on the surface color.
        scale = min(CELL_W / img.width, CELL_H / img.height)
        thumb = img.resize((max(1, round(img.width * scale)),
                            max(1, round(img.height * scale))), Image.LANCZOS)
        canvas = Image.new("RGB", (CELL_W, CELL_H), BG_SURFACE)
        canvas.paste(thumb, ((CELL_W - thumb.width) // 2, (CELL_H - thumb.height) // 2))

        label = os.path.basename(path)
        # Clip long labels to the cell width.
        while label_font.getlength(label) > CELL_W - 8 and len(label) > 8:
            label = label[:-4] + "…"

        sheet.paste(canvas, (x0 + PAD, y0 + PAD))
        # Accent tick under the frame number, then the label.
        draw.line((x0 + PAD, y0 + PAD + CELL_H + 4, x0 + PAD + 26, y0 + PAD + CELL_H + 4),
                  fill=ACCENT, width=2)
        draw.text((x0 + PAD, y0 + PAD + CELL_H + 10), label,
                  font=label_font, fill=TEXT_MUTED)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    sheet.save(args.out)
    print(f"wrote {args.out} ({sheet.size[0]}x{sheet.size[1]}, "
          f"{os.path.getsize(args.out) / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
