#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Draw the application icon source from the mark geometry.

    python3 scripts/generate-icon.py && pnpm tauri icon src-tauri/icons/source.png

Writes src-tauri/icons/source.png (1024 x 1024): the mark in paper on a
teal tile with the platform's rounded-square margin, from
web/ui/src/brand/geometry.json (`scoplen-docs/18-visual-identity.md`).
Requires Python 3 with Pillow.
"""

import json
import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
GEOMETRY = json.loads((ROOT / "web/ui/src/brand/geometry.json").read_text())
COLORS = GEOMETRY["colors"]
SIZE = 1024
SUPERSAMPLE = 4


def rotate(points):
    t = GEOMETRY["tilt"]
    a = math.radians(t["angle"])
    c, s = math.cos(a), math.sin(a)
    return [(t["x"] + (x - t["x"]) * c - (y - t["y"]) * s, t["y"] + (x - t["x"]) * s + (y - t["y"]) * c) for x, y in points]


def body_points(steps=64):
    """The egg (four cubic segments) as a polygon, tilted."""
    b = GEOMETRY["body"]
    cx, top, bot, w = b["centerX"], b["top"], b["bottom"], b["halfWidth"]
    mid = top + (bot - top) * b["waist"]
    ht, hb, k = mid - top, bot - mid, 0.56
    curves = [
        ((cx, top), (cx + w * k, top), (cx + w, mid - ht * 0.55), (cx + w, mid)),
        ((cx + w, mid), (cx + w, mid + hb * k), (cx + w * k, bot), (cx, bot)),
        ((cx, bot), (cx - w * k, bot), (cx - w, mid + hb * k), (cx - w, mid)),
        ((cx - w, mid), (cx - w, mid - ht * 0.55), (cx - w * k, top), (cx, top)),
    ]
    points = []
    for p0, p1, p2, p3 in curves:
        for i in range(steps):
            u = i / steps
            v = 1 - u
            points.append(tuple(v**3 * a + 3 * v * v * u * b + 3 * v * u * u * c + u**3 * d for a, b, c, d in zip(p0, p1, p2, p3)))
    return rotate(points)


def eye_points(e, steps=16):
    """A fully rounded bar, tilted."""
    x, y, w, h = e["x"], e["y"], e["width"], e["height"]
    r = min(w, h) / 2
    centers = [(x + w - r, y + r, -90), (x + w - r, y + h - r, 0), (x + r, y + h - r, 90), (x + r, y + r, 180)]
    points = []
    for cx, cy, start in centers:
        for i in range(steps + 1):
            a = math.radians(start + 90 * i / steps)
            points.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return rotate(points)


def main():
    big = SIZE * SUPERSAMPLE
    image = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    # The rounded-square tile occupies the central 824 of 1024 units, as the
    # macOS icon grid expects; Windows uses the same artwork.
    margin = 100 * SUPERSAMPLE
    draw.rounded_rectangle((margin, margin, big - margin, big - margin), 185 * SUPERSAMPLE, fill=COLORS["accent"])
    mark = 600 * SUPERSAMPLE
    offset = (big - mark) / 2
    scale = mark / 64

    def place(points):
        return [(offset + x * scale, offset + y * scale) for x, y in points]

    layer = Image.new("L", (big, big), 0)
    shape = ImageDraw.Draw(layer)
    shape.polygon(place(body_points()), fill=255)
    for eye in GEOMETRY["eyes"].values():
        shape.polygon(place(eye_points(eye)), fill=0)
    image.paste(Image.new("RGBA", (big, big), COLORS["paper"]), (0, 0), layer)
    out = ROOT / "src-tauri/icons/source.png"
    image.resize((SIZE, SIZE), Image.LANCZOS).save(out, optimize=True)
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
