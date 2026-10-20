#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the interface's Chinese heading font from Noto Serif SC.

Run from the repository root after `pnpm install`, whenever
web/app/src/messages/zh-Hans.ts changes (the catalog tests fail until you do):

    pnpm fonts

Noto Serif SC is published in Unicode-range slices, and Chinese characters are
spread across many of them. This takes exactly the characters the Chinese
catalog uses, fixes the weight at 600 (`scoplen-docs/18-visual-identity.md`),
and merges them into one WOFF2 in web/ui/src/fonts with a manifest of what it
covers. Requires Python 3 with fontTools and brotli.
"""

import json
import tempfile
from pathlib import Path

from fontTools import subset
from fontTools.merge import Merger
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "web/ui/node_modules/@fontsource-variable/noto-serif-sc"
TEXT = ROOT / "web/app/src/messages/zh-Hans.ts"
OUT = ROOT / "web/ui/src/fonts"
WEIGHT = 600


def parse_ranges(ranges):
    codes = set()
    for part in ranges.split(","):
        part = part.strip().removeprefix("U+")
        if "-" in part:
            start, end = part.split("-")
            codes.update(range(int(start, 16), int(end, 16) + 1))
        else:
            codes.add(int(part, 16))
    return codes


def main():
    # Every character from CJK punctuation upward; comments in the catalog
    # are Chinese too, so the font also covers anything quoted from them.
    wanted = {ord(c) for c in TEXT.read_text(encoding="utf-8") if ord(c) >= 0x2E80}
    slices = json.loads((SOURCE / "unicode.json").read_text())
    parts = []
    source_timestamps = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, ranges in slices.items():
            codes = parse_ranges(ranges) & wanted
            if not codes:
                continue
            key = name.strip("[]")
            font = TTFont(SOURCE / f"files/noto-serif-sc-{key}-wght-normal.woff2")
            source_timestamps.append(font["head"].created)
            font = instantiateVariableFont(font, {"wght": WEIGHT})
            options = subset.Options()
            options.layout_features = ["*"]
            options.name_IDs = ["*"]
            options.notdef_outline = True
            subsetter = subset.Subsetter(options)
            subsetter.populate(unicodes=codes)
            subsetter.subset(font)
            font.flavor = None
            path = Path(tmp) / f"{key}.ttf"
            font.save(path)
            parts.append(str(path))
        merged = Merger().merge(parts)
        merged.flavor = "woff2"
        merged.recalcTimestamp = False
        merged["head"].created = min(source_timestamps)
        merged["head"].modified = min(source_timestamps)
        OUT.mkdir(parents=True, exist_ok=True)
        merged.save(OUT / "scoplen-serif-sc.woff2")
        covered = sorted(merged.getBestCmap())

    missing = wanted - set(covered)
    if missing:
        raise SystemExit("Noto Serif SC lacks: " + "".join(chr(c) for c in sorted(missing)))
    (OUT / "scoplen-serif-sc.json").write_text(
        json.dumps({"weight": WEIGHT, "characters": "".join(chr(c) for c in covered)}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    size = (OUT / "scoplen-serif-sc.woff2").stat().st_size
    print(f"wrote web/ui/src/fonts/scoplen-serif-sc.woff2: {len(covered)} characters, {size // 1024} KB")


if __name__ == "__main__":
    main()
