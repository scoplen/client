// SPDX-License-Identifier: Apache-2.0
import type { IUnicodeVersionProvider } from "@xterm/xterm";
import { WIDE_BMP, WIDE_HIGH, ZERO_BMP, ZERO_HIGH } from "./unicode15-data";

function includes(point: number, ranges: readonly number[]): boolean {
  let lower = 0;
  let upper = ranges.length / 2 - 1;
  while (lower <= upper) {
    const middle = (lower + upper) >>> 1;
    if (point < ranges[middle * 2]) upper = middle - 1;
    else if (point > ranges[middle * 2 + 1]) lower = middle + 1;
    else return true;
  }
  return false;
}

/** Unicode 15 codepoint widths with xterm's ordinary combining-cell behavior. */
export class Unicode15Provider implements IUnicodeVersionProvider {
  readonly version = "15";

  wcwidth(point: number): 0 | 1 | 2 {
    if (point < 32 || (point >= 0x7f && point < 0xa0)) return 0;
    if (point < 0x7f) return 1;
    const bmp = point < 0x10000;
    if (includes(point, bmp ? ZERO_BMP : ZERO_HIGH)) return 0;
    return includes(point, bmp ? WIDE_BMP : WIDE_HIGH) ? 2 : 1;
  }

  charProperties(point: number, preceding: number): number {
    const width = this.wcwidth(point);
    // xterm 6 encodes cell width in bits 1-2 and joining in bit 0. A zero-width
    // character joins a preceding occupied cell, retaining that cell's width.
    const previousWidth = (preceding >>> 1) & 3;
    return width === 0 && previousWidth > 0 ? (previousWidth << 1) | 1 : width << 1;
  }
}
