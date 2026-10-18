// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * Text and accent pairs must meet WCAG 2.2 AA (4.5:1 for text) in every
 * theme and scheme (`scoplen-docs/18-visual-identity.md`). The values are read
 * from the stylesheet so that a token change, or a new theme, is checked.
 */
const css = readFileSync(fileURLToPath(new URL("../src/themes.css", import.meta.url)), "utf8");

function tokens(block: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [, name, value] of block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})\s*;/gi)) out[name!] = value!;
  return out;
}

/** Every theme and scheme block in the stylesheet, by its selector. */
const blocks = [...css.matchAll(/\[data-theme="([a-z]+)"\]\[data-scheme="(light|dark)"\]\s*\{([^}]*)\}/g)].map(
  ([, theme, scheme, body]) => [`${theme} ${scheme}`, tokens(body!)] as const,
);

function luminance(hex: string) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

function contrast(a: string, b: string) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

const pairs: [string, string][] = [
  ["foreground", "background"],
  ["foreground", "raised"],
  ["foreground", "inset"],
  ["muted-foreground", "background"],
  ["muted-foreground", "raised"],
  ["primary", "background"],
  ["primary-foreground", "primary"],
  ["primary-foreground", "primary-hover"],
  ["attention", "background"],
  ["attention-foreground", "attention"],
];

it("has every theme in both of its schemes", () => {
  expect(blocks.map(([name]) => name)).toEqual([
    "paper light",
    "paper dark",
    "brutal light",
    "brutal dark",
    "phosphor dark",
    "midnight dark",
    "sakura light",
    "sakura dark",
  ]);
});

describe.each(blocks)("%s tokens", (_, set) => {
  it.each(pairs)("%s on %s meets 4.5:1", (fg, bg) => {
    expect(set[fg], fg).toBeDefined();
    expect(set[bg], bg).toBeDefined();
    expect(contrast(set[fg]!, set[bg]!)).toBeGreaterThanOrEqual(4.5);
  });
});
