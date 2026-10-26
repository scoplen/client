// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { ScoplenTerminalElement, type TerminalBytes } from "@scoplen/terminal";
import { Unicode15Provider } from "../src/unicode15";

beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
  }));
});

afterEach(() => {
  document.body.replaceChildren();
  vi.unstubAllGlobals();
});

async function terminal(columns = 10) {
  const element = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
  const errors: unknown[] = [];
  element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent).detail));
  document.body.append(element);
  await element.restore({ version: 1, columns, rows: 4, data: "" });
  const replies: string[] = [];
  element.sink = (bytes) => {
    replies.push(new TextDecoder().decode(bytes));
  };
  expect(errors).toEqual([]);
  return { element, replies, errors };
}

describe("Unicode 15 widths", () => {
  it("matches an independent dense reference over every Unicode codepoint offline", () => {
    const provider = new Unicode15Provider();
    const widths = Uint8Array.from({ length: 0x110000 }, (_, point) => provider.wcwidth(point));
    // Reference: SHA-256 of one width byte per codepoint, generated independently
    // with Python csv/bytearray directly from the checksum-pinned UCD inputs.
    // This oracle does not use the production range tables or binary search.
    expect(createHash("sha256").update(widths).digest("hex")).toBe(
      "300f7f806f4a4c2e145566cf5e4b2f34aad756b5ad30ab36bfd192b9cddb3d90",
    );
    expect(provider.version).toBe("15");
    expect(provider.wcwidth(0)).toBe(0);
    expect(provider.wcwidth(0x1f)).toBe(0);
    expect(provider.wcwidth(0x7f)).toBe(0);
    expect(provider.wcwidth(0x9f)).toBe(0);
    expect(provider.wcwidth(0xa0)).toBe(1);
    expect(provider.wcwidth(0xad)).toBe(1);
  });

  it.each([
    ["Unicode 15 emoji", "\u{1fae8}X", 4],
    ["CJK", "中X", 4],
    ["supplementary CJK", "\u{30000}X", 4],
    ["fullwidth", "ＡX", 4],
    ["ambiguous stays narrow", "·X", 3],
    ["soft hyphen stays narrow", "\u00adX", 3],
    ["combining acute", "e\u0301X", 3],
    ["Unicode 15 combining mark", "e\u{1e4ec}X", 3],
    ["wide combining cell", "\u{1fae8}\u0301X", 4],
    ["format character", "a\u200dX", 3],
    ["Hangul Jamo", "\u1100\u1161\u11a8X", 4],
    ["variation selector preserves codepoint widths", "☀\ufe0fX", 3],
    ["ZWJ preserves codepoint widths", "👩\u200d💻X", 6],
  ])("reports the correct cursor after %s through the public source and sink", async (_, text, column) => {
    const { element, replies, errors } = await terminal();
    element.source = { subscribe: (emit) => emit(new TextEncoder().encode(`${text}\x1b[6n`)) };
    const snapshot = await element.serialize();
    await vi.waitFor(() => expect(replies).toEqual([`\x1b[1;${column.toString()}R`]));
    expect(snapshot.data).toContain(text);
    expect(errors).toEqual([]);
  });

  it("preserves xterm's leading combining-cell behavior without a base", async () => {
    const { element, replies, errors } = await terminal();
    element.source = { subscribe: (emit) => emit(new TextEncoder().encode("\u0301X\x1b[6n")) };
    expect((await element.serialize()).data).toContain("X");
    // xterm allocates a cell when a leading mark has no occupied base to join.
    await vi.waitFor(() => expect(replies).toEqual(["\x1b[1;3R"]));
    expect(errors).toEqual([]);
  });

  it("keeps UTF-8 and combining cells intact across byte chunks", async () => {
    const { element, replies, errors } = await terminal();
    const bytes = new TextEncoder().encode("\u{1fae8}\u0301X\x1b[6n");
    element.source = {
      subscribe(emit) {
        for (const byte of bytes) emit(Uint8Array.of(byte));
      },
    };
    expect((await element.serialize()).data).toContain("\u{1fae8}\u0301X");
    await vi.waitFor(() => expect(replies).toEqual(["\x1b[1;4R"]));
    expect(errors).toEqual([]);
  });

  it("wraps a wide cell with one column left and restores its exact rendered state", async () => {
    const { element, replies } = await terminal();
    element.source = { subscribe: (emit) => emit(new TextEncoder().encode("123456789\u{1fae8}X\x1b[6n")) };
    const snapshot = await element.serialize();
    await vi.waitFor(() => expect(replies).toEqual(["\x1b[2;4R"]));
    expect(snapshot.data).toContain("123456789");
    expect(snapshot.data).toContain("\u{1fae8}X");
    element.remove();

    const restored = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
    document.body.append(restored);
    await restored.restore(snapshot);
    expect(await restored.serialize()).toEqual(snapshot);
    const restoredReplies: string[] = [];
    restored.sink = (bytes) => {
      restoredReplies.push(new TextDecoder().decode(bytes));
    };
    restored.source = { subscribe: (emit) => emit(new TextEncoder().encode("\x1b[6n")) };
    await restored.serialize();
    await vi.waitFor(() => expect(restoredReplies).toEqual(["\x1b[2;4R"]));
  });

  it("re-registers Unicode 15 when the element reconnects and replays output", async () => {
    const { element, replies, errors } = await terminal();
    let emit: (bytes: TerminalBytes) => void = () => undefined;
    element.source = {
      subscribe: (onChunk) => {
        emit = onChunk;
      },
    };
    emit(new TextEncoder().encode("\u{1fae8}\u0301X"));
    await element.serialize();
    element.remove();
    document.body.append(element);
    emit(new TextEncoder().encode("\x1b[6n"));
    expect((await element.serialize()).data).toContain("\u{1fae8}\u0301X");
    await vi.waitFor(() => expect(replies).toEqual(["\x1b[1;4R"]));
    expect(errors).toEqual([]);
  });
});
