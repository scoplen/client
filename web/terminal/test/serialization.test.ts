// SPDX-License-Identifier: Apache-2.0
import { ScoplenTerminalElement, type TerminalSnapshot } from "../src";

function terminal() {
  const element = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
  document.body.append(element);
  return element;
}

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

it("flushes queued rendering and restores dimensions, colors and scrollback", async () => {
  const original = terminal();
  original.source = { subscribe: (emit) => emit(new TextEncoder().encode("\x1b[31mred\x1b[0m\r\n中文 🚀\r\nlast")) };
  const snapshot = await original.serialize();
  expect(snapshot.data).toContain("red");
  expect(snapshot.data).toContain("中文");
  original.remove();
  const restored = terminal();
  restored.readOnly = true;
  await restored.restore(snapshot);
  expect(restored.size).toEqual({ columns: snapshot.columns, rows: snapshot.rows });
  expect(restored.findNext("last")).toBe(true);
  expect((await restored.serialize()).data).toBe(snapshot.data);
});

it("discards parser replies, direct input, paste and broadcasts while restoring and read-only", async () => {
  const element = terminal();
  const inputs = vi.fn();
  const broadcast = vi.fn();
  element.addEventListener("terminal-input", inputs);
  element.addEventListener("terminal-broadcast-input", broadcast);
  await element.setBroadcastInput(true, () => true);
  element.clipboard = { readText: async () => "pasted secret" };
  element.readOnly = true;
  const restoration = element.restore({ version: 1, columns: 90, rows: 30, data: "saved\x1b[6n\x1b[c" });
  await element.send(new TextEncoder().encode("during"));
  expect(() => {
    element.sink = vi.fn(() => undefined);
  }).toThrow("restoration");
  expect(() => {
    element.source = { subscribe: vi.fn() };
  }).toThrow("restoration");
  await restoration;
  await element.send(new TextEncoder().encode("after"));
  await element.paste();
  await element.serialize();
  expect(inputs).not.toHaveBeenCalled();
  expect(broadcast).not.toHaveBeenCalled();
  element.readOnly = false;
  const sink = vi.fn();
  element.sink = sink;
  await element.send(new TextEncoder().encode("fresh input"));
  expect(sink).toHaveBeenCalledTimes(1);
});

it("rejects oversized UTF-8 and bad metadata without replacing rendered content", async () => {
  const element = terminal();
  const valid: TerminalSnapshot = { version: 1, columns: 80, rows: 24, data: "retained" };
  await element.restore(valid);
  await expect(element.restore({ ...valid, data: "中".repeat(400_000) })).rejects.toThrow("1 MiB");
  await expect(element.restore({ ...valid, columns: 0 })).rejects.toThrow("dimensions");
  expect(element.findNext("retained")).toBe(true);
});

it("keeps the configured raw-output bound while restoring complete rendered state", async () => {
  const element = terminal();
  element.maxOutputBytes = 4;
  await element.restore({ version: 1, columns: 80, rows: 24, data: "renderer-visible" });
  expect(element.getOutput()).toHaveLength(4);
  expect(new TextDecoder().decode(element.getOutput())).toBe("ible");
  expect(element.findNext("renderer-visible")).toBe(true);
});

it("cancels a pending snapshot when the element disconnects", async () => {
  const element = terminal();
  const pending = element.serialize();
  element.remove();
  await expect(pending).rejects.toThrow("disconnected");
});
