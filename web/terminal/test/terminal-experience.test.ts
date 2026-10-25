// SPDX-License-Identifier: Apache-2.0
import { ScoplenTerminalElement, TerminalError, type TerminalBytes } from "../src";

function mount(options: { source?: ScoplenTerminalElement["source"]; sink?: ScoplenTerminalElement["sink"] } = {}) {
  const element = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
  element.source = options.source ?? null;
  element.sink = options.sink ?? null;
  document.body.append(element);
  return element;
}

const flush = async () => {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
};

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

describe("terminal experience adapter", () => {
  it("does not write xterm constructor-only dimensions when applying a profile", () => {
    const element = mount();
    let assigned: Record<string, unknown> | undefined;
    const terminal = {
      options: { cols: 80, rows: 24, cursorBlink: false },
      dispose: () => undefined,
    } as unknown as { options: Record<string, unknown> };
    Object.defineProperty(terminal, "options", {
      configurable: true,
      get: () => ({ cols: 80, rows: 24, cursorBlink: false }),
      set: (value: Record<string, unknown>) => {
        assigned = value;
      },
    });
    (element as unknown as { terminal: typeof terminal }).terminal = terminal;

    element.profile = { cursorBlink: true, scrollback: 8 };

    expect(assigned).toMatchObject({ cursorBlink: true, scrollback: 8 });
    expect(assigned).not.toHaveProperty("cols");
    expect(assigned).not.toHaveProperty("rows");
  });

  it("uses xterm scrollback and search while retaining the bounded byte history", async () => {
    let emit: ((chunk: TerminalBytes) => void) | undefined;
    const element = mount({
      source: {
        subscribe(onChunk) {
          emit = onChunk;
          return () => undefined;
        },
      },
    });
    element.profile = { scrollback: 8, fontSize: 15, cursorStyle: "underline" };
    emit?.(new TextEncoder().encode("first line\r\nsecond line\r\nthird line"));
    await flush();

    expect(element.profile.scrollback).toBe(8);
    expect(element.findNext("second line")).toBe(true);
    expect(element.findPrevious("first line")).toBe(true);
    expect([...element.getOutput()]).toEqual([...new TextEncoder().encode("first line\r\nsecond line\r\nthird line")]);
    expect(element.getAttribute("role")).toBe("application");
    expect(element.getAttribute("aria-label")).toBe("Terminal");
  });

  it("copies all retained output, pastes through the binary sink, and reports clipboard failures", async () => {
    let emit: ((chunk: TerminalBytes) => void) | undefined;
    const writes: number[][] = [];
    const clipboard = {
      readText: async () => "paste me",
      writeText: async (text: string) => {
        if (text.length === 0) {
          throw new Error("empty clipboard write");
        }
      },
    };
    const element = mount({
      source: {
        subscribe(onChunk) {
          emit = onChunk;
          return () => undefined;
        },
      },
      sink: (bytes) => {
        writes.push([...bytes]);
      },
    });
    element.clipboard = clipboard;
    emit?.(new TextEncoder().encode("copy me"));
    await flush();
    expect(await element.copyAll()).toBe(true);
    expect(await element.paste()).toBe(true);
    await flush();
    expect(new TextDecoder().decode(Uint8Array.from(writes[0] ?? []))).toBe("paste me");

    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));
    element.clipboard = { writeText: async () => Promise.reject(new Error("permission denied")) };
    expect(await element.copyAll()).toBe(false);
    expect(errors).toHaveLength(1);
    expect(errors[0].code).toBe("clipboard");
  });

  it.each([
    ["enabled", "\x1b[?2004h", "\x1b[200~first\rsecond\r\x1b[201~"],
    ["disabled", "\x1b[?2004l", "first\rsecond\r"],
  ])("pastes normalized line endings with bracketed paste %s", async (_, mode, expected) => {
    const writes: number[][] = [];
    const element = mount({
      source: { subscribe: (emit) => emit(new TextEncoder().encode(mode)) },
      sink: (bytes) => {
        writes.push([...bytes]);
      },
    });
    element.clipboard = { readText: async () => "first\nsecond\r\n" };
    await element.serialize();

    expect(await element.paste()).toBe(true);
    await flush();

    expect(writes).toEqual([[...new TextEncoder().encode(expected)]]);
  });

  it.each(["sink replacement", "sink removal and reuse", "reconnect", "read-only roundtrip", "dispose"])(
    "discards a pending clipboard read after %s",
    async (change) => {
      let resolveRead: (text: string) => void = () => undefined;
      const text = new Promise<string>((resolve) => {
        resolveRead = resolve;
      });
      const previousSink = vi.fn<(bytes: TerminalBytes) => void>();
      const replacementSink = vi.fn<(bytes: TerminalBytes) => void>();
      const element = mount({ sink: previousSink });
      const errors = vi.fn();
      element.addEventListener("terminal-error", errors);
      element.clipboard = { readText: () => text };
      const pending = element.paste();

      if (change === "sink replacement") element.sink = replacementSink;
      else if (change === "sink removal and reuse") {
        element.sink = null;
        element.sink = previousSink;
      } else if (change === "reconnect") {
        element.remove();
        document.body.append(element);
      } else if (change === "read-only roundtrip") {
        element.readOnly = true;
        element.readOnly = false;
      } else await element.dispose();
      resolveRead("pending paste");

      expect(await pending).toBe(false);
      await flush();
      expect(previousSink).not.toHaveBeenCalled();
      expect(replacementSink).not.toHaveBeenCalled();
      expect(errors).not.toHaveBeenCalled();
    },
  );

  it("keeps a pending clipboard read when the same sink is assigned", async () => {
    let resolveRead: (text: string) => void = () => undefined;
    const text = new Promise<string>((resolve) => {
      resolveRead = resolve;
    });
    const sink = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink });
    element.clipboard = { readText: () => text };
    const pending = element.paste();
    element.sink = sink;
    resolveRead("current paste");

    expect(await pending).toBe(true);
    await flush();
    expect(sink.mock.calls.map(([bytes]) => [...bytes])).toEqual([[...new TextEncoder().encode("current paste")]]);
  });

  it.each(["enable", "disable", "mode roundtrip", "sink replacement", "sink removal and reuse"])(
    "discards a pending clipboard read after broadcast %s",
    async (change) => {
      let resolveRead: (text: string) => void = () => undefined;
      const text = new Promise<string>((resolve) => {
        resolveRead = resolve;
      });
      const primary = vi.fn<(bytes: TerminalBytes) => void>();
      const previous = vi.fn<(bytes: TerminalBytes) => void>();
      const replacement = vi.fn<(bytes: TerminalBytes) => void>();
      const element = mount({ sink: primary });
      element.broadcastSink = previous;
      if (change !== "enable") await element.setBroadcastInput(true, () => true);
      const broadcast = vi.fn();
      const errors = vi.fn();
      element.addEventListener("terminal-broadcast-input", broadcast);
      element.addEventListener("terminal-error", errors);
      element.clipboard = { readText: () => text };
      const pending = element.paste();

      if (change === "enable") await element.setBroadcastInput(true, () => true);
      else if (change === "disable") await element.setBroadcastInput(false);
      else if (change === "mode roundtrip") {
        await element.setBroadcastInput(false);
        await element.setBroadcastInput(true, () => true);
      } else if (change === "sink replacement") element.broadcastSink = replacement;
      else {
        element.broadcastSink = null;
        element.broadcastSink = previous;
      }
      resolveRead("old broadcast paste");

      expect(await pending).toBe(false);
      expect(primary).not.toHaveBeenCalled();
      expect(previous).not.toHaveBeenCalled();
      expect(replacement).not.toHaveBeenCalled();
      expect(broadcast).not.toHaveBeenCalled();
      expect(errors).not.toHaveBeenCalled();
    },
  );

  it("keeps a pending clipboard read for unchanged broadcast targets and refused enablement", async () => {
    let resolveRead: (text: string) => void = () => undefined;
    const text = new Promise<string>((resolve) => {
      resolveRead = resolve;
    });
    const primary = vi.fn<(bytes: TerminalBytes) => void>();
    const secondary = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink: primary });
    element.broadcastSink = secondary;
    element.clipboard = { readText: () => text };
    const pending = element.paste();
    element.broadcastSink = secondary;
    await element.setBroadcastInput(false);
    expect(await element.setBroadcastInput(true, () => false)).toBe(false);
    resolveRead("current paste");

    expect(await pending).toBe(true);
    expect(primary).toHaveBeenCalledTimes(1);
    expect(secondary).not.toHaveBeenCalled();
  });

  it.each(["enable", "disable", "mode roundtrip", "sink replacement", "sink removal and reuse"])(
    "does not redirect a paste after broadcast %s during its primary write",
    async (change) => {
      let finishWrite: () => void = () => undefined;
      const writing = new Promise<void>((resolve) => {
        finishWrite = resolve;
      });
      const primary = vi.fn(() => writing);
      const previous = vi.fn<(bytes: TerminalBytes) => void>();
      const replacement = vi.fn<(bytes: TerminalBytes) => void>();
      const element = mount({ sink: primary });
      element.broadcastSink = previous;
      if (change !== "enable") await element.setBroadcastInput(true, () => true);
      const broadcast = vi.fn();
      const errors = vi.fn();
      element.addEventListener("terminal-broadcast-input", broadcast);
      element.addEventListener("terminal-error", errors);
      element.clipboard = { readText: async () => "old broadcast paste" };
      const pending = element.paste();
      await flush();
      expect(primary).toHaveBeenCalledTimes(1);

      if (change === "enable") await element.setBroadcastInput(true, () => true);
      else if (change === "disable") await element.setBroadcastInput(false);
      else if (change === "mode roundtrip") {
        await element.setBroadcastInput(false);
        await element.setBroadcastInput(true, () => true);
      } else if (change === "sink replacement") element.broadcastSink = replacement;
      else {
        element.broadcastSink = null;
        element.broadcastSink = previous;
      }
      finishWrite();

      expect(await pending).toBe(true);
      expect(previous).not.toHaveBeenCalled();
      expect(replacement).not.toHaveBeenCalled();
      expect(broadcast).not.toHaveBeenCalled();
      expect(errors).not.toHaveBeenCalled();

      expect(await element.paste()).toBe(true);
      expect(primary).toHaveBeenCalledTimes(2);
      expect(broadcast).toHaveBeenCalledTimes(change === "disable" ? 0 : 1);
      expect(previous).toHaveBeenCalledTimes(change === "disable" || change === "sink replacement" ? 0 : 1);
      expect(replacement).toHaveBeenCalledTimes(change === "sink replacement" ? 1 : 0);
    },
  );

  it("preserves broadcast paste across unchanged targets while the primary write is pending", async () => {
    let finishWrite: () => void = () => undefined;
    const writing = new Promise<void>((resolve) => {
      finishWrite = resolve;
    });
    const primary = vi.fn(() => writing);
    const secondary = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink: primary });
    element.broadcastSink = secondary;
    await element.setBroadcastInput(true, () => true);
    element.clipboard = { readText: async () => "current paste" };
    const pending = element.paste();
    await flush();
    element.broadcastSink = secondary;
    expect(await element.setBroadcastInput(true)).toBe(true);
    finishWrite();

    expect(await pending).toBe(true);
    expect(primary).toHaveBeenCalledTimes(1);
    expect(secondary.mock.calls.map(([bytes]) => [...bytes])).toEqual([[...new TextEncoder().encode("current paste")]]);
  });

  it("keeps a primary send successful when its pending broadcast target is replaced", async () => {
    let finishWrite: () => void = () => undefined;
    const writing = new Promise<void>((resolve) => {
      finishWrite = resolve;
    });
    const primary = vi.fn(() => writing);
    const previous = vi.fn<(bytes: TerminalBytes) => void>();
    const replacement = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink: primary });
    element.broadcastSink = previous;
    await element.setBroadcastInput(true, () => true);
    const pending = element.send(new Uint8Array([65]));
    await flush();
    element.broadcastSink = replacement;
    finishWrite();

    await expect(pending).resolves.toBeUndefined();
    expect(primary).toHaveBeenCalledTimes(1);
    expect(previous).not.toHaveBeenCalled();
    expect(replacement).not.toHaveBeenCalled();
    await element.send(new Uint8Array([66]));
    expect(replacement.mock.calls.map(([bytes]) => [...bytes])).toEqual([[66]]);
  });

  it("does not redirect paste when a broadcast listener replaces the target", async () => {
    const primary = vi.fn<(bytes: TerminalBytes) => void>();
    const previous = vi.fn<(bytes: TerminalBytes) => void>();
    const replacement = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink: primary });
    element.broadcastSink = previous;
    await element.setBroadcastInput(true, () => true);
    element.clipboard = { readText: async () => "current paste" };
    element.addEventListener(
      "terminal-broadcast-input",
      () => {
        element.broadcastSink = replacement;
      },
      { once: true },
    );

    expect(await element.paste()).toBe(true);
    expect(primary).toHaveBeenCalledTimes(1);
    expect(previous).not.toHaveBeenCalled();
    expect(replacement).not.toHaveBeenCalled();
    expect(await element.paste()).toBe(true);
    expect(replacement).toHaveBeenCalledTimes(1);
  });

  it("does not report an old secondary paste failure to a replacement target", async () => {
    let rejectWrite: (error: Error) => void = () => undefined;
    const writing = new Promise<void>((_, reject) => {
      rejectWrite = reject;
    });
    const secondary = vi.fn(() => writing);
    const replacement = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink: vi.fn<(bytes: TerminalBytes) => void>() });
    element.broadcastSink = secondary;
    await element.setBroadcastInput(true, () => true);
    element.clipboard = { readText: async () => "current paste" };
    const errors = vi.fn();
    element.addEventListener("terminal-error", errors);
    const pending = element.paste();
    await flush();
    expect(secondary).toHaveBeenCalledTimes(1);
    element.broadcastSink = replacement;
    rejectWrite(new Error("old target closed"));

    expect(await pending).toBe(true);
    expect(errors).not.toHaveBeenCalled();
    expect(replacement).not.toHaveBeenCalled();
    expect(await element.paste()).toBe(true);
    expect(replacement).toHaveBeenCalledTimes(1);
  });

  it("discards a pending fallback paste when disposed without a renderer", async () => {
    vi.stubGlobal("matchMedia", undefined);
    let resolveRead: (text: string) => void = () => undefined;
    const text = new Promise<string>((resolve) => {
      resolveRead = resolve;
    });
    const sink = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({ sink });
    expect(element.size).toBeNull();
    element.clipboard = { readText: () => text };
    const pending = element.paste();
    await element.dispose();
    resolveRead("old fallback paste");

    expect(await pending).toBe(false);
    expect(sink).not.toHaveBeenCalled();
  });

  it("does not report a late clipboard failure to a replacement connection", async () => {
    let rejectRead: (error: Error) => void = () => undefined;
    const text = new Promise<string>((_, reject) => {
      rejectRead = reject;
    });
    const element = mount({ sink: vi.fn<(bytes: TerminalBytes) => void>() });
    const errors = vi.fn();
    element.addEventListener("terminal-error", errors);
    element.clipboard = { readText: () => text };
    const pending = element.paste();
    element.sink = vi.fn<(bytes: TerminalBytes) => void>();
    rejectRead(new Error("clipboard unavailable"));

    expect(await pending).toBe(false);
    expect(errors).not.toHaveBeenCalled();
  });

  it("refuses clipboard access while disconnected, read-only, or restoring", async () => {
    const element = mount();
    const readText = vi.fn(async () => "unrequested paste");
    element.clipboard = { readText };
    element.readOnly = true;
    expect(await element.paste()).toBe(false);
    element.readOnly = false;
    const restore = element.restore({ version: 1, columns: 80, rows: 24, data: "saved output" });
    expect(await element.paste()).toBe(false);
    await restore;
    element.remove();
    expect(await element.paste()).toBe(false);
    expect(readText).not.toHaveBeenCalled();
  });

  it("discards a clipboard read that crosses offline restoration", async () => {
    let resolveRead: (text: string) => void = () => undefined;
    const text = new Promise<string>((resolve) => {
      resolveRead = resolve;
    });
    const element = mount();
    const input = vi.fn();
    element.addEventListener("terminal-input", input);
    element.clipboard = { readText: () => text };
    const pending = element.paste();
    await element.restore({ version: 1, columns: 80, rows: 24, data: "saved output" });
    resolveRead("old paste");

    expect(await pending).toBe(false);
    expect(input).not.toHaveBeenCalled();
  });

  it("applies the input byte limit to the complete bracketed paste", async () => {
    const sink = vi.fn<(bytes: TerminalBytes) => void>();
    const element = mount({
      source: { subscribe: (emit) => emit(new TextEncoder().encode("\x1b[?2004h")) },
      sink,
    });
    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));
    element.clipboard = { readText: async () => "\u00e9\u00e9" };
    element.maxInputBytes = 15;
    await element.serialize();

    expect(await element.paste()).toBe(false);
    await flush();
    expect(sink).not.toHaveBeenCalled();
    expect(errors.map((error) => error.code)).toEqual(["bounds"]);

    element.maxInputBytes = 16;
    expect(await element.paste()).toBe(true);
    await flush();
    expect(sink.mock.calls.map(([bytes]) => [...bytes])).toEqual([
      [...new TextEncoder().encode("\x1b[200~\u00e9\u00e9\x1b[201~")],
    ]);
  });

  it("reports a failed paste sink once and returns false", async () => {
    const element = mount({ sink: async () => Promise.reject(new Error("transport closed")) });
    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));
    element.clipboard = { readText: async () => "paste" };

    expect(await element.paste()).toBe(false);
    expect(errors.map((error) => error.code)).toEqual(["stream"]);
  });

  it("waits for the primary paste write to finish", async () => {
    let finishWrite: () => void = () => undefined;
    const writing = new Promise<void>((resolve) => {
      finishWrite = resolve;
    });
    const sink = vi.fn(() => writing);
    const element = mount({ sink });
    element.clipboard = { readText: async () => "paste" };
    let finished = false;
    const pending = element.paste().then((result) => {
      finished = true;
      return result;
    });
    await flush();
    expect(sink).toHaveBeenCalledTimes(1);
    expect(finished).toBe(false);
    finishWrite();
    expect(await pending).toBe(true);
  });

  it("rejects a paste when the existing input queue is full", async () => {
    let finishWrite: () => void = () => undefined;
    const writing = new Promise<void>((resolve) => {
      finishWrite = resolve;
    });
    const sink = vi.fn(() => writing);
    const element = mount({ sink });
    element.maxPendingWrites = 1;
    element.clipboard = { readText: async () => "paste" };
    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));
    const first = element.send(new Uint8Array([65]));

    expect(await element.paste()).toBe(false);
    expect(errors.map((error) => error.code)).toEqual(["backpressure"]);
    expect(sink).toHaveBeenCalledTimes(1);
    finishWrite();
    await first;
  });

  it("reports a current clipboard read failure once", async () => {
    const element = mount({ sink: vi.fn<(bytes: TerminalBytes) => void>() });
    element.clipboard = { readText: async () => Promise.reject(new Error("clipboard unavailable")) };
    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));

    expect(await element.paste()).toBe(false);
    expect(errors.map((error) => error.code)).toEqual(["clipboard"]);
  });

  it("requires confirmation before enabling broadcast input and exposes the visible state", async () => {
    const primary: number[][] = [];
    const broadcast: number[][] = [];
    const element = mount({
      sink: (bytes) => {
        primary.push([...bytes]);
      },
    });
    element.broadcastSink = (bytes) => {
      broadcast.push([...bytes]);
    };
    expect(await element.setBroadcastInput(true)).toBe(false);
    expect(element.broadcastInput).toBe(false);
    expect(await element.setBroadcastInput(true, () => false)).toBe(false);
    expect(await element.setBroadcastInput(true, () => true)).toBe(true);
    const indicator = element.shadowRoot?.querySelector("[part='broadcast-indicator']") as HTMLElement;
    expect(element.broadcastInput).toBe(true);
    expect(indicator.hidden).toBe(false);

    const events: number[][] = [];
    element.addEventListener("terminal-broadcast-input", (event) =>
      events.push([...(event as CustomEvent<TerminalBytes>).detail]),
    );
    await element.send(new Uint8Array([65]));
    expect(primary).toEqual([[65]]);
    expect(broadcast).toEqual([[65]]);
    expect(events).toEqual([[65]]);
    await element.setBroadcastInput(false);
    expect(indicator.hidden).toBe(true);
  });

  it("reports a primary sink failure while keeping the write rejection visible", async () => {
    const element = mount({
      sink: {
        write: async () => {
          throw new Error("transport closed");
        },
      },
    });
    const errors: TerminalError[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent<TerminalError>).detail));
    await expect(element.send(new Uint8Array([1]))).rejects.toThrow("transport closed");
    expect(errors).toHaveLength(1);
    expect(errors[0].code).toBe("stream");
  });

  it("cleans xterm and source subscriptions on disconnect and restores the fallback on reconnect", async () => {
    let cancelled = 0;
    let emit: ((chunk: TerminalBytes) => void) | undefined;
    const element = mount({
      source: {
        subscribe(onChunk) {
          emit = onChunk;
          return () => {
            cancelled += 1;
          };
        },
      },
    });
    emit?.(new Uint8Array([120]));
    await flush();
    element.remove();
    expect(cancelled).toBe(1);
    document.body.append(element);
    expect(cancelled).toBe(1);
    expect(element.getOutput()).toEqual(new Uint8Array([120]));
  });
});
