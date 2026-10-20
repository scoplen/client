// SPDX-License-Identifier: Apache-2.0
import {
  ScoplenTerminalElement,
  TerminalBackpressureError,
  TerminalBoundsError,
  TerminalDisconnectedError,
  type TerminalBytes,
} from "../src";

function mount(options: { source?: ScoplenTerminalElement["source"]; sink?: ScoplenTerminalElement["sink"] } = {}) {
  const element = document.createElement("scoplen-terminal") as ScoplenTerminalElement;
  element.source = options.source ?? null;
  element.sink = options.sink ?? null;
  document.body.append(element);
  return element;
}

afterEach(() => {
  document.body.replaceChildren();
});

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("ScoplenTerminalElement", () => {
  it("loads xterm styles inside its shadow root", () => {
    const element = mount();
    const stylesheet = element.shadowRoot?.querySelector('link[rel="stylesheet"]');
    expect(stylesheet).toBeInstanceOf(HTMLLinkElement);
    expect(stylesheet?.getAttribute("href")).toMatch(/xterm\.css$/);
  });

  it("preserves a host-provided accessible label", () => {
    const element = document.createElement("scoplen-terminal");
    element.setAttribute("aria-label", "SSH terminal output");
    document.body.append(element);
    expect(element.getAttribute("aria-label")).toBe("SSH terminal output");
  });

  it("keeps output binary, renders text, and reports only an actual bound overflow", () => {
    let emit: ((chunk: TerminalBytes) => void) | undefined;
    const source = {
      subscribe(onChunk: (chunk: TerminalBytes) => void) {
        emit = onChunk;
        return () => undefined;
      },
    };
    const element = mount({ source });
    element.maxOutputBytes = 3;
    const errors: unknown[] = [];
    element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent).detail));
    emit?.(new Uint8Array([0x68, 0xc3, 0xa9]));
    emit?.(new Uint8Array([0x21]));
    expect([...element.getOutput()]).toEqual([0xc3, 0xa9, 0x21]);
    expect(element.shadowRoot?.querySelector("pre")?.textContent).toBe("é!");
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(TerminalBoundsError);
  });

  it("unsubscribes a source on disconnect and can attach again", () => {
    let subscriptions = 0;
    let cancellations = 0;
    let emit: ((chunk: TerminalBytes) => void) | undefined;
    const source = {
      subscribe(onChunk: (chunk: TerminalBytes) => void) {
        subscriptions += 1;
        emit = onChunk;
        return () => {
          cancellations += 1;
        };
      },
    };
    const element = mount({ source });
    expect(subscriptions).toBe(1);
    element.remove();
    expect(cancellations).toBe(1);
    emit?.(new Uint8Array([0x78]));
    expect(element.getOutput()).toHaveLength(0);
    document.body.append(element);
    expect(subscriptions).toBe(2);
    element.source = null;
    expect(cancellations).toBe(2);
  });

  it("serializes sink writes and rejects input when the pending bound is full", async () => {
    const writes: number[][] = [];
    const resolvers: Array<() => void> = [];
    const sink = {
      write(chunk: TerminalBytes) {
        writes.push([...chunk]);
        return new Promise<void>((resolve) => resolvers.push(resolve));
      },
    };
    const element = mount({ sink });
    element.maxPendingWrites = 2;
    const first = element.send(new Uint8Array([1]));
    const second = element.send(new Uint8Array([2]));
    await expect(element.send(new Uint8Array([3]))).rejects.toBeInstanceOf(TerminalBackpressureError);
    await Promise.resolve();
    expect(writes).toEqual([[1]]);
    resolvers.shift()?.();
    await flush();
    expect(writes).toEqual([[1], [2]]);
    resolvers.shift()?.();
    await expect(first).resolves.toBeUndefined();
    await expect(second).resolves.toBeUndefined();
  });

  it.each(["direct", "via-null", "reused-after-null"])(
    "cancels queued input when a sink is replaced %s without affecting the replacement",
    async (replacement) => {
      for (const failed of [false, true]) {
        const oldWrites: number[][] = [];
        const newWrites: number[][] = [];
        const broadcasts: number[][] = [];
        const errors: unknown[] = [];
        let release!: () => void;
        let reject!: (reason: unknown) => void;
        const pending = new Promise<void>((resolve, fail) => {
          release = resolve;
          reject = fail;
        });
        const oldSink = (bytes: TerminalBytes) => {
          oldWrites.push([...bytes]);
          if (oldWrites.length === 1) return pending;
        };
        const element = mount({ sink: oldSink });
        element.broadcastSink = (bytes) => {
          broadcasts.push([...bytes]);
        };
        await element.setBroadcastInput(true, () => true);
        element.addEventListener("terminal-error", (event) => errors.push((event as CustomEvent).detail));
        const first = element.send(new Uint8Array([1]));
        const queued = element.send(new Uint8Array([2]));
        const cancelled = Promise.allSettled([first, queued]);
        await flush();
        expect(oldWrites).toEqual([[1]]);
        if (replacement !== "direct") element.sink = null;
        element.sink =
          replacement === "reused-after-null"
            ? oldSink
            : (bytes) => {
                newWrites.push([...bytes]);
              };
        const control = element.send(new Uint8Array([3]));
        if (failed) reject(new Error("old transport failed"));
        else release();
        for (const result of await cancelled) {
          expect(result.status).toBe("rejected");
          if (result.status === "rejected") expect(result.reason).toBeInstanceOf(TerminalDisconnectedError);
        }
        await expect(control).resolves.toBeUndefined();
        expect(oldWrites).toEqual(replacement === "reused-after-null" ? [[1], [3]] : [[1]]);
        expect(newWrites).toEqual(replacement === "reused-after-null" ? [] : [[3]]);
        expect(broadcasts).toEqual([[3]]);
        expect(errors).toEqual([]);
        element.remove();
      }
    },
  );

  it("keeps queued input when the same sink is assigned again", async () => {
    const writes: number[][] = [];
    const sink = (bytes: TerminalBytes) => {
      writes.push([...bytes]);
    };
    const element = mount({ sink });
    const pending = element.send(new Uint8Array([1]));
    element.sink = sink;
    await pending;
    expect(writes).toEqual([[1]]);
  });

  it("maps keyboard input to bytes at the sink boundary", async () => {
    const writes: number[][] = [];
    const element = mount({
      sink: (chunk) => {
        writes.push([...chunk]);
      },
    });
    element.dispatchEvent(new KeyboardEvent("keydown", { key: "A", bubbles: true }));
    element.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    element.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowUp", bubbles: true }));
    element.dispatchEvent(new KeyboardEvent("keydown", { key: "c", ctrlKey: true, bubbles: true }));
    await flush();
    expect(writes).toEqual([[65], [13], [27, 91, 65], [3]]);
  });

  it("commits only compositionend text and never sends composition updates", async () => {
    const writes: string[] = [];
    const element = mount({
      sink: (chunk) => {
        writes.push(new TextDecoder().decode(chunk));
      },
    });
    element.dispatchEvent(new CompositionEvent("compositionstart", { data: "" }));
    element.dispatchEvent(new CompositionEvent("compositionupdate", { data: "n" }));
    element.dispatchEvent(new CompositionEvent("compositionupdate", { data: "ni" }));
    expect(writes).toEqual([]);
    element.dispatchEvent(new CompositionEvent("compositionend", { data: "你" }));
    await flush();
    expect(writes).toEqual(["你"]);
  });

  it("cancels composition on explicit cancellation and focus loss", async () => {
    const writes: string[] = [];
    const element = mount({
      sink: (chunk) => {
        writes.push(new TextDecoder().decode(chunk));
      },
    });
    element.dispatchEvent(new CompositionEvent("compositionstart", { data: "" }));
    element.dispatchEvent(new CompositionEvent("compositionupdate", { data: "候选" }));
    element.dispatchEvent(new CompositionEvent("compositioncancel", { data: "" }));
    element.dispatchEvent(new CompositionEvent("compositionend", { data: "候选" }));
    element.dispatchEvent(new CompositionEvent("compositionstart", { data: "" }));
    element.dispatchEvent(new CompositionEvent("compositionupdate", { data: "失焦" }));
    element.dispatchEvent(new FocusEvent("blur"));
    element.dispatchEvent(new CompositionEvent("compositionend", { data: "失焦" }));
    await flush();
    expect(writes).toEqual([]);
  });

  it("exposes a custom element constructor for direct consumers", () => {
    expect(document.createElement("scoplen-terminal")).toBeInstanceOf(ScoplenTerminalElement);
  });
});
