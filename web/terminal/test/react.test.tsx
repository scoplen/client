// SPDX-License-Identifier: Apache-2.0
import { render, act } from "@testing-library/react";
import { createRef } from "react";
import { Terminal } from "../src/react";
import type { ScoplenTerminalElement } from "../src";
import type { TerminalBytes, TerminalClipboard, TerminalSink } from "../src";

afterEach(() => {
  document.body.replaceChildren();
});

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("Terminal React binding", () => {
  it("passes binary source/sink and cleans up its source on unmount", async () => {
    let cancelled = 0;
    let emit: ((bytes: TerminalBytes) => void) | undefined;
    const source = {
      subscribe(onChunk: (bytes: TerminalBytes) => void) {
        emit = onChunk;
        onChunk(new Uint8Array([7]));
        return () => {
          cancelled += 1;
        };
      },
    };
    const writes: number[][] = [];
    const outputs: number[][] = [];
    const view = render(
      <Terminal
        source={source}
        sink={(bytes) => {
          writes.push([...bytes]);
        }}
        onTerminalOutput={(bytes) => outputs.push([...bytes])}
      />,
    );
    const element = view.container.firstElementChild;
    expect(element).toBeInstanceOf(HTMLElement);
    expect(outputs).toEqual([[7]]);
    emit?.(new Uint8Array([0, 255]));
    (element as HTMLElement).dispatchEvent(new KeyboardEvent("keydown", { key: "x", bubbles: true }));
    await act(flush);
    expect(outputs).toEqual([[7], [0, 255]]);
    expect(writes).toEqual([[120]]);
    view.unmount();
    expect(cancelled).toBe(1);
  });

  it("updates the profile without restarting the same source", () => {
    const unsubscribe = vi.fn();
    const subscribe = vi.fn(() => ({ unsubscribe }));
    const source = { subscribe };
    const ref = createRef<ScoplenTerminalElement>();
    const view = render(<Terminal ref={ref} source={source} profile={{ scrollback: 12 }} />);
    expect(subscribe).toHaveBeenCalledOnce();

    view.rerender(<Terminal ref={ref} source={source} profile={{ scrollback: 24 }} />);
    expect(ref.current?.profile.scrollback).toBe(24);
    expect(subscribe).toHaveBeenCalledOnce();
    expect(unsubscribe).not.toHaveBeenCalled();

    view.unmount();
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it("passes profile, clipboard, broadcast sink, and broadcast events", async () => {
    const ref = createRef<ScoplenTerminalElement>();
    const primary: number[][] = [];
    const broadcast: number[][] = [];
    const clipboard: TerminalClipboard = { readText: async () => "unused" };
    const broadcastSink: TerminalSink = (bytes) => {
      broadcast.push([...bytes]);
    };
    const states: boolean[] = [];
    render(
      <Terminal
        ref={ref}
        sink={(bytes) => {
          primary.push([...bytes]);
        }}
        broadcastSink={broadcastSink}
        clipboard={clipboard}
        profile={{ scrollback: 12 }}
        onTerminalBroadcastState={(enabled) => states.push(enabled)}
      />,
    );

    await act(async () => {
      await ref.current?.setBroadcastInput(true, () => true);
      await ref.current?.send(new Uint8Array([9]));
    });
    expect(ref.current?.profile.scrollback).toBe(12);
    expect(ref.current?.clipboard).toBe(clipboard);
    expect(primary).toEqual([[9]]);
    expect(broadcast).toEqual([[9]]);
    expect(states).toEqual([true]);
  });
});
