// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import type { Channel } from "@tauri-apps/api/core";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { AppearanceProvider } from "@scoplen/ui";
import { I18nProvider } from "../src/i18n";
import { TerminalColorsProvider } from "../src/terminal-colors";
import { SessionTerminal } from "../src/session";
import type { PreparationEvent, PreparationContext } from "../src/ipc/bindings";
import type { ScoplenTerminalElement } from "@scoplen/terminal";

afterEach(() => clearMocks());

it("routes terminal input to the live SSH session and closes its transport", async () => {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_connect") return new Promise(() => undefined);
    return null;
  });

  const close = vi.fn();
  const { container } = render(
    <StrictMode>
      <AppearanceProvider>
        <TerminalColorsProvider>
          <I18nProvider locale="en">
            <SessionTerminal profileId="profile-1" label="server · root" onClose={close} />
          </I18nProvider>
        </TerminalColorsProvider>
      </AppearanceProvider>
    </StrictMode>,
  );
  await waitFor(() => expect(calls.some((call) => call.command === "session_connect")).toBe(true));
  expect(calls.filter((call) => call.command === "session_connect")).toHaveLength(1);
  const terminal = container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  const connection = calls.find((call) => call.command === "session_connect");
  const ready = connection?.args.ready as Channel<null>;
  expect(screen.getByRole("status").textContent).toContain("Connecting");
  await act(() => ready.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("Connected");
  await terminal.send(new Uint8Array([108, 115, 13]));
  const input = calls.find((call) => call.command === "session_input");
  expect(input?.args).toMatchObject({ sessionId: connection?.args.sessionId, data: [108, 115, 13] });

  await userEvent.click(screen.getByRole("button", { name: "Close session" }));
  expect(close).toHaveBeenCalledOnce();
  expect(
    calls.some(
      (call) => call.command === "session_close_transport" && call.args.sessionId === connection?.args.sessionId,
    ),
  ).toBe(true);
});

function sessionView(locale: "en" | "zh-Hans", onStateChange: (state: string) => void) {
  return (
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale={locale}>
          <SessionTerminal
            profileId="profile-1"
            label="Silent server"
            onClose={vi.fn()}
            onStateChange={onStateChange}
          />
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>
  );
}

function renderSession(onStateChange = vi.fn()) {
  return render(sessionView("en", onStateChange));
}

it.each(["connecting", "connected"])("keeps the same SSH transport when locale changes while %s", async (state) => {
  const calls: string[] = [];
  let ready: Channel<null> | undefined;
  mockIPC((command, args) => {
    calls.push(command);
    if (command === "session_connect") {
      ready = (args as { ready: Channel<null> }).ready;
      return new Promise(() => undefined);
    }
    return null;
  });
  const onStateChange = vi.fn();
  const view = renderSession(onStateChange);
  await waitFor(() => expect(ready).toBeDefined());
  if (state === "connected") await act(() => ready!.onmessage(null));
  calls.length = 0;
  view.rerender(sessionView("zh-Hans", onStateChange));
  expect(screen.getByRole("status").textContent).toContain(state === "connected" ? "已连接" : "正在连接");
  expect(calls).not.toContain("session_host_key");
  expect(calls).not.toContain("session_connect");
  expect(calls).not.toContain("session_close_transport");
});

it("makes a silent shell ready without terminal bytes and resizes its PTY", async () => {
  let ready: Channel<null> | undefined;
  const resize = vi.fn();
  mockIPC((command, args) => {
    if (command === "session_connect") {
      ready = (args as { ready: Channel<null> }).ready;
      return new Promise(() => undefined);
    }
    if (command === "session_resize") resize(args);
    return null;
  });
  const { container } = renderSession();
  await waitFor(() => expect(ready).toBeDefined());
  const terminal = container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => {
    terminal.dispatchEvent(new CustomEvent("terminal-resize", { detail: { columns: 120, rows: 40 } }));
  });
  expect(resize).not.toHaveBeenCalled();
  await act(() => ready!.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("Connected");
  await waitFor(() => expect(resize).toHaveBeenCalledWith(expect.objectContaining({ columns: 120, rows: 40 })));
});

it.each(["closed", "failed"])("does not revive a %s connection from late readiness or output", async (ending) => {
  let ready: Channel<null> | undefined;
  let frames: Channel<ArrayBuffer> | undefined;
  let finish: (() => void) | undefined;
  mockIPC((command, args) => {
    if (command === "session_connect") {
      ({ ready, frames } = args as { ready: Channel<null>; frames: Channel<ArrayBuffer> });
      return new Promise<void>((resolve, reject) => {
        finish = () => (ending === "closed" ? resolve() : reject("authentication failed"));
      });
    }
    return null;
  });
  const { container } = renderSession();
  await waitFor(() => expect(finish).toBeDefined());
  await act(() => frames!.onmessage(new ArrayBuffer(0)));
  expect(screen.getByRole("status").textContent).toContain("Connecting");
  await act(async () => {
    finish!();
  });
  if (ending === "failed") expect(screen.getByRole("alert").textContent).toBe("authentication failed");
  const status = screen.getByRole("status").textContent;
  expect(status).toContain(ending === "closed" ? "closed" : "failed");
  await act(() => {
    ready!.onmessage(null);
    frames!.onmessage(new Uint8Array([98, 121, 101]).buffer);
  });
  expect(screen.getByRole("status").textContent).toBe(status);
  const terminal = container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("bye");
});

it("ignores a late readiness notification after unmounting and closes the transport", async () => {
  let ready: Channel<null> | undefined;
  const close = vi.fn();
  mockIPC((command, args) => {
    if (command === "session_connect") {
      ready = (args as { ready: Channel<null> }).ready;
      return new Promise(() => undefined);
    }
    if (command === "session_close_transport") close(args);
    return null;
  });
  const report = vi.fn();
  const view = renderSession(report);
  await waitFor(() => expect(ready).toBeDefined());
  view.unmount();
  report.mockClear();
  await act(() => ready!.onmessage(null));
  expect(report).not.toHaveBeenCalled();
  expect(close).toHaveBeenCalled();
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

function fixture() {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const connections: Array<{
    sessionId: string;
    ready: Channel<null>;
    frames: Channel<ArrayBuffer>;
    preparation: Channel<PreparationEvent>;
    finish: ReturnType<typeof deferred<null>>;
  }> = [];
  const replies: Array<ReturnType<typeof deferred<null>>> = [];
  const inputs: Array<ReturnType<typeof deferred<null>>> = [];
  const reservations: Array<ReturnType<typeof deferred<null>>> = [];
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_reserve_transport") return reservations.shift()?.promise ?? null;
    if (command === "session_connect") {
      const finish = deferred<null>();
      connections.push({ ...(payload as unknown as (typeof connections)[number]), finish });
      return finish.promise;
    }
    if (command === "session_respond") return replies.shift()?.promise ?? null;
    if (command === "session_input") return inputs.shift()?.promise ?? null;
    return null;
  });
  return { calls, connections, replies, inputs, reservations };
}

function context(position = 1, target = false): PreparationContext {
  return {
    profileId: `profile-${position}`,
    hostId: `host-${position}`,
    login: `Login ${position}`,
    host: `Host ${position}`,
    username: "ops",
    address: `jump${position}.example`,
    port: 2222,
    position,
    total: 3,
    target,
  };
}

function trust(position = 1, changed = false): PreparationEvent {
  return {
    kind: "trust",
    context: context(position, position === 3),
    promptId: `trust-${position}`,
    hostKey: { algorithm: "ssh-ed25519", key: `public-${position}`, fingerprint: `SHA256:hop-${position}`, changed },
  };
}

function passphrase(position = 1, incorrect = false): PreparationEvent {
  return {
    kind: "passphrase",
    context: context(position, position === 3),
    promptId: `pass-${position}-${incorrect}`,
    incorrect,
  };
}

it("closes a late reservation ACK after its tab closes without starting SSH, then connects a fresh tab", async () => {
  const f = fixture();
  const pending = deferred<null>();
  f.reservations.push(pending);
  const first = renderSession();
  await waitFor(() => expect(f.calls.filter((c) => c.command === "session_reserve_transport")).toHaveLength(1));
  const oldId = f.calls.find((c) => c.command === "session_reserve_transport")!.args.sessionId;
  first.unmount();
  const closesBeforeACK = f.calls.filter((c) => c.command === "session_close_transport").length;
  await act(() => pending.resolve(null));
  expect(f.connections).toHaveLength(0);
  expect(f.calls.filter((c) => c.command === "session_close_transport")).toHaveLength(closesBeforeACK + 1);
  expect(f.calls.filter((c) => c.command === "session_close_transport").at(-1)?.args.sessionId).toBe(oldId);

  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  expect(f.connections[0]!.sessionId).not.toBe(oldId);
  await act(() => f.connections[0]!.ready.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("Connected");
});

it("requests a fresh blank passphrase after reconnect and fences the prior prompt", async () => {
  const f = fixture();
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const first = f.connections[0]!;
  await act(() => first.preparation.onmessage(passphrase(2)));
  await userEvent.type(screen.getByLabelText("Key passphrase"), "old-disposable");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  await act(() => first.finish.reject("connection lost"));
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(f.connections).toHaveLength(2));
  const second = f.connections[1]!;
  await act(() => second.preparation.onmessage(passphrase(3)));
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
  await act(() => first.preparation.onmessage(passphrase(1, true)));
  expect(screen.getByText("Host 3 · Login 3")).toBeTruthy();
  await userEvent.type(screen.getByLabelText("Key passphrase"), "fresh-disposable");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(f.calls.filter((c) => c.command === "session_respond").at(-1)?.args).toMatchObject({
    sessionId: second.sessionId,
    promptId: "pass-3-false",
    intent: { kind: "passphrase", value: "fresh-disposable" },
  });
});

it("presents and accepts each hop's exact current prompt without renderer-supplied trust data", async () => {
  const f = fixture();
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const connection = f.connections[0]!;
  for (const position of [1, 2, 3]) {
    await act(() => connection.preparation.onmessage(trust(position, position === 2)));
    expect(screen.getByText(`Host ${position} · Login ${position}`)).toBeTruthy();
    expect(screen.getByText(`ops@jump${position}.example:2222`)).toBeTruthy();
    expect(screen.getByText(`SHA256:hop-${position}`)).toBeTruthy();
    expect(screen.getByText(`${position === 3 ? "Target host" : "Jump host"} · ${position} / 3`)).toBeTruthy();
    if (position === 2) expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(f.calls.filter((c) => c.command === "session_respond").at(-1)?.args).toEqual({
      sessionId: connection.sessionId,
      promptId: `trust-${position}`,
      intent: { kind: "acceptHostKey" },
    });
  }
  expect(f.connections).toHaveLength(1);
  await act(() => connection.ready.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("Connected");
});

it("identifies the current jump while connection preparation is running", async () => {
  const f = fixture();
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  await act(() =>
    f.connections[0]!.preparation.onmessage({
      kind: "progress",
      context: context(2),
      phase: "connecting",
    }),
  );
  expect(screen.getByText("Jump host · 2 / 3")).toBeTruthy();
  expect(screen.getByText("Host 2 · Login 2")).toBeTruthy();
  expect(screen.getByText("ops@jump2.example:2222")).toBeTruthy();
});

it("clears each one-time passphrase, retries locally, and keeps one preparation transport", async () => {
  const f = fixture();
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const connection = f.connections[0]!;
  await act(() => connection.preparation.onmessage(passphrase()));
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(screen.getByText("Enter the key passphrase to connect.")).toBeTruthy();
  for (const [value, incorrect] of [
    ["wrong-disposable", false],
    ["correct-disposable", true],
  ] as const) {
    if (incorrect) {
      await act(() => connection.preparation.onmessage(passphrase(1, true)));
      expect(screen.getByText("That passphrase did not unlock the key. Check it and try again.")).toBeTruthy();
    }
    const input = screen.getByLabelText("Key passphrase") as HTMLInputElement;
    expect(input.value).toBe("");
    await userEvent.type(input, value);
    await userEvent.keyboard("{Enter}");
    expect(input.value).toBe("");
    expect(f.calls.filter((c) => c.command === "session_respond").at(-1)?.args).toMatchObject({
      promptId: `pass-1-${incorrect}`,
      intent: { kind: "passphrase", value },
    });
  }
  await act(() => connection.preparation.onmessage(passphrase(2)));
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
  expect(screen.getByText("Host 2 · Login 2")).toBeTruthy();
  expect(f.connections).toHaveLength(1);
});

it("does not let a delayed reply erase the next hop's prompt or duplicate a trust intent", async () => {
  const f = fixture();
  const first = deferred<null>();
  f.replies.push(first);
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  await act(() => f.connections[0]!.preparation.onmessage(trust()));
  const button = screen.getByRole("button", { name: "Trust and connect" });
  act(() => {
    button.click();
    button.click();
  });
  expect(f.calls.filter((c) => c.command === "session_respond")).toHaveLength(1);
  await act(() => f.connections[0]!.preparation.onmessage(trust(2)));
  await act(() => first.resolve(null));
  expect(screen.getByText("SHA256:hop-2")).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  expect(f.calls.filter((c) => c.command === "session_respond")).toHaveLength(2);
});

it.each(["trust", "passphrase"])("cancels a %s prompt and ignores late progress or readiness", async (kind) => {
  const f = fixture();
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const connection = f.connections[0]!;
  await act(() => connection.preparation.onmessage(kind === "trust" ? trust() : passphrase()));
  await userEvent.click(screen.getAllByRole("button", { name: "Cancel" }).at(-1)!);
  expect(
    f.calls.some((c) => c.command === "session_close_transport" && c.args.sessionId === connection.sessionId),
  ).toBe(true);
  expect(f.calls.filter((c) => c.command === "session_respond")).toHaveLength(0);
  await act(() => {
    connection.preparation.onmessage(trust(2));
    connection.ready.onmessage(null);
  });
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("failed");
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await act(() => connection.finish.resolve(null));
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
});

it.each(["closed", "failed"])("reconnects a %s session with fresh channels and retained output", async (ending) => {
  const f = fixture();
  const view = renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const first = f.connections[0]!;
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => {
    first.ready.onmessage(null);
    first.frames.onmessage(new TextEncoder().encode("first session\r\n").buffer);
  });
  await act(() => (ending === "closed" ? first.finish.resolve(null) : first.finish.reject("disconnected")));
  const button = screen.getByRole("button", { name: "Reconnect" });
  act(() => {
    button.click();
    button.click();
  });
  await waitFor(() => expect(f.connections).toHaveLength(2));
  const second = f.connections[1]!;
  expect(second.sessionId).not.toBe(first.sessionId);
  expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
  await act(() => {
    first.preparation.onmessage(trust());
    first.ready.onmessage(null);
    first.frames.onmessage(new TextEncoder().encode("stale").buffer);
  });
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\n");
  await act(() => second.preparation.onmessage(trust(2, true)));
  expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await act(() => {
    second.ready.onmessage(null);
    second.frames.onmessage(new TextEncoder().encode("second").buffer);
  });
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\nsecond");
  await terminal.send(new Uint8Array([13]));
  expect(f.calls.filter((c) => c.command === "session_input").at(-1)?.args.sessionId).toBe(second.sessionId);
});

it("waits for a failed terminal transport to settle and rejects late readiness", async () => {
  const f = fixture();
  const view = renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const terminal = view.container.querySelector("scoplen-terminal")!;
  act(() => terminal.dispatchEvent(new CustomEvent("terminal-error", { detail: { message: "write failed" } })));
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await act(() => f.connections[0]!.ready.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("failed");
  await act(() => f.connections[0]!.finish.resolve(null));
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(f.connections).toHaveLength(2));
});

it("cancels pending and queued old input without failing the replacement transport", async () => {
  const f = fixture();
  const pending = deferred<null>();
  f.inputs.push(pending);
  const view = renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => f.connections[0]!.ready.onmessage(null));
  const cancelled = Promise.allSettled([terminal.send(new Uint8Array([13])), terminal.send(new Uint8Array([14]))]);
  await waitFor(() => expect(f.calls.filter((c) => c.command === "session_input")).toHaveLength(1));
  await act(() => f.connections[0]!.finish.resolve(null));
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(f.connections).toHaveLength(2));
  await act(() => f.connections[1]!.ready.onmessage(null));
  await act(async () => {
    pending.reject("old input failed");
    expect((await cancelled).map((r) => r.status)).toEqual(["rejected", "rejected"]);
  });
  expect(screen.getByRole("status").textContent).toContain("Connected");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(f.calls.filter((c) => c.command === "session_input")).toHaveLength(1);
  await terminal.send(new Uint8Array([15]));
  expect(f.calls.filter((c) => c.command === "session_input").at(-1)?.args.sessionId).toBe(f.connections[1]!.sessionId);
});

it("retains current prompt after a response error and cancels an in-flight trust reply", async () => {
  const f = fixture();
  const rejected = deferred<null>();
  f.replies.push(rejected);
  renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  await act(() => f.connections[0]!.preparation.onmessage(trust()));
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await act(() => rejected.reject("store unavailable"));
  expect(screen.getByText("SHA256:hop-1")).toBeTruthy();
  expect(screen.getByRole("alert").textContent).toBe("store unavailable");
  const pending = deferred<null>();
  f.replies.push(pending);
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await userEvent.keyboard("{Escape}");
  await act(() => pending.resolve(null));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("failed");
});

it("ignores all late preparation events and responses after closing its tab", async () => {
  const f = fixture();
  const pending = deferred<null>();
  f.replies.push(pending);
  const view = renderSession();
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const connection = f.connections[0]!;
  await act(() => connection.preparation.onmessage(trust()));
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  view.unmount();
  await act(() => {
    pending.resolve(null);
    connection.preparation.onmessage(passphrase());
    connection.ready.onmessage(null);
    connection.finish.reject("late failure");
  });
  expect(f.calls.filter((c) => c.command === "session_respond")).toHaveLength(1);
  expect(
    f.calls.some((c) => c.command === "session_close_transport" && c.args.sessionId === connection.sessionId),
  ).toBe(true);
});
