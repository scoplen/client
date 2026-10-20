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
import type { PreparationEvent, PreparationContext, SessionEvent } from "../src/ipc/bindings";
import type { ScoplenTerminalElement } from "@scoplen/terminal";

afterEach(() => clearMocks());

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
    messages: Channel<SessionEvent | ArrayBuffer>;
    finish: ReturnType<typeof deferred<null>>;
  }> = [];
  const pending = new Map<string, Array<ReturnType<typeof deferred<null>>>>();
  const delay = (command: string) => {
    const reply = deferred<null>();
    pending.set(command, [...(pending.get(command) ?? []), reply]);
    return reply;
  };
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_connect") {
      const finish = deferred<null>();
      connections.push({ ...(payload as unknown as (typeof connections)[number]), finish });
      return finish.promise;
    }
    return pending.get(command)?.shift()?.promise ?? null;
  });
  return { connections, delay, matching: (command: string) => calls.filter((c) => c.command === command) };
}

function sessionView(locale: "en" | "zh-Hans" = "en", active = true, onClose = vi.fn(), onStateChange = vi.fn()) {
  return (
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale={locale}>
          <SessionTerminal
            profileId="profile-1"
            label="Silent server"
            active={active}
            onClose={onClose}
            onStateChange={onStateChange}
          />
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>
  );
}

async function connect(f: ReturnType<typeof fixture>, index = 0) {
  await waitFor(() => expect(f.connections).toHaveLength(index + 1));
  const connection = f.connections[index]!;
  const channel = connection.messages;
  const start = async (automatic = false) => {
    const transportId = crypto.randomUUID();
    await act(() => channel.onmessage({ kind: "starting", transportId, automatic }));
    return {
      transportId,
      ready: () => act(() => channel.onmessage({ kind: "ready", transportId })),
      prepare: (event: PreparationEvent) => act(() => channel.onmessage({ kind: "preparation", transportId, event })),
      output: (text: string) => act(() => channel.onmessage(outputFrame(transportId, text))),
    };
  };
  return {
    ...connection,
    start,
    emit: (event: SessionEvent) => act(() => channel.onmessage(event)),
    ...(await start()),
  };
}

function outputFrame(transportId: string, text: string): ArrayBuffer {
  const data = new TextEncoder().encode(text);
  const bytes = new Uint8Array(16 + data.length);
  const uuid = transportId.replaceAll("-", "");
  for (let index = 0; index < 16; index++) bytes[index] = Number.parseInt(uuid.slice(index * 2, index * 2 + 2), 16);
  bytes.set(data, 16);
  return bytes.buffer;
}

function context(position = 1): PreparationContext {
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
    target: position === 3,
  };
}
function trust(position = 1, changed = false): PreparationEvent {
  return {
    kind: "trust",
    context: context(position),
    promptId: `trust-${position}`,
    hostKey: { algorithm: "ssh-ed25519", key: `public-${position}`, fingerprint: `SHA256:hop-${position}`, changed },
  };
}
function passphrase(position = 1, incorrect = false): PreparationEvent {
  return { kind: "passphrase", context: context(position), promptId: `pass-${position}-${incorrect}`, incorrect };
}

it("reserves once in StrictMode, routes input/resize to the exact attempt, and closes", async () => {
  const f = fixture();
  const close = vi.fn();
  const view = render(<StrictMode>{sessionView("en", true, close)}</StrictMode>);
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => terminal.dispatchEvent(new CustomEvent("terminal-resize", { detail: { columns: 120, rows: 40 } })));
  expect(f.matching("session_resize")).toHaveLength(0);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("Connected");
  await waitFor(() =>
    expect(f.matching("session_resize").at(-1)?.args).toMatchObject({
      sessionId: c.sessionId,
      transportId: c.transportId,
      columns: 120,
      rows: 40,
    }),
  );
  await terminal.send(new Uint8Array([108, 115, 13]));
  expect(f.matching("session_input").at(-1)?.args).toMatchObject({
    sessionId: c.sessionId,
    transportId: c.transportId,
    data: [108, 115, 13],
  });
  expect(f.connections).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Close session" }));
  expect(close).toHaveBeenCalledOnce();
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
});

it.each(["connecting", "connected"])("keeps the transport when locale changes while %s", async (state) => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  if (state === "connected") await c.ready();
  view.rerender(sessionView("zh-Hans"));
  expect(screen.getByRole("status").textContent).toContain(state === "connected" ? "已连接" : "正在连接");
  expect(f.connections).toHaveLength(1);
  expect(f.matching("session_close_transport")).toHaveLength(0);
});

it.each(["closed", "failed"] as const)(
  "reconnects a %s attempt with retained output and no stale input/output",
  async (ending) => {
    const f = fixture();
    const view = render(sessionView());
    const c = await connect(f);
    const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
    await c.ready();
    await c.output("first session\r\n");
    await c.emit(
      ending === "closed" ? { kind: "closed" } : { kind: "failed", error: "disconnected", exhausted: false },
    );
    await c.ready();
    await c.output("stale");
    expect(screen.getByRole("status").textContent).toContain(ending);
    const button = screen.getByRole("button", { name: "Reconnect" });
    act(() => {
      button.click();
      button.click();
    });
    expect(f.matching("session_retry_transport")).toHaveLength(1);
    const second = await c.start();
    expect(second.transportId).not.toBe(c.transportId);
    expect(f.connections).toHaveLength(1);
    expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
    await c.prepare(trust());
    await c.output("stale");
    expect(screen.queryByRole("dialog")).toBeNull();
    await second.prepare(trust(2, true));
    expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    await second.ready();
    await second.output("second");
    expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\nsecond");
    await terminal.send(new Uint8Array([13]));
    expect(f.matching("session_input").at(-1)?.args).toMatchObject({
      sessionId: c.sessionId,
      transportId: second.transportId,
    });
  },
);

it("keeps the first frame delivered immediately after starting on the same channel", async () => {
  const f = fixture();
  const view = render(sessionView());
  await waitFor(() => expect(f.connections).toHaveLength(1));
  const channel = f.connections[0]!.messages;
  const transportId = crypto.randomUUID();
  await act(() => {
    channel.onmessage({ kind: "starting", transportId, automatic: false });
    channel.onmessage(outputFrame(transportId, "first prompt"));
    channel.onmessage({ kind: "ready", transportId });
  });
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("first prompt");
});

it("renders automatic backoff and waits for Stop cleanup before allowing manual retry", async () => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  await c.ready();
  await c.output("old output");
  await c.emit({ kind: "retrying", attempt: 2, delaySeconds: 2, error: "Network connection lost" });
  expect(screen.getByRole("status").textContent).toContain("Retry 2 of 5 in 2 seconds");
  expect(screen.getByText("Reconnecting starts a new remote shell. Your terminal output stays here.")).toBeTruthy();
  await c.output("stale");
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("old output");
  await userEvent.click(screen.getByRole("button", { name: "Stop reconnecting" }));
  expect(f.matching("session_stop_reconnecting")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("closed");
  await c.emit({ kind: "closed" });
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
});

it("reports a failed Stop intent without leaving controls stuck", async () => {
  const f = fixture();
  const pending = f.delay("session_stop_reconnecting");
  render(sessionView());
  const c = await connect(f);
  await c.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  await userEvent.click(screen.getByRole("button", { name: "Stop reconnecting" }));
  await act(() => pending.reject("session control unavailable"));
  expect(screen.getByRole("alert").textContent).toBe("session control unavailable");
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
});

it.each(["reservation", "manager"])("recreates a failed %s and retains the terminal", async (failure) => {
  const f = fixture();
  const pending = failure === "reservation" ? f.delay("session_reserve_transport") : null;
  const view = render(sessionView());
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  if (pending) {
    await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(1));
    await act(() => pending.reject("reservation failed"));
  } else {
    const c = await connect(f);
    await c.ready();
    await c.output("keep this");
    await act(() => c.finish.reject("manager failed"));
  }
  const oldId = f.matching("session_reserve_transport")[0]!.args.sessionId;
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(2));
  expect(f.matching("session_reserve_transport")[1]?.args.sessionId).not.toBe(oldId);
  expect(f.matching("session_retry_transport")).toHaveLength(0);
  expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
  if (!pending) expect(new TextDecoder().decode(terminal.getOutput())).toBe("keep this");
});

it("closes a late reservation ACK after tab closure without starting SSH", async () => {
  const f = fixture();
  const pending = f.delay("session_reserve_transport");
  const view = render(sessionView());
  await waitFor(() => expect(f.matching("session_reserve_transport")).toHaveLength(1));
  const oldId = f.matching("session_reserve_transport")[0]!.args.sessionId;
  view.unmount();
  const count = f.matching("session_close_transport").length;
  await act(() => pending.resolve(null));
  expect(f.connections).toHaveLength(0);
  expect(f.matching("session_close_transport")).toHaveLength(count + 1);
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(oldId);
});

it("accepts each hop's exact current prompt without renderer-supplied trust data", async () => {
  const f = fixture();
  render(sessionView());
  const c = await connect(f);
  await c.prepare({ kind: "progress", context: context(2), phase: "connecting" });
  expect(screen.getByText("Jump host · 2 / 3")).toBeTruthy();
  for (const position of [1, 2, 3]) {
    await c.prepare(trust(position, position === 2));
    expect(screen.getByText(`Host ${position} · Login ${position}`)).toBeTruthy();
    expect(screen.getByText(`ops@jump${position}.example:2222`)).toBeTruthy();
    expect(screen.getByText(`SHA256:hop-${position}`)).toBeTruthy();
    if (position === 2) expect(screen.getByRole("heading", { name: "Host key changed" })).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(f.matching("session_respond").at(-1)?.args).toEqual({
      sessionId: c.sessionId,
      promptId: `trust-${position}`,
      intent: { kind: "acceptHostKey" },
    });
  }
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("Connected");
});

it("clears one-time passphrases, handles incorrect replies, and asks again on a fresh attempt", async () => {
  const f = fixture();
  render(sessionView());
  const c = await connect(f);
  await c.prepare(passphrase());
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(screen.getByText("Enter the key passphrase to connect.")).toBeTruthy();
  for (const [value, incorrect] of [
    ["wrong-disposable", false],
    ["correct-disposable", true],
  ] as const) {
    if (incorrect) {
      await c.prepare(passphrase(1, true));
      expect(screen.getByText("That passphrase did not unlock the key. Check it and try again.")).toBeTruthy();
    }
    const input = screen.getByLabelText("Key passphrase") as HTMLInputElement;
    expect(input.value).toBe("");
    await userEvent.type(input, value);
    await userEvent.keyboard("{Enter}");
    expect(input.value).toBe("");
    expect(f.matching("session_respond").at(-1)?.args).toMatchObject({
      promptId: `pass-1-${incorrect}`,
      intent: { kind: "passphrase", value },
    });
  }
  await c.emit({ kind: "failed", error: "connection lost", exhausted: false });
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  const second = await c.start();
  await second.prepare(passphrase(3));
  await c.prepare(passphrase(1, true));
  expect(screen.getByText("Host 3 · Login 3")).toBeTruthy();
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
});

it("fences delayed prompt responses and duplicate trust intents", async () => {
  const f = fixture();
  const first = f.delay("session_respond");
  render(sessionView());
  const c = await connect(f);
  await c.prepare(trust());
  const button = screen.getByRole("button", { name: "Trust and connect" });
  act(() => {
    button.click();
    button.click();
  });
  expect(f.matching("session_respond")).toHaveLength(1);
  await c.prepare(trust(2));
  await act(() => first.resolve(null));
  expect(screen.getByText("SHA256:hop-2")).toBeTruthy();
  const rejected = f.delay("session_respond");
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await act(() => rejected.reject("store unavailable"));
  expect(screen.getByRole("alert").textContent).toBe("store unavailable");
  const pending = f.delay("session_respond");
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  await userEvent.keyboard("{Escape}");
  await act(() => pending.resolve(null));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("closed");
});

it.each(["trust", "passphrase"])(
  "cancels a %s prompt and waits for cleanup without destroying its logical session",
  async (kind) => {
    const f = fixture();
    render(sessionView());
    const c = await connect(f);
    await c.prepare(kind === "trust" ? trust() : passphrase());
    await userEvent.click(screen.getAllByRole("button", { name: "Cancel" }).at(-1)!);
    expect(f.matching("session_stop_reconnecting").at(-1)?.args.sessionId).toBe(c.sessionId);
    expect(f.matching("session_close_transport")).toHaveLength(0);
    await c.prepare(trust(2));
    await c.ready();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
    await c.emit({ kind: "closed" });
    expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("alert").textContent).toContain("cancelled");
    await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
    expect(f.matching("session_retry_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
    const second = await c.start();
    await second.prepare(trust(3));
    expect(screen.getByText("SHA256:hop-3")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    await second.ready();
    expect(screen.getByRole("status").textContent).toContain("Connected");
    expect(f.connections).toHaveLength(1);
  },
);

it("waits for renderer failure cleanup and rejects late readiness", async () => {
  const f = fixture();
  const view = render(sessionView());
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal")!;
  act(() => terminal.dispatchEvent(new CustomEvent("terminal-error", { detail: { message: "write failed" } })));
  expect(f.matching("session_fail_transport")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await c.ready();
  expect(screen.getByRole("status").textContent).toContain("failed");
  await c.emit({ kind: "failed", error: "terminal unusable", exhausted: false });
  expect(screen.getByRole("alert").textContent).toBe("write failed");
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  expect(f.matching("session_retry_transport")).toHaveLength(1);
});

it("cancels pending and queued old input without failing an automatic replacement", async () => {
  const f = fixture();
  const pending = f.delay("session_input");
  const view = render(sessionView());
  const c = await connect(f);
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await c.ready();
  const cancelled = Promise.allSettled([terminal.send(new Uint8Array([13])), terminal.send(new Uint8Array([14]))]);
  await waitFor(() => expect(f.matching("session_input")).toHaveLength(1));
  await c.emit({ kind: "retrying", attempt: 1, delaySeconds: 1, error: "Network connection lost" });
  const second = await c.start(true);
  await second.ready();
  await act(async () => {
    pending.reject("old input failed");
    expect((await cancelled).map((r) => r.status)).toEqual(["rejected", "rejected"]);
  });
  expect(screen.getByRole("status").textContent).toContain("Connected");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(f.matching("session_input")).toHaveLength(1);
  await terminal.send(new Uint8Array([15]));
  expect(f.matching("session_input").at(-1)?.args.transportId).toBe(second.transportId);
});

it("defers background prompts until selection and discards hidden passphrase input", async () => {
  const f = fixture();
  const view = render(sessionView("en", false));
  const c = await connect(f);
  await c.prepare(trust());
  expect(screen.queryByRole("dialog")).toBeNull();
  view.rerender(sessionView());
  expect(screen.getByRole("dialog")).toBeTruthy();
  await c.prepare(passphrase());
  await userEvent.type(screen.getByLabelText("Key passphrase"), "discard-when-hidden");
  view.rerender(sessionView("en", false));
  expect(screen.queryByRole("dialog")).toBeNull();
  view.rerender(sessionView());
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");
  expect(f.matching("session_stop_reconnecting")).toHaveLength(0);
});

it("ignores late prompts, readiness, output and replies after tab closure", async () => {
  const f = fixture();
  const pending = f.delay("session_respond");
  const report = vi.fn();
  const view = render(sessionView("en", true, vi.fn(), report));
  const c = await connect(f);
  await c.prepare(trust());
  await userEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
  view.unmount();
  report.mockClear();
  await act(() => pending.resolve(null));
  await c.prepare(passphrase());
  await c.ready();
  await c.output("stale");
  await act(() => c.finish.reject("late failure"));
  expect(report).not.toHaveBeenCalled();
  expect(f.matching("session_respond")).toHaveLength(1);
  expect(f.matching("session_close_transport").at(-1)?.args.sessionId).toBe(c.sessionId);
});
