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
import type { ScoplenTerminalElement } from "@scoplen/terminal";

afterEach(() => clearMocks());

it("routes terminal input to the live SSH session and closes its transport", async () => {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_host_key") {
      return { algorithm: "ssh-ed25519", key: "ssh-ed25519 example", fingerprint: "SHA256:example", status: "trusted" };
    }
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
    if (command === "session_host_key") {
      return { algorithm: "ssh-ed25519", key: "key", fingerprint: "SHA256:example", status: "trusted" };
    }
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
    if (command === "session_host_key") {
      return { algorithm: "ssh-ed25519", key: "key", fingerprint: "SHA256:example", status: "trusted" };
    }
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
    if (command === "session_host_key") {
      return { algorithm: "ssh-ed25519", key: "key", fingerprint: "SHA256:example", status: "trusted" };
    }
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
    if (command === "session_host_key") {
      return { algorithm: "ssh-ed25519", key: "key", fingerprint: "SHA256:example", status: "trusted" };
    }
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

it("asks for an encrypted key passphrase after host trust and cancels without connecting", async () => {
  const calls: string[] = [];
  mockIPC((command) => {
    calls.push(command);
    if (command === "session_host_key") {
      return {
        algorithm: "ssh-ed25519",
        key: "key",
        fingerprint: "SHA256:example",
        status: "new",
        passphraseRequired: true,
      };
    }
    return null;
  });
  renderSession();
  await userEvent.click(await screen.findByRole("button", { name: "Trust and connect" }));
  expect(await screen.findByLabelText("Key passphrase")).toBeTruthy();
  expect(calls).not.toContain("session_connect");
  await userEvent.click(screen.getAllByRole("button", { name: "Cancel" })[1]!);
  expect(calls).not.toContain("session_connect");
  expect(screen.getByRole("alert").textContent).toContain("cancelled before the key was unlocked");
});

it("clears each entered passphrase and allows a wrong passphrase to be retried", async () => {
  const attempts: Array<Record<string, unknown>> = [];
  mockIPC((command, args) => {
    if (command === "session_host_key") {
      return {
        algorithm: "ssh-ed25519",
        key: "key",
        fingerprint: "SHA256:example",
        status: "trusted",
        passphraseRequired: true,
      };
    }
    if (command === "session_connect") {
      attempts.push((args ?? {}) as Record<string, unknown>);
      if (attempts.length === 1) throw { kind: "invalidPrivateKeyPassphrase" };
      return new Promise(() => undefined);
    }
    return null;
  });
  renderSession();
  const field = (await screen.findByLabelText("Key passphrase")) as HTMLInputElement;
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  expect(screen.getByText("Enter the key passphrase to connect.")).toBeTruthy();
  expect(attempts).toHaveLength(0);

  await userEvent.type(field, "wrong-passphrase");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  await waitFor(() =>
    expect(screen.getByText("That passphrase did not unlock the key. Check it and try again.")).toBeTruthy(),
  );
  expect(attempts[0]?.passphrase).toBe("wrong-passphrase");
  expect((screen.getByLabelText("Key passphrase") as HTMLInputElement).value).toBe("");

  await userEvent.type(screen.getByLabelText("Key passphrase"), "correct-passphrase");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  await waitFor(() => expect(attempts).toHaveLength(2));
  expect(attempts[1]?.passphrase).toBe("correct-passphrase");
  expect(screen.getByRole("status").textContent).toContain("Connecting");
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

function reconnectFixture() {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const connections: Array<{
    sessionId: string;
    frames: Channel<ArrayBuffer>;
    ready: Channel<null>;
    passphrase: string | null;
    finish: { resolve(): void; reject(reason: unknown): void };
  }> = [];
  const hostKeys: Array<unknown> = [];
  const trusts: Array<ReturnType<typeof deferred<null>>> = [];
  const inputs: Array<ReturnType<typeof deferred<null>>> = [];
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (command === "session_host_key") {
      return (
        hostKeys.shift() ?? {
          algorithm: "ssh-ed25519",
          key: "saved key",
          fingerprint: "SHA256:saved",
          status: "trusted",
        }
      );
    }
    if (command === "session_trust_host_key") return trusts.shift()?.promise ?? null;
    if (command === "session_input") return inputs.shift()?.promise ?? null;
    if (command === "session_connect") {
      const finish = deferred<null>();
      connections.push({
        ...(payload as unknown as (typeof connections)[number]),
        finish: { resolve: () => finish.resolve(null), reject: finish.reject },
      });
      return finish.promise;
    }
    return null;
  });
  return { calls, connections, hostKeys, trusts, inputs };
}

it.each(["closed", "failed"])(
  "reconnects a %s session in place with fresh channels and preserved output",
  async (ending) => {
    const fixture = reconnectFixture();
    const view = renderSession();
    await waitFor(() => expect(fixture.connections).toHaveLength(1));
    const first = fixture.connections[0]!;
    const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
    await act(() => {
      first.ready.onmessage(null);
      first.frames.onmessage(new TextEncoder().encode("first session\r\n").buffer);
    });
    await act(() => {
      if (ending === "closed") first.finish.resolve();
      else first.finish.reject("server disconnected");
    });
    expect(screen.getByRole("status").textContent).toContain(ending === "closed" ? "closed" : "failed");
    expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
    const reconnect = screen.getByRole("button", { name: "Reconnect" });
    act(() => {
      reconnect.click();
      reconnect.click();
    });
    await waitFor(() => expect(fixture.connections).toHaveLength(2));
    const second = fixture.connections[1]!;
    expect(second.sessionId).not.toBe(first.sessionId);
    expect(fixture.calls.filter((call) => call.command === "session_host_key")).toHaveLength(2);
    expect(view.container.querySelector("scoplen-terminal")).toBe(terminal);
    expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\n");
    expect(screen.getByRole("status").textContent).toContain("Connecting");
    await act(() => {
      first.ready.onmessage(null);
      first.frames.onmessage(new TextEncoder().encode("stale output").buffer);
    });
    expect(screen.getByRole("status").textContent).toContain("Connecting");
    expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\n");
    await act(() => {
      second.ready.onmessage(null);
      second.frames.onmessage(new TextEncoder().encode("second session").buffer);
    });
    expect(new TextDecoder().decode(terminal.getOutput())).toBe("first session\r\nsecond session");
    await terminal.send(new Uint8Array([13]));
    expect(fixture.calls.filter((call) => call.command === "session_input").at(-1)?.args.sessionId).toBe(
      second.sessionId,
    );
    expect(
      fixture.calls.some(
        (call) => call.command === "session_close_transport" && call.args.sessionId === first.sessionId,
      ),
    ).toBe(true);
  },
);

it("waits for a failed terminal transport to settle before allowing reconnect", async () => {
  const fixture = reconnectFixture();
  const view = renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  act(() => {
    terminal.dispatchEvent(new CustomEvent("terminal-error", { detail: { message: "terminal write failed" } }));
  });
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", true);
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  expect(fixture.connections).toHaveLength(1);
  await act(() => fixture.connections[0]!.ready.onmessage(null));
  expect(screen.getByRole("status").textContent).toContain("failed");
  await act(() => fixture.connections[0]!.finish.resolve());
  expect(screen.getByRole("button", { name: "Reconnect" })).toHaveProperty("disabled", false);
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
});

it("reviews a changed host key again, then re-reads trust after a cancelled reconnect", async () => {
  const fixture = reconnectFixture();
  renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  await act(() => fixture.connections[0]!.finish.resolve());
  fixture.hostKeys.push({
    algorithm: "ssh-ed25519",
    key: "rotated key",
    fingerprint: "SHA256:rotated",
    status: "changed",
  });
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  expect(await screen.findByText("Host key changed")).toBeTruthy();
  expect(screen.getByText("SHA256:rotated")).toBeTruthy();
  expect(fixture.connections).toHaveLength(1);
  await userEvent.click(screen.getAllByRole("button", { name: "Cancel" })[1]!);
  expect(fixture.calls.filter((call) => call.command === "session_trust_host_key")).toHaveLength(0);
  expect(fixture.connections).toHaveLength(1);
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
  expect(fixture.calls.filter((call) => call.command === "session_host_key")).toHaveLength(3);
});

it("prompts for a fresh one-time key passphrase after reconnect", async () => {
  const fixture = reconnectFixture();
  const encryptedKey = {
    algorithm: "ssh-ed25519",
    key: "key",
    fingerprint: "SHA256:saved",
    status: "trusted",
    passphraseRequired: true,
  };
  fixture.hostKeys.push(encryptedKey, encryptedKey);
  renderSession();
  await userEvent.type(await screen.findByLabelText("Key passphrase"), "first-unlock");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  await act(() => fixture.connections[0]!.finish.resolve());
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  const field = (await screen.findByLabelText("Key passphrase")) as HTMLInputElement;
  expect(field.value).toBe("");
  expect(fixture.connections).toHaveLength(1);
  await userEvent.type(field, "second-unlock");
  await userEvent.click(screen.getByRole("button", { name: "Unlock and connect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
  expect(fixture.connections.map((connection) => connection.passphrase)).toEqual(["first-unlock", "second-unlock"]);
  expect(fixture.connections[1]!.sessionId).not.toBe(fixture.connections[0]!.sessionId);
});

it.each(["probe", "trust"])("ignores a late reconnect %s result after closing its tab", async (stage) => {
  const fixture = reconnectFixture();
  const view = renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  await act(() => fixture.connections[0]!.finish.resolve());
  const probe = deferred<unknown>();
  const trust = deferred<null>();
  if (stage === "probe") fixture.hostKeys.push(probe.promise);
  else {
    fixture.hostKeys.push({ algorithm: "ssh-ed25519", key: "changed", fingerprint: "SHA256:new", status: "changed" });
    fixture.trusts.push(trust);
  }
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  if (stage === "trust") await userEvent.click(await screen.findByRole("button", { name: "Trust and connect" }));
  else await waitFor(() => expect(fixture.calls.filter((call) => call.command === "session_host_key")).toHaveLength(2));
  if (stage === "probe") await userEvent.click(screen.getByRole("button", { name: "Close session" }));
  view.unmount();
  await act(() => {
    probe.resolve({ algorithm: "ssh-ed25519", key: "key", fingerprint: "SHA256:saved", status: "trusted" });
    trust.resolve(null);
  });
  expect(fixture.connections).toHaveLength(1);
});

it("cancels pending and queued input from an old transport after reconnect", async () => {
  const fixture = reconnectFixture();
  const pending = deferred<null>();
  fixture.inputs.push(pending);
  const view = renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  const first = fixture.connections[0]!;
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await act(() => first.ready.onmessage(null));
  const write = terminal.send(new Uint8Array([13]));
  const queued = terminal.send(new Uint8Array([14]));
  const cancelled = Promise.allSettled([write, queued]);
  await waitFor(() => expect(fixture.calls.filter((call) => call.command === "session_input")).toHaveLength(1));
  await act(() => first.finish.resolve());
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
  await act(() => fixture.connections[1]!.ready.onmessage(null));
  await act(async () => {
    pending.reject("old input failed");
    expect((await cancelled).map((result) => result.status)).toEqual(["rejected", "rejected"]);
  });
  expect(screen.getByRole("status").textContent).toContain("Connected");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(fixture.calls.filter((call) => call.command === "session_input")).toHaveLength(1);
  await terminal.send(new Uint8Array([15]));
  expect(fixture.calls.filter((call) => call.command === "session_input").at(-1)?.args).toMatchObject({
    sessionId: fixture.connections[1]!.sessionId,
    data: [15],
  });
});

it("uses only the reviewed replacement key when trusting a reconnect", async () => {
  const fixture = reconnectFixture();
  renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  await act(() => fixture.connections[0]!.finish.resolve());
  fixture.hostKeys.push({
    algorithm: "ecdsa-sha2-nistp256",
    key: "rotated key",
    fingerprint: "SHA256:new",
    status: "changed",
  });
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await userEvent.click(await screen.findByRole("button", { name: "Trust and connect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
  expect(fixture.calls.filter((call) => call.command === "session_trust_host_key")).toEqual([
    {
      command: "session_trust_host_key",
      args: { profileId: "profile-1", algorithm: "ecdsa-sha2-nistp256", key: "rotated key", fingerprint: "SHA256:new" },
    },
  ]);
});

it("closes a pending reconnect and ignores its late ready, output, and failure", async () => {
  const fixture = reconnectFixture();
  const view = renderSession();
  await waitFor(() => expect(fixture.connections).toHaveLength(1));
  await act(() => fixture.connections[0]!.finish.resolve());
  await userEvent.click(screen.getByRole("button", { name: "Reconnect" }));
  await waitFor(() => expect(fixture.connections).toHaveLength(2));
  const second = fixture.connections[1]!;
  const terminal = view.container.querySelector("scoplen-terminal") as ScoplenTerminalElement;
  await userEvent.click(screen.getByRole("button", { name: "Close session" }));
  await act(() => {
    second.ready.onmessage(null);
    second.frames.onmessage(new TextEncoder().encode("late data").buffer);
    second.finish.reject("late failure");
  });
  expect(new TextDecoder().decode(terminal.getOutput())).toBe("");
  expect(screen.getByRole("status").textContent).toContain("Connecting");
  expect(
    fixture.calls.some(
      (call) => call.command === "session_close_transport" && call.args.sessionId === second.sessionId,
    ),
  ).toBe(true);
});
