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
