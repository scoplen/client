// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { render, screen, waitFor } from "@testing-library/react";
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
  await terminal.send(new Uint8Array([108, 115, 13]));
  const connection = calls.find((call) => call.command === "session_connect");
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
