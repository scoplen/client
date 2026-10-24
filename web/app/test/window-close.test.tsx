// SPDX-License-Identifier: Apache-2.0
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppearanceProvider } from "@scoplen/ui";
import { I18nProvider } from "../src/i18n";
import { Shell } from "../src/shell";

const native = vi.hoisted(() => ({
  handler: undefined as undefined | ((event: { preventDefault(): void }) => void),
  close: vi.fn<() => Promise<void>>(),
  checkpoint: vi.fn<() => Promise<boolean>>(),
}));
vi.mock("@tauri-apps/api/core", async (original) => ({ ...(await original<object>()), isTauri: () => true }));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    close: native.close,
    onCloseRequested: (handler: typeof native.handler) => {
      native.handler = handler;
      return Promise.resolve(() => undefined);
    },
  }),
}));
vi.mock("../src/inventory/home", () => ({
  HostsHome: ({ onConnect }: { onConnect: (id: string, label: string) => void }) => (
    <button onClick={() => onConnect("profile", "Fixture host")}>Start fixture</button>
  ),
}));
vi.mock("../src/session", async () => {
  const { useEffect } = await import("react");
  return {
    SessionTerminal: ({ registerClose }: { registerClose: (close: () => Promise<boolean>) => () => void }) => {
      useEffect(() => registerClose(native.checkpoint), [registerClose]);
      return <p>Retained terminal view</p>;
    },
  };
});

beforeEach(() => {
  native.handler = undefined;
  native.close.mockReset().mockResolvedValue();
  native.checkpoint.mockReset().mockResolvedValue(true);
});

async function open() {
  render(
    <AppearanceProvider>
      <I18nProvider locale="en">
        <Shell
          info={{ version: "0.1.0", platform: "windows", locale: "en" }}
          status={{ state: "open", protection: "keystore" }}
          onStatus={vi.fn()}
        />
      </I18nProvider>
    </AppearanceProvider>,
  );
  await userEvent.click(screen.getByRole("button", { name: "Start fixture" }));
  await waitFor(() => expect(native.handler).toBeDefined());
}

it("prevents native close until the final checkpoint succeeds, then requests normal close again", async () => {
  await open();
  let finish!: (saved: boolean) => void;
  native.checkpoint.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const preventDefault = vi.fn();
  await act(() => native.handler?.({ preventDefault }));
  expect(preventDefault).toHaveBeenCalledOnce();
  expect(native.close).not.toHaveBeenCalled();
  await act(() => finish(true));
  await waitFor(() => expect(native.close).toHaveBeenCalledOnce());
  const allowed = vi.fn();
  await act(() => native.handler?.({ preventDefault: allowed }));
  expect(allowed).not.toHaveBeenCalled();
});

it("retains the window after a failed save and rechecks saves on a later native close", async () => {
  await open();
  native.checkpoint.mockResolvedValueOnce(false);
  const prevented = vi.fn();
  await act(() => native.handler?.({ preventDefault: prevented }));
  expect(prevented).toHaveBeenCalledOnce();
  expect(native.close).not.toHaveBeenCalled();
  expect(screen.getByText("Retained terminal view")).toBeTruthy();
  await act(() => native.handler?.({ preventDefault: vi.fn() }));
  await waitFor(() => expect(native.close).toHaveBeenCalledOnce());
  expect(native.checkpoint).toHaveBeenCalledTimes(2);
});

it("a failed native close does not bypass checkpoints on the next attempt", async () => {
  await open();
  native.close.mockRejectedValueOnce(new Error("fixture close failure"));
  await act(() => native.handler?.({ preventDefault: vi.fn() }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  const prevented = vi.fn();
  await act(() => native.handler?.({ preventDefault: prevented }));
  expect(prevented).toHaveBeenCalledOnce();
  await waitFor(() => expect(native.close).toHaveBeenCalledTimes(2));
  expect(native.checkpoint).toHaveBeenCalledTimes(2);
});
