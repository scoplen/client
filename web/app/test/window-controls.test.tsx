// SPDX-License-Identifier: Apache-2.0
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { WindowControls } from "../src/window-controls";
import { violations } from "../../ui/test/axe";

const native = vi.hoisted(() => ({
  tauri: true,
  decorated: false,
  maximized: false,
  resize: undefined as (() => void) | undefined,
  stop: vi.fn(),
  minimize: vi.fn(),
  toggleMaximize: vi.fn(),
  close: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => native.tauri }));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    isDecorated: async () => native.decorated,
    isMaximized: async () => native.maximized,
    onResized: async (handler: () => void) => {
      native.resize = handler;
      return native.stop;
    },
    minimize: native.minimize,
    toggleMaximize: native.toggleMaximize,
    close: native.close,
  }),
}));

beforeEach(() => {
  native.tauri = true;
  native.decorated = false;
  native.maximized = false;
  native.resize = undefined;
  native.stop.mockReset();
  native.minimize.mockReset().mockResolvedValue(undefined);
  native.toggleMaximize.mockReset().mockImplementation(async () => {
    native.maximized = !native.maximized;
  });
  native.close.mockReset().mockResolvedValue(undefined);
});
afterEach(cleanup);

function open(standalone = false, locale: "en" | "zh-Hans" = "en") {
  return render(
    <I18nProvider locale={locale}>
      <WindowControls standalone={standalone} />
    </I18nProvider>,
  );
}

it("uses normal native close and exposes themed, accessible window actions", async () => {
  const { container } = open();
  await screen.findByRole("group", { name: "Window controls" });
  await userEvent.click(screen.getByRole("button", { name: "Minimize window" }));
  expect(native.minimize).toHaveBeenCalledOnce();
  await userEvent.click(screen.getByRole("button", { name: "Maximize window" }));
  expect(await screen.findByRole("button", { name: "Restore window" })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Restore window" }));
  expect(await screen.findByRole("button", { name: "Maximize window" })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Close window" }));
  expect(native.close).toHaveBeenCalledOnce();
  expect(await violations(container)).toEqual([]);
});

it("tracks native maximize changes and releases the listener", async () => {
  const view = open();
  await waitFor(() => expect(native.resize).toBeDefined());
  native.maximized = true;
  await act(async () => native.resize?.());
  expect(screen.getByRole("button", { name: "Restore window" })).toBeTruthy();
  view.unmount();
  await waitFor(() => expect(native.stop).toHaveBeenCalledOnce());
});

it("keeps startup and unlock screens draggable and supports keyboard operation in Chinese", async () => {
  const { container } = open(true, "zh-Hans");
  const button = await screen.findByRole("button", { name: "最小化窗口" });
  expect(container.firstElementChild?.hasAttribute("data-tauri-drag-region")).toBe(true);
  await userEvent.tab();
  expect(document.activeElement).toBe(button);
  await userEvent.keyboard("{Enter}");
  expect(native.minimize).toHaveBeenCalledOnce();
});

it("reports action failures without exposing native diagnostics and allows retry", async () => {
  native.minimize.mockRejectedValueOnce(new Error("private native diagnostic"));
  open();
  const button = await screen.findByRole("button", { name: "Minimize window" });
  await userEvent.click(button);
  expect((await screen.findByRole("alert")).textContent).toContain("Try again");
  expect(screen.queryByText(/private native diagnostic/)).toBeNull();
  await userEvent.click(button);
  expect(screen.queryByRole("alert")).toBeNull();
});

it("preserves native macOS controls and does not expose desktop actions in a browser", async () => {
  native.decorated = true;
  const view = open();
  await act(async () => undefined);
  expect(screen.queryByRole("group")).toBeNull();
  expect(native.resize).toBeUndefined();
  view.unmount();
  native.tauri = false;
  open();
  expect(screen.queryByRole("group")).toBeNull();
});
