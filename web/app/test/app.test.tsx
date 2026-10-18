// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "../src/app";
import type { AppInfo, Status } from "../src/ipc/bindings";
import { violations } from "../../ui/test/axe";

const info: AppInfo = { version: "0.1.0", platform: "macos", locale: "en" };

afterEach(() => clearMocks());

type Handler = (cmd: string, args: Record<string, unknown>) => unknown;

/** Mocks the core: `status` answers `local_data_status`; `handle` answers the rest. */
function defaultInventory(cmd: string): unknown {
  if (cmd === "inventory_areas") return { favorites: false, recent: false, groups: false, keys: false, routes: false };
  if (cmd === "inventory_groups" || cmd === "inventory_hosts") return [];
  if (cmd === "inventory_host") return null;
  if (cmd === "inventory_set_favorite" || cmd === "inventory_undo_delete") return null;
  if (cmd === "inventory_delete_host") return { token: "00000000-0000-7000-8000-000000000000" };
  if (cmd === "choose_key_file") return null;
  return undefined;
}

function core(status: Status, handle: Handler = defaultInventory, locale: AppInfo["locale"] = "en") {
  const calls: { cmd: string; args: Record<string, unknown> }[] = [];
  mockIPC(
    (cmd, args) => {
      const payload = (args ?? {}) as Record<string, unknown>;
      calls.push({ cmd, args: payload });
      if (cmd === "app_info") return { ...info, locale };
      if (cmd === "local_data_status") return status;
      return handle(cmd, payload) ?? defaultInventory(cmd);
    },
    { shouldMockEvents: true },
  );
  return calls;
}

describe("startup", () => {
  it("shows progress while the core is still starting", () => {
    mockIPC((cmd) => (cmd === "app_info" || cmd === "local_data_status" ? new Promise(() => undefined) : undefined), {
      shouldMockEvents: true,
    });
    render(<App />);
    expect(screen.getByRole("heading", { level: 1, name: "Starting Scoplen" })).toBeTruthy();
    expect(screen.getByText("Connecting to the application core…")).toBeTruthy();
  });

  it("opens on the hosts screen in the core's language and reports ready", async () => {
    const calls = core({ state: "open", protection: "keystore" }, undefined, "zh-Hans");
    const { container } = render(<App />);
    expect(await screen.findByRole("heading", { level: 2, name: "还没有主机" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "添加主机" }).length).toBeGreaterThan(0);
    expect(document.documentElement.lang).toBe("zh-Hans");
    expect(calls.map((c) => c.cmd)).toContain("shell_ready");
    expect(await violations(container)).toEqual([]);
  });

  it("explains a failure to reach the core and retries", async () => {
    let attempts = 0;
    mockIPC(
      (cmd) => {
        if (cmd === "app_info") {
          attempts += 1;
          if (attempts === 1) throw new Error("ipc unavailable");
          return info;
        }
        if (cmd === "local_data_status") return { state: "open", protection: "keystore" };
        return defaultInventory(cmd);
      },
      { shouldMockEvents: true },
    );
    const { container } = render(<App />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Nothing was changed.");
    expect(alert.textContent).toContain("ipc unavailable");
    expect(await violations(container)).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 2, name: "No hosts yet" })).toBeTruthy();
  });
});

describe("unlocking", () => {
  it("asks for the passphrase, shows a wrong one next to the field, and opens on the right one", async () => {
    const calls = core({ state: "needsPassphrase", protection: "keystoreAndPassphrase" }, (cmd, args) => {
      if (cmd === "unlock_local_data") {
        if (args.passphrase === "right") return { state: "open", protection: "keystoreAndPassphrase" };
        return Promise.reject({ kind: "wrongPassphrase" });
      }
    });
    const { container } = render(<App />);
    const field = await screen.findByLabelText("Local passphrase");
    expect(await violations(container)).toEqual([]);

    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(calls.some((c) => c.cmd === "unlock_local_data")).toBe(false);

    await userEvent.type(field, "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("That passphrase is not correct. Nothing was changed; try again.")).toBeTruthy();
    expect((field as HTMLInputElement).value).toBe("wrong");

    await userEvent.clear(field);
    await userEvent.type(field, "right");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByRole("heading", { level: 2, name: "No hosts yet" })).toBeTruthy();
  });
});

describe("first launch without a keystore", () => {
  it("requires a passphrase entered twice", async () => {
    const calls = core({ state: "needsNewPassphrase" }, (cmd) =>
      cmd === "create_local_passphrase" ? { state: "open", protection: "passphraseOnly" } : undefined,
    );
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "Choose a local passphrase" });
    expect(screen.getByText("If you forget it, the data on this device cannot be recovered.")).toBeTruthy();
    expect(await violations(container)).toEqual([]);

    await userEvent.type(screen.getByLabelText("Passphrase"), "one");
    await userEvent.type(screen.getByLabelText("Repeat passphrase"), "two");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByText("The two passphrases are different.")).toBeTruthy();
    expect(calls.some((c) => c.cmd === "create_local_passphrase")).toBe(false);

    await userEvent.clear(screen.getByLabelText("Repeat passphrase"));
    await userEvent.type(screen.getByLabelText("Repeat passphrase"), "one");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { level: 2, name: "No hosts yet" })).toBeTruthy();
    expect(calls.find((c) => c.cmd === "create_local_passphrase")?.args).toEqual({ passphrase: "one" });
  });
});

describe("unreadable local data", () => {
  it("starts with empty data only after confirmation", async () => {
    const calls = core({ state: "unreadable", reason: "keyMissing" }, (cmd) =>
      cmd === "start_with_empty_local_data" ? { state: "open", protection: "keystore" } : undefined,
    );
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "Scoplen cannot open its local data" });
    expect(screen.getByText(/it is not deleted/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Start with empty data" }));
    expect(calls.some((c) => c.cmd === "start_with_empty_local_data")).toBe(false);
    expect(await violations(container)).toEqual([]);

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await userEvent.click(screen.getByRole("button", { name: "Start with empty data" }));
    const buttons = screen.getAllByRole("button", { name: "Start with empty data" });
    await userEvent.click(buttons[0]!);
    expect(await screen.findByRole("heading", { level: 2, name: "No hosts yet" })).toBeTruthy();
  });

  it("does not offer to start over when a newer version wrote the data", async () => {
    core({ state: "unreadable", reason: "newerVersion" });
    render(<App />);
    await screen.findByText(/Install that version or a later one/);
    expect(screen.queryByRole("button", { name: "Start with empty data" })).toBeNull();
  });
});

describe("settings", () => {
  it("sets and removes the local passphrase", async () => {
    const calls = core({ state: "open", protection: "keystore" }, (cmd) => {
      if (cmd === "set_local_passphrase") return { state: "open", protection: "keystoreAndPassphrase" };
      if (cmd === "remove_local_passphrase") return { state: "open", protection: "keystore" };
    });
    const { container } = render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Settings" }));
    await userEvent.click(screen.getByRole("tab", { name: "Local data" }));
    expect(screen.getByRole("button", { name: "Settings" }).getAttribute("aria-pressed")).toBe("true");
    await userEvent.click(screen.getByRole("button", { name: "Set passphrase" }));
    expect(await violations(container)).toEqual([]);

    await userEvent.type(screen.getByLabelText("New passphrase"), "secret");
    await userEvent.type(screen.getByLabelText("Repeat new passphrase"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Save passphrase" }));
    expect(await screen.findByText("Passphrase saved.")).toBeTruthy();
    expect(screen.getByText(/in addition to the system keystore/)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Remove passphrase" }));
    expect(await screen.findByText("Passphrase removed.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Set passphrase" })).toBeTruthy();
    expect(calls.find((c) => c.cmd === "set_local_passphrase")?.args).toEqual({ passphrase: "secret" });
  });

  it("does not offer removal when the passphrase is the only protection", async () => {
    core({ state: "open", protection: "passphraseOnly" });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Settings" }));
    await userEvent.click(screen.getByRole("tab", { name: "Local data" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Change passphrase" })).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Remove passphrase" })).toBeNull();
  });
});
