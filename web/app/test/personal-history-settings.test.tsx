// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PersonalInventoryHistory, PersonalInventoryObject } from "../src/ipc/bindings";
import { PersonalHistorySettings } from "../src/personal-history-settings";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());

const object: PersonalInventoryObject = {
  id: "019a0123-4567-7890-8123-456789abcdef",
  name: "Production",
  category: "host",
  sharedSecret: false,
  personal: true,
  dirty: false,
  deleted: false,
  excluded: false,
};
const history: PersonalInventoryHistory = {
  token: "rust-review",
  objectId: object.id,
  versions: [
    {
      sequence: "1",
      object: {
        ...object,
        name: "Earlier shared credential",
        category: "credential",
        sharedSecret: true,
        deleted: true,
      },
    },
    { sequence: "9007199254740993", object },
  ],
};

function fixture({
  authenticated = true,
  disabled = false,
  locale = "en",
}: {
  authenticated?: boolean;
  disabled?: boolean;
  locale?: "en" | "zh-Hans";
} = {}) {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const handlers = new Map<string, () => unknown>();
  const busy = vi.fn();
  const restored = vi.fn(async () => {});
  mockIPC((command, input) => {
    calls.push({ command, args: input as Record<string, unknown> });
    if (handlers.has(command)) return handlers.get(command)!();
    if (command === "query_personal_inventory_history") return history;
    if (command === "restore_personal_inventory_history") return undefined;
    throw new Error("Unexpected command");
  });
  return {
    calls,
    handlers,
    busy,
    restored,
    view: () => (
      <I18nProvider locale={locale}>
        <h3>Personal account</h3>
        <h4>Inventory sync</h4>
        <PersonalHistorySettings
          objects={[object]}
          authenticated={authenticated}
          disabled={disabled}
          onBusyChange={busy}
          onRestored={restored}
        />
      </I18nProvider>
    ),
  };
}

async function query() {
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "Synced object" }), object.id);
  await userEvent.click(screen.getByRole("button", { name: "View version history" }));
  return screen.findByRole("dialog");
}

it("queries only the explicitly selected object and requires a second confirmation before restoring the exact sequence", async () => {
  const f = fixture();
  const { container } = render(f.view());
  expect(f.calls).toEqual([]);
  expect((screen.getByRole("button", { name: "View version history" }) as HTMLButtonElement).disabled).toBe(true);
  const dialog = await query();
  expect(f.calls).toEqual([{ command: "query_personal_inventory_history", args: { objectId: object.id } }]);
  expect(within(dialog).getByText("Version 9007199254740993")).toBeTruthy();
  expect((within(dialog).getByRole("button", { name: "Create local copy" }) as HTMLButtonElement).disabled).toBe(true);
  expect(await violations(dialog)).toEqual([]);
  await userEvent.click(within(dialog).getByRole("radio", { name: /Version 9007199254740993/ }));
  await userEvent.click(within(dialog).getByRole("button", { name: "Create local copy" }));
  let confirmation = await screen.findByRole("alertdialog");
  expect(within(confirmation).getByText(/original and any current edits stay in place/)).toBeTruthy();
  expect(f.calls).toHaveLength(1);
  expect(await violations(confirmation)).toEqual([]);
  await userEvent.click(within(confirmation).getByRole("button", { name: "Cancel" }));
  await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Create local copy" }));
  confirmation = await screen.findByRole("alertdialog");
  await userEvent.click(within(confirmation).getByRole("button", { name: "Create local copy" }));
  expect((await screen.findByRole("status")).textContent).toContain("Created a new local copy");
  expect(f.calls).toEqual([
    { command: "query_personal_inventory_history", args: { objectId: object.id } },
    {
      command: "restore_personal_inventory_history",
      args: { reviewToken: "rust-review", sequence: "9007199254740993" },
    },
  ]);
  expect(f.restored).toHaveBeenCalledTimes(1);
  expect(f.busy.mock.calls).toEqual([[true], [false], [true], [false]]);
  expect(await violations(container)).toEqual([]);
});

it("shows the selected version's deletion and shared-secret flags and restores only once while busy", async () => {
  const f = fixture();
  let finish!: () => void;
  f.handlers.set(
    "restore_personal_inventory_history",
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
  );
  render(f.view());
  const dialog = await query();
  await userEvent.click(within(dialog).getByRole("radio", { name: /Version 1.*Earlier shared credential/ }));
  expect(within(dialog).getByText(/Deleted.*Includes shared secret/)).toBeTruthy();
  await userEvent.click(within(dialog).getByRole("button", { name: "Create local copy" }));
  const confirmation = await screen.findByRole("alertdialog");
  expect(within(confirmation).getByText(/includes shared credential content/)).toBeTruthy();
  await userEvent.dblClick(within(confirmation).getByRole("button", { name: "Create local copy" }));
  expect(f.calls.filter((call) => call.command === "restore_personal_inventory_history")).toEqual([
    { command: "restore_personal_inventory_history", args: { reviewToken: "rust-review", sequence: "1" } },
  ]);
  await act(async () => finish());
  await screen.findByRole("status");
});

it("rejects duplicate query intents and displays only localized safe failures", async () => {
  const f = fixture();
  let fail!: (reason: unknown) => void;
  f.handlers.set(
    "query_personal_inventory_history",
    () =>
      new Promise((_, reject) => {
        fail = reject;
      }),
  );
  render(f.view());
  await userEvent.selectOptions(screen.getByRole("combobox"), object.id);
  await userEvent.dblClick(screen.getByRole("button", { name: "View version history" }));
  expect(f.calls).toHaveLength(1);
  await act(async () => fail("secret arbitrary transport diagnostic"));
  expect((await screen.findByRole("alert")).textContent).not.toContain("secret arbitrary");
  expect(screen.queryByRole("dialog")).toBeNull();
  f.handlers.set("query_personal_inventory_history", () => Promise.reject("historyNotFound"));
  await userEvent.click(screen.getByRole("button", { name: "View version history" }));
  expect((await screen.findByRole("alert")).textContent).toContain("no retained versions");
});

it("requires authentication for a query and respects account activity", async () => {
  for (const options of [{ authenticated: false }, { disabled: true }]) {
    const f = fixture(options);
    const { unmount } = render(f.view());
    if (!options.disabled) await userEvent.selectOptions(screen.getByRole("combobox"), object.id);
    expect((screen.getByRole("button", { name: "View version history" }) as HTMLButtonElement).disabled).toBe(true);
    expect(f.calls).toEqual([]);
    unmount();
  }
});

it("localizes restoration errors and clears the consumed review instead of retrying", async () => {
  const f = fixture({ locale: "zh-Hans" });
  f.handlers.set("restore_personal_inventory_history", () => Promise.reject("previewExpired"));
  render(f.view());
  await userEvent.selectOptions(screen.getByRole("combobox", { name: "已同步对象" }), object.id);
  await userEvent.click(screen.getByRole("button", { name: "查看版本历史" }));
  const dialog = await screen.findByRole("dialog");
  await userEvent.click(within(dialog).getByRole("radio", { name: /版本 9007199254740993/ }));
  await userEvent.click(within(dialog).getByRole("button", { name: "创建本地副本" }));
  await userEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "创建本地副本" }));
  expect((await screen.findByRole("alert")).textContent).not.toContain("previewExpired");
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  expect(f.calls).toHaveLength(2);
  expect(f.restored).not.toHaveBeenCalled();
});
