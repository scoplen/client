// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PersonalInventoryError, PersonalInventoryObject, PersonalInventoryStatus } from "../src/ipc/bindings";
import { PersonalInventorySettings } from "../src/personal-inventory-settings";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());

const host: PersonalInventoryObject = {
  id: "019a0123-4567-7890-8123-456789abcdef",
  name: "Production",
  category: "host",
  sharedSecret: false,
  personal: false,
  dirty: false,
  deleted: false,
  excluded: false,
};
const credential: PersonalInventoryObject = {
  ...host,
  id: "019a0123-4567-7890-8123-456789abcdee",
  name: "Shared key",
  category: "credential",
  sharedSecret: true,
};

function fixture({
  authenticated = true,
  locale = "en",
  backups = false,
}: { authenticated?: boolean; locale?: "en" | "zh-Hans"; backups?: boolean } = {}) {
  let status: PersonalInventoryStatus = {
    vaultId: "019a0123-4567-7890-8123-456789abcddd",
    objects: [host, credential],
    backups: backups ? [host] : [],
    recovery: [],
    pending: 0,
    appliedCursor: "9007199254740993",
    acknowledgedCursor: "9007199254740992",
  };
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const handlers = new Map<string, (args: Record<string, unknown>) => unknown>();
  const busy = vi.fn();
  let reviewed: string[] = [];
  mockIPC((command, input) => {
    const args = (input ?? {}) as Record<string, unknown>;
    calls.push({ command, args });
    if (handlers.has(command)) return handlers.get(command)!(args);
    if (command === "personal_inventory_status") return status;
    if (command === "preview_personal_inventory") {
      reviewed = args.ids as string[];
      return {
        token: "opaque-review",
        objects: status.objects.filter((object) => reviewed.includes(object.id)),
        missing: [],
      };
    }
    if (command === "synchronize_personal_inventory") {
      if (args.reviewToken)
        status = {
          ...status,
          objects: status.objects.map((object) =>
            reviewed.includes(object.id) ? { ...object, personal: true } : object,
          ),
          backups: status.objects.filter((object) => reviewed.includes(object.id)),
        };
      return { downloaded: 2, uploaded: 2, more: false };
    }
    if (command === "restore_personal_inventory" || command === "restore_personal_inventory_recovery")
      return (args.ids as string[]).length;
    throw new Error("Unexpected command");
  });
  return {
    calls,
    handlers,
    busy,
    set: (next: PersonalInventoryStatus) => {
      status = next;
    },
    status: () => status,
    view: () => (
      <I18nProvider locale={locale}>
        <h3>Personal sync</h3>
        <PersonalInventorySettings authenticated={authenticated} disabled={false} onBusyChange={busy} />
      </I18nProvider>
    ),
  };
}

it("reads progress locally and requires exact selection, a review, and explicit shared-secret consent", async () => {
  const f = fixture();
  const { container } = render(f.view());
  expect(await screen.findByText("9007199254740993")).toBeTruthy();
  expect(screen.getByText("9007199254740992")).toBeTruthy();
  expect(f.calls.map((call) => call.command)).toEqual(["personal_inventory_status"]);
  await userEvent.click(screen.getByRole("checkbox", { name: /Shared key/ }));
  await userEvent.click(screen.getByRole("button", { name: "Review selected (1)" }));
  const review = await screen.findByRole("dialog");
  expect(await violations(review)).toEqual([]);
  expect(within(review).getByText("Includes shared secret", { exact: false })).toBeTruthy();
  expect(within(review).queryByText("Production")).toBeNull();
  expect(f.calls.find((call) => call.command === "preview_personal_inventory")?.args).toEqual({ ids: [credential.id] });
  const enable = within(review).getByRole("button", { name: "Enable and sync selected" });
  expect((enable as HTMLButtonElement).disabled).toBe(true);
  expect(f.calls.some((call) => call.command === "synchronize_personal_inventory")).toBe(false);
  await userEvent.click(within(review).getByRole("checkbox", { name: /I have reviewed/ }));
  await userEvent.click(enable);
  expect(await screen.findByText(/This cycle is complete/)).toBeTruthy();
  expect(f.calls.filter((call) => call.command === "synchronize_personal_inventory").map((call) => call.args)).toEqual([
    { reviewToken: "opaque-review" },
  ]);
  expect(f.busy.mock.calls).toEqual([[true], [false], [true], [false]]);
  expect((screen.getByRole("checkbox", { name: /Production/ }) as HTMLInputElement).checked).toBe(false);
  expect(f.status().objects.find((object) => object.id === host.id)?.personal).toBe(false);
  expect(await violations(container)).toEqual([]);
});

it("names missing references without selecting them or allowing upload", async () => {
  const f = fixture();
  f.handlers.set("preview_personal_inventory", () => ({ token: null, objects: [host], missing: [credential] }));
  render(f.view());
  await userEvent.click(await screen.findByRole("checkbox", { name: /Production/ }));
  await userEvent.click(screen.getByRole("button", { name: "Review selected (1)" }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getByText(/referenced local objects are missing/)).toBeTruthy();
  expect(within(dialog).getByText("Shared key")).toBeTruthy();
  expect(within(dialog).queryByRole("checkbox")).toBeNull();
  expect((within(dialog).getByRole("button", { name: "Enable and sync selected" }) as HTMLButtonElement).disabled).toBe(
    true,
  );
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect((screen.getByRole("checkbox", { name: /Shared key/ }) as HTMLInputElement).checked).toBe(false);
  expect(f.calls.some((call) => call.command === "synchronize_personal_inventory")).toBe(false);
});

it("synchronizes only previously adopted objects without selecting new objects and blocks duplicate intents", async () => {
  const f = fixture();
  let finish!: (value: { downloaded: number; uploaded: number; more: boolean }) => void;
  f.handlers.set(
    "synchronize_personal_inventory",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(f.view());
  const sync = await screen.findByRole("button", { name: "Sync now" });
  await userEvent.dblClick(sync);
  expect((sync as HTMLButtonElement).disabled).toBe(true);
  expect(f.calls.filter((call) => call.command === "synchronize_personal_inventory").map((call) => call.args)).toEqual([
    { reviewToken: null },
  ]);
  await act(async () => finish({ downloaded: 8, uploaded: 0, more: true }));
  expect(await screen.findByText(/More work remains/)).toBeTruthy();
  expect(f.calls.some((call) => call.command === "preview_personal_inventory")).toBe(false);
  expect((screen.getByRole("checkbox", { name: /Production/ }) as HTMLInputElement).checked).toBe(false);
});

it("restores exact immutable copies offline after confirmation without any sync intent", async () => {
  const f = fixture({ authenticated: false, backups: true });
  f.set({ ...f.status(), objects: [] });
  render(f.view());
  const original = await screen.findByRole("checkbox", { name: /Production/ });
  expect((screen.getByRole("button", { name: "Sync now" }) as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(original);
  await userEvent.click(screen.getByRole("button", { name: "Restore selected copies (1)" }));
  const confirmation = await screen.findByRole("alertdialog");
  expect(await violations(confirmation)).toEqual([]);
  expect(within(confirmation).getByText(/does not undo any server change/)).toBeTruthy();
  expect(f.calls.some((call) => call.command === "restore_personal_inventory")).toBe(false);
  await userEvent.click(within(confirmation).getByRole("button", { name: "Cancel" }));
  expect(f.calls.some((call) => call.command === "restore_personal_inventory")).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Restore selected copies (1)" }));
  await userEvent.click(
    within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Create local copies" }),
  );
  expect(await screen.findByText(/Created 1 local copies/)).toBeTruthy();
  expect(f.calls.find((call) => call.command === "restore_personal_inventory")?.args).toEqual({ ids: [host.id] });
  expect(f.calls.some((call) => call.command === "synchronize_personal_inventory")).toBe(false);
});

it("separates quarantined edits from originals and restores only exact recovery copies offline", async () => {
  const f = fixture({ authenticated: false, backups: true });
  const copy = { id: "019a0123-4567-7890-8123-456789abce01", object: { ...host, name: "Unsynced edit" } };
  const older = { id: "019a0123-4567-7890-8123-456789abce02", object: { ...host, name: "Older edit" } };
  f.set({ ...f.status(), objects: [], recovery: [copy, older] });
  const { container } = render(f.view());
  const edits = await screen.findByRole("group", { name: "Local edits need attention (2)" });
  expect(within(edits).getByText(/will not upload/)).toBeTruthy();
  await userEvent.click(within(edits).getByRole("checkbox", { name: /Unsynced edit/ }));
  expect((within(edits).getByRole("checkbox", { name: /Older edit/ }) as HTMLInputElement).disabled).toBe(true);
  expect((screen.getByRole("checkbox", { name: /Production/ }) as HTMLInputElement).checked).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Recover selected edits (1)" }));
  let confirmation = await screen.findByRole("alertdialog");
  expect(within(confirmation).getByText(/had not yet synced/)).toBeTruthy();
  expect(within(confirmation).getByText(/separate upload review/)).toBeTruthy();
  expect(within(confirmation).queryByText("Older edit")).toBeNull();
  await userEvent.click(within(confirmation).getByRole("button", { name: "Cancel" }));
  expect(f.calls.some((call) => call.command === "restore_personal_inventory_recovery")).toBe(false);
  await userEvent.click(screen.getByRole("button", { name: "Recover selected edits (1)" }));
  confirmation = await screen.findByRole("alertdialog");
  expect(await violations(confirmation)).toEqual([]);
  await userEvent.click(within(confirmation).getByRole("button", { name: "Create local copies" }));
  expect(await screen.findByText(/Created 1 local copies/)).toBeTruthy();
  expect(f.calls.find((call) => call.command === "restore_personal_inventory_recovery")?.args).toEqual({
    ids: [copy.id],
  });
  expect(
    f.calls.some((call) =>
      ["restore_personal_inventory", "synchronize_personal_inventory", "preview_personal_inventory"].includes(
        call.command,
      ),
    ),
  ).toBe(false);
  expect(f.status().recovery).toEqual([copy, older]);
  expect(await violations(container)).toEqual([]);
});

it("reveals new recovery copies after an uncertain acknowledgement without retrying sync", async () => {
  const f = fixture({ locale: "zh-Hans" });
  f.handlers.set("synchronize_personal_inventory", () => {
    f.set({ ...f.status(), objects: [], recovery: [{ id: "recovery-copy", object: host }] });
    return Promise.reject("acknowledgementUnknown");
  });
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "立即同步" }));
  expect(await screen.findByRole("group", { name: "本地编辑需要处理（1）" })).toBeTruthy();
  expect((await screen.findByRole("alert")).textContent).toContain("回执尚未确认");
  expect(f.calls.filter((call) => call.command === "synchronize_personal_inventory")).toHaveLength(1);
  expect((screen.getByRole("checkbox", { name: /Production/ }) as HTMLInputElement).checked).toBe(false);
});

it.each<PersonalInventoryError>([
  "storage",
  "busy",
  "notConfigured",
  "authenticationRequired",
  "network",
  "invalidSyncResponse",
  "rotationRequired",
  "reconciliationRequired",
  "writeOutcomeUnknown",
  "acknowledgementUnknown",
  "concurrentChanges",
  "clock",
  "selection",
  "resourceLimit",
  "trustReviewRequired",
  "previewExpired",
])("localizes %s and preserves manual recovery without an automatic retry", async (error) => {
  const f = fixture({ locale: "zh-Hans" });
  f.handlers.set("synchronize_personal_inventory", () => Promise.reject(error));
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "立即同步" }));
  expect((await screen.findByRole("alert")).textContent).not.toContain("settings.personal");
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "立即同步" }) as HTMLButtonElement).disabled).toBe(false),
  );
  expect(f.calls.filter((call) => call.command === "synchronize_personal_inventory")).toHaveLength(1);
});

it("reloads durable local state after uncertainty and redacts unexpected IPC failures", async () => {
  const f = fixture();
  f.handlers.set("synchronize_personal_inventory", () => {
    f.set({ ...f.status(), objects: [{ ...host, personal: true, dirty: true }], backups: [host], pending: 1 });
    return Promise.reject("writeOutcomeUnknown");
  });
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Sync now" }));
  expect((await screen.findByRole("alert")).textContent).toContain("may have saved");
  await screen.findByRole("checkbox", { name: /Production/ });
  expect(screen.getByText("1")).toBeTruthy();
  f.handlers.set("synchronize_personal_inventory", () => Promise.reject(new Error("private response body")));
  await waitFor(() =>
    expect((screen.getByRole("button", { name: "Sync now" }) as HTMLButtonElement).disabled).toBe(false),
  );
  await userEvent.click(screen.getByRole("button", { name: "Sync now" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Local sync data");
  expect(document.body.textContent).not.toContain("private response body");
});

it("recovers a failed local load without starting a network operation", async () => {
  const f = fixture({ authenticated: false });
  f.handlers.set("personal_inventory_status", () => Promise.reject("storage"));
  render(f.view());
  await screen.findByRole("alert");
  f.handlers.delete("personal_inventory_status");
  await userEvent.click(screen.getByRole("button", { name: "Refresh local status" }));
  expect(await screen.findByRole("checkbox", { name: /Production/ })).toBeTruthy();
  expect(f.calls.every((call) => call.command === "personal_inventory_status")).toBe(true);
});

it("maps unexpected serialized native failures to safe text without rendering their body", async () => {
  const f = fixture();
  f.handlers.set("synchronize_personal_inventory", () => Promise.reject({ message: "private serialized body" }));
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Sync now" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Local sync data");
  expect(document.body.textContent).not.toContain("private serialized body");
});
