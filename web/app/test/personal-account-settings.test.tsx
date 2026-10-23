// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PersonalAccountSnapshot, PersonalServerError } from "../src/ipc/bindings";
import { PersonalAccountSettings } from "../src/personal-account-settings";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());

const saved: PersonalAccountSnapshot = {
  accountId: "0199a653-8392-7355-8b91-70ab85182e3a",
  email: null,
  queriedAt: "1792713600000",
  devices: [
    { id: "0199a653-8392-7355-8b91-70ab85182e3b", name: "Office desktop", platform: "windows", current: true },
    { id: "0199a653-8392-7355-8b91-70ab85182e3c", name: "旅行用 Mac", platform: "macos", current: false },
  ],
};

function fixture(
  snapshot: PersonalAccountSnapshot | null = null,
  authenticated = true,
  locale: "en" | "zh-Hans" = "en",
) {
  const calls: string[] = [];
  const busy = vi.fn();
  const handlers = new Map<string, () => unknown>();
  mockIPC((command) => {
    calls.push(command);
    if (handlers.has(command)) return handlers.get(command)!();
    if (command === "personal_account_snapshot") return snapshot;
    if (command === "query_personal_account") return saved;
    throw new Error("Unexpected command");
  });
  const view = () => (
    <I18nProvider locale={locale}>
      <PersonalAccountSettings authenticated={authenticated} disabled={false} onBusyChange={busy} />
    </I18nProvider>
  );
  return { calls, busy, handlers, view };
}

it("reads only local status on mount and queries through an explicit keyboard action", async () => {
  const f = fixture();
  const { container } = render(f.view());
  const query = screen.getByRole("button", { name: "Refresh account and devices" });
  await waitFor(() => expect((query as HTMLButtonElement).disabled).toBe(false));
  expect(f.calls).toEqual(["personal_account_snapshot"]);
  expect(screen.getByText(/No account results have been saved/)).toBeTruthy();
  query.focus();
  await userEvent.keyboard("{Enter}");
  const devices = await screen.findByRole("list", { name: "Account-signed devices" });
  expect(within(devices).getAllByRole("listitem")).toHaveLength(2);
  expect(within(devices).getByText("Office desktop")).toBeTruthy();
  expect(within(devices).getByText("Signed platform: windows")).toBeTruthy();
  expect(within(devices).getAllByText("This device")).toHaveLength(1);
  expect(screen.getByText("No email on this account")).toBeTruthy();
  expect(screen.getByText("Last manual query")).toBeTruthy();
  expect(screen.queryByRole("button", { name: /revoke|remove device/i })).toBeNull();
  expect(f.calls).toEqual(["personal_account_snapshot", "query_personal_account"]);
  expect(f.busy.mock.calls).toEqual([[true], [false]]);
  expect(document.activeElement).toBe(query);
  expect(await violations(container)).toEqual([]);
});

it("keeps the last manually queried results visible offline in Chinese without renewing a session", async () => {
  const f = fixture(saved, false, "zh-Hans");
  render(f.view());
  expect(await screen.findByText("Office desktop")).toBeTruthy();
  expect(screen.getByText("上次手动查询")).toBeTruthy();
  expect(screen.getByText("此账号未设置邮箱")).toBeTruthy();
  expect(screen.getByRole("status").textContent).toContain("可离线查看");
  expect(screen.getByText(/不代表近期活动/)).toBeTruthy();
  const query = screen.getByRole("button", { name: "刷新账号与设备" }) as HTMLButtonElement;
  expect(query.disabled).toBe(true);
  await userEvent.click(query);
  expect(f.calls).toEqual(["personal_account_snapshot"]);
});

it("prevents duplicate intents and preserves previous results after a rejected whole snapshot", async () => {
  const f = fixture(saved);
  let finish!: (value: PersonalAccountSnapshot) => void;
  f.handlers.set(
    "query_personal_account",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(f.view());
  await screen.findByText("Office desktop");
  await userEvent.dblClick(screen.getByRole("button", { name: "Refresh account and devices" }));
  expect(f.calls.filter((command) => command === "query_personal_account")).toHaveLength(1);
  expect(screen.getByText("Office desktop")).toBeTruthy();
  expect(screen.getByText(/Querying your server/)).toBeTruthy();
  await act(async () => finish({ ...saved, email: "MiA+sync@Example.Test" }));
  expect(await screen.findByText("MiA+sync@Example.Test")).toBeTruthy();
  f.handlers.set("query_personal_account", () => Promise.reject("invalidAccountResponse"));
  await userEvent.click(screen.getByRole("button", { name: "Refresh account and devices" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Saved results were retained");
  expect(screen.getByText("MiA+sync@Example.Test")).toBeTruthy();
  expect(screen.getByText("Office desktop")).toBeTruthy();
  expect(f.calls.filter((command) => command === "personal_account_snapshot")).toHaveLength(1);
});

it.each<PersonalServerError>([
  "authenticationRequired",
  "refreshDeferred",
  "permissionDenied",
  "invalidAccountResponse",
  "network",
])("localizes %s and does not retry the request", async (error) => {
  const f = fixture(saved, true, "zh-Hans");
  f.handlers.set("query_personal_account", () => Promise.reject(error));
  render(f.view());
  await screen.findByText("Office desktop");
  await userEvent.click(screen.getByRole("button", { name: "刷新账号与设备" }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).not.toContain("settings.personal.");
  expect(alert.textContent).not.toContain(error);
  expect(f.calls).toEqual(["personal_account_snapshot", "query_personal_account"]);
  expect(screen.getByText("Office desktop")).toBeTruthy();
});

it("redacts unexpected native diagnostics and can recover from a failed offline read", async () => {
  const f = fixture();
  f.handlers.set("personal_account_snapshot", () => Promise.reject(new Error("private body and token")));
  const { container } = render(f.view());
  await screen.findByRole("alert");
  expect(container.textContent).not.toContain("private body and token");
  await userEvent.click(screen.getByRole("button", { name: "Refresh account and devices" }));
  expect(await screen.findByText("Office desktop")).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("renders signed claims as text and distinguishes an absent signed name without inventing device facts", async () => {
  const f = fixture({
    ...saved,
    devices: [
      { ...saved.devices[0]!, name: "<script>signed text</script>", platform: "platform/claim" },
      { ...saved.devices[1]!, name: "", platform: "" },
    ],
  });
  const { container } = render(f.view());
  expect(await screen.findByText("<script>signed text</script>")).toBeTruthy();
  expect(screen.getByText("No signed device name")).toBeTruthy();
  expect(screen.getByText("Signed platform: Not specified")).toBeTruthy();
  expect(container.querySelector("script")).toBeNull();
  expect(container.textContent).not.toContain("Last seen");
});
