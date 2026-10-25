// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { events, type PersonalSyncFailure, type PersonalSyncKeyStatus } from "../src/ipc/bindings";
import { PersonalSyncSettings } from "../src/personal-sync-settings";
import { violations } from "../../ui/test/axe";

afterEach(() => {
  cleanup();
  clearMocks();
  vi.restoreAllMocks();
});

function fixture(saved: PersonalSyncKeyStatus = "notConnected", authenticated = true, locale: "en" | "zh-Hans" = "en") {
  const calls: string[] = [];
  const busy = vi.fn();
  const handlers = new Map<string, () => unknown>();
  mockIPC(
    (command) => {
      if (command === "personal_sync_background_status") return handlers.get(command)?.() ?? "connected";
      if (command.startsWith("plugin:event|")) return 0;
      calls.push(command);
      if (handlers.has(command)) return handlers.get(command)!();
      if (command === "personal_sync_key_status") return saved;
      if (command === "connect_personal_sync") return "verified";
      if (command === "personal_inventory_status")
        return {
          vaultId: "vault",
          objects: [],
          backups: [],
          recovery: [],
          pending: 0,
          appliedCursor: "0",
          acknowledgedCursor: "0",
        };
      throw new Error("Unexpected IPC command");
    },
    { shouldMockEvents: true },
  );
  const view = () => (
    <I18nProvider locale={locale}>
      <PersonalSyncSettings authenticated={authenticated} disabled={false} onBusyChange={busy} />
    </I18nProvider>
  );
  return { calls, busy, handlers, view };
}

it("checks saved keys locally and connects only after an explicit action", async () => {
  const f = fixture();
  const { container } = render(f.view());
  const connect = await screen.findByRole("button", { name: "Verify sync keys" });
  await waitFor(() => expect((connect as HTMLButtonElement).disabled).toBe(false));
  expect(f.calls).toEqual(["personal_sync_key_status"]);
  expect(screen.getByText(/Hosts and credentials remain local/)).toBeTruthy();
  connect.focus();
  await userEvent.keyboard("{Enter}");
  expect(await screen.findByText(/Sync keys are verified on this device/)).toBeTruthy();
  expect(f.calls).toEqual(["personal_sync_key_status", "connect_personal_sync", "personal_inventory_status"]);
  expect(f.busy.mock.calls).toEqual([[true], [false]]);
  expect(await violations(container)).toEqual([]);
});

it("shows actionable native background state without issuing a sync request", async () => {
  const f = fixture("verified");
  f.handlers.set("personal_sync_background_status", () => "rotationRequired");
  render(f.view());
  expect((await screen.findByRole("alert")).textContent).toContain("unsupported key rotation");
  expect(f.calls).toEqual(["personal_sync_key_status", "personal_inventory_status"]);
});

it("registers the listener before reading state and keeps a newer event over a delayed snapshot", async () => {
  const f = fixture("verified");
  let register!: (unlisten: () => void) => void;
  let snapshot!: (value: "polling") => void;
  let notify!: Parameters<typeof events.personalSyncChanged.listen>[0];
  const listen = vi.spyOn(events.personalSyncChanged, "listen").mockImplementation((listener) => {
    notify = listener;
    return new Promise((resolve) => {
      register = resolve;
    });
  });
  const read = vi.fn(
    () =>
      new Promise((resolve) => {
        snapshot = resolve;
      }),
  );
  f.handlers.set("personal_sync_background_status", read);
  const stop = vi.fn();
  const rendered = render(f.view());
  await screen.findByText(/Sync keys are verified on this device/);
  await waitFor(() => expect(listen).toHaveBeenCalledOnce());
  expect(read).not.toHaveBeenCalled();
  await act(async () => register(stop));
  await waitFor(() => expect(read).toHaveBeenCalledOnce());
  act(() =>
    notify({
      event: "personal-sync-changed",
      id: 1,
      payload: { status: "authenticationRequired", profileGeneration: "" },
    }),
  );
  await act(async () => snapshot("polling"));
  expect((await screen.findByRole("alert")).textContent).toContain("Authenticate this device");
  rendered.unmount();
  expect(stop).toHaveBeenCalledOnce();
});

it("keeps saved keys visible offline while requiring authentication before server access", async () => {
  const f = fixture("verified", false, "zh-Hans");
  render(f.view());
  expect(await screen.findByText(/本机同步密钥已验证/)).toBeTruthy();
  const connect = screen.getByRole("button", { name: "验证同步密钥" }) as HTMLButtonElement;
  expect(connect.disabled).toBe(true);
  expect(screen.getByText("请先在上方认证此设备，再连接服务器。")).toBeTruthy();
  await userEvent.click(connect);
  expect(f.calls).toEqual(["personal_sync_key_status", "personal_inventory_status"]);
});

it("prevents repeated requests and retains verified keys after a rejected recheck", async () => {
  const f = fixture("verified");
  let finish!: (status: PersonalSyncKeyStatus) => void;
  f.handlers.set(
    "connect_personal_sync",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(f.view());
  await screen.findByText(/Sync keys are verified on this device/);
  const connect = screen.getByRole("button", { name: "Verify sync keys" });
  await userEvent.dblClick(connect);
  expect(f.calls.filter((name) => name === "connect_personal_sync")).toHaveLength(1);
  expect((connect as HTMLButtonElement).disabled).toBe(true);
  await act(async () => finish("verified"));
  await screen.findByText(/Sync keys are verified on this device/);
  f.handlers.set("connect_personal_sync", () => Promise.reject("rotationRequired"));
  await userEvent.click(screen.getByRole("button", { name: "Verify sync keys" }));
  expect((await screen.findByRole("alert")).textContent).toContain("key rotation support");
  expect(screen.getByText(/Sync keys are verified on this device/)).toBeTruthy();
  expect(f.calls.filter((name) => name === "personal_sync_key_status")).toHaveLength(1);
});

it.each<PersonalSyncFailure>(["authenticationRequired", "invalidSyncResponse", "rotationRequired"])(
  "localizes %s and keeps the retry action available",
  async (error) => {
    const f = fixture("notConnected", true, "zh-Hans");
    f.handlers.set("connect_personal_sync", () => Promise.reject(error));
    render(f.view());
    const connect = screen.getByRole("button", { name: "验证同步密钥" });
    await waitFor(() => expect((connect as HTMLButtonElement).disabled).toBe(false));
    await userEvent.click(connect);
    expect((await screen.findByRole("alert")).textContent).not.toContain("settings.personal.error");
    expect((connect as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByText(/本机同步密钥已验证/)).toBeNull();
  },
);

it("redacts unexpected native errors and recovers from a failed local status check", async () => {
  const f = fixture();
  f.handlers.set("personal_sync_key_status", () => Promise.reject(new Error("private server body")));
  const { container } = render(f.view());
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(container.textContent).not.toContain("private server body");
  await userEvent.click(screen.getByRole("button", { name: "Verify sync keys" }));
  expect(await screen.findByText(/Sync keys are verified on this device/)).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each(["refreshDeferred", "permissionDenied"] as const)(
  "localizes %s without making another network request",
  async (error) => {
    const f = fixture("verified", true, "zh-Hans");
    f.handlers.set("connect_personal_sync", () => Promise.reject(error));
    render(f.view());
    await userEvent.click(await screen.findByRole("button", { name: "验证同步密钥" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      error === "refreshDeferred" ? "稍后再同步" : "访问权限",
    );
    expect(f.calls.filter((name) => name === "connect_personal_sync")).toHaveLength(1);
    expect(screen.getByText(/本机同步密钥已验证/)).toBeTruthy();
  },
);
