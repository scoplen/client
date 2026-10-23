// SPDX-License-Identifier: Apache-2.0
import type { Channel } from "@tauri-apps/api/core";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PairingError, PairingStatus } from "../src/ipc/bindings";
import { PersonalPairingSettings } from "../src/personal-pairing-settings";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());

const idle: PairingStatus = {
  phase: "idle",
  side: null,
  origin: null,
  publicLink: null,
  deviceName: null,
  peerName: null,
  peerPlatform: null,
};
const waiting: PairingStatus = {
  ...idle,
  phase: "waiting",
  side: "new_device",
  origin: "https://ssh.example.test",
  publicLink: "https://ssh.example.test/pair#id=0199a653-8392-7355-8b91-70ab85182e3a",
  deviceName: "Travel laptop",
};
const review: PairingStatus = {
  ...waiting,
  phase: "confirm_device",
  side: "old_device",
  peerName: "Travel laptop",
  peerPlatform: "macos",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { resolve, reject, promise };
}

function fixture(initial = idle, configured = false, locale: "en" | "zh-Hans" = "en") {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const handlers = new Map<string, () => unknown>();
  const watchers: Array<{ messages: Channel<PairingStatus>; finish: ReturnType<typeof deferred<null>> }> = [];
  const busy = vi.fn();
  mockIPC((command, args) => {
    const payload = (args ?? {}) as Record<string, unknown>;
    calls.push({ command, args: payload });
    if (handlers.has(command)) return handlers.get(command)!();
    if (command === "personal_pairing_status") return initial;
    if (command === "create_personal_pairing") return { status: waiting, password: "AB12CD34" };
    if (command === "join_personal_pairing") return review;
    if (command === "prepare_personal_pairing_watch") return crypto.randomUUID();
    if (command === "watch_personal_pairing") {
      const finish = deferred<null>();
      watchers.push({ messages: payload.messages as Channel<PairingStatus>, finish });
      return finish.promise;
    }
    if (command === "stop_personal_pairing_watch") return null;
    if (command === "cancel_personal_pairing") return { ...initial, phase: "cancelled" };
    if (command === "recover_personal_pairing") return { ...initial, phase: "completed" };
    if (command === "confirm_personal_pairing") return { ...review, phase: "waiting_acceptance" };
    throw new Error("Unexpected pairing command");
  });
  const view = () => (
    <I18nProvider locale={locale}>
      <PersonalPairingSettings
        configured={configured}
        authenticated={configured}
        disabled={false}
        onBusyChange={busy}
      />
    </I18nProvider>
  );
  return {
    calls,
    handlers,
    watchers,
    busy,
    view,
    matching: (name: string) => calls.filter((call) => call.command === name),
  };
}

it("reads only local status on mount and opens the new-device form with the keyboard", async () => {
  const f = fixture();
  const { container } = render(f.view());
  const start = await screen.findByRole("button", { name: "Join an existing account" });
  expect(f.calls.map((call) => call.command)).toEqual(["personal_pairing_status"]);
  start.focus();
  await userEvent.keyboard("{Enter}");
  expect(screen.getByLabelText("Server address")).toBeTruthy();
  expect(screen.getByLabelText("Device name")).toBeTruthy();
  expect(f.matching("create_personal_pairing")).toHaveLength(0);
  expect(await violations(container)).toEqual([]);
});

it("clears the secret and restores focus when the old-device form closes", async () => {
  const f = fixture(idle, true);
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Pair another device" }));
  const input = screen.getByLabelText("8-character secret password") as HTMLInputElement;
  await userEvent.type(input, "AB12CD34");
  await userEvent.click(screen.getByRole("button", { name: "Close" }));
  expect(input.value).toBe("");
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Pair another device" }));
  expect(f.matching("join_personal_pairing")).toHaveLength(0);
});

it("reports old-device admission without claiming verification on the new device", async () => {
  const f = fixture({ ...review, phase: "completed" }, true);
  render(f.view());
  expect(await screen.findByText(/Device admission confirmed/)).toBeTruthy();
  expect(screen.queryByText(/Device authentication and sync keys are verified/)).toBeNull();
});

it("shows a password once, copies only the public link and clears the password after termination", async () => {
  const f = fixture();
  userEvent.setup();
  const clipboard = vi.spyOn(navigator.clipboard, "writeText");
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Join an existing account" }));
  await userEvent.type(screen.getByLabelText("Server address"), "https://ssh.example.test");
  await userEvent.type(screen.getByLabelText("Device name"), "Travel laptop");
  await userEvent.click(screen.getByRole("button", { name: "Create pairing session" }));
  expect(await screen.findByText("AB12CD34")).toBeTruthy();
  await waitFor(() => expect(f.watchers).toHaveLength(1));
  expect(f.matching("create_personal_pairing")[0]?.args).toEqual({
    origin: waiting.origin,
    deviceName: "Travel laptop",
  });
  await userEvent.click(screen.getByRole("button", { name: "Copy pairing link" }));
  expect(clipboard).toHaveBeenCalledExactlyOnceWith(waiting.publicLink);
  await act(() => f.watchers[0]!.messages.onmessage({ ...waiting, phase: "completed" }));
  await act(() => f.watchers[0]!.finish.resolve(null));
  expect(screen.queryByText("AB12CD34")).toBeNull();
  expect(screen.getByText(/Pairing complete/)).toBeTruthy();
  expect(f.busy).toHaveBeenLastCalledWith(false);
  expect(f.calls.some((call) => JSON.stringify(call.args).includes("AB12CD34"))).toBe(false);
  clipboard.mockRestore();
});

it("submits the old-device password write-only and requires explicit peer approval", async () => {
  const f = fixture(idle, true);
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Pair another device" }));
  await userEvent.type(screen.getByLabelText("Pairing link"), waiting.publicLink!);
  const password = screen.getByLabelText("8-character secret password") as HTMLInputElement;
  expect(password.type).toBe("password");
  expect(password.autocomplete).toBe("off");
  await userEvent.type(password, "AB12CD34");
  const answer = deferred<PairingStatus>();
  f.handlers.set("join_personal_pairing", () => answer.promise);
  await userEvent.dblClick(screen.getByRole("button", { name: "Verify pairing password" }));
  expect(password.value).toBe("");
  expect(f.matching("join_personal_pairing")).toHaveLength(1);
  expect(f.matching("join_personal_pairing")[0]?.args).toEqual({
    publicLink: waiting.publicLink,
    password: "AB12CD34",
  });
  await act(() => answer.resolve(review));
  expect(await screen.findByText("Travel laptop")).toBeTruthy();
  expect(screen.getByText("macos")).toBeTruthy();
  expect(f.matching("confirm_personal_pairing")).toHaveLength(0);
  expect(f.watchers).toHaveLength(0);
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Pair a device" }));
  await userEvent.click(screen.getByRole("button", { name: "Approve this device" }));
  await waitFor(() => expect(f.watchers).toHaveLength(1));
  expect(f.matching("confirm_personal_pairing")).toHaveLength(1);
  await act(() => f.watchers[0]!.finish.resolve(null));
});

it("does not resume a saved pairing on mount and checks admission only on an explicit intent", async () => {
  const f = fixture({ ...waiting, phase: "admission_unconfirmed" });
  const { container } = render(f.view());
  const recover = await screen.findByRole("button", { name: "Check and continue pairing" });
  expect(f.calls.map((call) => call.command)).toEqual(["personal_pairing_status"]);
  expect(container.textContent).not.toContain("AB12CD34");
  await userEvent.click(recover);
  expect(await screen.findByText(/Pairing complete/)).toBeTruthy();
  expect(f.matching("recover_personal_pairing")).toHaveLength(1);
  expect(f.matching("create_personal_pairing")).toHaveLength(0);
});

it("waits for the detached core tick before cancelling and fences its late progress", async () => {
  const f = fixture(waiting);
  f.handlers.set("recover_personal_pairing", () => waiting);
  const { container } = render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Check and continue pairing" }));
  await waitFor(() => expect(f.watchers).toHaveLength(1));
  await userEvent.click(screen.getByRole("button", { name: "Cancel pairing" }));
  expect(f.matching("stop_personal_pairing_watch")).toHaveLength(1);
  expect(f.matching("cancel_personal_pairing")).toHaveLength(0);
  expect((screen.getByRole("button", { name: "Cancel pairing" }) as HTMLButtonElement).disabled).toBe(true);
  await act(() => f.watchers[0]!.messages.onmessage(review));
  expect(screen.queryByRole("button", { name: "Approve this device" })).toBeNull();
  await act(() => f.watchers[0]!.finish.resolve(null));
  await screen.findByText(/Pairing cancelled/);
  expect(screen.queryByRole("button", { name: "Approve this device" })).toBeNull();
  expect(container.textContent).not.toContain("AB12CD34");
  expect(f.matching("cancel_personal_pairing")).toHaveLength(1);
});

it("detaches a foreground observer on unmount without cancelling the saved protocol", async () => {
  const f = fixture(waiting);
  f.handlers.set("recover_personal_pairing", () => waiting);
  const mounted = render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Check and continue pairing" }));
  await waitFor(() => expect(f.watchers).toHaveLength(1));
  mounted.unmount();
  expect(f.matching("stop_personal_pairing_watch")).toHaveLength(1);
  expect(f.matching("cancel_personal_pairing")).toHaveLength(0);
  await act(() => f.watchers[0]!.finish.resolve(null));
});

it.each([false, true])("detaches a late registration before any polling after leaving=%s", async (leaving) => {
  const f = fixture(waiting);
  const registration = deferred<string>();
  f.handlers.set("recover_personal_pairing", () => waiting);
  f.handlers.set("prepare_personal_pairing_watch", () => registration.promise);
  const view = render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Check and continue pairing" }));
  await waitFor(() => expect(f.matching("prepare_personal_pairing_watch")).toHaveLength(1));
  if (leaving) view.unmount();
  else await userEvent.click(screen.getByRole("button", { name: "Cancel pairing" }));
  expect(f.matching("cancel_personal_pairing")).toHaveLength(0);
  await act(() => registration.resolve("late-registration"));
  await waitFor(() => expect(f.matching("stop_personal_pairing_watch")).toHaveLength(1));
  expect(f.matching("stop_personal_pairing_watch")[0]?.args).toEqual({ watchId: "late-registration" });
  expect(f.matching("watch_personal_pairing")).toHaveLength(0);
  if (leaving) expect(f.matching("cancel_personal_pairing")).toHaveLength(0);
  else {
    await screen.findByText(/Pairing cancelled/);
    expect(f.matching("cancel_personal_pairing")).toHaveLength(1);
  }
});

it("reloads the local restart checkpoint after a failed password and reuses retained device metadata", async () => {
  const f = fixture(waiting);
  f.handlers.set("recover_personal_pairing", () => waiting);
  render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Check and continue pairing" }));
  await waitFor(() => expect(f.watchers).toHaveLength(1));
  f.handlers.set("personal_pairing_status", () => ({ ...waiting, phase: "restart_required" }));
  await act(() => f.watchers[0]!.finish.reject("invalid_response"));
  expect(await screen.findByRole("alert")).toBeTruthy();
  await userEvent.click(await screen.findByRole("button", { name: "Join an existing account" }));
  const origin = screen.getByLabelText("Server address") as HTMLInputElement;
  const name = screen.getByLabelText("Device name") as HTMLInputElement;
  expect(origin.value).toBe(waiting.origin);
  expect(name.value).toBe(waiting.deviceName);
  expect(origin.readOnly && name.readOnly).toBe(true);
  await userEvent.click(screen.getByRole("button", { name: "Create pairing session" }));
  await waitFor(() => expect(f.watchers).toHaveLength(2));
  expect(f.matching("create_personal_pairing")[0]?.args).toEqual({
    origin: waiting.origin,
    deviceName: waiting.deviceName,
  });
  await act(() => f.watchers[1]!.finish.resolve(null));
});

it("reads the local uncertain-admission checkpoint after failed approval without resuming the network", async () => {
  const f = fixture(review, true);
  render(f.view());
  await screen.findByRole("button", { name: "Approve this device" });
  f.handlers.set("confirm_personal_pairing", () => Promise.reject({ personal: "network" }));
  f.handlers.set("personal_pairing_status", () => ({ ...review, phase: "admission_unconfirmed" }));
  await userEvent.click(screen.getByRole("button", { name: "Approve this device" }));
  expect(await screen.findByText(/The server may have added this device/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Check and continue pairing" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Approve this device" })).toBeNull();
  expect(f.watchers).toHaveLength(0);
  expect(f.matching("recover_personal_pairing")).toHaveLength(0);
  expect(f.matching("personal_pairing_status")).toHaveLength(2);
});

it.each<PairingError>([
  "invalid_input",
  "invalid_response",
  "expired",
  "restart_required",
  "conflict",
  "authentication_required",
  { personal: "network" },
])("localizes safe error %s and never renders arbitrary native diagnostics", async (error) => {
  const f = fixture({ ...waiting, phase: "admission_unconfirmed" }, false, "zh-Hans");
  f.handlers.set("recover_personal_pairing", () => Promise.reject(error));
  const { container } = render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "检查并继续配对" }));
  expect((await screen.findByRole("alert")).textContent).not.toContain("settings.personal.");
  expect(container.textContent).not.toContain("AB12CD34");
  expect(f.matching("recover_personal_pairing")).toHaveLength(1);
  expect(await violations(container)).toEqual([]);
});

it("renders authenticated peer claims as text and redacts an unexpected IPC failure", async () => {
  const f = fixture({ ...review, peerName: "<script>device</script>" }, true);
  const { container } = render(f.view());
  expect(await screen.findByText("<script>device</script>")).toBeTruthy();
  expect(container.querySelector("script")).toBeNull();
  f.handlers.set("confirm_personal_pairing", () => Promise.reject(new Error("secret native body")));
  await userEvent.click(screen.getByRole("button", { name: "Approve this device" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Could not read pairing progress");
  expect(container.textContent).not.toContain("secret native body");
});
