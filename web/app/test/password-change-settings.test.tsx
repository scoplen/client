// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import { PasswordChangeSettings } from "../src/password-change-settings";
import type { PasswordChangeView } from "../src/ipc/bindings";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());
const ready: PasswordChangeView = {
  phase: "ready",
  operationId: "0199a653-8392-7355-8b91-70ab85182e3a",
  retryNotBeforeMs: null,
};
function fixture(initial: PasswordChangeView | null = null, locale: "en" | "zh-Hans" = "en") {
  let saved = initial;
  const calls: { command: string; args: unknown }[] = [];
  const handlers = new Map<string, (args: unknown) => unknown>();
  const busy = vi.fn();
  mockIPC((command, args) => {
    calls.push({ command, args });
    if (handlers.has(command)) return handlers.get(command)!(args);
    if (command === "password_change_status") return saved;
    if (command === "begin_password_change") {
      saved = ready;
      return saved;
    }
    if (command === "exchange_password_change") {
      saved = { ...ready, phase: "committed" };
      return saved;
    }
    if (command === "discard_password_change") {
      saved = null;
      return;
    }
    if (command === "stop_account_operation") return;
    throw new Error("Unexpected command");
  });
  const view = () => (
    <I18nProvider locale={locale}>
      <PasswordChangeSettings disabled={false} onBusyChange={busy} />
    </I18nProvider>
  );
  return {
    view,
    calls,
    handlers,
    busy,
    set: (value: PasswordChangeView | null) => {
      saved = value;
    },
  };
}

it("reads only encrypted status, invokes passwords once and clears the DOM immediately", async () => {
  const f = fixture();
  const { container } = render(f.view());
  const oldPassword = (await screen.findByLabelText("Current account password")) as HTMLInputElement;
  const newPassword = screen.getByLabelText("New account password") as HTMLInputElement;
  expect(f.calls.map((c) => c.command)).toEqual(["password_change_status"]);
  expect(screen.getByText(/signs out all browser sessions/)).toBeTruthy();
  let finish!: (value: PasswordChangeView) => void;
  f.handlers.set(
    "begin_password_change",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await userEvent.type(oldPassword, "current valid account password");
  await userEvent.type(newPassword, "different valid account password");
  screen.getByRole("button", { name: "Verify current password" }).focus();
  await userEvent.keyboard("{Enter}");
  expect(oldPassword.value).toBe("");
  expect(newPassword.value).toBe("");
  expect(f.calls.filter((c) => c.command === "begin_password_change")).toHaveLength(1);
  const invocation = f.calls.find((c) => c.command === "begin_password_change")!;
  expect(invocation.args).toMatchObject({
    oldPassword: "current valid account password",
    newPassword: "different valid account password",
  });
  f.set(ready);
  await act(async () => finish(ready));
  expect(await screen.findByRole("button", { name: "Change password" })).toBeTruthy();
  expect(screen.queryByLabelText("Current account password")).toBeNull();
  expect(f.calls.filter((c) => c.command === "exchange_password_change")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Change password" }));
  expect(await screen.findByText(/use your most recent password/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Change password" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Done" }));
  expect(await screen.findByLabelText("Current account password")).toBeTruthy();
  expect(await violations(container)).toEqual([]);
});

it.each(["en", "zh-Hans"] as const)(
  "reopens unknown with only exact confirmation and redacts a denied confirmation in %s",
  async (locale) => {
    const unknown: PasswordChangeView = { ...ready, phase: "outcomeUnknown" };
    const f = fixture(unknown, locale);
    f.handlers.set("exchange_password_change", () => Promise.reject("authenticationDenied"));
    const { container } = render(f.view());
    const confirm = await screen.findByRole("button", {
      name: locale === "en" ? "Check this change" : "查询本次修改",
    });
    expect(screen.getAllByRole("button")).toEqual([confirm]);
    expect(screen.queryByLabelText("Current account password")).toBeNull();
    await userEvent.click(confirm);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toContain("authenticationDenied");
    expect(screen.getAllByRole("button")).toEqual([confirm]);
    expect(f.calls.filter((c) => c.command === "exchange_password_change")).toHaveLength(1);
    expect(f.calls.find((c) => c.command === "exchange_password_change")!.args).toMatchObject({
      operationId: ready.operationId,
      intent: "confirm",
    });
    expect(await violations(container)).toEqual([]);
  },
);

it("uses explicit retry only for the original unchanged operation and displays its saved delay", async () => {
  const f = fixture({ ...ready, phase: "retryAvailable", retryNotBeforeMs: "1792713600000" });
  render(f.view());
  const retry = await screen.findByRole("button", { name: "Retry this change" });
  expect(screen.getByText(/Retry is available after/)).toBeTruthy();
  expect(f.calls.map((c) => c.command)).toEqual(["password_change_status"]);
  await userEvent.click(retry);
  await screen.findByRole("button", { name: "Done" });
  expect(f.calls.find((c) => c.command === "exchange_password_change")!.args).toMatchObject({
    operationId: ready.operationId,
    intent: "retry",
  });
});

it("stops view-owned I/O on unmount and reloads durable uncertainty without replay", async () => {
  const f = fixture(ready);
  let finish!: (value: PasswordChangeView) => void;
  f.handlers.set(
    "exchange_password_change",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const first = render(f.view());
  await userEvent.click(await screen.findByRole("button", { name: "Change password" }));
  first.unmount();
  f.set({ ...ready, phase: "outcomeUnknown" });
  expect(f.calls.filter((c) => c.command === "stop_account_operation")).toHaveLength(1);
  render(f.view());
  await screen.findByRole("button", { name: "Check this change" });
  await act(async () => finish({ ...ready, phase: "committed" }));
  expect(screen.getByRole("button", { name: "Check this change" })).toBeTruthy();
  expect(f.calls.filter((c) => c.command === "exchange_password_change")).toHaveLength(1);
});

it.each(["samePassword", "unsupportedService", "storage", "untrusted private detail"])(
  "renders a fixed error for %s without automatic resubmission",
  async (error) => {
    const f = fixture(null, "zh-Hans");
    f.handlers.set("begin_password_change", () => Promise.reject(error));
    render(f.view());
    await userEvent.type(await screen.findByLabelText("当前账号密码"), "current valid account password");
    await userEvent.type(screen.getByLabelText("新账号密码"), "different valid account password");
    await userEvent.click(screen.getByRole("button", { name: "验证当前密码" }));
    expect((await screen.findByRole("alert")).textContent).not.toContain(error);
    expect(f.calls.filter((c) => c.command === "begin_password_change")).toHaveLength(1);
    expect((screen.getByLabelText("新账号密码") as HTMLInputElement).value).toBe("");
  },
);

it("fails closed when saved status is unavailable and reloads only on explicit action", async () => {
  const f = fixture();
  f.handlers.set("password_change_status", () => Promise.reject("storage"));
  render(f.view());
  const reload = await screen.findByRole("button", { name: "Reload saved change" });
  expect(screen.queryByLabelText("Current account password")).toBeNull();
  f.handlers.delete("password_change_status");
  await userEvent.click(reload);
  expect(await screen.findByLabelText("Current account password")).toBeTruthy();
  await waitFor(() =>
    expect(f.calls.map((c) => c.command)).toEqual(["password_change_status", "password_change_status"]),
  );
});
