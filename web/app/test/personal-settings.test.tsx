// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { AppearanceProvider } from "@scoplen/ui";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PersonalServerError, PersonalServerStatus } from "../src/ipc/bindings";
import { PersonalSettings } from "../src/personal-settings";
import { SettingsView } from "../src/settings";
import { TerminalColorsProvider } from "../src/terminal-colors";
import { violations } from "../../ui/test/axe";

afterEach(() => clearMocks());

const empty: PersonalServerStatus = {
  phase: "not_configured",
  origin: null,
  accountId: null,
  deviceId: null,
  personalVaultId: null,
  deviceName: null,
  recoveryKeySaved: false,
  recoveryKeyConfirmed: false,
};
const prepared: PersonalServerStatus = {
  ...empty,
  phase: "recovery_required",
  origin: "https://ssh.example.test",
  accountId: "account",
  deviceId: "device",
  personalVaultId: "vault",
  deviceName: "Work laptop",
};
const unconfirmed: PersonalServerStatus = {
  ...prepared,
  phase: "enrollment_unconfirmed",
  recoveryKeySaved: true,
  recoveryKeyConfirmed: true,
};

function fixture(initial = empty) {
  let status = initial;
  const calls: Array<{ command: string; args: Record<string, unknown> }> = [];
  const handlers = new Map<string, () => unknown>();
  mockIPC((command, args) => {
    calls.push({ command, args: (args ?? {}) as Record<string, unknown> });
    if (handlers.has(command)) return handlers.get(command)!();
    if (command === "personal_sync_key_status") return "notConnected";
    if (command === "personal_server_status") return status;
    if (command === "prepare_personal_enrollment") status = prepared;
    else if (command === "save_personal_recovery_key") status = { ...status, recoveryKeySaved: true };
    else if (command === "confirm_personal_recovery_key")
      status = { ...status, phase: "ready_to_enroll", recoveryKeyConfirmed: true };
    else if (command === "submit_personal_enrollment" || command === "authenticate_personal_server")
      status = { ...status, phase: "authenticated" };
    return status;
  });
  return {
    calls,
    handlers,
    set: (next: PersonalServerStatus) => {
      status = next;
    },
    matching: (name: string) => calls.filter((call) => call.command === name),
  };
}

function view(locale: "en" | "zh-Hans" = "en") {
  return (
    <I18nProvider locale={locale}>
      <PersonalSettings />
    </I18nProvider>
  );
}

it("clears the write-only invitation immediately and prepares only on explicit submit", async () => {
  const f = fixture();
  const { container } = render(view());
  const invitation = await screen.findByLabelText("Invitation link");
  expect(invitation.getAttribute("type")).toBe("password");
  const link = "https://ssh.example.test/#invitation=secret";
  await userEvent.type(invitation, link);
  await userEvent.type(screen.getByLabelText("Device name"), "Work laptop");
  expect(f.matching("prepare_personal_enrollment")).toHaveLength(0);
  let finish!: (value: PersonalServerStatus) => void;
  f.handlers.set(
    "prepare_personal_enrollment",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await userEvent.click(screen.getByRole("button", { name: "Prepare account" }));
  expect((invitation as HTMLInputElement).value).toBe("");
  expect(f.matching("prepare_personal_enrollment")[0]?.args).toEqual({
    invitationUrl: link,
    deviceName: "Work laptop",
  });
  expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
  await act(async () => finish(prepared));
  expect(document.activeElement).toBe(await screen.findByRole("heading", { name: "Save your recovery key" }));
  expect(container.textContent).not.toContain("secret");
  expect(await violations(container)).toEqual([]);
});

it("focuses the next setup heading after keyboard actions without stealing focus on initial load or the same phase", async () => {
  fixture(prepared);
  render(
    <>
      <button type="button">Keep focus here</button>
      {view()}
    </>,
  );
  const outside = screen.getByRole("button", { name: "Keep focus here" });
  outside.focus();
  const save = await screen.findByRole("button", { name: "Save recovery file" });
  expect(document.activeElement).toBe(outside);

  save.focus();
  await userEvent.keyboard("{Enter}");
  await screen.findByRole("button", { name: "Save recovery file again" });
  expect(document.activeElement).toBe(save);

  screen.getByRole("checkbox").focus();
  await userEvent.keyboard(" ");
  screen.getByRole("button", { name: "Confirm recovery file" }).focus();
  await userEvent.keyboard("{Enter}");
  expect(document.activeElement).toBe(await screen.findByRole("heading", { name: "Join this server" }));

  await userEvent.tab();
  expect(document.activeElement).toBe(screen.getByRole("button", { name: "Join this server" }));
  await userEvent.keyboard("{Enter}");
  expect(document.activeElement).toBe(await screen.findByRole("heading", { name: "This device is authenticated" }));
});

it("requires successful native recovery export and a separate explicit confirmation before joining", async () => {
  const f = fixture(prepared);
  render(view());
  const save = await screen.findByRole("button", { name: "Save recovery file" });
  expect(screen.queryByRole("checkbox")).toBeNull();
  f.handlers.set("save_personal_recovery_key", () => prepared);
  await userEvent.click(save);
  expect(screen.queryByRole("checkbox")).toBeNull();
  f.handlers.delete("save_personal_recovery_key");
  await userEvent.click(save);
  const confirm = await screen.findByRole("button", { name: "Confirm recovery file" });
  expect((confirm as HTMLButtonElement).disabled).toBe(true);
  await userEvent.click(screen.getByRole("checkbox"));
  expect(f.matching("confirm_personal_recovery_key")).toHaveLength(0);
  await userEvent.click(confirm);
  const join = await screen.findByRole("button", { name: "Join this server" });
  expect(screen.getByText("https://ssh.example.test")).toBeTruthy();
  expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
  await userEvent.click(join);
  expect(await screen.findByText("This device is authenticated")).toBeTruthy();
  expect(f.matching("submit_personal_enrollment")).toHaveLength(1);
  expect(screen.getByText(/Local inventory is not uploaded/)).toBeTruthy();
});

it("recovers an uncertain submission through fresh authentication without exposing the IPC error", async () => {
  const ready = { ...prepared, phase: "ready_to_enroll", recoveryKeySaved: true, recoveryKeyConfirmed: true } as const;
  const f = fixture(ready);
  f.handlers.set("submit_personal_enrollment", () => {
    f.set({ ...ready, phase: "enrollment_unconfirmed" });
    throw new Error("secret invitation and token must not render");
  });
  const { container } = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Join this server" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  const authenticate = await screen.findByRole("button", { name: "Authenticate this device" });
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Authenticate this device" }));
  expect(screen.queryByRole("button", { name: "Join this server" })).toBeNull();
  expect(container.textContent).not.toContain("secret invitation");
  await userEvent.click(authenticate);
  expect(await screen.findByText("This device is authenticated")).toBeTruthy();
  expect(f.matching("submit_personal_enrollment")).toHaveLength(1);
  expect(f.matching("authenticate_personal_server")).toHaveLength(1);
});

it("does not enroll or authenticate automatically when a saved pending identity is reopened", async () => {
  const f = fixture({ ...prepared, phase: "enrollment_unconfirmed" });
  render(view());
  expect(await screen.findByRole("button", { name: "Authenticate this device" })).toBeTruthy();
  expect(f.calls.map((call) => call.command)).toEqual(["personal_server_status", "personal_sync_key_status"]);
  expect(screen.queryByLabelText("Invitation link")).toBeNull();
});

it("imports a replacement only through Rust, clears its secret, and requires a separate Join", async () => {
  const f = fixture(unconfirmed);
  f.handlers.set("update_personal_invitation", () => ({ ...unconfirmed, phase: "ready_to_enroll" }));
  const { container } = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Use a new invitation" }));
  const input = screen.getByLabelText("New invitation link") as HTMLInputElement;
  expect(input.type).toBe("password");
  expect(document.activeElement).toBe(input);
  const link = "https://ssh.example.test/invite#token=replacement-secret";
  await userEvent.type(input, link);
  expect(f.matching("update_personal_invitation")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Check and use invitation" }));
  const join = await screen.findByRole("button", { name: "Join this server" });
  expect(input.value).toBe("");
  expect(f.matching("update_personal_invitation")[0]?.args).toEqual({ invitationUrl: link });
  expect(f.matching("authenticate_personal_server")).toHaveLength(0);
  expect(f.matching("prepare_personal_enrollment")).toHaveLength(0);
  expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
  expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Join this server" }));
  expect(container.textContent).not.toContain("replacement-secret");
  expect(screen.queryByRole("button", { name: "Use a new invitation" })).toBeNull();
  expect(await violations(container)).toEqual([]);
  await userEvent.click(join);
  expect(await screen.findByRole("heading", { name: "This device is authenticated" })).toBeTruthy();
  expect(f.matching("submit_personal_enrollment")).toHaveLength(1);
});

it("ends recovery when replacement authentication succeeds without joining again", async () => {
  const f = fixture(unconfirmed);
  f.handlers.set("update_personal_invitation", () => ({ ...unconfirmed, phase: "authenticated" }));
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Use a new invitation" }));
  const input = screen.getByLabelText("New invitation link") as HTMLInputElement;
  await userEvent.type(input, "https://ssh.example.test/invite#token=unused-secret");
  await userEvent.click(screen.getByRole("button", { name: "Check and use invitation" }));
  expect(await screen.findByRole("heading", { name: "This device is authenticated" })).toBeTruthy();
  expect(input.value).toBe("");
  expect(screen.queryByRole("button", { name: "Join this server" })).toBeNull();
  expect(screen.queryByLabelText("New invitation link")).toBeNull();
  expect(f.matching("update_personal_invitation")).toHaveLength(1);
  expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
});

it.each<PersonalServerError>(["authentication", "network", "invalidResponse", "invitation"])(
  "keeps a rejected replacement pending on %s without offering Join",
  async (error) => {
    const f = fixture(unconfirmed);
    f.handlers.set("update_personal_invitation", () => Promise.reject(error));
    render(view());
    await userEvent.click(await screen.findByRole("button", { name: "Use a new invitation" }));
    const input = screen.getByLabelText("New invitation link") as HTMLInputElement;
    await userEvent.type(input, "https://ssh.example.test/invite#token=rejected-secret");
    await userEvent.click(screen.getByRole("button", { name: "Check and use invitation" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    await waitFor(() => expect(input.disabled).toBe(false));
    expect(input.value).toBe("");
    expect(screen.getByRole("button", { name: "Authenticate this device" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Join this server" })).toBeNull();
    expect(document.body.textContent).not.toContain("rejected-secret");
    expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
    expect(f.matching("update_personal_invitation")).toHaveLength(1);
  },
);

it("blocks repeated replacement and authentication while the core checks a new invitation", async () => {
  const f = fixture(unconfirmed);
  let finish!: (value: PersonalServerStatus) => void;
  f.handlers.set(
    "update_personal_invitation",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Use a new invitation" }));
  const input = screen.getByLabelText("New invitation link") as HTMLInputElement;
  await userEvent.type(input, "https://ssh.example.test/invite#token=secret");
  await userEvent.dblClick(screen.getByRole("button", { name: "Check and use invitation" }));
  expect(f.matching("update_personal_invitation")).toHaveLength(1);
  expect(input.value).toBe("");
  expect(input.disabled).toBe(true);
  expect(screen.getByRole("button", { name: "Cancel new invitation" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getAllByRole("button", { name: "Working…" }).every((button) => button.hasAttribute("disabled"))).toBe(
    true,
  );
  expect(f.matching("authenticate_personal_server")).toHaveLength(0);
  await act(async () => finish({ ...unconfirmed, phase: "ready_to_enroll" }));
  expect(await screen.findByRole("button", { name: "Join this server" })).toBeTruthy();
});

it("clears a cancelled replacement and localizes the pending recovery path", async () => {
  const f = fixture(unconfirmed);
  f.handlers.set("update_personal_invitation", () => Promise.reject("authentication"));
  render(view("zh-Hans"));
  const toggle = await screen.findByRole("button", { name: "使用新邀请" });
  await userEvent.click(toggle);
  const cancelled = screen.getByLabelText("新邀请链接") as HTMLInputElement;
  await userEvent.type(cancelled, "cancelled-secret");
  await userEvent.click(screen.getByRole("button", { name: "取消新邀请" }));
  expect(cancelled.value).toBe("");
  expect(document.activeElement).toBe(toggle);
  expect(f.matching("update_personal_invitation")).toHaveLength(0);
  await userEvent.click(toggle);
  const input = screen.getByLabelText("新邀请链接") as HTMLInputElement;
  expect(input.value).toBe("");
  await userEvent.type(input, "rejected-secret");
  await userEvent.click(screen.getByRole("button", { name: "检查并使用邀请" }));
  expect((await screen.findByRole("alert")).textContent).toContain("服务器未能认证此设备");
  expect(input.value).toBe("");
  expect(screen.queryByRole("button", { name: "加入此服务器" })).toBeNull();
  expect(document.body.textContent).not.toContain("rejected-secret");
});

it("keeps enrollment disabled while the request is pending", async () => {
  const f = fixture({ ...prepared, phase: "ready_to_enroll" });
  let finish!: (value: PersonalServerStatus) => void;
  f.handlers.set(
    "submit_personal_enrollment",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(view());
  const join = await screen.findByRole("button", { name: "Join this server" });
  await userEvent.dblClick(join);
  expect(f.matching("submit_personal_enrollment")).toHaveLength(1);
  expect((screen.getByRole("button", { name: "Working…" }) as HTMLButtonElement).disabled).toBe(true);
  await act(async () => finish({ ...prepared, phase: "authenticated" }));
});

it("retries a failed status read without sending account requests", async () => {
  const f = fixture();
  f.handlers.set("personal_server_status", () => {
    throw new Error("unavailable");
  });
  render(view());
  const retry = await screen.findByRole("button", { name: "Reload account status" });
  f.handlers.delete("personal_server_status");
  await userEvent.click(retry);
  expect(await screen.findByLabelText("Invitation link")).toBeTruthy();
  expect(f.matching("submit_personal_enrollment")).toHaveLength(0);
});

it("renders authenticated status in Chinese with no recovery key or token controls", async () => {
  fixture({ ...prepared, phase: "authenticated" });
  const { container } = render(view("zh-Hans"));
  expect(await screen.findByText("此设备已通过认证")).toBeTruthy();
  expect(screen.queryByRole("textbox")).toBeNull();
  await waitFor(async () => expect(await violations(container)).toEqual([]));
});

it("reaches the Personal setup tab with keyboard navigation and keeps one tab stop", async () => {
  fixture();
  const { container } = render(
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale="en">
          <SettingsView status={{ state: "open", protection: "keystore" }} onStatus={() => undefined} />
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>,
  );
  const appearance = screen.getByRole("tab", { name: "Appearance" });
  appearance.focus();
  await userEvent.keyboard("{End}");
  const personal = screen.getByRole("tab", { name: "Personal account" });
  expect(document.activeElement).toBe(personal);
  expect(personal.getAttribute("aria-selected")).toBe("true");
  expect(await screen.findByLabelText("Invitation link")).toBeTruthy();
  expect(screen.getAllByRole("tab").filter((tab) => tab.tabIndex === 0)).toEqual([personal]);
  expect(await violations(container)).toEqual([]);
  await userEvent.keyboard("{ArrowRight}");
  expect(document.activeElement).toBe(appearance);
  await userEvent.keyboard("{ArrowLeft}");
  expect(document.activeElement).toBe(personal);
  await userEvent.keyboard("{Home}");
  expect(document.activeElement).toBe(appearance);
});

it("localizes a typed invalid-invitation error without displaying the rejected secret", async () => {
  const f = fixture();
  f.handlers.set("prepare_personal_enrollment", () => Promise.reject("invitation"));
  render(view("zh-Hans"));
  const input = await screen.findByLabelText("邀请链接");
  await userEvent.type(input, "rejected-secret");
  await userEvent.type(screen.getByLabelText("设备名称"), "Work laptop");
  await userEvent.click(screen.getByRole("button", { name: "准备账号" }));
  expect((await screen.findByRole("alert")).textContent).toContain("邀请链接无效");
  expect((input as HTMLInputElement).value).toBe("");
  expect(document.body.textContent).not.toContain("rejected-secret");
});
