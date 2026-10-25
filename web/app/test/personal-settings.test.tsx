// SPDX-License-Identifier: Apache-2.0
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { AppearanceProvider } from "@scoplen/ui";
import { StrictMode } from "react";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider } from "../src/i18n";
import type { PersonalServerError, PersonalServerStatus } from "../src/ipc/bindings";
import { PersonalSettings } from "../src/personal-settings";
import { SettingsView } from "../src/settings";
import { TerminalColorsProvider } from "../src/terminal-colors";
import { violations } from "../../ui/test/axe";

afterEach(() => {
  cleanup();
  clearMocks();
});

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
const confirmed: PersonalServerStatus = {
  ...empty,
  phase: "authentication_required",
  origin: "https://ssh.example.test",
  accountId: "account",
  deviceId: "device",
  personalVaultId: "vault",
  deviceName: "Work laptop",
};

function fixture(initial = empty) {
  let status = initial;
  const calls: string[] = [];
  const handlers = new Map<string, () => unknown>();
  mockIPC(
    (command) => {
      calls.push(command);
      if (handlers.has(command)) return handlers.get(command)!();
      if (command === "personal_server_status") return status;
      if (command === "authenticate_personal_server") {
        status = { ...status, phase: "authenticated" };
        return status;
      }
      if (command === "revalidate_retained_device") {
        status = { ...status, phase: "authenticated" };
        return status;
      }
      if (command === "personal_account_snapshot") return null;
      if (command === "personal_sync_key_status") return "notConnected";
      if (command === "personal_sync_background_status") return "inactive";
      throw new Error(`Unexpected command: ${command}`);
    },
    { shouldMockEvents: true },
  );
  return {
    calls,
    handlers,
    set: (next: PersonalServerStatus) => {
      status = next;
    },
    matching: (name: string) => calls.filter((call) => call === name),
  };
}

function view(locale: "en" | "zh-Hans" = "en") {
  return (
    <I18nProvider locale={locale}>
      <PersonalSettings />
    </I18nProvider>
  );
}

it.each(["en", "zh-Hans"] as const)(
  "explains unavailable password admission without fake or retired controls (%s)",
  async (locale) => {
    const f = fixture();
    const { container } = render(view(locale));
    expect(
      await screen.findByText(
        locale === "en"
          ? /Account registration and password sign-in are not available/
          : /此版本尚不支持账号注册和密码登录/,
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
    expect(f.calls).toEqual(["personal_server_status"]);
    expect(await violations(container)).toEqual([]);
  },
);

it("preserves a retired pending profile without attempting account access", async () => {
  const f = fixture({ ...confirmed, phase: "retired_entry" });
  const { container } = render(view());
  expect(await screen.findByText(/This unfinished setup uses a retired invitation or pairing protocol/)).toBeTruthy();
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(f.calls).toEqual(["personal_server_status"]);
  expect(await violations(container)).toEqual([]);
});

it.each(["en", "zh-Hans"] as const)(
  "explicitly revalidates retained keys before enabling sync (%s)",
  async (locale) => {
    const f = fixture({ ...confirmed, phase: "revalidation_required" });
    const { container } = render(view(locale));
    const revalidate = await screen.findByRole("button", {
      name: locale === "en" ? "Revalidate this device" : "重新验证此设备",
    });
    expect(screen.getByText(confirmed.origin!)).toBeTruthy();
    expect(f.calls).toEqual(["personal_server_status"]);
    expect(screen.queryByRole("button", { name: "Verify sync keys" })).toBeNull();
    revalidate.focus();
    await userEvent.keyboard("{Enter}");
    expect(
      await screen.findByRole("button", { name: locale === "en" ? "Authenticate this device" : "认证此设备" }),
    ).toBeTruthy();
    expect(f.matching("revalidate_retained_device")).toHaveLength(1);
    expect(f.matching("authenticate_personal_server")).toHaveLength(0);
    expect(await violations(container)).toEqual([]);
  },
);

it("retains revalidation context after failure and ignores a late closed-view result", async () => {
  const f = fixture({ ...confirmed, phase: "revalidation_required" });
  f.handlers.set("revalidate_retained_device", () => Promise.reject("admissionUnverified"));
  const rendered = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Revalidate this device" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(screen.getByText(confirmed.origin!)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Verify sync keys" })).toBeNull();
  let finish!: (status: PersonalServerStatus) => void;
  f.handlers.set(
    "revalidate_retained_device",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  await userEvent.dblClick(screen.getByRole("button", { name: "Revalidate this device" }));
  expect(f.matching("revalidate_retained_device")).toHaveLength(2);
  expect(screen.getByRole("button", { name: "Working…" }).hasAttribute("disabled")).toBe(true);
  rendered.unmount();
  const reads = f.matching("personal_server_status").length;
  await act(async () => finish({ ...confirmed, phase: "authenticated" }));
  expect(f.matching("personal_server_status")).toHaveLength(reads);
});

it.each<PersonalServerError>(["admissionUnverified", "storage"])(
  "allows a failed local status read to be retried safely (%s)",
  async (error) => {
    const f = fixture();
    f.handlers.set("personal_server_status", () => Promise.reject(error));
    render(view());
    expect(await screen.findByRole("alert")).toBeTruthy();
    const retry = screen.getByRole("button", { name: "Reload account status" });
    f.handlers.delete("personal_server_status");
    await userEvent.click(retry);
    expect(await screen.findByText(/Account registration and password sign-in are not available/)).toBeTruthy();
    expect(f.calls).toEqual(["personal_server_status", "personal_server_status"]);
  },
);

it("retains confirmed metadata and authenticates only on explicit keyboard intent", async () => {
  const f = fixture(confirmed);
  const { container } = render(view());
  const authenticate = await screen.findByRole("button", { name: "Authenticate this device" });
  expect(screen.getByText("https://ssh.example.test")).toBeTruthy();
  expect(screen.getByText("account")).toBeTruthy();
  expect(screen.getByText("Work laptop")).toBeTruthy();
  expect(f.matching("authenticate_personal_server")).toHaveLength(0);
  const connect = screen.getByRole("button", { name: "Verify sync keys" });
  expect(connect.hasAttribute("disabled")).toBe(true);
  authenticate.focus();
  await userEvent.keyboard("{Enter}");
  await waitFor(() => expect(connect.hasAttribute("disabled")).toBe(false));
  expect(f.matching("authenticate_personal_server")).toHaveLength(1);
  expect(await violations(container)).toEqual([]);
});

it("blocks repeated authentication and parallel child actions while the core is busy", async () => {
  const f = fixture({ ...confirmed, phase: "authenticated" });
  let finish!: (value: PersonalServerStatus) => void;
  f.handlers.set(
    "authenticate_personal_server",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(view());
  await userEvent.dblClick(await screen.findByRole("button", { name: "Authenticate this device" }));
  expect(f.matching("authenticate_personal_server")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Working…" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Verify sync keys" }).hasAttribute("disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "Refresh account and devices" }).hasAttribute("disabled")).toBe(true);
  await act(async () => finish({ ...confirmed, phase: "authenticated" }));
});

it("localizes authentication failure without displaying arbitrary diagnostics", async () => {
  const f = fixture(confirmed);
  f.handlers.set("authenticate_personal_server", () => Promise.reject("authentication"));
  const { container } = render(view("zh-Hans"));
  await userEvent.click(await screen.findByRole("button", { name: "认证此设备" }));
  expect((await screen.findByRole("alert")).textContent).toContain("服务器未能认证此设备");
  expect(screen.getByText("Work laptop")).toBeTruthy();
  expect(await violations(container)).toEqual([]);
});

it("drops late completions after the account view closes", async () => {
  const f = fixture(confirmed);
  let finish!: (value: PersonalServerStatus) => void;
  f.handlers.set(
    "authenticate_personal_server",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const rendered = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Authenticate this device" }));
  rendered.unmount();
  await act(async () => finish({ ...confirmed, phase: "authenticated" }));
  expect(f.matching("personal_server_status")).toHaveLength(1);
});

it("ignores a stale initial read after a StrictMode effect restart", async () => {
  const f = fixture(confirmed);
  const pending: ((value: PersonalServerStatus) => void)[] = [];
  f.handlers.set("personal_server_status", () => new Promise((resolve) => pending.push(resolve)));
  render(<StrictMode>{view()}</StrictMode>);
  await waitFor(() => expect(pending).toHaveLength(2));
  await act(async () => pending[1]!(confirmed));
  expect(await screen.findByText("Work laptop")).toBeTruthy();
  await act(async () => pending[0]!(empty));
  expect(screen.getByText("Work laptop")).toBeTruthy();
  expect(screen.queryByText(/Account registration and password sign-in are not available/)).toBeNull();
});

it("refreshes safe account state after an uncertain child refresh without automatic authentication", async () => {
  const f = fixture({ ...confirmed, phase: "authenticated" });
  f.handlers.set("connect_personal_sync", () => {
    f.set(confirmed);
    return Promise.reject("authenticationRequired");
  });
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Verify sync keys" }));
  expect(await screen.findByText(/This session expired or could not be safely renewed/)).toBeTruthy();
  expect(f.matching("connect_personal_sync")).toHaveLength(1);
  expect(f.matching("authenticate_personal_server")).toHaveLength(0);
});

it("discards an older child status read after a new authentication completes", async () => {
  const f = fixture({ ...confirmed, phase: "authenticated" });
  f.handlers.set("connect_personal_sync", () => Promise.reject("authenticationRequired"));
  render(view());
  await screen.findByRole("button", { name: "Authenticate this device" });
  let stale!: (value: PersonalServerStatus) => void;
  f.handlers.set("personal_server_status", () => new Promise((resolve) => (stale = resolve)));
  await userEvent.click(screen.getByRole("button", { name: "Verify sync keys" }));
  await waitFor(() => expect(f.matching("personal_server_status")).toHaveLength(2));
  f.handlers.delete("personal_server_status");
  await userEvent.click(screen.getByRole("button", { name: "Authenticate this device" }));
  expect(await screen.findByText(/Your account identity is ready/)).toBeTruthy();
  await act(async () => stale(empty));
  expect(screen.getByText("Work laptop")).toBeTruthy();
  expect(screen.queryByText(/Account registration and password sign-in are not available/)).toBeNull();
});

it("reaches Personal account with keyboard tab navigation and one tab stop", async () => {
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
  expect(await screen.findByText(/Account registration and password sign-in are not available/)).toBeTruthy();
  expect(screen.getAllByRole("tab").filter((tab) => tab.tabIndex === 0)).toEqual([personal]);
  expect(await violations(container)).toEqual([]);
  await userEvent.keyboard("{ArrowRight}");
  expect(document.activeElement).toBe(appearance);
});
