// SPDX-License-Identifier: Apache-2.0
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { AppearanceProvider } from "@scoplen/ui";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { AccountProfilesBoundary, ProfileSwitcher, useProfileCommands } from "../src/account-profiles";
import { AccountRegistration } from "../src/account-registration";
import { I18nProvider } from "../src/i18n";
import { commands, type ProfileSnapshot, type RegistrationView, type PasswordSignInView } from "../src/ipc/bindings";
import { createInventoryApi } from "../src/inventory/core-api";
import { violations } from "../../ui/test/axe";

afterEach(() => {
  cleanup();
  clearMocks();
  vi.restoreAllMocks();
});

const local: ProfileSnapshot = { generation: "1", selected: null, accounts: [], retainedProfile: false };
const preparation: RegistrationView = {
  phase: "recoveryRequired",
  operationId: "01900000-0000-7000-8000-000000000001",
  origin: "https://personal.example.test",
  username: "alex",
  recoverySaved: false,
  recoveryConfirmed: false,
  retryNotBeforeMs: null,
};

const signInPreparation: PasswordSignInView = {
  phase: "ready",
  operationId: "01900000-0000-7000-8000-000000000004",
  origin: preparation.origin,
  username: preparation.username,
  retryNotBeforeMs: null,
};

function fixture(initial: RegistrationView | null = null, initialSignIn: PasswordSignInView | null = null) {
  let pending = initial;
  let signIn = initialSignIn;
  const calls: { command: string; args: Record<string, unknown> }[] = [];
  const handlers = new Map<string, (args: Record<string, unknown>) => unknown>();
  mockIPC(
    (command, payload) => {
      const args = (payload ?? {}) as Record<string, unknown>;
      calls.push({ command, args });
      if (handlers.has(command)) return handlers.get(command)!(args);
      if (command === "account_profiles_snapshot") return local;
      if (command === "registration_status") return pending;
      if (command === "password_sign_in_status") return signIn;
      if (command === "begin_password_sign_in") return (signIn = signInPreparation);
      if (command === "discard_password_sign_in") {
        signIn = null;
        return null;
      }
      if (command === "prepare_account_registration") return (pending = preparation);
      if (command === "save_registration_recovery") return (pending = { ...preparation, recoverySaved: true });
      if (command === "confirm_registration_recovery")
        return (pending = { ...preparation, recoverySaved: true, recoveryConfirmed: true, phase: "ready" });
      if (command === "discard_registration_preparation") {
        pending = null;
        return null;
      }
      if (command === "stop_account_operation") return;
      throw new Error(`Unexpected command: ${command}`);
    },
    { shouldMockEvents: true },
  );
  return {
    calls,
    handlers,
    setSignIn: (next: PasswordSignInView) => {
      signIn = next;
    },
    set: (next: RegistrationView) => {
      pending = next;
    },
  };
}

function view() {
  return (
    <AppearanceProvider>
      <I18nProvider locale="en">
        <AccountProfilesBoundary>
          <ProfileSwitcher />
          <AccountRegistration />
        </AccountProfilesBoundary>
      </I18nProvider>
    </AppearanceProvider>
  );
}

it("keeps profile commands available during StrictMode effect replay", async () => {
  fixture();
  render(<StrictMode>{view()}</StrictMode>);
  expect(await screen.findByRole("button", { name: "Create account" })).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("prepares only on intent, clears the password, and requires native recovery export and explicit confirmation", async () => {
  const f = fixture();
  const { container } = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Create account" }));
  expect(f.calls.map((call) => call.command)).toEqual([
    "account_profiles_snapshot",
    "registration_status",
    "password_sign_in_status",
  ]);
  await userEvent.type(screen.getByLabelText("Personal server URL"), preparation.origin);
  await userEvent.type(screen.getByLabelText("Username"), preparation.username);
  await userEvent.type(screen.getByLabelText("Name for this device"), "Work laptop");
  const password = screen.getByLabelText("Account password") as HTMLInputElement;
  await userEvent.type(password, "test-password-123456");
  await userEvent.click(screen.getByRole("button", { name: "Prepare account" }));
  expect(await screen.findByRole("button", { name: "Save recovery key…" })).toBeTruthy();
  expect(password.value).toBe("");
  expect(f.calls.filter((call) => call.command === "prepare_account_registration")).toHaveLength(1);
  expect(screen.queryByRole("button", { name: "Submit registration" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Save recovery key…" }));
  await userEvent.click(await screen.findByRole("button", { name: "I saved the recovery key safely" }));
  expect(await screen.findByRole("button", { name: "Submit registration" })).toBeTruthy();
  expect(f.calls.some((call) => call.command === "exchange_account_registration")).toBe(false);
  expect(await violations(container)).toEqual([]);
});

it("keeps a preparation when the native recovery picker is cancelled and discards only on explicit intent", async () => {
  const f = fixture(preparation);
  f.handlers.set("save_registration_recovery", () => null);
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Save recovery key…" }));
  expect(await screen.findByText(/Registration has not been submitted/)).toBeTruthy();
  expect(screen.queryByLabelText("Account password")).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Discard preparation" }));
  expect(await screen.findByLabelText("Account password")).toBeTruthy();
  expect(f.calls.filter((call) => call.command === "discard_registration_preparation")).toHaveLength(1);
});

it("restores unknown work through remount and exposes only exact Confirm before a trusted explicit Retry", async () => {
  const f = fixture({ ...preparation, phase: "outcomeUnknown" });
  f.handlers.set("exchange_account_registration", (args) => {
    expect(args.intent).toBe("confirm");
    const next = { ...preparation, phase: "retryAvailable" as const };
    f.set(next);
    return next;
  });
  const first = render(view());
  expect(await screen.findByRole("button", { name: "Confirm original result" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Retry registration" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Discard preparation" })).toBeNull();
  first.unmount();
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Confirm original result" }));
  expect(await screen.findByRole("button", { name: "Retry registration" })).toBeTruthy();
  expect(f.calls.filter((call) => call.command === "exchange_account_registration")).toHaveLength(1);
});

it("retains committed work after installation failure and clears its independent local passphrase", async () => {
  const f = fixture({ ...preparation, phase: "committed" });
  f.handlers.set("install_registered_profile", () => Promise.reject("installation"));
  render(view());
  const passphrase = (await screen.findByLabelText("Profile local passphrase (if required)")) as HTMLInputElement;
  await userEvent.type(passphrase, "independent-local-passphrase");
  await userEvent.click(screen.getByRole("button", { name: "Install account profile" }));
  expect((await screen.findByRole("alert")).textContent).toContain("confirmed registration and its keys are retained");
  expect(passphrase.value).toBe("");
  expect(screen.getByRole("button", { name: "Install account profile" })).toBeTruthy();
  const request = f.calls.find((call) => call.command === "install_registered_profile")!;
  expect(request.args.generation).toBe("1");
  expect(request.args.operationId).toBe(preparation.operationId);
});

it("Stop targets the pending ticket and unmount preserves the unknown operation", async () => {
  const f = fixture({ ...preparation, phase: "ready" });
  let finish!: (value: RegistrationView) => void;
  f.handlers.set(
    "exchange_account_registration",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const rendered = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Submit registration" }));
  await userEvent.click(screen.getByRole("button", { name: "Stop" }));
  const exchange = f.calls.find((call) => call.command === "exchange_account_registration")!;
  expect(f.calls.find((call) => call.command === "stop_account_operation")!.args.ticket).toBe(exchange.args.ticket);
  rendered.unmount();
  await act(async () => finish({ ...preparation, phase: "outcomeUnknown" }));
  expect(f.calls.some((call) => call.command === "discard_registration_preparation")).toBe(false);
});

it("remounts views on profile change and rejects old invokers before dispatch and after a late reply", async () => {
  const f = fixture();
  let current!: typeof commands;
  let finish!: (value: null) => void;
  f.handlers.set(
    "personal_account_snapshot",
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  function Probe() {
    current = useProfileCommands();
    return <span>Profile view</span>;
  }
  const internals = window as unknown as { __TAURI_INTERNALS__: { invoke: typeof invoke } };
  const spy = vi.spyOn(internals.__TAURI_INTERNALS__, "invoke");
  render(
    <I18nProvider locale="en">
      <AccountProfilesBoundary>
        <Probe />
      </AccountProfilesBoundary>
    </I18nProvider>,
  );
  await screen.findByText("Profile view");
  const old = current;
  const late = old.personalAccountSnapshot();
  const lateCheck = expect(late).rejects.toThrow("profileChanged");
  const invocation = spy.mock.calls.find((call) => call[0] === "personal_account_snapshot")!;
  expect(new Headers(invocation[2]?.headers).get("x-scoplen-profile-generation")).toBe("1");
  await act(async () => {
    await emit("profile-changed", { snapshot: { ...local, generation: "2" } });
  });
  expect(current).not.toBe(old);
  await expect(old.personalAccountSnapshot()).rejects.toThrow("profileChanged");
  await act(async () => finish(null));
  await lateCheck;
  expect(f.calls.filter((call) => call.command === "personal_account_snapshot")).toHaveLength(1);
});

it("ignores old-profile inventory and session events after switching", async () => {
  fixture();
  const listener = vi.fn();
  const stop = createInventoryApi(commands, "new").onChange(listener);
  await waitFor(async () => {
    await emit("store-changed", { profileGeneration: "new", recordType: "host", ids: [] });
    expect(listener).toHaveBeenCalled();
  });
  listener.mockClear();
  await emit("store-changed", { profileGeneration: "old", recordType: "host", ids: [] });
  await emit("session-changed", { profileGeneration: "old", sessionId: "old", change: "closed" });
  expect(listener).not.toHaveBeenCalled();
  await emit("session-changed", { profileGeneration: "new", sessionId: "new", change: "opened" });
  expect(listener).toHaveBeenCalledOnce();
  stop();
});

it("selects a ready account only after explicit session-shutdown confirmation", async () => {
  const f = fixture();
  const account = {
    id: "01900000-0000-7000-8000-000000000002",
    origin: preparation.origin,
    accountId: "01900000-0000-7000-8000-000000000003",
    ready: true,
  };
  const before = { ...local, accounts: [account] };
  f.handlers.set("account_profiles_snapshot", () => before);
  f.handlers.set("select_account_profile", () => ({ ...before, generation: "2", selected: account.id }));
  render(view());
  await userEvent.selectOptions(await screen.findByLabelText("Open profile"), account.id);
  expect(f.calls.some((call) => call.command === "select_account_profile")).toBe(false);
  expect(await screen.findByRole("dialog")).toBeTruthy();
  expect(screen.getByText(/Switching closes every SSH session/)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Switch profile" }));
  await waitFor(() => expect((screen.getByLabelText("Open profile") as HTMLSelectElement).value).toBe(account.id));
  const selection = f.calls.find((call) => call.command === "select_account_profile")!;
  expect(selection.args).toEqual({ generation: "1", profileId: account.id, localPassphrase: null });
});

it("keeps a retained root accessible without requesting registration state or relabeling it Local", async () => {
  const f = fixture();
  f.handlers.set("account_profiles_snapshot", () => ({ ...local, retainedProfile: true }));
  render(view());
  expect(await screen.findByText("Retained account profile")).toBeTruthy();
  expect(screen.getByText(/This retained account remains available/)).toBeTruthy();
  expect(screen.queryByLabelText("Open profile")).toBeNull();
  expect(f.calls.map((call) => call.command)).toEqual(["account_profiles_snapshot"]);
});

async function fillPasswordForm() {
  await userEvent.type(screen.getByLabelText("Personal server URL"), preparation.origin);
  await userEvent.type(screen.getByLabelText("Username"), preparation.username);
  await userEvent.type(screen.getByLabelText("Name for this device"), "Second laptop");
  await userEvent.type(screen.getByLabelText("Account password"), "test-password-123456");
}

it("signs in only on explicit intent and requires device admission before installation without recovery export", async () => {
  const f = fixture();
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Sign in" }));
  expect(f.calls.some((call) => call.command === "begin_password_sign_in")).toBe(false);
  await fillPasswordForm();
  const input = screen.getByLabelText("Account password") as HTMLInputElement;
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("button", { name: "Admit this device" })).toBeTruthy();
  expect(input.value).toBe("");
  expect(screen.queryByRole("button", { name: "Save recovery key…" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Install account profile" })).toBeNull();
  expect(f.calls.filter((call) => call.command === "begin_password_sign_in")).toHaveLength(1);
  expect(f.calls.some((call) => call.command === "exchange_password_sign_in")).toBe(false);
});

it("restores unknown sign-in with Confirm only, then safely restarts a known unchanged expired capability", async () => {
  const f = fixture(null, { ...signInPreparation, phase: "outcomeUnknown" });
  f.handlers.set("exchange_password_sign_in", (args) => {
    expect(args.intent).toBe("confirm");
    const next = { ...signInPreparation, phase: "signInRequired" as const };
    f.setSignIn(next);
    return next;
  });
  render(view());
  expect(await screen.findByRole("button", { name: "Confirm original result" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Admit this device" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Cancel and sign in again" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Retry device admission" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Confirm original result" }));
  expect(await screen.findByText(/needs fresh sign-in/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Retry device admission" })).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Cancel and sign in again" }));
  expect(await screen.findByLabelText("Account password")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  expect(f.calls.filter((call) => call.command === "discard_password_sign_in")).toHaveLength(1);
  expect(f.calls.some((call) => call.command === "begin_password_sign_in")).toBe(false);
});

it("guides an existing catalog account to its saved profile without offering replacement", async () => {
  const f = fixture();
  f.handlers.set("begin_password_sign_in", () => Promise.reject("signInExisting"));
  const { container } = render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Sign in" }));
  await fillPasswordForm();
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Open its saved profile in the selector");
  expect(screen.queryByRole("button", { name: /replace/i })).toBeNull();
  expect(await violations(container)).toEqual([]);
});

it("installs a confirmed sign-in using its exact original admission and captured generation", async () => {
  const f = fixture(null, { ...signInPreparation, phase: "committed" });
  f.handlers.set("install_password_sign_in_profile", () => Promise.reject("installation"));
  render(view());
  await userEvent.click(await screen.findByRole("button", { name: "Install account profile" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  const install = f.calls.find((call) => call.command === "install_password_sign_in_profile")!;
  expect(install.args.generation).toBe("1");
  expect(install.args.operationId).toBe(signInPreparation.operationId);
  expect(f.calls.some((call) => call.command === "install_registered_profile")).toBe(false);
});
