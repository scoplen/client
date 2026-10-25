// SPDX-License-Identifier: Apache-2.0
//
// The interface gallery: every screen and state with sample data, for
// reviewing the design during development (`pnpm --dir web/app dev`, then
// /gallery.html). It is not part of the application and is never built into it.

import "@scoplen/ui/styles.css";
import {
  AppearanceProvider,
  applyStoredAppearance,
  themes,
  useAppearance,
  type SchemeChoice,
  type ThemeId,
} from "@scoplen/ui";
import { mockIPC } from "@tauri-apps/api/mocks";
import { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Frame } from "../frame";
import { I18nProvider, useI18n } from "../i18n";
import { HostsHome } from "../inventory/home";
import { InventoryContext } from "../inventory/api";
import type {
  Locale,
  Platform,
  SessionEvent,
  Status,
  RegistrationView,
  ProfileSnapshot,
  PasswordSignInView,
} from "../ipc/bindings";
import { AccountProfilesBoundary } from "../account-profiles";
import { CreatePassphraseScreen, UnlockScreen, UnreadableScreen } from "../local-data";
import { Menus } from "../menus";
import { SettingsView } from "../settings";
import { SessionTerminal, type SessionState } from "../session";
import { TerminalColorsProvider } from "../terminal-colors";
import { sampleHosts, sampleInventory } from "./sample-inventory";

const remotePath = (path: string) => Array.from(new TextEncoder().encode(path));
let interactivePreview: { sessionId: string; transportId: string; emit: (event: SessionEvent) => void } | null = null;
const registrationFixture: RegistrationView = {
  phase: "recoveryRequired",
  operationId: "01900000-0000-7000-8000-000000000001",
  origin: "https://personal.example.test",
  username: "alex",
  recoverySaved: false,
  recoveryConfirmed: false,
  retryNotBeforeMs: null,
};
let registrationPreview: RegistrationView | null = null;
const signInFixture: PasswordSignInView = {
  phase: "ready",
  operationId: "01900000-0000-7000-8000-000000000004",
  origin: registrationFixture.origin,
  username: registrationFixture.username,
  retryNotBeforeMs: null,
};
let signInPreview: PasswordSignInView | null = null;
let profilePreview: ProfileSnapshot = {
  generation: "1",
  selected: null,
  retainedProfile: false,
  accounts: [
    {
      id: "01900000-0000-7000-8000-000000000002",
      origin: registrationFixture.origin,
      accountId: "01900000-0000-7000-8000-000000000003",
      ready: true,
    },
  ],
};

function previewChallenge(transportId: string, informational: boolean): SessionEvent {
  return {
    kind: "preparation",
    transportId,
    event: {
      kind: "keyboardInteractive",
      context: {
        profileId: "gallery-interactive",
        hostId: "gallery-api-01",
        login: "deploy",
        host: "api-01",
        username: "deploy",
        address: "api.example.com",
        port: 22,
        position: 2,
        total: 2,
        target: true,
      },
      promptId: informational ? "gallery-continue" : "gallery-answers",
      name: "Example PAM service",
      instruction: informational
        ? "Your authentication request is ready to continue."
        : "Confirm the account and enter this connection's one-time code.",
      prompts: informational
        ? []
        : [
            { text: "Account", echo: true },
            { text: "One-time code", echo: false },
          ],
    },
  };
}

// The local-data screens call the core; answer them as a core would.
mockIPC(
  (cmd, args) => {
    const payload = (args ?? {}) as {
      passphrase?: string;
      localPassphrase?: string;
      origin?: string;
      username?: string;
      intent?: string;
      profileId?: string;
      sessionId?: string;
      transportId?: string;
      promptId?: string;
      path?: number[];
      messages?: { onmessage: (event: SessionEvent) => void };
    };
    if (cmd === "account_profiles_snapshot") return profilePreview;
    if (cmd === "personal_server_status")
      return {
        phase: "not_configured",
        origin: null,
        accountId: null,
        deviceId: null,
        personalVaultId: null,
        deviceName: null,
        recoveryKeySaved: false,
        recoveryKeyConfirmed: false,
      };
    if (cmd === "registration_status") return registrationPreview;
    if (cmd === "password_sign_in_status") return signInPreview;
    if (cmd === "begin_password_sign_in")
      return (signInPreview = { ...signInFixture, origin: payload.origin!, username: payload.username! });
    if (cmd === "exchange_password_sign_in")
      return (signInPreview = {
        ...signInFixture,
        phase: payload.intent === "confirm" ? "signInRequired" : "committed",
      });
    if (cmd === "discard_password_sign_in") {
      signInPreview = null;
      return null;
    }
    if (cmd === "prepare_account_registration")
      return (registrationPreview = {
        ...registrationFixture,
        origin: payload.origin!,
        username: payload.username!,
      });
    if (cmd === "save_registration_recovery")
      return (registrationPreview = { ...registrationFixture, recoverySaved: true });
    if (cmd === "confirm_registration_recovery")
      return (registrationPreview = {
        ...registrationFixture,
        recoverySaved: true,
        recoveryConfirmed: true,
        phase: "ready",
      });
    if (cmd === "exchange_account_registration")
      return (registrationPreview = {
        ...registrationFixture,
        recoverySaved: true,
        recoveryConfirmed: true,
        phase: payload.intent === "confirm" ? "retryAvailable" : "committed",
      });
    if (cmd === "discard_registration_preparation") {
      registrationPreview = null;
      return null;
    }
    if (
      cmd === "install_registered_profile" ||
      cmd === "install_password_sign_in_profile" ||
      cmd === "select_account_profile"
    )
      return (profilePreview = {
        ...profilePreview,
        generation: String(Number(profilePreview.generation) + 1),
        selected: payload.profileId ?? (cmd !== "select_account_profile" ? profilePreview.accounts[0]!.id : null),
      });
    if (cmd === "unlock_local_data") {
      return payload.passphrase === "scoplen"
        ? { state: "open", protection: "keystoreAndPassphrase" }
        : Promise.reject({ kind: "wrongPassphrase" });
    }
    if (cmd === "create_local_passphrase" || cmd === "set_local_passphrase")
      return { state: "open", protection: "keystoreAndPassphrase" };
    if (cmd === "remove_local_passphrase" || cmd === "start_with_empty_local_data")
      return { state: "open", protection: "keystore" };
    if (cmd === "session_connect") {
      const transportId = crypto.randomUUID();
      queueMicrotask(() => {
        payload.messages?.onmessage({ kind: "starting", transportId, automatic: false });
        if (payload.profileId === "gallery-interactive" && payload.messages) {
          interactivePreview = { sessionId: payload.sessionId!, transportId, emit: payload.messages.onmessage };
          payload.messages.onmessage(previewChallenge(transportId, false));
        } else payload.messages?.onmessage({ kind: "ready", transportId });
      });
      return new Promise(() => undefined);
    }
    const preview = interactivePreview;
    if (cmd === "session_respond" && preview && preview.transportId === payload.transportId) {
      preview.emit(
        payload.promptId === "gallery-answers"
          ? previewChallenge(preview.transportId, true)
          : { kind: "ready", transportId: preview.transportId },
      );
      return null;
    }
    if (
      (cmd === "session_close_transport" || cmd === "session_stop_reconnecting") &&
      preview &&
      preview.sessionId === payload.sessionId
    ) {
      interactivePreview = null;
      preview.emit({ kind: "closed" });
      return null;
    }
    if (cmd === "session_list_files") {
      const root = remotePath(".");
      const logs = remotePath("./logs");
      return {
        entries:
          payload.path?.length === root.length
            ? [
                { name: "logs", path: logs, kind: "directory", sizeBytes: null },
                { name: "deploy.log", path: remotePath("./deploy.log"), kind: "file", sizeBytes: "1280" },
              ]
            : [{ name: "today.log", path: remotePath("./logs/today.log"), kind: "file", sizeBytes: "896" }],
      };
    }
    if (cmd === "session_download_file") return false;
    if (cmd === "session_upload_file") return { status: "unknown", message: null, stagingMayRemain: true };
    return null;
  },
  { shouldMockEvents: true },
);

const screens = {
  hosts: "Hosts",
  firstRun: "Hosts: first run",
  failed: "Hosts: failed to load",
  settings: "Settings",
  accountCreate: "Account: create",
  accountRecovery: "Account: recovery key",
  accountUnknown: "Account: unknown result",
  accountCommitted: "Account: install",
  accountSignIn: "Account: sign in",
  accountAdmissionUnknown: "Account: admission unknown",
  accountAdmissionExpired: "Account: fresh sign-in required",
  files: "Session: files",
  interactive: "Session: keyboard-interactive",
  unlock: "Unlock",
  create: "Choose a passphrase",
  unreadable: "Unreadable data",
} as const;
type Screen = keyof typeof screens;

function Gallery() {
  const [screen, setScreen] = useState<Screen>("hosts");
  const [locale, setLocale] = useState<Locale>("en");
  const [platform, setPlatform] = useState<Platform>("macos");
  const [status, setStatus] = useState<Status>({ state: "open", protection: "keystore" });
  const inventory = useMemo(
    () => sampleInventory(screen === "firstRun" ? [] : sampleHosts(), { failHosts: screen === "failed" }),
    [screen],
  );

  return (
    <I18nProvider locale={locale}>
      <Menus>
        <InventoryContext.Provider value={inventory}>
          <LangAttribute locale={locale} />
          <Screen
            key={`${screen}-${locale}`}
            screen={screen}
            platform={platform}
            status={status}
            onStatus={setStatus}
            onSettings={setScreen}
          />
        </InventoryContext.Provider>
        <aside
          aria-label="Gallery controls"
          className="fixed right-3 bottom-3 z-50 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-raised p-2 text-xs shadow-lg"
        >
          <select
            aria-label="Screen"
            value={screen}
            onChange={(e) => {
              const next = e.target.value as Screen;
              signInPreview =
                next === "accountAdmissionUnknown"
                  ? { ...signInFixture, phase: "outcomeUnknown" }
                  : next === "accountAdmissionExpired"
                    ? { ...signInFixture, phase: "signInRequired" }
                    : null;
              registrationPreview =
                next === "accountCreate" || next === "accountSignIn" || signInPreview
                  ? null
                  : next === "accountUnknown"
                    ? { ...registrationFixture, phase: "outcomeUnknown" }
                    : next === "accountCommitted"
                      ? { ...registrationFixture, phase: "committed" }
                      : { ...registrationFixture };
              setScreen(next);
            }}
            className="rounded border border-border bg-inset px-1 py-0.5"
          >
            {Object.entries(screens).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <select
            aria-label="Language"
            value={locale}
            onChange={(e) => setLocale(e.target.value as Locale)}
            className="rounded border border-border bg-inset px-1 py-0.5"
          >
            <option value="en">English</option>
            <option value="zh-Hans">简体中文</option>
          </select>
          <ThemeControls />
          <select
            aria-label="Platform"
            value={platform}
            onChange={(e) => setPlatform(e.target.value as Platform)}
            className="rounded border border-border bg-inset px-1 py-0.5"
          >
            <option value="macos">macOS</option>
            <option value="windows">Windows</option>
          </select>
        </aside>
      </Menus>
    </I18nProvider>
  );
}

function ThemeControls() {
  const { appearance, setAppearance } = useAppearance();
  return (
    <>
      <select
        aria-label="Theme"
        value={appearance.theme}
        onChange={(e) => setAppearance({ ...appearance, theme: e.target.value as ThemeId })}
        className="rounded border border-border bg-inset px-1 py-0.5"
      >
        {themes.map((theme) => (
          <option key={theme.id} value={theme.id}>
            {theme.id}
          </option>
        ))}
      </select>
      <select
        aria-label="Scheme"
        value={appearance.scheme}
        onChange={(e) => setAppearance({ ...appearance, scheme: e.target.value as SchemeChoice })}
        className="rounded border border-border bg-inset px-1 py-0.5"
      >
        <option value="system">system</option>
        <option value="light">light</option>
        <option value="dark">dark</option>
      </select>
    </>
  );
}

function LangAttribute({ locale }: { locale: Locale }) {
  document.documentElement.lang = locale;
  return null;
}

function Screen({
  screen,
  platform,
  status,
  onStatus,
  onSettings,
}: {
  screen: Screen;
  platform: Platform;
  status: Status;
  onStatus: (status: Status) => void;
  onSettings: (screen: Screen) => void;
}) {
  const { t } = useI18n();
  const [filesState, setFilesState] = useState<SessionState>("connecting");
  if (screen === "unlock") return <UnlockScreen onStatus={onStatus} />;
  if (screen === "create") return <CreatePassphraseScreen onStatus={onStatus} />;
  if (screen === "unreadable") return <UnreadableScreen reason="keyMissing" onStatus={onStatus} />;
  const account = screen.startsWith("account");
  const settings = screen === "settings" || account;
  const files = screen === "files" || screen === "interactive";
  const content = (
    <Frame
      platform={platform}
      tabs={[
        { id: "hosts", label: t("frame.hosts") },
        ...(files ? [{ id: "files", label: "api-01", state: filesState, seed: "gallery-api-01" }] : []),
      ]}
      active={files ? "files" : "hosts"}
      onTab={(id) => onSettings(id === "files" ? screen : "hosts")}
      onSettings={() => onSettings(settings ? "hosts" : "settings")}
      settingsActive={settings}
    >
      {settings ? (
        <SettingsView
          section={account ? "personal" : undefined}
          status={status.state === "open" ? status : { state: "open", protection: "keystore" }}
          onStatus={onStatus}
        />
      ) : files ? (
        <SessionTerminal
          profileId={screen === "interactive" ? "gallery-interactive" : "gallery-api-01"}
          label="api-01"
          onClose={() => onSettings("hosts")}
          onStateChange={setFilesState}
        />
      ) : (
        <HostsHome manage />
      )}
    </Frame>
  );
  return account ? <AccountProfilesBoundary>{content}</AccountProfilesBoundary> : content;
}

applyStoredAppearance();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AppearanceProvider>
      <TerminalColorsProvider>
        <Gallery />
      </TerminalColorsProvider>
    </AppearanceProvider>
  </StrictMode>,
);
