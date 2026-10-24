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
import type { Locale, Platform, Status } from "../ipc/bindings";
import { CreatePassphraseScreen, UnlockScreen, UnreadableScreen } from "../local-data";
import { Menus } from "../menus";
import { SettingsView } from "../settings";
import { SessionTerminal, type SessionState } from "../session";
import { TerminalColorsProvider } from "../terminal-colors";
import { sampleHosts, sampleInventory } from "./sample-inventory";

const remotePath = (path: string) => Array.from(new TextEncoder().encode(path));

// The local-data screens call the core; answer them as a core would.
mockIPC((cmd, args) => {
  const payload = (args ?? {}) as {
    passphrase?: string;
    path?: number[];
    messages?: { onmessage: (event: { kind: "starting" | "ready"; transportId: string; automatic?: boolean }) => void };
  };
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
      payload.messages?.onmessage({ kind: "ready", transportId });
    });
    return new Promise(() => undefined);
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
});

const screens = {
  hosts: "Hosts",
  firstRun: "Hosts: first run",
  failed: "Hosts: failed to load",
  settings: "Settings",
  files: "Session: files",
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
            onChange={(e) => setScreen(e.target.value as Screen)}
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
  const settings = screen === "settings";
  const files = screen === "files";
  return (
    <Frame
      platform={platform}
      tabs={[
        { id: "hosts", label: t("frame.hosts") },
        ...(files ? [{ id: "files", label: "api-01", state: filesState, seed: "gallery-api-01" }] : []),
      ]}
      active={files ? "files" : "hosts"}
      onTab={(id) => onSettings(id === "files" ? "files" : "hosts")}
      onSettings={() => onSettings(settings ? "hosts" : "settings")}
      settingsActive={settings}
    >
      {settings ? (
        <SettingsView
          status={status.state === "open" ? status : { state: "open", protection: "keystore" }}
          onStatus={onStatus}
        />
      ) : files ? (
        <SessionTerminal
          profileId="gallery-api-01"
          label="api-01"
          onClose={() => onSettings("hosts")}
          onStateChange={setFilesState}
        />
      ) : (
        <HostsHome manage />
      )}
    </Frame>
  );
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
