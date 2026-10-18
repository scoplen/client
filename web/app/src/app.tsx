// SPDX-License-Identifier: Apache-2.0
import { AppearanceProvider, Button, SkipLink } from "@scoplen/ui";
import { useCallback, useEffect, useState } from "react";
import { I18nProvider, useI18n } from "./i18n";
import { commands, type AppInfo, type Locale, type Status } from "./ipc/bindings";
import { CreatePassphraseScreen, UnlockScreen, UnreadableScreen } from "./local-data";
import { Shell } from "./shell";
import { TerminalColorsProvider } from "./terminal-colors";

type Startup =
  { state: "loading" } | { state: "ready"; info: AppInfo; status: Status } | { state: "failed"; reference: string };

/**
 * The language used only if the core cannot be reached, when its choice
 * (`Locale::negotiate` in scoplen-client-core) is unavailable: the webview's
 * own preference, with Traditional Chinese falling back to English.
 */
function initialLocale(): Locale {
  const tag = navigator.language.toLowerCase();
  return tag.startsWith("zh") && !/hant|tw|hk|mo/.test(tag) ? "zh-Hans" : "en";
}

export function App() {
  const [startup, setStartup] = useState<Startup>({ state: "loading" });

  // Asks the core; state changes only when it answers.
  const request = useCallback(() => {
    Promise.all([commands.appInfo(), commands.localDataStatus()]).then(
      ([info, status]) =>
        status.status === "ok"
          ? setStartup({ state: "ready", info, status: status.data })
          : setStartup({
              state: "failed",
              reference: status.error.kind === "failed" ? status.error.reference : status.error.kind,
            }),
      (error: unknown) => setStartup({ state: "failed", reference: String(error) }),
    );
  }, []);

  useEffect(request, [request]);

  const retry = () => {
    setStartup({ state: "loading" });
    request();
  };

  const locale = startup.state === "ready" ? startup.info.locale : initialLocale();
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    if (startup.state !== "loading") void commands.shellReady();
  }, [startup.state]);

  const setStatus = (status: Status) =>
    setStartup((current) => (current.state === "ready" ? { ...current, status } : current));

  return (
    <AppearanceProvider>
      <TerminalColorsProvider>
        <I18nProvider locale={locale}>
          <SkipTarget />
          {startup.state === "loading" ? <StartupLoading /> : null}
          {startup.state === "ready" ? <Gate info={startup.info} status={startup.status} onStatus={setStatus} /> : null}
          {startup.state === "failed" ? <StartupError reference={startup.reference} onRetry={retry} /> : null}
        </I18nProvider>
      </TerminalColorsProvider>
    </AppearanceProvider>
  );
}

function SkipTarget() {
  const { t } = useI18n();
  return <SkipLink target="main">{t("shell.skip")}</SkipLink>;
}

function StartupLoading() {
  const { t } = useI18n();
  return (
    <main id="main" className="mx-auto max-w-xl px-6 py-16" aria-busy="true" aria-live="polite">
      <h1 className="ui-display text-xl">{t("startup.loading.title")}</h1>
      <p className="mt-3 text-sm text-muted-foreground">{t("startup.loading.body")}</p>
    </main>
  );
}

/** Shows the screen the state of the local data calls for. */
function Gate({ info, status, onStatus }: { info: AppInfo; status: Status; onStatus: (status: Status) => void }) {
  switch (status.state) {
    case "open":
      return <Shell info={info} status={status} onStatus={onStatus} />;
    case "needsPassphrase":
      return <UnlockScreen onStatus={onStatus} />;
    case "needsNewPassphrase":
      return <CreatePassphraseScreen onStatus={onStatus} />;
    case "unreadable":
      return <UnreadableScreen reason={status.reason} onStatus={onStatus} />;
  }
}

function StartupError({ reference, onRetry }: { reference: string; onRetry: () => void }) {
  const { t } = useI18n();
  return (
    <main id="main" className="mx-auto max-w-xl px-6 py-16">
      <div role="alert">
        <h1 className="ui-display text-xl">{t("startup.error.title")}</h1>
        <p className="mt-3 text-sm">{t("startup.error.body")}</p>
        <p className="mt-3 font-mono text-xs text-muted-foreground select-all">
          {t("startup.error.reference", { reference })}
        </p>
      </div>
      <Button variant="primary" className="mt-6" onClick={onRetry}>
        {t("startup.error.retry")}
      </Button>
    </main>
  );
}
