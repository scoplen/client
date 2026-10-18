// SPDX-License-Identifier: Apache-2.0
import { Button, Field, Mark, type MarkMood } from "@scoplen/ui";
import { useState, type FormEvent } from "react";
import { useI18n } from "./i18n";
import { commands, type LocalDataError, type Status, type UnreadableReason } from "./ipc/bindings";

type Outcome = { status: "ok"; data: Status } | { status: "error"; error: LocalDataError };

/** The outcome of a command as an error message for the user, or null. */
function useErrorText() {
  const { t } = useI18n();
  return (error: LocalDataError): string =>
    error.kind === "wrongPassphrase"
      ? t("unlock.wrong")
      : error.kind === "emptyPassphrase"
        ? t("passphrase.empty")
        : `${t("failed.body")} ${t("startup.error.reference", { reference: error.kind === "failed" ? error.reference : error.kind })}`;
}

/** Runs a command while showing it as busy, then reports the outcome. */
function useCommand(onStatus: (status: Status) => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<LocalDataError | null>(null);
  const run = async (command: () => Promise<Outcome>) => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await command();
      if (outcome.status === "ok") onStatus(outcome.data);
      else setError(outcome.error);
    } catch (thrown) {
      setError({ kind: "failed", reference: String(thrown) });
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

/**
 * A screen before the store is open: one card in the middle of the window,
 * the mark above it. The mark sleeps while the data is locked, is awake for
 * a new start, and looks worried when the data cannot be read; it shakes its
 * head when something is refused.
 */
function Screen({
  title,
  children,
  mood = "rest",
  attention,
  shake,
}: {
  title: string;
  children: React.ReactNode;
  mood?: MarkMood;
  attention?: boolean;
  shake?: unknown;
}) {
  return (
    <main id="main" className="grid h-screen place-items-center overflow-y-auto bg-background px-6 py-12">
      <div className="scoplen-rise flex w-full max-w-md flex-col items-center">
        <Mark
          size="4rem"
          mood={mood}
          gesture={{ name: "shake", at: shake }}
          className={`mb-6 ${attention ? "text-attention" : "text-primary"}`}
        />
        <div className="ui-surface w-full p-7 shadow-(--scoplen-shadow-popover)">
          <h1 className="ui-display text-2xl">{title}</h1>
          {children}
        </div>
      </div>
    </main>
  );
}

/** Asks for the local passphrase before the store can be opened. */
export function UnlockScreen({ onStatus }: { onStatus: (status: Status) => void }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [passphrase, setPassphrase] = useState("");
  const { busy, error, setError, run } = useCommand(onStatus);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (passphrase === "") return setError({ kind: "emptyPassphrase" });
    void run(() => commands.unlockLocalData(passphrase));
  };

  return (
    <Screen title={t("unlock.title")} mood="closed" shake={error}>
      <p className="mt-3 text-sm text-muted-foreground">{t("unlock.body")}</p>
      <form className="mt-8 flex flex-col gap-6" onSubmit={submit} noValidate>
        <Field
          label={t("unlock.field")}
          type="password"
          autoComplete="current-password"
          autoFocus
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          error={error ? errorText(error) : undefined}
        />
        <Button type="submit" variant="primary" busy={busy} className="w-full">
          {t("unlock.submit")}
        </Button>
      </form>
    </Screen>
  );
}

/** A new passphrase entered twice; `onSubmit` receives it once both match. */
function NewPassphrase({
  labels,
  warning,
  submitLabel,
  busy,
  serverError,
  onSubmit,
  onCancel,
}: {
  labels: [string, string];
  warning: string;
  submitLabel: string;
  busy: boolean;
  serverError?: string;
  onSubmit: (passphrase: string) => void;
  onCancel?: () => void;
}) {
  const { t } = useI18n();
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [problem, setProblem] = useState<"empty" | "mismatch" | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (first === "") return setProblem("empty");
    if (first !== second) return setProblem("mismatch");
    setProblem(null);
    onSubmit(first);
  };

  return (
    <form className="flex flex-col gap-5" onSubmit={submit} noValidate>
      <Field
        label={labels[0]}
        type="password"
        autoComplete="new-password"
        autoFocus
        value={first}
        onChange={(e) => setFirst(e.target.value)}
        error={problem === "empty" ? t("passphrase.empty") : (serverError ?? undefined)}
        hint={warning}
      />
      <Field
        label={labels[1]}
        type="password"
        autoComplete="new-password"
        value={second}
        onChange={(e) => setSecond(e.target.value)}
        error={problem === "mismatch" ? t("passphrase.mismatch") : undefined}
      />
      <div className="flex gap-3">
        <Button type="submit" variant="primary" busy={busy}>
          {submitLabel}
        </Button>
        {onCancel ? (
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            {t("settings.passphrase.cancel")}
          </Button>
        ) : null}
      </div>
    </form>
  );
}

/** First launch on a system without a keystore. */
export function CreatePassphraseScreen({ onStatus }: { onStatus: (status: Status) => void }) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const { busy, error, run } = useCommand(onStatus);
  return (
    <Screen title={t("create.title")} mood="awake">
      <p className="mt-3 mb-8 text-sm text-muted-foreground">{t("create.body")}</p>
      <NewPassphrase
        labels={[t("create.field"), t("create.confirm")]}
        warning={t("create.warning")}
        submitLabel={t("create.submit")}
        busy={busy}
        serverError={error ? errorText(error) : undefined}
        onSubmit={(passphrase) => void run(() => commands.createLocalPassphrase(passphrase))}
      />
    </Screen>
  );
}

/** The store exists but cannot be opened on this device. */
export function UnreadableScreen({
  reason,
  onStatus,
}: {
  reason: UnreadableReason;
  onStatus: (status: Status) => void;
}) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const { busy, error, run } = useCommand(onStatus);
  const [confirming, setConfirming] = useState(false);
  const canStartFresh = reason !== "newerVersion";

  return (
    <Screen title={t("unreadable.title")} mood="low" attention shake={error}>
      <p className="mt-3 text-sm">{t(`unreadable.${reason}`)}</p>
      {canStartFresh ? <p className="mt-3 text-sm text-muted-foreground">{t("unreadable.startFresh")}</p> : null}
      {error ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {errorText(error)}
        </p>
      ) : null}
      {canStartFresh && !confirming ? (
        <Button className="mt-8" onClick={() => setConfirming(true)}>
          {t("unreadable.start")}
        </Button>
      ) : null}
      {confirming ? (
        <div
          role="group"
          aria-labelledby="start-fresh-confirm"
          className="mt-8 rounded-md border-(length:--scoplen-border-width) border-attention bg-[color-mix(in_srgb,var(--attention)_6%,transparent)] p-4"
        >
          <p id="start-fresh-confirm" className="text-sm">
            {t("unreadable.confirm")}
          </p>
          <div className="mt-4 flex gap-3">
            <Button
              variant="destructive"
              busy={busy}
              onClick={() => void run(() => commands.startWithEmptyLocalData())}
            >
              {t("unreadable.start")}
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => setConfirming(false)} autoFocus>
              {t("unreadable.cancel")}
            </Button>
          </div>
        </div>
      ) : null}
    </Screen>
  );
}

/** Settings: how the local data is protected, and the passphrase. */
export function PassphraseSettings({
  status,
  onStatus,
}: {
  status: Status & { state: "open" };
  onStatus: (status: Status) => void;
}) {
  const { t } = useI18n();
  const errorText = useErrorText();
  const [editing, setEditing] = useState(false);
  const [notice, setNotice] = useState("");
  const { busy, error, run } = useCommand((next) => {
    setEditing(false);
    onStatus(next);
  });
  const hasPassphrase = status.protection !== "keystore";

  return (
    <section aria-labelledby="passphrase-title" className="mt-10">
      <h2 id="passphrase-title" className="ui-display text-lg">
        {t("settings.passphrase.title")}
      </h2>
      <p className="mt-2 text-sm text-muted-foreground">{t(`settings.passphrase.${status.protection}`)}</p>
      <p role="status" className="mt-2 text-sm text-primary">
        {notice}
      </p>
      {editing ? (
        <div className="mt-4">
          <NewPassphrase
            labels={[t("settings.passphrase.new"), t("settings.passphrase.repeat")]}
            warning={t("settings.passphrase.warning")}
            submitLabel={t("settings.passphrase.save")}
            busy={busy}
            serverError={error ? errorText(error) : undefined}
            onSubmit={(passphrase) =>
              void run(async () => {
                const outcome = await commands.setLocalPassphrase(passphrase);
                if (outcome.status === "ok") setNotice(t("settings.passphrase.saved"));
                return outcome;
              })
            }
            onCancel={() => setEditing(false)}
          />
        </div>
      ) : (
        <div className="mt-4 flex gap-3">
          <Button onClick={() => (setNotice(""), setEditing(true))}>
            {hasPassphrase ? t("settings.passphrase.change") : t("settings.passphrase.set")}
          </Button>
          {status.protection === "keystoreAndPassphrase" ? (
            <Button
              variant="ghost"
              busy={busy}
              onClick={() =>
                void run(async () => {
                  const outcome = await commands.removeLocalPassphrase();
                  if (outcome.status === "ok") setNotice(t("settings.passphrase.removed"));
                  return outcome;
                })
              }
            >
              {t("settings.passphrase.remove")}
            </Button>
          ) : null}
        </div>
      )}
      {error && !editing ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {errorText(error)}
        </p>
      ) : null}
    </section>
  );
}
