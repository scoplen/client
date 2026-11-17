// SPDX-License-Identifier: Apache-2.0
import { Button, Field } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import { commands as applicationCommands, type PasswordChangeView, type RegistrationIntent } from "./ipc/bindings";

const errors = [
  "busy",
  "profileChanged",
  "invalidInput",
  "samePassword",
  "verification",
  "storage",
  "notPrepared",
  "outcomeUnknown",
  "signInRequired",
  "explicitRetryRequired",
  "retryDeferred",
  "cancelled",
  "network",
  "unsupportedService",
  "authenticationDenied",
  "policyDenied",
  "serviceUnavailable",
] as const;

export function PasswordChangeSettings({
  disabled,
  onBusyChange,
}: {
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const [pending, setPending] = useState<PasswordChangeView | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [reload, setReload] = useState(0);
  const form = useRef<HTMLFormElement>(null);
  const ticket = useRef<string | null>(null);
  const epoch = useRef(0);

  useEffect(() => {
    const activeEpoch = ++epoch.current;
    return () => {
      epoch.current = activeEpoch + 1;
      if (ticket.current) {
        void applicationCommands.stopAccountOperation(ticket.current).catch(() => undefined);
        ticket.current = null;
        onBusyChange(false);
      }
    };
  }, [commands, onBusyChange]);

  useEffect(() => {
    let active = true;
    void commands.passwordChangeStatus().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") {
          setPending(result.data);
          setLoaded(true);
        } else setFailed(result.error);
        setLoading(false);
      },
      () => {
        if (active) {
          setFailed("storage");
          setLoading(false);
        }
      },
    );
    return () => {
      active = false;
    };
  }, [commands, reload]);

  const run = async (
    operation: (
      id: string,
    ) => Promise<{ status: "ok"; data: PasswordChangeView | null } | { status: "error"; error: string }>,
  ) => {
    if (ticket.current || disabled || loading || !loaded) return;
    const id = crypto.randomUUID();
    const started = epoch.current;
    ticket.current = id;
    setBusy(true);
    setFailed(null);
    onBusyChange(true);
    try {
      const result = await operation(id);
      if (started !== epoch.current) return;
      if (result.status === "ok") setPending(result.data);
      else setFailed(result.error);
      const saved = await commands.passwordChangeStatus();
      if (started !== epoch.current) return;
      if (saved.status === "ok") setPending(saved.data);
      else {
        setFailed(saved.error);
        setLoaded(false);
      }
    } catch {
      if (started === epoch.current) {
        setFailed("storage");
        setLoaded(false);
      }
    } finally {
      if (ticket.current === id) ticket.current = null;
      if (started === epoch.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  };
  const prepare = () => {
    const current = form.current;
    if (!current || !current.reportValidity()) return;
    const oldPassword = current.elements.namedItem("oldPassword") as HTMLInputElement;
    const newPassword = current.elements.namedItem("newPassword") as HTMLInputElement;
    void run((id) => {
      try {
        return commands.beginPasswordChange(id, oldPassword.value, newPassword.value);
      } finally {
        oldPassword.value = "";
        newPassword.value = "";
      }
    });
  };
  const exchange = (intent: RegistrationIntent) => {
    if (pending) void run((id) => commands.exchangePasswordChange(id, pending.operationId, intent));
  };
  const discard = () => {
    if (pending)
      void run(async () => {
        const result = await commands.discardPasswordChange(pending.operationId);
        return result.status === "ok" ? { status: "ok", data: null } : result;
      });
  };
  const unavailable = disabled || busy || loading || !loaded;
  const error = errors.find((code) => code === failed) ?? "verification";

  return (
    <section
      aria-labelledby="password-change-title"
      aria-busy={busy || loading}
      className="mt-6 border-t border-border pt-6"
    >
      <h3 id="password-change-title" className="text-sm font-medium">
        {t("passwordChange.title")}
      </h3>
      <p id="password-change-consequences" className="mt-2 text-sm text-muted-foreground">
        {t("passwordChange.consequences")}
      </p>
      {loading ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {t("passwordChange.loading")}
        </p>
      ) : null}
      {pending ? (
        <>
          <p role="status" className="mt-4 text-sm text-muted-foreground">
            {t(`passwordChange.phase.${pending.phase}`)}
          </p>
          <p className="mt-2 break-all select-text font-mono text-xs text-muted-foreground">
            {t("passwordChange.operation", { id: pending.operationId })}
          </p>
          {pending.retryNotBeforeMs ? (
            <p className="mt-2 text-sm text-muted-foreground">
              {t("passwordChange.retryAfter", {
                time: new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "medium" }).format(
                  Number(pending.retryNotBeforeMs),
                ),
              })}
            </p>
          ) : null}
          <div className="mt-4 flex flex-wrap gap-2">
            {pending.phase === "ready" ? (
              <Button
                disabled={unavailable}
                onClick={() => exchange("submit")}
                aria-describedby="password-change-consequences"
              >
                {t("passwordChange.submit")}
              </Button>
            ) : null}
            {pending.phase === "outcomeUnknown" ? (
              <Button disabled={unavailable} onClick={() => exchange("confirm")}>
                {t("passwordChange.confirm")}
              </Button>
            ) : null}
            {pending.phase === "retryAvailable" ? (
              <Button disabled={unavailable} onClick={() => exchange("retry")}>
                {t("passwordChange.retry")}
              </Button>
            ) : null}
            {pending.phase !== "outcomeUnknown" ? (
              <Button variant="secondary" disabled={unavailable} onClick={discard}>
                {t(pending.phase === "committed" ? "passwordChange.acknowledge" : "passwordChange.discard")}
              </Button>
            ) : null}
          </div>
        </>
      ) : loaded && !loading ? (
        <form
          ref={form}
          className="mt-4 grid max-w-md gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            prepare();
          }}
        >
          <Field
            name="oldPassword"
            type="password"
            autoComplete="current-password"
            required
            disabled={unavailable}
            label={t("passwordChange.oldPassword")}
          />
          <Field
            name="newPassword"
            type="password"
            autoComplete="new-password"
            required
            disabled={unavailable}
            label={t("passwordChange.newPassword")}
            hint={t("passwordChange.passwordHint")}
          />
          <div>
            <Button type="submit" disabled={unavailable}>
              {t(busy ? "passwordChange.working" : "passwordChange.prepare")}
            </Button>
          </div>
        </form>
      ) : null}
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(`passwordChange.error.${error}`)}
        </p>
      ) : null}
      {!loaded && !loading ? (
        <Button
          variant="secondary"
          className="mt-4"
          disabled={disabled || busy}
          onClick={() => {
            setLoading(true);
            setFailed(null);
            setReload((value) => value + 1);
          }}
        >
          {t("passwordChange.reload")}
        </Button>
      ) : null}
    </section>
  );
}
