// SPDX-License-Identifier: Apache-2.0
import { Button, Field } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import {
  commands as applicationCommands,
  type RegistrationView,
  type PasswordSignInView,
  type RegistrationIntent,
} from "./ipc/bindings";
import { AccountError, useProfile, useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";

export function AccountRegistration() {
  const profile = useProfile();
  const retained = profile?.snapshot.retainedProfile ?? false;
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const [mode, setMode] = useState<"registration" | "signIn">("registration");
  const [pending, setPending] = useState<RegistrationView | PasswordSignInView | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [reload, setReload] = useState(0);
  const mounted = useRef(false);
  const ticket = useRef<string | null>(null);
  const form = useRef<HTMLFormElement>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (ticket.current) void applicationCommands.stopAccountOperation(ticket.current).catch(() => undefined);
    };
  }, []);
  useEffect(() => {
    if (retained) return;
    let active = true;
    void Promise.all([commands.registrationStatus(), commands.passwordSignInStatus()])
      .then(([registration, signIn]) => {
        if (!active) return;
        if (registration.status === "error") setFailed(registration.error);
        else if (signIn.status === "error") setFailed(signIn.error);
        else {
          const resumed = signIn.data ?? registration.data;
          setPending(resumed);
          if (resumed) {
            setMode(signIn.data ? "signIn" : "registration");
            setOpen(true);
          }
        }
        setLoading(false);
      })
      .catch(() => {
        if (active) {
          setFailed("storage");
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, [commands, reload, retained]);

  const run = async (
    operation: (
      id: string,
    ) => Promise<
      { status: "ok"; data: RegistrationView | PasswordSignInView | null } | { status: "error"; error: string }
    >,
  ) => {
    if (ticket.current) return;
    const id = crypto.randomUUID();
    ticket.current = id;
    setBusy(true);
    setFailed(null);
    try {
      const result = await operation(id);
      if (!mounted.current) return;
      if (result.status === "ok") {
        if (result.data) {
          setPending(result.data);
          setOpen(true);
        }
      } else setFailed(result.error);
    } catch {
      if (mounted.current) setFailed("storage");
    } finally {
      ticket.current = null;
      if (mounted.current) {
        setBusy(false);
        setReload((value) => value + 1);
      }
    }
  };
  const prepare = () => {
    const current = form.current;
    if (!current || !current.reportValidity()) return;
    const value = (name: string) => (current.elements.namedItem(name) as HTMLInputElement).value;
    const input = current.elements.namedItem("password") as HTMLInputElement;
    void run((id) => {
      const begin = mode === "signIn" ? commands.beginPasswordSignIn : commands.prepareAccountRegistration;
      const result = begin(id, value("origin"), value("username"), value("deviceName"), input.value);
      input.value = "";
      return result;
    });
  };
  const install = () => {
    if (!profile || !pending) return;
    const input = form.current?.elements.namedItem("passphrase") as HTMLInputElement | null;
    void run(async (id) => {
      const apply =
        mode === "signIn"
          ? applicationCommands.installPasswordSignInProfile
          : applicationCommands.installRegisteredProfile;
      const request = apply(profile.snapshot.generation, id, pending.operationId, input?.value || null);
      if (input) input.value = "";
      const result = await request;
      if (result.status === "ok") {
        profile.accept(result.data);
        return { status: "ok", data: null };
      }
      return result;
    });
  };
  const exchange = (intent: RegistrationIntent) => {
    if (!pending) return;
    const send = mode === "signIn" ? commands.exchangePasswordSignIn : commands.exchangeAccountRegistration;
    void run((id) => send(id, pending.operationId, intent));
  };
  const discard = () => {
    if (!pending) return;
    void run(async () => {
      const cancel = mode === "signIn" ? commands.discardPasswordSignIn : commands.discardRegistrationPreparation;
      const result = await cancel(pending.operationId);
      return result.status === "ok" ? { status: "ok", data: null } : result;
    });
  };
  if (profile?.snapshot.retainedProfile)
    return <p className="mt-4 text-sm text-muted-foreground">{t("accounts.retainedBody")}</p>;
  return (
    <section className="mt-6" aria-labelledby="registration-title" aria-busy={busy || loading}>
      <h3 id="registration-title" className="text-sm font-medium">
        {t("accounts.entryTitle")}
      </h3>
      <p className="mt-2 text-sm text-muted-foreground">{t("accounts.entryBody")}</p>
      {loading ? (
        <p role="status" className="mt-3 text-sm">
          {t("accounts.loading")}
        </p>
      ) : null}
      {failed ? <AccountError code={failed} /> : null}
      {!open && !loading ? (
        <div className="mt-4 flex flex-wrap gap-3">
          <Button
            onClick={() => {
              setMode("registration");
              setOpen(true);
            }}
          >
            {t("accounts.create")}
          </Button>
          <Button
            onClick={() => {
              setMode("signIn");
              setOpen(true);
            }}
          >
            {t("accounts.signIn")}
          </Button>
        </div>
      ) : null}
      {open && !pending && !loading ? (
        <form
          ref={form}
          className="mt-5 grid max-w-lg gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            prepare();
          }}
        >
          <p className="text-sm font-medium">
            {t(mode === "signIn" ? "accounts.signInTitle" : "accounts.createTitle")}
          </p>
          <p className="text-sm text-muted-foreground">
            {t(mode === "signIn" ? "accounts.signInBody" : "accounts.createBody")}
          </p>
          <Field
            name="origin"
            type="url"
            required
            label={t("accounts.origin")}
            placeholder="https://"
            disabled={busy}
            autoComplete="url"
          />
          <Field
            name="username"
            required
            minLength={3}
            maxLength={64}
            label={t("accounts.username")}
            hint={t("accounts.usernameHint")}
            disabled={busy}
            autoComplete="username"
          />
          <Field
            name="deviceName"
            required
            maxLength={128}
            label={t("accounts.deviceName")}
            disabled={busy}
            autoComplete="off"
          />
          <Field
            name="password"
            type="password"
            required
            minLength={15}
            maxLength={256}
            label={t("accounts.password")}
            hint={t("accounts.passwordHint")}
            disabled={busy}
            autoComplete={mode === "signIn" ? "current-password" : "new-password"}
          />
          <div className="flex flex-wrap gap-3">
            <Button
              disabled={busy}
              onClick={() => {
                form.current?.reset();
                setOpen(false);
              }}
            >
              {t("accounts.keep")}
            </Button>
            <Button variant="primary" type="submit" disabled={busy}>
              {t(busy ? "accounts.preparing" : mode === "signIn" ? "accounts.signIn" : "accounts.prepare")}
            </Button>
          </div>
        </form>
      ) : null}
      {open && pending ? (
        <div className="mt-5 max-w-lg">
          <p className="break-all text-sm font-medium">
            {pending.username} · {pending.origin}
          </p>
          <p role="status" className="mt-3 text-sm text-muted-foreground">
            {pending.phase === "recoveryRequired"
              ? t("accounts.phase.recoveryRequired")
              : pending.phase === "signInRequired"
                ? t("accounts.signIn.phase.signInRequired")
                : t(mode === "signIn" ? `accounts.signIn.phase.${pending.phase}` : `accounts.phase.${pending.phase}`)}
          </p>
          {pending.retryNotBeforeMs ? (
            <p className="mt-2 text-sm">
              {t("accounts.retryAt", { time: new Date(Number(pending.retryNotBeforeMs)).toLocaleTimeString(locale) })}
            </p>
          ) : null}
          <div className="mt-4 flex flex-wrap gap-3">
            {pending.phase === "recoveryRequired" ? (
              <>
                <Button
                  disabled={busy}
                  onClick={() => void run((id) => commands.saveRegistrationRecovery(pending.operationId, id))}
                >
                  {t("accounts.saveRecovery")}
                </Button>
                {pending.recoverySaved ? (
                  <Button
                    variant="primary"
                    disabled={busy}
                    onClick={() => void run(() => commands.confirmRegistrationRecovery(pending.operationId))}
                  >
                    {t("accounts.confirmRecovery")}
                  </Button>
                ) : null}
              </>
            ) : null}
            {pending.phase === "ready" ? (
              <Button variant="primary" disabled={busy} onClick={() => exchange("submit")}>
                {t(mode === "signIn" ? "accounts.signIn.submit" : "accounts.submit")}
              </Button>
            ) : null}
            {pending.phase === "outcomeUnknown" ? (
              <Button variant="primary" disabled={busy} onClick={() => exchange("confirm")}>
                {t("accounts.confirmResult")}
              </Button>
            ) : null}
            {pending.phase === "retryAvailable" ? (
              <Button variant="primary" disabled={busy} onClick={() => exchange("retry")}>
                {t(mode === "signIn" ? "accounts.signIn.retry" : "accounts.retry")}
              </Button>
            ) : null}
            {pending.phase === "recoveryRequired" ||
            pending.phase === "ready" ||
            (mode === "signIn" && (pending.phase === "retryAvailable" || pending.phase === "signInRequired")) ? (
              <Button disabled={busy} onClick={discard}>
                {t(mode === "signIn" ? "accounts.signIn.discard" : "accounts.discard")}
              </Button>
            ) : null}
          </div>
          {pending.phase === "committed" ? (
            <form
              ref={form}
              className="mt-4 grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                install();
              }}
            >
              <Field
                name="passphrase"
                type="password"
                autoComplete="off"
                label={t("accounts.passphrase")}
                hint={t("accounts.installPassphraseHint")}
                disabled={busy}
              />
              <Button variant="primary" type="submit" disabled={busy}>
                {t(busy ? "accounts.installing" : "accounts.install")}
              </Button>
            </form>
          ) : null}
        </div>
      ) : null}
      {busy ? (
        <div className="mt-4 flex items-center gap-3">
          <p role="status" className="text-sm">
            {t("accounts.working")}
          </p>
          <Button
            onClick={() => {
              if (ticket.current) void applicationCommands.stopAccountOperation(ticket.current).catch(() => undefined);
            }}
          >
            {t("accounts.stop")}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
