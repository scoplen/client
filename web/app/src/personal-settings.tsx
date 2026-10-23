// SPDX-License-Identifier: Apache-2.0
import { Button, Field } from "@scoplen/ui";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useI18n } from "./i18n";
import { commands, type PersonalServerError, type PersonalServerStatus } from "./ipc/bindings";
import { PersonalSyncSettings } from "./personal-sync-settings";
import { PersonalAccountSettings } from "./personal-account-settings";
import { PersonalPairingSettings } from "./personal-pairing-settings";

type Outcome = { status: "ok"; data: PersonalServerStatus } | { status: "error"; error: PersonalServerError };

export function PersonalSettings() {
  const { t } = useI18n();
  const [status, setStatus] = useState<PersonalServerStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<PersonalServerError | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [replacementOpen, setReplacementOpen] = useState(false);
  const invitation = useRef<HTMLInputElement>(null);
  const replacement = useRef<HTMLInputElement>(null);
  const device = useRef<HTMLInputElement>(null);
  const pending = useRef(false);
  const title = useRef<HTMLHeadingElement>(null);
  const stepTitle = useRef<HTMLHeadingElement>(null);
  const focusNextStep = useRef(false);

  useEffect(() => {
    let active = true;
    void commands.personalServerStatus().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") setStatus(result.data);
        else setFailed(result.error);
      },
      () => {
        if (active) setFailed("storage");
      },
    );
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!focusNextStep.current) return;
    focusNextStep.current = false;
    (stepTitle.current ?? title.current)?.focus();
  }, [status?.phase]);

  useEffect(() => {
    if (!replacementOpen || status?.phase !== "enrollment_unconfirmed") return;
    const input = replacement.current;
    input?.focus();
    return () => {
      if (input) input.value = "";
    };
  }, [replacementOpen, status?.phase]);

  const updateStatus = (next: PersonalServerStatus) => {
    if (status && next.phase !== status.phase) focusNextStep.current = true;
    if (next.phase !== "enrollment_unconfirmed") setReplacementOpen(false);
    setStatus(next);
  };

  const run = async (operation: () => Promise<Outcome>) => {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setFailed(null);
    try {
      const result = await operation();
      if (result.status === "ok") updateStatus(result.data);
      else {
        setFailed(result.error);
        const latest = await commands.personalServerStatus();
        if (latest.status === "ok") updateStatus(latest.data);
      }
    } catch {
      setFailed("storage");
      try {
        const latest = await commands.personalServerStatus();
        if (latest.status === "ok") updateStatus(latest.data);
      } catch {
        /* Keep the last known phase until the core can be reached. */
      }
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };

  const prepare = (event: FormEvent) => {
    event.preventDefault();
    if (pending.current || !invitation.current || !device.current) return;
    const url = invitation.current.value;
    const deviceName = device.current.value;
    invitation.current.value = "";
    void run(() => commands.preparePersonalEnrollment(url, deviceName));
  };

  const replaceInvitation = (event: FormEvent) => {
    event.preventDefault();
    if (pending.current || !replacement.current) return;
    const url = replacement.current.value;
    replacement.current.value = "";
    void run(() => commands.updatePersonalInvitation(url));
  };

  const onChildBusyChange = (next: boolean) => {
    setBusy(next);
    if (!next)
      void commands
        .personalServerStatus()
        .then((latest) => {
          if (latest.status === "ok") updateStatus(latest.data);
        })
        .catch(() => {
          /* Preserve the visible phase until the encrypted store is available. */
        });
  };

  return (
    <section aria-labelledby="personal-title" className="mt-8 max-w-lg" aria-busy={busy}>
      <h2 ref={title} id="personal-title" tabIndex={-1} className="ui-display text-lg">
        {t("settings.personal.title")}
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">{t("settings.personal.body")}</p>
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(`settings.personal.error.${failed}`)}
        </p>
      ) : null}
      {!status ? (
        failed ? (
          <Button className="mt-4" disabled={busy} onClick={() => void run(commands.personalServerStatus)}>
            {t("settings.personal.reload")}
          </Button>
        ) : (
          <p role="status" className="mt-4 text-sm text-muted-foreground">
            {t("settings.personal.loading")}
          </p>
        )
      ) : status.phase === "not_configured" ? (
        <form onSubmit={prepare} className="mt-6 flex flex-col gap-4">
          <Field
            ref={invitation}
            label={t("settings.personal.invitation")}
            hint={t("settings.personal.invitationHint")}
            type="password"
            required
            autoComplete="off"
            spellCheck={false}
            autoCapitalize="none"
            maxLength={4096}
            disabled={busy}
          />
          <Field
            ref={device}
            label={t("settings.personal.deviceName")}
            required
            maxLength={128}
            autoComplete="off"
            disabled={busy}
          />
          <div>
            <Button type="submit" disabled={busy}>
              {t(busy ? "settings.personal.working" : "settings.personal.prepare")}
            </Button>
          </div>
        </form>
      ) : (
        <div className="mt-6">
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t("settings.personal.server")}</dt>
            <dd className="m-0 break-all font-medium">{status.origin}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.deviceName")}</dt>
            <dd className="m-0 break-words">{status.deviceName}</dd>
          </dl>
          {status.phase === "recovery_required" ? (
            <div className="mt-6">
              <h3 ref={stepTitle} tabIndex={-1} className="text-sm font-medium">
                {t("settings.personal.recoveryTitle")}
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.recoveryBody")}</p>
              <Button
                className="mt-4"
                disabled={busy}
                variant={status.recoveryKeySaved ? "secondary" : "primary"}
                onClick={() => void run(commands.savePersonalRecoveryKey)}
              >
                {t(status.recoveryKeySaved ? "settings.personal.saveAgain" : "settings.personal.saveRecovery")}
              </Button>
              {status.recoveryKeySaved ? (
                <div className="mt-4">
                  <label className="flex items-start gap-2 text-sm">
                    <input
                      type="checkbox"
                      className="mt-1 accent-primary"
                      checked={confirmed}
                      disabled={busy}
                      onChange={(event) => setConfirmed(event.target.checked)}
                    />
                    <span>{t("settings.personal.recoveryConfirm")}</span>
                  </label>
                  <Button
                    className="mt-4"
                    disabled={busy || !confirmed}
                    onClick={() => void run(commands.confirmPersonalRecoveryKey)}
                  >
                    {t("settings.personal.continue")}
                  </Button>
                </div>
              ) : null}
            </div>
          ) : status.phase === "ready_to_enroll" ? (
            <div className="mt-6">
              <h3 ref={stepTitle} tabIndex={-1} className="text-sm font-medium">
                {t("settings.personal.join")}
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.readyBody")}</p>
              <Button className="mt-4" disabled={busy} onClick={() => void run(commands.submitPersonalEnrollment)}>
                {t(busy ? "settings.personal.working" : "settings.personal.join")}
              </Button>
            </div>
          ) : status.phase === "enrollment_unconfirmed" ? (
            <div className="mt-6">
              <h3 ref={stepTitle} tabIndex={-1} className="text-sm font-medium">
                {t("settings.personal.authenticate")}
              </h3>
              <p role="status" className="mt-2 text-sm text-muted-foreground">
                {t("settings.personal.unconfirmedBody")}
              </p>
              <Button className="mt-4" disabled={busy} onClick={() => void run(commands.authenticatePersonalServer)}>
                {t(busy ? "settings.personal.working" : "settings.personal.authenticate")}
              </Button>
              <div className="mt-4">
                <Button
                  variant="secondary"
                  disabled={busy}
                  aria-expanded={replacementOpen}
                  aria-controls={replacementOpen ? "personal-replacement" : undefined}
                  onClick={() => setReplacementOpen(!replacementOpen)}
                >
                  {t(replacementOpen ? "settings.personal.cancelReplacement" : "settings.personal.replaceInvitation")}
                </Button>
              </div>
              {replacementOpen ? (
                <form id="personal-replacement" onSubmit={replaceInvitation} className="mt-4 flex flex-col gap-4">
                  <p className="text-sm text-muted-foreground">{t("settings.personal.replacementBody")}</p>
                  <Field
                    ref={replacement}
                    label={t("settings.personal.newInvitation")}
                    hint={t("settings.personal.newInvitationHint")}
                    type="password"
                    required
                    autoComplete="off"
                    spellCheck={false}
                    autoCapitalize="none"
                    maxLength={4096}
                    disabled={busy}
                  />
                  <div>
                    <Button type="submit" disabled={busy}>
                      {t(busy ? "settings.personal.working" : "settings.personal.checkInvitation")}
                    </Button>
                  </div>
                </form>
              ) : null}
            </div>
          ) : status.phase === "authentication_required" ? (
            <div className="mt-6">
              <h3 ref={stepTitle} tabIndex={-1} className="text-sm font-medium">
                {t("settings.personal.authenticate")}
              </h3>
              <p role="status" className="mt-2 text-sm text-muted-foreground">
                {t("settings.personal.authenticationRequiredBody")}
              </p>
              <Button className="mt-4" disabled={busy} onClick={() => void run(commands.authenticatePersonalServer)}>
                {t(busy ? "settings.personal.working" : "settings.personal.authenticate")}
              </Button>
            </div>
          ) : (
            <div className="mt-6">
              <h3 ref={stepTitle} tabIndex={-1} className="text-sm font-medium">
                {t("settings.personal.authenticated")}
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.authenticatedBody")}</p>
              <Button
                className="mt-4"
                variant="secondary"
                disabled={busy}
                onClick={() => void run(commands.authenticatePersonalServer)}
              >
                {t(busy ? "settings.personal.working" : "settings.personal.authenticate")}
              </Button>
            </div>
          )}
          {status.phase === "authenticated" ||
          status.phase === "enrollment_unconfirmed" ||
          status.phase === "authentication_required" ? (
            <>
              <PersonalAccountSettings
                authenticated={status.phase === "authenticated"}
                disabled={busy}
                onBusyChange={onChildBusyChange}
              />
              <PersonalSyncSettings
                authenticated={status.phase === "authenticated"}
                disabled={busy}
                onBusyChange={onChildBusyChange}
              />
            </>
          ) : null}
        </div>
      )}
      {status ? (
        <PersonalPairingSettings
          configured={status.phase !== "not_configured"}
          authenticated={status.phase === "authenticated"}
          disabled={busy}
          onBusyChange={onChildBusyChange}
        />
      ) : null}
    </section>
  );
}
