// SPDX-License-Identifier: Apache-2.0
import { Button } from "@scoplen/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type PersonalServerError, type PersonalServerStatus } from "./ipc/bindings";
import { PersonalSyncSettings } from "./personal-sync-settings";
import { PersonalAccountSettings } from "./personal-account-settings";

export function PersonalSettings() {
  const { t } = useI18n();
  const [status, setStatus] = useState<PersonalServerStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<PersonalServerError | null>(null);
  const mounted = useRef(false);
  const pending = useRef(false);
  const statusRequest = useRef(0);

  const reload = useCallback(async () => {
    const request = ++statusRequest.current;
    try {
      const result = await commands.personalServerStatus();
      if (!mounted.current || request !== statusRequest.current) return;
      if (result.status === "ok") setStatus(result.data);
      else setFailed(result.error);
    } catch {
      if (mounted.current && request === statusRequest.current) setFailed("storage");
    }
  }, []);

  useEffect(() => {
    let active = true;
    mounted.current = true;
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
      mounted.current = false;
    };
  }, []);

  const authenticate = async () => {
    if (pending.current) return;
    pending.current = true;
    ++statusRequest.current;
    setBusy(true);
    setFailed(null);
    try {
      const result = await (status?.phase === "revalidation_required"
        ? commands.revalidateRetainedDevice()
        : commands.authenticatePersonalServer());
      if (!mounted.current) return;
      if (result.status === "ok") setStatus(result.data);
      else setFailed(result.error);
      await reload();
    } catch {
      if (mounted.current) setFailed("storage");
    } finally {
      pending.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  const childBusy = useCallback(
    (value: boolean) => {
      pending.current = value;
      if (!mounted.current) return;
      setBusy(value);
      if (!value) void reload();
    },
    [reload],
  );

  const revalidation = status?.phase === "revalidation_required";
  const configured = revalidation || status?.phase === "authenticated" || status?.phase === "authentication_required";
  const authenticated = status?.phase === "authenticated";
  const context = `${status?.origin ?? ""}/${status?.accountId ?? ""}/${status?.deviceId ?? ""}`;

  return (
    <section aria-labelledby="personal-title" aria-busy={busy}>
      <h2 id="personal-title" className="text-base font-medium">
        {t("settings.personal.title")}
      </h2>
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(`settings.personal.error.${failed}`)}
        </p>
      ) : null}
      {failed ? (
        <Button
          className="mt-4"
          variant="secondary"
          disabled={busy}
          onClick={() => {
            setFailed(null);
            void reload();
          }}
        >
          {t("settings.personal.reload")}
        </Button>
      ) : null}
      {!status && !failed ? (
        <p role="status" className="mt-2 text-sm text-muted-foreground">
          {t("settings.personal.loading")}
        </p>
      ) : null}
      {status?.phase === "not_configured" ? (
        <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.signInUnavailable")}</p>
      ) : status?.phase === "retired_entry" ? (
        <p role="status" className="mt-2 text-sm text-muted-foreground">
          {t("settings.personal.error.retiredEntry")}
        </p>
      ) : null}
      {configured && status ? (
        <div key={context}>
          <dl className="mt-4 grid gap-3 text-sm">
            <div>
              <dt className="text-muted-foreground">{t("settings.personal.server")}</dt>
              <dd className="break-all">{status.origin}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("settings.personal.account.id")}</dt>
              <dd className="break-all">{status.accountId}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">{t("settings.personal.deviceName")}</dt>
              <dd className="break-words">{status.deviceName}</dd>
            </div>
          </dl>
          <p role="status" className="mt-4 text-sm text-muted-foreground">
            {t(
              revalidation
                ? "settings.personal.revalidationBody"
                : authenticated
                  ? "settings.personal.authenticatedBody"
                  : "settings.personal.authenticationRequiredBody",
            )}
          </p>
          <Button className="mt-4" disabled={busy} onClick={() => void authenticate()}>
            {t(
              busy
                ? "settings.personal.working"
                : revalidation
                  ? "settings.personal.revalidate"
                  : "settings.personal.authenticate",
            )}
          </Button>
          {!revalidation ? (
            <>
              <PersonalAccountSettings authenticated={authenticated} disabled={busy} onBusyChange={childBusy} />
              <PersonalSyncSettings authenticated={authenticated} disabled={busy} onBusyChange={childBusy} />
            </>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
