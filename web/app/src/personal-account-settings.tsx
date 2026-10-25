// SPDX-License-Identifier: Apache-2.0
import { useProfileCommands } from "./account-profiles";
import { Button } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { type PersonalAccountSnapshot, type PersonalServerError } from "./ipc/bindings";

export function PersonalAccountSettings({
  authenticated,
  disabled,
  onBusyChange,
}: {
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const [snapshot, setSnapshot] = useState<PersonalAccountSnapshot | null>(null);
  const [failed, setFailed] = useState<PersonalServerError | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);

  useEffect(() => {
    let active = true;
    void commands.personalAccountSnapshot().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") setSnapshot(result.data);
        else setFailed(result.error);
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
  }, [commands]);

  const query = async () => {
    if (pending.current || disabled || !authenticated || loading) return;
    pending.current = true;
    setBusy(true);
    setFailed(null);
    onBusyChange(true);
    try {
      const result = await commands.queryPersonalAccount();
      if (result.status === "ok") setSnapshot(result.data);
      else setFailed(result.error);
    } catch {
      setFailed("storage");
    } finally {
      pending.current = false;
      setBusy(false);
      onBusyChange(false);
    }
  };

  return (
    <section aria-labelledby="personal-account-title" className="mt-6 border-t border-border pt-6" aria-busy={busy}>
      <h3 id="personal-account-title" className="text-sm font-medium">
        {t("settings.personal.account.title")}
      </h3>
      <p role="status" className="mt-2 text-sm text-muted-foreground">
        {t(
          busy
            ? "settings.personal.account.querying"
            : loading
              ? "settings.personal.account.loading"
              : snapshot
                ? "settings.personal.account.saved"
                : "settings.personal.account.empty",
        )}
      </p>
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(
            failed === "network" || failed === "connectionBeforeRequest"
              ? "settings.personal.account.network"
              : failed === "authenticationRequired"
                ? "settings.personal.account.authenticate"
                : failed === "refreshDeferred"
                  ? "settings.personal.account.deferred"
                  : `settings.personal.error.${failed}`,
          )}
        </p>
      ) : null}
      {snapshot ? (
        <>
          <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t("settings.personal.account.id")}</dt>
            <dd className="m-0 break-all select-text">{snapshot.accountId}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.account.email")}</dt>
            <dd className="m-0 break-all select-text">{snapshot.email ?? t("settings.personal.account.noEmail")}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.account.queriedAt")}</dt>
            <dd className="m-0 break-words">
              {new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(
                Number(snapshot.queriedAt),
              )}
            </dd>
          </dl>
          <ul className="mt-4 list-none divide-y divide-border p-0" aria-label={t("settings.personal.account.devices")}>
            {snapshot.devices.map((device) => (
              <li key={device.id} className="min-w-0 py-3">
                <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className="min-w-0 break-words font-medium [overflow-wrap:anywhere]">
                    {device.name || t("settings.personal.account.unnamed")}
                  </span>
                  {device.current ? (
                    <span className="text-xs text-muted-foreground">{t("settings.personal.account.current")}</span>
                  ) : null}
                </div>
                <p className="mt-1 break-words text-sm text-muted-foreground [overflow-wrap:anywhere]">
                  {t("settings.personal.account.platform", {
                    platform: device.platform || t("settings.personal.account.unspecified"),
                  })}
                </p>
                <p className="mt-1 break-all select-text font-mono text-xs text-muted-foreground">{device.id}</p>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted-foreground">{t("settings.personal.account.claims")}</p>
        </>
      ) : null}
      {!authenticated ? (
        <p className="mt-3 text-sm text-muted-foreground">{t("settings.personal.account.authenticate")}</p>
      ) : null}
      <Button
        className="mt-4"
        variant="secondary"
        disabled={busy || disabled || loading || !authenticated}
        onClick={() => void query()}
      >
        {t(busy ? "settings.personal.working" : "settings.personal.account.query")}
      </Button>
    </section>
  );
}
