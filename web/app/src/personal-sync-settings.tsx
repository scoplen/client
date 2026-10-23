// SPDX-License-Identifier: Apache-2.0
import { Button } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type PersonalSyncCommandError, type PersonalSyncKeyStatus } from "./ipc/bindings";

export function PersonalSyncSettings({
  authenticated,
  disabled,
  onBusyChange,
}: {
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const { t } = useI18n();
  const [status, setStatus] = useState<PersonalSyncKeyStatus | null>(null);
  const [failed, setFailed] = useState<PersonalSyncCommandError | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const pending = useRef(false);

  useEffect(() => {
    let active = true;
    void commands.personalSyncKeyStatus().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") setStatus(result.data);
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
  }, []);

  const connect = async () => {
    if (pending.current || disabled || !authenticated || loading) return;
    pending.current = true;
    setBusy(true);
    onBusyChange(true);
    setFailed(null);
    try {
      const result = await commands.connectPersonalSync();
      if (result.status === "ok") setStatus(result.data);
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
    <section aria-labelledby="personal-sync-title" className="mt-6 border-t border-border pt-6" aria-busy={busy}>
      <h3 id="personal-sync-title" className="text-sm font-medium">
        {t("settings.personal.sync.title")}
      </h3>
      <p role="status" className="mt-2 text-sm text-muted-foreground">
        {t(
          busy
            ? "settings.personal.sync.connecting"
            : status === "verified"
              ? "settings.personal.sync.verified"
              : status === "notConnected"
                ? "settings.personal.sync.body"
                : failed
                  ? "settings.personal.sync.unavailable"
                  : "settings.personal.sync.loading",
        )}
      </p>
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(`settings.personal.error.${failed}`)}
        </p>
      ) : null}
      {!authenticated ? (
        <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.sync.authenticate")}</p>
      ) : null}
      <Button className="mt-4" disabled={busy || disabled || !authenticated || loading} onClick={() => void connect()}>
        {t(busy ? "settings.personal.working" : "settings.personal.sync.connect")}
      </Button>
    </section>
  );
}
