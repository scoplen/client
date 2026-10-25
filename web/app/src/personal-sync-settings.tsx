// SPDX-License-Identifier: Apache-2.0
import { useProfile, useProfileCommands } from "./account-profiles";
import { Button } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import {
  events,
  type PersonalBackgroundStatus,
  type PersonalSyncCommandError,
  type PersonalSyncKeyStatus,
} from "./ipc/bindings";
import { PersonalInventorySettings } from "./personal-inventory-settings";

export function PersonalSyncSettings({
  authenticated,
  disabled,
  onBusyChange,
}: {
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const commands = useProfileCommands();
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
  }, [commands]);

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
      {status === "verified" ? (
        <>
          <BackgroundStatus />
          <PersonalInventorySettings
            authenticated={authenticated}
            disabled={busy || disabled}
            onBusyChange={onBusyChange}
          />
        </>
      ) : null}
    </section>
  );
}

function BackgroundStatus() {
  const commands = useProfileCommands();
  const generation = useProfile()?.snapshot.generation;
  const { t } = useI18n();
  const [status, setStatus] = useState<PersonalBackgroundStatus>("inactive");
  useEffect(() => {
    let active = true;
    let changed = false;
    let stop: (() => void) | undefined;
    void events.personalSyncChanged
      .listen((event) => {
        if (active && (generation === undefined || event.payload.profileGeneration === generation)) {
          changed = true;
          setStatus(event.payload.status);
        }
      })
      .then(async (unlisten) => {
        if (!active) {
          unlisten();
          return;
        }
        stop = unlisten;
        const saved = await commands.personalSyncBackgroundStatus();
        if (active && !changed) setStatus(saved);
      })
      .catch(() => {});
    return () => {
      active = false;
      stop?.();
    };
  }, [commands, generation]);
  const attention =
    status === "authenticationRequired" ||
    status === "rotationRequired" ||
    status === "permissionDenied" ||
    status === "failed";
  return (
    <p
      role={attention ? "alert" : "status"}
      className={`mt-2 text-sm ${attention ? "text-attention" : "text-muted-foreground"}`}
    >
      {t(`settings.personal.sync.background.${status}`)}
    </p>
  );
}
