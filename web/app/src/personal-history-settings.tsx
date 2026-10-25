// SPDX-License-Identifier: Apache-2.0
import { useProfileCommands } from "./account-profiles";
import { Button, Confirm, Dialog } from "@scoplen/ui";
import { useEffect, useId, useRef, useState } from "react";
import { catalogs, useI18n } from "./i18n";
import {
  type PersonalInventoryError,
  type PersonalInventoryHistory,
  type PersonalInventoryObject,
} from "./ipc/bindings";

export function PersonalHistorySettings({
  objects,
  authenticated,
  disabled,
  onBusyChange,
  onRestored,
}: {
  objects: PersonalInventoryObject[];
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  onRestored: () => Promise<void>;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const id = useId();
  const [objectId, setObjectId] = useState("");
  const [history, setHistory] = useState<PersonalInventoryHistory | null>(null);
  const [sequence, setSequence] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<PersonalInventoryError | null>(null);
  const [restored, setRestored] = useState<"complete" | "refreshFailed" | null>(null);
  const pending = useRef(false);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = async (restore: boolean) => {
    if (pending.current || disabled || (!restore && (!authenticated || !objectId))) return;
    if (restore && (!history || !sequence)) return;
    pending.current = true;
    setBusy(true);
    setFailed(null);
    setRestored(null);
    onBusyChange(true);
    try {
      const result = restore
        ? await commands.restorePersonalInventoryHistory(history!.token, sequence!)
        : await commands.queryPersonalInventoryHistory(objectId);
      if (!mounted.current) return;
      if (result.status === "error") throw result.error;
      if (restore) {
        setHistory(null);
        setConfirming(false);
        setRestored("complete");
        try {
          await onRestored();
        } catch {
          if (mounted.current) setRestored("refreshFailed");
        }
      } else {
        setHistory(result.data as PersonalInventoryHistory);
        setSequence(null);
      }
    } catch (error) {
      if (mounted.current) {
        setHistory(null);
        setConfirming(false);
        setFailed(
          typeof error === "string" && Object.hasOwn(catalogs.en, `settings.personal.inventory.error.${error}`)
            ? (error as PersonalInventoryError)
            : "storage",
        );
      }
    } finally {
      pending.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  };
  if (objects.length === 0) return null;
  const chosen = history?.versions.find((version) => version.sequence === sequence);

  return (
    <section className="mt-6" aria-labelledby={`${id}-title`} aria-busy={busy}>
      <h5 id={`${id}-title`} className="text-sm font-medium">
        {t("settings.personal.history.title")}
      </h5>
      <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.history.body")}</p>
      <label className="mt-3 block text-sm" htmlFor={`${id}-object`}>
        {t("settings.personal.history.object")}
      </label>
      <select
        id={`${id}-object`}
        className="mt-2 block w-full min-w-0 rounded-md border border-border bg-background p-2 text-sm"
        value={objectId}
        disabled={disabled || busy}
        onChange={(event) => {
          setObjectId(event.target.value);
          setHistory(null);
        }}
      >
        <option value="">{t("settings.personal.history.choose")}</option>
        {objects.map((object) => (
          <option key={object.id} value={object.id}>
            {object.name ?? object.id}
          </option>
        ))}
      </select>
      <Button
        className="mt-3"
        disabled={disabled || busy || !authenticated || !objectId}
        onClick={() => void run(false)}
      >
        {t(busy ? "settings.personal.working" : "settings.personal.history.query")}
      </Button>
      {failed ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {t(`settings.personal.inventory.error.${failed}`)}
        </p>
      ) : null}
      {restored ? (
        <p role="status" className="mt-3 text-sm">
          {t(
            restored === "refreshFailed"
              ? "settings.personal.history.restoredRefreshFailed"
              : "settings.personal.history.restored",
          )}
        </p>
      ) : null}
      <Dialog
        open={history !== null && !confirming}
        onOpenChange={(open) => {
          if (!open && !pending.current) setHistory(null);
        }}
        title={t("settings.personal.history.title")}
        closeLabel={t("settings.personal.inventory.cancel")}
        footer={
          <>
            <Button onClick={() => setHistory(null)}>{t("settings.personal.inventory.cancel")}</Button>
            <Button variant="primary" disabled={!chosen || busy} onClick={() => setConfirming(true)}>
              {t("settings.personal.history.restore")}
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted-foreground">{t("settings.personal.history.retention")}</p>
        <fieldset className="mt-4 min-w-0" disabled={busy}>
          <legend className="sr-only">{t("settings.personal.history.version")}</legend>
          <ul className="max-h-64 list-none space-y-3 overflow-y-auto p-0">
            {[...(history?.versions ?? [])].reverse().map((version) => (
              <li key={version.sequence}>
                <label className="flex min-w-0 items-start gap-3 text-sm">
                  <input
                    className="mt-1 shrink-0 accent-primary"
                    type="radio"
                    name={`${id}-version`}
                    checked={sequence === version.sequence}
                    onChange={() => setSequence(version.sequence)}
                  />
                  <span className="min-w-0 break-words [overflow-wrap:anywhere]">
                    <span className="block font-medium">
                      {t("settings.personal.history.sequence", { sequence: version.sequence })}
                    </span>
                    <span className="block">{version.object.name ?? version.object.id}</span>
                    <span className="block text-xs text-muted-foreground">
                      {t(`settings.personal.inventory.category.${version.object.category}`)}
                      {version.object.deleted ? ` · ${t("settings.personal.inventory.deleted")}` : ""}
                      {version.object.sharedSecret ? ` · ${t("settings.personal.inventory.secret")}` : ""}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      </Dialog>
      <Confirm
        open={confirming}
        onOpenChange={(open) => {
          if (!pending.current) setConfirming(open);
        }}
        title={t("settings.personal.history.confirmTitle")}
        body={
          <>
            <p>{t("settings.personal.history.confirmBody")}</p>
            <p className="mt-3 break-words font-medium [overflow-wrap:anywhere]">
              {chosen?.object.name ?? history?.objectId}
            </p>
            {chosen ? (
              <p className="mt-1 text-sm">{t("settings.personal.history.sequence", { sequence: chosen.sequence })}</p>
            ) : null}
            {chosen?.object.sharedSecret ? (
              <p className="mt-3 text-sm">{t("settings.personal.history.secret")}</p>
            ) : null}
          </>
        }
        confirmLabel={t("settings.personal.history.restore")}
        cancelLabel={t("settings.personal.inventory.cancel")}
        busy={busy}
        onConfirm={() => void run(true)}
      />
    </section>
  );
}
