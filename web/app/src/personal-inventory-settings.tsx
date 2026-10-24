// SPDX-License-Identifier: Apache-2.0
import { Button, Confirm, Dialog } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { catalogs, useI18n } from "./i18n";
import { PersonalHistorySettings } from "./personal-history-settings";
import {
  commands,
  type PersonalInventoryError,
  type PersonalInventoryObject,
  type PersonalInventoryPreview,
  type PersonalInventoryResult,
  type PersonalInventoryStatus,
} from "./ipc/bindings";

type Outcome<T> = { status: "ok"; data: T } | { status: "error"; error: PersonalInventoryError };

function safeFailure(error: unknown): PersonalInventoryError {
  return typeof error === "string" && Object.hasOwn(catalogs.en, `settings.personal.inventory.error.${error}`)
    ? (error as PersonalInventoryError)
    : "storage";
}

export function PersonalInventorySettings({
  authenticated,
  disabled,
  onBusyChange,
}: {
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const { t } = useI18n();
  const [status, setStatus] = useState<PersonalInventoryStatus | null>(null);
  const [failed, setFailed] = useState<PersonalInventoryError | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [backupSelected, setBackupSelected] = useState<Set<string>>(new Set());
  const [recoverySelected, setRecoverySelected] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<PersonalInventoryPreview | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [restoreSource, setRestoreSource] = useState<"original" | "recovery">("original");
  const [result, setResult] = useState<PersonalInventoryResult | null>(null);
  const [restored, setRestored] = useState<number | null>(null);
  const pending = useRef(false);
  const mounted = useRef(false);
  const blocked = disabled || busy || loading;

  useEffect(() => {
    let active = true;
    mounted.current = true;
    void commands.personalInventoryStatus().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") setStatus(result.data);
        else setFailed(safeFailure(result.error));
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
      mounted.current = false;
    };
  }, []);

  const run = async <T,>(operation: () => Promise<Outcome<T>>, success: (data: T) => void) => {
    if (pending.current || disabled) return;
    pending.current = true;
    setBusy(true);
    onBusyChange(true);
    setFailed(null);
    setResult(null);
    setRestored(null);
    try {
      try {
        const outcome = await operation();
        if (!mounted.current) return;
        if (outcome.status === "ok") success(outcome.data);
        else setFailed(safeFailure(outcome.error));
      } catch {
        if (mounted.current) setFailed("storage");
      }
      if (!mounted.current) return;
      // Failure can still follow durable adoption, a committed remote write, or an
      // applied page. Always reload local truth without retrying a network intent.
      const latest = await commands.personalInventoryStatus();
      if (mounted.current) {
        if (latest.status === "ok") {
          setStatus(latest.data);
          const local = new Set(
            latest.data.objects
              .filter((object) => !object.personal && !object.deleted && !object.excluded)
              .map((object) => object.id),
          );
          setSelected((ids) => new Set([...ids].filter((id) => local.has(id))));
        } else setFailed((current) => current ?? safeFailure(latest.error));
      }
    } catch {
      if (mounted.current) setFailed((current) => current ?? "storage");
    } finally {
      pending.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  };

  const sync = (reviewToken: string | null) => {
    if (!authenticated || (reviewToken !== null && !confirmed)) return;
    setPreview(null);
    setConfirmed(false);
    void run(() => commands.synchronizePersonalInventory(reviewToken), setResult);
  };
  const toggle = (id: string, source: "local" | "original" | "recovery" = "local") => {
    const update =
      source === "original" ? setBackupSelected : source === "recovery" ? setRecoverySelected : setSelected;
    update((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setPreview(null);
    setConfirmed(false);
  };
  const label = (object: PersonalInventoryObject) => object.name ?? object.id;
  const selectedRecoveryObjects = new Set(
    status?.recovery.filter((copy) => recoverySelected.has(copy.id)).map((copy) => copy.object.id),
  );
  const describe = (object: PersonalInventoryObject) => (
    <>
      <span className="block break-words font-medium">{label(object)}</span>
      <span className="block text-xs text-muted-foreground">
        {t(`settings.personal.inventory.category.${object.category}`)}
        {object.sharedSecret ? ` · ${t("settings.personal.inventory.secret")}` : ""}
        {object.dirty ? ` · ${t("settings.personal.inventory.dirty")}` : ""}
        {object.deleted ? ` · ${t("settings.personal.inventory.deleted")}` : ""}
        {object.excluded ? ` · ${t("settings.personal.inventory.excluded")}` : ""}
      </span>
      {object.name ? <span className="block break-all text-xs text-muted-foreground">{object.id}</span> : null}
    </>
  );

  return (
    <section
      aria-labelledby="personal-inventory-title"
      className="mt-6 border-t border-border pt-6"
      aria-busy={busy || loading}
    >
      <h4 id="personal-inventory-title" className="text-sm font-medium">
        {t("settings.personal.inventory.title")}
      </h4>
      <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.body")}</p>
      <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.content")}</p>
      {failed ? (
        <p role="alert" className="mt-4 text-sm text-attention">
          {t(`settings.personal.inventory.error.${failed}`)}
        </p>
      ) : null}
      {loading ? (
        <p role="status" className="mt-4 text-sm text-muted-foreground">
          {t("settings.personal.inventory.loading")}
        </p>
      ) : null}
      {status ? (
        <>
          <dl className="mt-4 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t("settings.personal.inventory.pending")}</dt>
            <dd className="m-0">{status.pending}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.inventory.applied")}</dt>
            <dd className="m-0 break-all">{status.appliedCursor}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.inventory.acknowledged")}</dt>
            <dd className="m-0 break-all">{status.acknowledgedCursor}</dd>
          </dl>
          <p className="mt-2 break-all text-xs text-muted-foreground">
            {t("settings.personal.inventory.vault", { id: status.vaultId })}
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Button variant="primary" disabled={blocked || !authenticated} onClick={() => sync(null)}>
              {t("settings.personal.inventory.sync")}
            </Button>
            <Button disabled={blocked} onClick={() => void run(commands.personalInventoryStatus, setStatus)}>
              {t("settings.personal.inventory.reload")}
            </Button>
          </div>
          {!authenticated ? (
            <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.authenticate")}</p>
          ) : null}
          {status.recovery.length > 0 ? (
            <fieldset className="mt-6 min-w-0 border-l-2 border-attention pl-4" disabled={blocked}>
              <legend className="text-sm font-medium text-attention">
                {t("settings.personal.inventory.recovery", { count: status.recovery.length })}
              </legend>
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.recoveryBody")}</p>
              <ul className="mt-3 max-h-64 list-none space-y-3 overflow-y-auto p-0">
                {status.recovery.map((copy) => (
                  <li key={copy.id}>
                    <label className="flex min-w-0 items-start gap-3 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1 shrink-0 accent-primary"
                        checked={recoverySelected.has(copy.id)}
                        disabled={!recoverySelected.has(copy.id) && selectedRecoveryObjects.has(copy.object.id)}
                        onChange={() => toggle(copy.id, "recovery")}
                      />
                      <span className="min-w-0">
                        {describe(copy.object)}
                        <span className="block break-all text-xs text-muted-foreground">
                          {t("settings.personal.inventory.copy", { id: copy.id })}
                        </span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
              <Button
                className="mt-4"
                disabled={blocked || recoverySelected.size === 0}
                onClick={() => {
                  setRestoreSource("recovery");
                  setRestoring(true);
                }}
              >
                {t("settings.personal.inventory.recover", { count: recoverySelected.size })}
              </Button>
            </fieldset>
          ) : null}
          <fieldset className="mt-6 min-w-0" disabled={blocked}>
            <legend className="text-sm font-medium">{t("settings.personal.inventory.local")}</legend>
            <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.selectBody")}</p>
            <ul className="mt-3 max-h-64 list-none space-y-3 overflow-y-auto p-0">
              {status.objects
                .filter((object) => !object.personal && !object.deleted)
                .map((object) => (
                  <li key={object.id}>
                    <label className="flex min-w-0 items-start gap-3 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1 shrink-0 accent-primary"
                        checked={selected.has(object.id)}
                        disabled={object.excluded}
                        onChange={() => toggle(object.id)}
                      />
                      <span className="min-w-0">{describe(object)}</span>
                    </label>
                  </li>
                ))}
            </ul>
            {!status.objects.some((object) => !object.personal && !object.deleted) ? (
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.empty")}</p>
            ) : null}
            <Button
              className="mt-4"
              disabled={blocked || selected.size === 0 || !authenticated}
              onClick={() =>
                void run(
                  () => commands.previewPersonalInventory([...selected]),
                  (data) => {
                    setPreview(data);
                    setConfirmed(false);
                  },
                )
              }
            >
              {t("settings.personal.inventory.review", { count: selected.size })}
            </Button>
          </fieldset>
          {status.objects.some((object) => object.personal) ? (
            <details className="mt-6 text-sm">
              <summary className="cursor-pointer font-medium">{t("settings.personal.inventory.adopted")}</summary>
              <ul className="mt-3 max-h-64 list-none space-y-3 overflow-y-auto p-0">
                {status.objects
                  .filter((object) => object.personal)
                  .map((object) => (
                    <li key={object.id}>{describe(object)}</li>
                  ))}
              </ul>
            </details>
          ) : null}
          <PersonalHistorySettings
            objects={status.objects.filter((object) => object.personal)}
            authenticated={authenticated}
            disabled={blocked}
            onBusyChange={(active) => {
              setBusy(active);
              onBusyChange(active);
            }}
            onRestored={async () => {
              const latest = await commands.personalInventoryStatus();
              if (latest.status === "error") throw latest.error;
              if (mounted.current) setStatus(latest.data);
            }}
          />
          <fieldset className="mt-6 min-w-0" disabled={blocked}>
            <legend className="text-sm font-medium">{t("settings.personal.inventory.backups")}</legend>
            <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.restoreBody")}</p>
            <ul className="mt-3 max-h-64 list-none space-y-3 overflow-y-auto p-0">
              {status.backups.map((object) => (
                <li key={object.id}>
                  <label className="flex min-w-0 items-start gap-3 text-sm">
                    <input
                      type="checkbox"
                      className="mt-1 shrink-0 accent-primary"
                      checked={backupSelected.has(object.id)}
                      onChange={() => toggle(object.id, "original")}
                    />
                    <span className="min-w-0">{describe(object)}</span>
                  </label>
                </li>
              ))}
            </ul>
            {status.backups.length === 0 ? (
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.inventory.noBackups")}</p>
            ) : null}
            <Button
              className="mt-4"
              disabled={blocked || backupSelected.size === 0}
              onClick={() => {
                setRestoreSource("original");
                setRestoring(true);
              }}
            >
              {t("settings.personal.inventory.restore", { count: backupSelected.size })}
            </Button>
          </fieldset>
        </>
      ) : !loading ? (
        <Button
          className="mt-4"
          disabled={blocked}
          onClick={() => void run(commands.personalInventoryStatus, setStatus)}
        >
          {t("settings.personal.inventory.reload")}
        </Button>
      ) : null}
      {result ? (
        <p role="status" className="mt-4 text-sm">
          {t("settings.personal.inventory.result", { downloaded: result.downloaded, uploaded: result.uploaded })}{" "}
          {result.more ? t("settings.personal.inventory.more") : t("settings.personal.inventory.done")}
        </p>
      ) : null}
      {restored !== null ? (
        <p role="status" className="mt-4 text-sm">
          {t("settings.personal.inventory.restored", { count: restored })}
        </p>
      ) : null}
      <Dialog
        open={preview !== null}
        onOpenChange={(open) => {
          if (!open && !pending.current) {
            setPreview(null);
            setConfirmed(false);
          }
        }}
        title={t("settings.personal.inventory.reviewTitle")}
        description={t("settings.personal.inventory.reviewBody")}
        closeLabel={t("settings.personal.inventory.close")}
        footer={
          <Button
            variant="primary"
            disabled={!preview?.token || !confirmed || blocked || !authenticated}
            onClick={() => {
              if (preview?.token) sync(preview.token);
            }}
          >
            {t("settings.personal.inventory.adopt")}
          </Button>
        }
      >
        <p className="text-sm text-muted-foreground">{t("settings.personal.inventory.backupBody")}</p>
        <ul className="mt-4 list-none space-y-3 p-0 text-sm">
          {preview?.objects.map((object) => (
            <li key={object.id}>{describe(object)}</li>
          ))}
        </ul>
        {preview?.missing.length ? (
          <div className="mt-4 text-sm text-attention">
            <p>{t("settings.personal.inventory.missing")}</p>
            <ul className="mt-2 list-none space-y-3 p-0">
              {preview.missing.map((object) => (
                <li key={object.id}>{describe(object)}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {preview?.token ? (
          <label className="mt-4 flex items-start gap-3 text-sm">
            <input
              type="checkbox"
              className="mt-1 shrink-0 accent-primary"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            <span>{t("settings.personal.inventory.confirm")}</span>
          </label>
        ) : null}
      </Dialog>
      <Confirm
        open={restoring}
        onOpenChange={(open) => {
          if (!pending.current) setRestoring(open);
        }}
        title={t(
          restoreSource === "recovery"
            ? "settings.personal.inventory.recoverTitle"
            : "settings.personal.inventory.restoreTitle",
        )}
        body={
          <>
            <p>
              {t(
                restoreSource === "recovery"
                  ? "settings.personal.inventory.recoverBody"
                  : "settings.personal.inventory.restoreBody",
              )}
            </p>
            <ul className="mt-3 max-h-48 list-none space-y-2 overflow-y-auto p-0">
              {restoreSource === "recovery"
                ? status?.recovery
                    .filter((copy) => recoverySelected.has(copy.id))
                    .map((copy) => <li key={copy.id}>{describe(copy.object)}</li>)
                : status?.backups
                    .filter((object) => backupSelected.has(object.id))
                    .map((object) => <li key={object.id}>{describe(object)}</li>)}
            </ul>
          </>
        }
        confirmLabel={t("settings.personal.inventory.restoreConfirm")}
        cancelLabel={t("settings.personal.inventory.cancel")}
        busy={busy}
        onConfirm={() => {
          const recovery = restoreSource === "recovery";
          setRestoring(false);
          void run(
            () =>
              recovery
                ? commands.restorePersonalInventoryRecovery([...recoverySelected])
                : commands.restorePersonalInventory([...backupSelected]),
            (count) => {
              setRestored(count);
              setBackupSelected(new Set());
              setRecoverySelected(new Set());
            },
          );
        }}
      />
    </section>
  );
}
