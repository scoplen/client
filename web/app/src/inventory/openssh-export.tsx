// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useEffect, useId, useRef, useState } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type OpenSshExportChoice,
  type OpenSshExportError,
  type OpenSshExportPreview,
  type OpenSshExportResult,
} from "./api";

export function OpenSshExportDialog({ initial, onClose }: { initial: OpenSshExportPreview; onClose: () => void }) {
  const api = useInventory();
  const { t, locale } = useI18n();
  const id = useId();
  const [preview, setPreview] = useState(initial);
  const [choices, setChoices] = useState(initial.choices);
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [saved, setSaved] = useState<OpenSshExportResult | null>(null);
  const feedback = useRef<HTMLDivElement>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const restoreFocus = useRef(false);

  useEffect(() => {
    if (busy || !restoreFocus.current) return;
    restoreFocus.current = false;
    if (error || cancelled || saved) feedback.current?.focus();
    else refreshButton.current?.focus();
  }, [busy, error, cancelled, saved]);

  const load = async (next: OpenSshExportChoice[]) => {
    setStale(true);
    const result = await api.previewOpenSshExport(next);
    if (result.status === "ok") {
      setPreview(result.data);
      setChoices(result.data.choices);
      setStale(false);
    } else setError(openSshExportErrorText(t, result.error));
  };

  const refresh = async () => {
    if (busy) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    setCancelled(false);
    try {
      await load(choices);
    } catch {
      setError(t("export.error.preview"));
    } finally {
      setBusy(false);
    }
  };

  const chooseIdentity = async (profileId: string) => {
    if (busy) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    setCancelled(false);
    let selected = false;
    try {
      const path = await api.chooseKeyFile();
      if (!path) return;
      selected = true;
      const next = [...choices.filter((choice) => choice.profileId !== profileId), { profileId, identityFile: path }];
      setChoices(next);
      await load(next);
    } catch {
      setError(t(selected ? "export.error.preview" : "export.error.picker"));
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (busy || stale || saved || preview.entries.length === 0) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    setCancelled(false);
    try {
      const result = await api.exportOpenSshConfig(preview, locale === "zh-Hans" ? "zh-Hans" : "en");
      if (result.status === "ok") {
        if (result.data) setSaved(result.data);
        else setCancelled(true);
      } else {
        if (["inventoryChanged", "sourceChanged", "contextChanged"].includes(result.error.kind)) setStale(true);
        setError(openSshExportErrorText(t, result.error));
      }
    } catch {
      setStale(true);
      setError(t("export.error.unknown"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !busy && onClose()}
      title={t("export.title")}
      closeLabel={t("export.close")}
      footer={
        saved ? (
          <Button variant="primary" onClick={onClose}>
            {t("export.done")}
          </Button>
        ) : (
          <>
            <Button variant="ghost" autoFocus disabled={busy} onClick={onClose}>
              {t("import.cancel")}
            </Button>
            <Button ref={refreshButton} variant="secondary" disabled={busy} onClick={() => void refresh()}>
              {t("import.refresh")}
            </Button>
            <Button
              variant="primary"
              busy={busy}
              disabled={stale || preview.entries.length === 0}
              onClick={() => void save()}
            >
              {t("export.save")}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-5 text-sm">
        {saved || cancelled || error ? (
          <div ref={feedback} tabIndex={-1} className="space-y-2 outline-none">
            {saved ? (
              <div role="status" className="space-y-2">
                <p className="m-0 font-medium">{t("export.saved", { count: saved.hosts, files: saved.files })}</p>
                <p className="m-0 break-all font-mono text-xs">{saved.directory}</p>
                <p className="m-0 text-muted-foreground">{t("export.use")}</p>
                <p className="m-0 break-all font-mono text-xs">
                  {t("export.config", { path: `${saved.directory}/config` })}
                </p>
                <p className="m-0 break-all font-mono text-xs">{`ssh -F <config> ${preview.entries[0]!.alias}`}</p>
              </div>
            ) : null}
            {cancelled ? (
              <p role="status" className="m-0 text-muted-foreground">
                {t("export.cancelled")}
              </p>
            ) : null}
            {error ? (
              <p role="alert" className="m-0 break-all text-attention">
                {error}
              </p>
            ) : null}
          </div>
        ) : null}
        <div className="space-y-2">
          <p className="m-0">{t("export.scope")}</p>
          <p className="m-0 text-muted-foreground">{t("export.files")}</p>
          <p className="m-0 text-muted-foreground">{t("export.secrets")}</p>
          <p className="m-0 font-medium">
            {t("export.summary", {
              count: preview.entries.length,
              skipped: preview.skipped.length,
              trust: preview.trustRecords,
            })}
          </p>
          {busy ? (
            <p className="m-0 text-muted-foreground" role="status">
              {t("export.working")}
            </p>
          ) : null}
        </div>
        <section aria-labelledby={`${id}-entries`}>
          <h3 id={`${id}-entries`} className="m-0 font-medium">
            {t("export.entries", { count: preview.entries.length })}
          </h3>
          {preview.entries.length === 0 ? (
            <p>{t("export.empty")}</p>
          ) : (
            <ul className="mt-2 mb-0 list-none divide-y divide-border p-0">
              {preview.entries.map((entry) => (
                <li key={entry.profileId} className="space-y-1.5 py-3 first:pt-0">
                  <p className="m-0 break-all font-medium">{entry.alias}</p>
                  <p className="m-0 break-all text-muted-foreground">
                    {entry.hostName}
                    {entry.loginName ? ` · ${entry.loginName}` : ""}
                  </p>
                  <p className="m-0 break-all font-mono text-xs">
                    {entry.username}@{entry.address}
                    {entry.port === 22 ? "" : `:${entry.port}`}
                  </p>
                  <p className="m-0 break-all text-muted-foreground">
                    {entry.route.kind === "direct"
                      ? t("host.route.direct")
                      : entry.route.kind === "jump"
                        ? t("import.route.jump", { hops: entry.route.hops.join(" → ") })
                        : t("import.route.command", { command: entry.route.command })}
                  </p>
                  <p className="m-0 text-muted-foreground">{t(`export.authentication.${entry.authentication}`)}</p>
                  {entry.identityFile ? (
                    <p className="m-0 break-all font-mono text-xs text-muted-foreground">{entry.identityFile}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>
        {preview.skipped.length > 0 ? (
          <section aria-labelledby={`${id}-skipped`}>
            <h3 id={`${id}-skipped`} className="m-0 font-medium">
              {t("export.skipped", { count: preview.skipped.length })}
            </h3>
            <p className="text-muted-foreground">{t("export.skippedHint")}</p>
            <ul className="mt-2 mb-0 list-none space-y-3 p-0">
              {preview.skipped.map((entry, index) => (
                <li key={entry.profileId ?? `${entry.hostId}:${index}`} className="space-y-1.5">
                  <p className="m-0 break-all font-medium">
                    {entry.hostName}
                    {entry.loginName ? ` · ${entry.loginName}` : ""}
                  </p>
                  <p className="m-0 text-muted-foreground">{t(`export.skip.${entry.reason}`)}</p>
                  {choices.find((choice) => choice.profileId === entry.profileId) ? (
                    <p className="m-0 break-all font-mono text-xs text-muted-foreground">
                      {choices.find((choice) => choice.profileId === entry.profileId)!.identityFile}
                    </p>
                  ) : null}
                  {!saved &&
                  entry.profileId &&
                  ["identityFileRequired", "identityFileMismatch"].includes(entry.reason) ? (
                    <Button
                      variant="secondary"
                      className="h-auto min-h-9 max-w-full py-2 text-left break-all whitespace-normal"
                      disabled={busy}
                      onClick={() => void chooseIdentity(entry.profileId!)}
                    >
                      {t("export.chooseIdentity", { name: entry.loginName ?? entry.hostName })}
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}
        {stale && !busy ? <p className="m-0 text-attention">{t("import.reviewAgain")}</p> : null}
      </div>
    </Dialog>
  );
}

export function openSshExportErrorText(t: ReturnType<typeof useI18n>["t"], error: OpenSshExportError): string {
  if (error.kind === "writeFailed") {
    return error.directory ? t("export.error.partial", { path: error.directory }) : t("export.error.writeFailed");
  }
  return t(`export.error.${error.kind}`);
}
