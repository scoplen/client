// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field } from "@scoplen/ui";
import { useEffect, useId, useRef, useState, type RefObject } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type PortableArchiveDestination,
  type PortableArchiveError,
  type PortableArchiveExportResult,
  type PortableArchiveImportConsent,
  type PortableArchiveImportPreview,
  type PortableArchiveImportResult,
} from "./api";

export function PortableTransferSettings() {
  const api = useInventory();
  const { t, locale } = useI18n();
  const id = useId();
  const [preparing, setPreparing] = useState(false);
  const [importing, setImporting] = useState<{ preview: PortableArchiveImportPreview | null } | null>(null);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<PortableArchiveImportResult | null>(null);
  const importButton = useRef<HTMLButtonElement>(null);
  const exportButton = useRef<HTMLButtonElement>(null);

  useEffect(
    () => () => {
      void api.portableArchiveDiscard().catch(() => undefined);
    },
    [api],
  );

  const prepare = async () => {
    if (preparing) return;
    setPreparing(true);
    setError(null);
    setDone(null);
    try {
      const result = await api.portableArchivePreview(true, null, locale === "zh-Hans" ? "zh-Hans" : "en");
      if (result.status === "ok") {
        if (result.data) setImporting({ preview: result.data });
      } else if (result.error === "passphraseRequired") setImporting({ preview: null });
      else setError(portableArchiveErrorText(t, result.error));
    } catch {
      setError(t("archive.error.io"));
    } finally {
      setPreparing(false);
    }
  };

  const closeImport = () => {
    void api.portableArchiveDiscard().catch(() => undefined);
    setImporting(null);
  };

  return (
    <section aria-labelledby={`${id}-title`} className="mt-8 border-t border-border pt-6">
      <h3 id={`${id}-title`} className="text-sm font-medium">
        {t("archive.title")}
      </h3>
      <p className="mt-2 max-w-lg text-sm text-muted-foreground">{t("archive.body")}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button
          ref={importButton}
          busy={preparing}
          disabled={exporting || importing !== null}
          onClick={() => void prepare()}
        >
          {t("archive.import")}
        </Button>
        <Button
          ref={exportButton}
          disabled={preparing || importing !== null || exporting}
          onClick={() => {
            setError(null);
            setDone(null);
            setExporting(true);
          }}
        >
          {t("archive.export")}
        </Button>
      </div>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {error}
        </p>
      ) : null}
      {done ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {t("archive.imported", { ...done })}
        </p>
      ) : null}
      {importing ? (
        <PortableImportDialog
          initial={importing.preview}
          onClose={closeImport}
          finalFocus={importButton}
          onUnencryptedSecrets={() => {
            setError(t("archive.error.unencryptedSecrets"));
            closeImport();
          }}
          onImported={(result) => {
            setDone(result);
            closeImport();
          }}
        />
      ) : null}
      {exporting ? <PortableExportDialog onClose={() => setExporting(false)} finalFocus={exportButton} /> : null}
    </section>
  );
}

function Destination({ value }: { value: PortableArchiveDestination }) {
  const { t } = useI18n();
  return (
    <div className="space-y-1">
      <p className="m-0 font-medium">
        {t(value.scope === "local" ? "archive.destination.local" : "archive.destination.personal")}
      </p>
      {value.scope === "personal" ? (
        <dl className="m-0 space-y-1 text-xs text-muted-foreground">
          <div>
            <dt>{t("archive.destination.account")}</dt>
            <dd className="m-0 break-all font-mono">{value.ownerId}</dd>
          </div>
          <div>
            <dt>{t("archive.destination.vault")}</dt>
            <dd className="m-0 break-all font-mono">{value.vaultId}</dd>
          </div>
        </dl>
      ) : null}
    </div>
  );
}

function PortableImportDialog({
  initial,
  onClose,
  onImported,
  onUnencryptedSecrets,
  finalFocus,
}: {
  initial: PortableArchiveImportPreview | null;
  onClose: () => void;
  onImported: (result: PortableArchiveImportResult) => void;
  onUnencryptedSecrets: () => void;
  finalFocus: RefObject<HTMLButtonElement | null>;
}) {
  const api = useInventory();
  const { t, locale } = useI18n();
  const formId = useId();
  const [preview, setPreview] = useState(initial);
  const [encrypted, setEncrypted] = useState(initial === null);
  const [consent, setConsent] = useState<PortableArchiveImportConsent>({
    retainSecretSourceIds: [],
    trustSourceIds: [],
  });
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState(false);
  const [hasPassphrase, setHasPassphrase] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passphrase = useRef<HTMLInputElement>(null);
  const feedback = useRef<HTMLDivElement>(null);
  const restoreFocus = useRef(false);

  useEffect(() => api.onChange(() => setStale(true)), [api]);
  useEffect(() => {
    if (!busy && restoreFocus.current) {
      restoreFocus.current = false;
      feedback.current?.focus();
    }
  }, [busy]);

  const takePassphrase = () => {
    const value = passphrase.current?.value || null;
    if (passphrase.current) passphrase.current.value = "";
    setHasPassphrase(false);
    return value;
  };
  const choose = (kind: keyof PortableArchiveImportConsent, sourceId: string, checked: boolean) => {
    setConsent((current) => ({
      ...current,
      [kind]: checked ? [...current[kind], sourceId] : current[kind].filter((id) => id !== sourceId),
    }));
  };
  const load = async (chooseFile: boolean) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setStale(true);
    setConsent({ retainSecretSourceIds: [], trustSourceIds: [] });
    restoreFocus.current = true;
    const secret = takePassphrase();
    try {
      const result = await api.portableArchivePreview(
        chooseFile,
        chooseFile ? null : secret,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      );
      if (result.status === "ok") {
        if (!result.data) {
          onClose();
          return;
        }
        setPreview(result.data);
        if (chooseFile) setEncrypted(false);
        setStale(false);
      } else {
        if (result.error === "passphraseRequired") {
          setEncrypted(true);
          setPreview(null);
        } else if (result.error === "unencryptedSecrets") onUnencryptedSecrets();
        else setError(portableArchiveErrorText(t, result.error));
      }
    } catch {
      setError(t("archive.error.io"));
    } finally {
      setBusy(false);
    }
  };
  const choicesComplete =
    preview?.entries.every(
      (entry) =>
        (!entry.trust?.requiresConsent || consent.trustSourceIds.includes(entry.sourceId)) &&
        (!(entry.objectType === "Credential" && entry.retainSecretAvailable) ||
          consent.retainSecretSourceIds.includes(entry.sourceId)),
    ) ?? false;
  const canConfirm = !!preview?.canImport && !stale && choicesComplete && (!encrypted || hasPassphrase);
  const confirm = async () => {
    if (busy || !canConfirm || !preview) return;
    setBusy(true);
    setError(null);
    restoreFocus.current = true;
    const secret = takePassphrase();
    try {
      const result = await api.portableArchiveImport(preview.id, secret, consent);
      if (result.status === "ok") onImported(result.data);
      else if (result.error === "unencryptedSecrets") onUnencryptedSecrets();
      else {
        setStale(true);
        setError(portableArchiveErrorText(t, result.error));
      }
    } catch {
      setStale(true);
      setError(t("archive.importUnknown"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      title={t("archive.review")}
      description={t("archive.reviewBody")}
      closeLabel={t("archive.close")}
      finalFocus={finalFocus}
      onOpenChange={(open) => !open && !busy && onClose()}
      footer={
        <>
          <Button variant="ghost" autoFocus disabled={busy} onClick={onClose}>
            {t("import.cancel")}
          </Button>
          <Button disabled={busy} onClick={() => void load(true)}>
            {t("archive.chooseAnother")}
          </Button>
          {preview ? (
            <Button disabled={busy || (encrypted && !hasPassphrase)} onClick={() => void load(false)}>
              {t("import.refresh")}
            </Button>
          ) : null}
          <Button
            variant="primary"
            type="submit"
            form={formId}
            busy={busy}
            disabled={preview ? !canConfirm : !hasPassphrase}
          >
            {t(preview ? "archive.confirm" : "archive.unlock")}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        className="space-y-5 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          if (preview) void confirm();
          else if (hasPassphrase) void load(false);
        }}
      >
        <div ref={feedback} tabIndex={-1} className="space-y-2 outline-none" aria-live="polite">
          {error ? (
            <p role="alert" className="m-0 text-attention">
              {error}
            </p>
          ) : null}
          {stale && preview ? <p className="m-0 text-attention">{t("archive.reviewAgain")}</p> : null}
          {preview ? (
            <>
              <Destination value={preview.destination} />
              <p className="m-0 text-muted-foreground">
                {t("archive.summary", {
                  created: preview.entries.filter((entry) => entry.action === "create").length,
                  updated: preview.entries.filter((entry) => entry.action === "replace").length,
                  unchanged: preview.entries.filter((entry) => entry.action === "unchanged").length,
                  count: preview.entries.filter((entry) => entry.action === "blocked").length,
                })}
              </p>
              {!preview.canImport ? <p className="m-0 text-attention">{t("archive.blocked")}</p> : null}
            </>
          ) : (
            <p className="m-0 text-muted-foreground">{t("archive.unlockBody")}</p>
          )}
        </div>
        {preview ? (
          <ul aria-label={t("archive.entries")} className="m-0 list-none divide-y divide-border p-0">
            {preview.entries.map((entry) => (
              <li key={entry.sourceId} className="space-y-2 py-4 first:pt-0">
                <p className="m-0 font-medium">
                  {entry.objectType} · {t(`archive.action.${entry.action}`)}
                </p>
                <dl id={`${formId}-${entry.sourceId}-identity`} className="m-0 space-y-1 text-xs text-muted-foreground">
                  <div>
                    <dt>{t("archive.source")}</dt>
                    <dd className="m-0 break-all font-mono">{entry.sourceId}</dd>
                  </div>
                  <div>
                    <dt>{t("archive.target")}</dt>
                    <dd className="m-0 break-all font-mono">{entry.targetId ?? t("archive.newTarget")}</dd>
                  </div>
                </dl>
                {entry.problem ? <p className="m-0 text-attention">{t(`archive.problem.${entry.problem}`)}</p> : null}
                {entry.omittedSecrets.length ? (
                  <p className="m-0 text-muted-foreground">
                    {t("archive.omitted", { count: entry.omittedSecrets.length })}
                  </p>
                ) : null}
                {entry.requiresDeviceSetup ? (
                  <p className="m-0 text-muted-foreground">{t("archive.deviceSetup")}</p>
                ) : null}
                {entry.retainSecretAvailable ? (
                  <label className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      className="mt-1 shrink-0 accent-primary"
                      aria-describedby={`${formId}-${entry.sourceId}-identity`}
                      disabled={busy || stale}
                      checked={consent.retainSecretSourceIds.includes(entry.sourceId)}
                      onChange={(event) => choose("retainSecretSourceIds", entry.sourceId, event.target.checked)}
                    />
                    <span>
                      {t(entry.objectType === "Credential" ? "archive.retainCredential" : "archive.retainSnippet")}
                    </span>
                  </label>
                ) : null}
                {entry.objectType === "Snippet" && entry.omittedSecrets.length ? (
                  <p className="m-0 text-muted-foreground">
                    {t(entry.retainSecretAvailable ? "archive.snippetOmission" : "archive.snippetMissingDefaults")}
                  </p>
                ) : null}
                {entry.trust ? (
                  <div className="space-y-2">
                    <p id={`${formId}-${entry.sourceId}-key-kind`} className="m-0">
                      {t(entry.trust.isCa ? "archive.trust.ca" : "archive.trust.host")} ·{" "}
                      {t(entry.trust.revoked ? "archive.trust.revoked" : "archive.trust.active")}
                    </p>
                    <p id={`${formId}-${entry.sourceId}-algorithm`} className="m-0 break-all font-mono text-xs">
                      {entry.trust.algorithm}
                    </p>
                    <p id={`${formId}-${entry.sourceId}-fingerprint`} className="m-0 break-all font-mono text-xs">
                      {entry.trust.fingerprint}
                    </p>
                    {entry.trust.requiresConsent ? (
                      <label className="flex items-start gap-3">
                        <input
                          type="checkbox"
                          className="mt-1 shrink-0 accent-primary"
                          aria-describedby={`${formId}-${entry.sourceId}-identity ${formId}-${entry.sourceId}-key-kind ${formId}-${entry.sourceId}-algorithm ${formId}-${entry.sourceId}-fingerprint`}
                          disabled={busy || stale}
                          checked={consent.trustSourceIds.includes(entry.sourceId)}
                          onChange={(event) => choose("trustSourceIds", entry.sourceId, event.target.checked)}
                        />
                        <span>{t("archive.acceptTrust")}</span>
                      </label>
                    ) : null}
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
        {encrypted ? (
          <Field
            ref={passphrase}
            label={t("archive.passphrase")}
            type="password"
            autoComplete="off"
            disabled={busy}
            hint={t(preview ? "archive.confirmPassphrase" : "archive.importPassphrase")}
            onChange={(event) => setHasPassphrase(event.target.value.length > 0)}
          />
        ) : null}
      </form>
    </Dialog>
  );
}

function PortableExportDialog({
  onClose,
  finalFocus,
}: {
  onClose: () => void;
  finalFocus: RefObject<HTMLButtonElement | null>;
}) {
  const api = useInventory();
  const { t, locale } = useI18n();
  const formId = useId();
  const [includeSecrets, setIncludeSecrets] = useState(false);
  const [passphraseConfirmed, setPassphraseConfirmed] = useState(false);
  const [passphraseMismatch, setPassphraseMismatch] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState<PortableArchiveExportResult | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passphrase = useRef<HTMLInputElement>(null);
  const confirmation = useRef<HTMLInputElement>(null);
  const feedback = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!busy && (saved || cancelled || error)) feedback.current?.focus();
  }, [busy, saved, cancelled, error]);
  const checkPassphrases = () => {
    const first = passphrase.current?.value || "";
    const second = confirmation.current?.value || "";
    setPassphraseConfirmed(first.length > 0 && first === second);
    setPassphraseMismatch(second.length > 0 && first !== second);
  };
  const clearPassphrases = () => {
    if (passphrase.current) passphrase.current.value = "";
    if (confirmation.current) confirmation.current.value = "";
    setPassphraseConfirmed(false);
    setPassphraseMismatch(false);
  };
  const close = () => {
    clearPassphrases();
    onClose();
  };
  const save = async () => {
    if (busy || saved || (includeSecrets && !passphraseConfirmed)) return;
    const secret = includeSecrets ? passphrase.current?.value || null : null;
    if (includeSecrets && (!secret || secret !== confirmation.current?.value)) {
      setPassphraseMismatch(true);
      return;
    }
    setBusy(true);
    setError(null);
    setCancelled(false);
    clearPassphrases();
    try {
      const result = await api.portableArchiveExport(
        { secrets: includeSecrets ? "included" : "omitted" },
        secret,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      );
      if (result.status === "ok") {
        if (result.data) setSaved(result.data);
        else setCancelled(true);
      } else setError(portableArchiveErrorText(t, result.error));
    } catch {
      setError(t("archive.error.io"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      title={t("archive.exportTitle")}
      description={t("archive.exportBody")}
      closeLabel={t("archive.close")}
      finalFocus={finalFocus}
      onOpenChange={(open) => !open && !busy && close()}
      footer={
        saved ? (
          <Button variant="primary" onClick={close}>
            {t("export.done")}
          </Button>
        ) : (
          <>
            <Button variant="ghost" autoFocus disabled={busy} onClick={close}>
              {t("import.cancel")}
            </Button>
            <Button
              variant="primary"
              type="submit"
              form={formId}
              busy={busy}
              disabled={includeSecrets && !passphraseConfirmed}
            >
              {t("archive.save")}
            </Button>
          </>
        )
      }
    >
      <form
        id={formId}
        className="space-y-4 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        {saved || cancelled || error ? (
          <div ref={feedback} tabIndex={-1} className="space-y-2 outline-none">
            {saved ? (
              <div role="status" className="space-y-2">
                <p className="m-0">{t("archive.exported", { count: saved.objects })}</p>
                <Destination value={saved.destination} />
                <p className="m-0 text-muted-foreground">
                  {t(saved.secrets === "included" ? "archive.encryptedSaved" : "archive.jsonSaved")}
                </p>
              </div>
            ) : null}
            {cancelled ? (
              <p role="status" className="m-0 text-muted-foreground">
                {t("archive.cancelled")}
              </p>
            ) : null}
            {error ? (
              <p role="alert" className="m-0 text-attention">
                {error}
              </p>
            ) : null}
          </div>
        ) : null}
        {!saved ? (
          <>
            <p className="m-0 text-muted-foreground">{t("archive.jsonDefault")}</p>
            <label className="flex items-start gap-3">
              <input
                type="checkbox"
                className="mt-1 shrink-0 accent-primary"
                checked={includeSecrets}
                disabled={busy}
                onChange={(event) => {
                  clearPassphrases();
                  setIncludeSecrets(event.target.checked);
                }}
              />
              <span>{t("archive.includeSecrets")}</span>
            </label>
            {includeSecrets ? (
              <>
                <Field
                  ref={passphrase}
                  label={t("archive.passphrase")}
                  type="password"
                  autoComplete="new-password"
                  disabled={busy}
                  hint={t("archive.exportPassphrase")}
                  onChange={checkPassphrases}
                />
                <Field
                  ref={confirmation}
                  label={t("create.confirm")}
                  type="password"
                  autoComplete="new-password"
                  disabled={busy}
                  error={passphraseMismatch ? t("passphrase.mismatch") : undefined}
                  onChange={checkPassphrases}
                />
              </>
            ) : null}
            <p className="m-0 text-muted-foreground">{t("archive.deviceExcluded")}</p>
          </>
        ) : null}
      </form>
    </Dialog>
  );
}

export function portableArchiveErrorText(t: ReturnType<typeof useI18n>["t"], error: PortableArchiveError): string {
  return t(`archive.error.${error}`);
}
