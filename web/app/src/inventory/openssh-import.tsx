// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Select, Tag } from "@scoplen/ui";
import { useId, useState } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type OpenSshImportChoice,
  type OpenSshImportEntry,
  type OpenSshImportError,
  type OpenSshImportPreview,
  type OpenSshImportResult,
  type OpenSshSkipReason,
} from "./api";

export function OpenSshImportDialog({
  initial,
  onClose,
  onImported,
}: {
  initial: OpenSshImportPreview;
  onClose: () => void;
  onImported: (result: OpenSshImportResult) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const [preview, setPreview] = useState(initial);
  const [choices, setChoices] = useState(initial.choices);
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  const unresolved = preview.entries.filter((entry) => entry.needsCredential).length;
  const counts = {
    created: preview.entries.filter((entry) => entry.action === "create").length,
    updated: preview.entries.filter((entry) => entry.action === "update").length,
    unchanged: preview.entries.filter((entry) => entry.action === "unchanged").length,
  };

  const refresh = async (next = choices) => {
    if (busy) return;
    setBusy(true);
    setStale(true);
    setError(null);
    try {
      const result = await api.previewOpenSshConfig(preview.path, next);
      if (result.status === "ok") {
        setPreview(result.data);
        setChoices(result.data.choices);
        setStale(false);
      } else setError(`${t("import.previewError")} ${openSshImportErrorText(t, result.error)}`);
    } catch {
      setError(t("import.error.refresh"));
    } finally {
      setBusy(false);
    }
  };

  const choose = (entry: OpenSshImportEntry, value: string) => {
    const next: OpenSshImportChoice[] = choices.filter((choice) => choice.alias !== entry.alias);
    if (value) {
      next.push({
        alias: entry.alias,
        identityFile: value.startsWith("file:") ? value.slice(5) : null,
        credentialId: value.startsWith("credential:") ? value.slice(11) : null,
      });
    }
    setChoices(next);
    void refresh(next);
  };

  const confirm = async () => {
    if (busy || stale || unresolved || preview.entries.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.importOpenSshConfig(preview);
      if (result.status === "ok") onImported(result.data);
      else {
        setStale(true);
        setError(`${t("import.error")} ${openSshImportErrorText(t, result.error)}`);
      }
    } catch {
      setStale(true);
      setError(t("import.error.unexpected"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !busy && onClose()}
      title={t("import.title")}
      closeLabel={t("import.close")}
      footer={
        <>
          <Button variant="ghost" autoFocus disabled={busy} onClick={onClose}>
            {t("import.cancel")}
          </Button>
          <Button variant="secondary" disabled={busy} onClick={() => void refresh()}>
            {t("import.refresh")}
          </Button>
          <Button
            variant="primary"
            busy={busy}
            disabled={stale || unresolved > 0 || preview.entries.length === 0}
            onClick={() => void confirm()}
          >
            {t("import.confirm")}
          </Button>
        </>
      }
    >
      <div className="space-y-5 text-sm">
        <div className="space-y-2">
          <p className="m-0 break-all text-muted-foreground">{t("import.file", { path: preview.path })}</p>
          <p className="m-0">{t("import.body", { count: preview.files })}</p>
          <p className="m-0 font-medium">{t("import.summary", counts)}</p>
          {counts.updated > 0 ? <p className="m-0 text-attention">{t("import.updates")}</p> : null}
          {unresolved > 0 ? (
            <p className="m-0 text-attention" role="status">
              {t("import.credentialsRequired", { count: unresolved })}
            </p>
          ) : null}
          {busy ? (
            <p className="m-0 text-muted-foreground" role="status">
              {t("import.working")}
            </p>
          ) : null}
        </div>
        <section aria-labelledby={`${id}-ready`}>
          <h3 id={`${id}-ready`} className="m-0 font-medium">
            {t("import.ready", { count: preview.entries.length })}
          </h3>
          {preview.entries.length === 0 ? (
            <p>{t("import.none")}</p>
          ) : (
            <ul className="mt-2 mb-0 list-none divide-y divide-border p-0">
              {preview.entries.map((entry, index) => {
                const choice = choices.find((item) => item.alias === entry.alias);
                const identityFile = choice ? choice.identityFile : entry.identityFile;
                const credentialId = choice ? choice.credentialId : entry.credentialId;
                const value = identityFile ? `file:${identityFile}` : credentialId ? `credential:${credentialId}` : "";
                const fieldId = `${id}-identity-${index}`;
                return (
                  <li key={entry.alias} className="space-y-2 py-3 first:pt-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="break-all font-medium">{entry.alias}</span>
                      <Tag>{t(`import.action.${entry.action}`)}</Tag>
                    </div>
                    <p className="m-0 break-all font-mono text-xs">
                      {entry.username}@{entry.address}
                      {entry.port === 22 ? "" : `:${entry.port}`}
                    </p>
                    <p className="m-0 break-all text-xs text-muted-foreground">
                      {entry.sourceFile} · {t("import.line", { line: entry.line })}
                    </p>
                    <p className="m-0 break-all text-muted-foreground">
                      {entry.route.kind === "direct"
                        ? t("host.route.direct")
                        : entry.route.kind === "jump"
                          ? t("import.route.jump", { hops: entry.route.hops.join(" → ") })
                          : t("import.route.command", { command: entry.route.command })}
                    </p>
                    <p className="m-0 text-xs text-muted-foreground">
                      {t("import.trustRecords", { count: entry.trustRecords })}
                    </p>
                    <div className="flex min-w-0 flex-col gap-1.5">
                      <label htmlFor={fieldId} className="font-medium">
                        {t("import.identity", { alias: entry.alias })}
                      </label>
                      <Select
                        id={fieldId}
                        label={t("import.identity", { alias: entry.alias })}
                        size="field"
                        className="w-full"
                        value={value}
                        disabled={busy}
                        onValueChange={(next) => choose(entry, next)}
                        options={[
                          { value: "", label: t("import.identity.default") },
                          ...entry.identityFiles.map((path) => ({
                            value: `file:${path}`,
                            label: path,
                            group: t("import.identity.files"),
                          })),
                          ...preview.eligibleCredentials.map((credential) => ({
                            value: `credential:${credential.id}`,
                            label: credential.name ?? t(`objects.credential.kind.${credential.kind}`),
                            group: t("import.identity.saved"),
                          })),
                        ]}
                      />
                      {identityFile ? (
                        <p className="m-0 break-all font-mono text-xs text-muted-foreground">{identityFile}</p>
                      ) : null}
                      {entry.needsCredential ? (
                        <p className="m-0 text-xs text-attention">
                          {entry.identityFiles.length || preview.eligibleCredentials.length
                            ? t("import.identity.choose")
                            : t("import.identity.none")}
                        </p>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
        {preview.skippedHosts.length > 0 ? (
          <section aria-labelledby={`${id}-skipped`}>
            <h3 id={`${id}-skipped`} className="m-0 font-medium">
              {t("import.skipped", { count: preview.skippedHosts.length })}
            </h3>
            <ul className="mt-2 mb-0 list-none space-y-2 p-0">
              {preview.skippedHosts.map((host, index) => (
                <li key={index} className="break-all">
                  <span className="font-medium">{host.alias}</span>
                  {" · "}
                  {openSshSkipReasonText(t, host.reason)}
                  <p className="m-0 text-xs text-muted-foreground">
                    {host.sourceFile} · {t("import.line", { line: host.line })}
                  </p>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
        {preview.unsupported.length > 0 ? (
          <section aria-labelledby={`${id}-unsupported`}>
            <h3 id={`${id}-unsupported`} className="m-0 font-medium">
              {t("import.unsupported", { count: preview.unsupported.length })}
            </h3>
            <ul className="mt-2 mb-0 list-none space-y-2 p-0 text-muted-foreground">
              {preview.unsupported.map((item, index) => (
                <li key={index} className="break-all">
                  <span>
                    {t("import.line", { line: item.line })}: {item.directive}
                  </span>
                  <p className="m-0 text-xs">{item.sourceFile}</p>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
        {stale && !busy ? <p className="m-0 text-attention">{t("import.reviewAgain")}</p> : null}
        {error ? (
          <p role="alert" className="m-0 break-words text-attention">
            {error}
          </p>
        ) : null}
      </div>
    </Dialog>
  );
}

export function openSshImportErrorText(t: ReturnType<typeof useI18n>["t"], error: OpenSshImportError): string {
  switch (error.kind) {
    case "fileNotFound":
      return t("import.error.fileNotFound");
    case "notText":
      return t("import.error.notText");
    case "tooLarge":
      return t("import.error.tooLarge");
    case "sourceChanged":
      return t("import.error.sourceChanged");
    case "inventoryChanged":
      return t("import.error.inventoryChanged");
    case "credentialsRequired":
      return t("import.error.credentialsRequired");
    case "credentialUnavailable":
      return t("import.error.credentialUnavailable", { alias: error.alias });
    case "noHosts":
      return t("import.error.noHosts");
    case "identityNotFound":
      return t("import.error.identityNotFound", { path: error.path });
    case "failed":
      return t("startup.error.reference", { reference: error.reference });
  }
}

function openSshSkipReasonText(t: ReturnType<typeof useI18n>["t"], reason: OpenSshSkipReason): string {
  switch (reason.kind) {
    case "unsupportedDirective":
      return t("import.skip.unsupportedDirective", { directive: reason.directive });
    case "globalRules":
      return t("import.skip.globalRules", { directive: reason.directive });
    case "routeDependency":
      return t("import.skip.routeDependency", { alias: reason.alias });
    case "invalidValue":
      return t("import.skip.invalidValue", { directive: reason.directive });
  }
}
