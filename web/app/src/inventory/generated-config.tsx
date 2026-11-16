// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useEffect, useId, useRef, useState, type RefObject } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type OpenSshExportChoice,
  type OpenSshGeneratedError,
  type OpenSshGeneratedPreview,
  type OpenSshGeneratedResult,
  type OpenSshGeneratedStatus,
} from "./api";
import { OpenSshExportReport } from "./openssh-export";

export function GeneratedConfigSettings() {
  const api = useInventory();
  const { t } = useI18n();
  const id = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [initial, setInitial] = useState<{
    status: OpenSshGeneratedStatus;
    preview: OpenSshGeneratedPreview;
  } | null>(null);

  const prepare = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const status = await api.generatedOpenSshStatus();
      if (status.status === "error") {
        setError(generatedConfigErrorText(t, status.error));
        return;
      }
      const preview = await api.generatedOpenSshPreview();
      if (preview.status === "ok") setInitial({ status: status.data, preview: preview.data });
      else setError(generatedConfigErrorText(t, preview.error));
    } catch {
      setError(t("include.error.load"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby={`${id}-title`} className="mt-8 border-t border-border pt-6">
      <h3 id={`${id}-title`} className="text-sm font-medium">
        {t("include.title")}
      </h3>
      <p className="mt-2 max-w-lg text-sm text-muted-foreground">{t("include.body")}</p>
      <Button ref={trigger} className="mt-4" busy={busy} onClick={() => void prepare()}>
        {t("include.manage")}
      </Button>
      {error ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {error}
        </p>
      ) : null}
      {initial ? (
        <GeneratedConfigDialog initial={initial} finalFocus={trigger} onClose={() => setInitial(null)} />
      ) : null}
    </section>
  );
}

function IncludeLine({ status }: { status: OpenSshGeneratedStatus }) {
  const { t } = useI18n();
  return (
    <div className="space-y-2">
      <p className="m-0 font-medium">
        {t(status.destination.scope === "local" ? "archive.destination.local" : "archive.destination.personal")}
      </p>
      <p className="m-0 text-muted-foreground">{t("include.instructions")}</p>
      <p className="m-0 break-all rounded-md border border-border bg-surface p-3 font-mono text-xs select-all">
        <code>{status.includeLine}</code>
      </p>
    </div>
  );
}

function GeneratedConfigDialog({
  initial,
  finalFocus,
  onClose,
}: {
  initial: { status: OpenSshGeneratedStatus; preview: OpenSshGeneratedPreview };
  finalFocus: RefObject<HTMLButtonElement | null>;
  onClose: () => void;
}) {
  const api = useInventory();
  const { t } = useI18n();
  const id = useId();
  const [status, setStatus] = useState(initial.status);
  const [preview, setPreview] = useState(initial.preview);
  const [choices, setChoices] = useState(initial.preview.report.choices);
  const [busy, setBusy] = useState(false);
  const [stale, setStale] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generated, setGenerated] = useState<OpenSshGeneratedResult | null>(null);
  const [cleared, setCleared] = useState<OpenSshGeneratedStatus | null>(null);
  const feedback = useRef<HTMLDivElement>(null);
  const refreshButton = useRef<HTMLButtonElement>(null);
  const restoreFocus = useRef(false);
  const complete = generated !== null || cleared !== null;

  useEffect(
    () => () => {
      void api.generatedOpenSshDiscard().catch(() => undefined);
    },
    [api],
  );

  useEffect(() => {
    if (busy || !restoreFocus.current) return;
    restoreFocus.current = false;
    if (error || complete) feedback.current?.focus();
    else refreshButton.current?.focus();
  }, [busy, error, complete]);

  const load = async (next: OpenSshExportChoice[]) => {
    setStale(true);
    let result = await api.generatedOpenSshPreview(next);
    if (result.status === "error" && result.error.kind === "invalidSelection" && next.length > 0) {
      setError(generatedConfigErrorText(t, result.error));
      result = await api.generatedOpenSshPreview();
    }
    if (result.status === "ok") {
      setPreview(result.data);
      setChoices(result.data.report.choices);
      setStale(false);
    } else setError(generatedConfigErrorText(t, result.error));
  };

  const refresh = async () => {
    if (busy) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    try {
      await load(choices);
    } catch {
      setError(t("include.error.load"));
    } finally {
      setBusy(false);
    }
  };

  const chooseIdentity = async (profileId: string) => {
    if (busy) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    try {
      const path = await api.chooseKeyFile();
      if (!path) return;
      const next = [...choices.filter((choice) => choice.profileId !== profileId), { profileId, identityFile: path }];
      setChoices(next);
      await load(next);
    } catch {
      setError(t("include.error.load"));
    } finally {
      setBusy(false);
    }
  };

  const generate = async () => {
    if (busy || stale || complete) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    setStale(true);
    try {
      const result = await api.generatedOpenSshGenerate(preview.id);
      if (result.status === "ok") setGenerated(result.data);
      else setError(generatedConfigErrorText(t, result.error));
    } catch {
      setError(t("include.error.generate"));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    if (busy || complete) return;
    restoreFocus.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await api.generatedOpenSshClear();
      if (result.status === "ok") setCleared(result.data);
      else {
        setError(generatedConfigErrorText(t, result.error));
        if (result.error.kind === "clearFailed") {
          const current = await api.generatedOpenSshStatus();
          if (current.status === "ok") setStatus(current.data);
        }
      }
    } catch {
      setError(t("include.error.clear"));
    } finally {
      setConfirmClear(false);
      setStale(true);
      setBusy(false);
    }
  };

  return (
    <Dialog
      open
      title={t(confirmClear ? "include.clearTitle" : "include.review")}
      closeLabel={t("export.close")}
      finalFocus={finalFocus}
      onOpenChange={(open) => {
        if (open || busy) return;
        if (confirmClear) setConfirmClear(false);
        else onClose();
      }}
      footer={
        complete ? (
          <Button variant="primary" onClick={onClose}>
            {t("export.done")}
          </Button>
        ) : confirmClear ? (
          <>
            <Button variant="ghost" autoFocus disabled={busy} onClick={() => setConfirmClear(false)}>
              {t("import.cancel")}
            </Button>
            <Button variant="destructive" busy={busy} onClick={() => void clear()}>
              {t("include.clear")}
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" autoFocus disabled={busy} onClick={onClose}>
              {t("import.cancel")}
            </Button>
            <Button ref={refreshButton} variant="secondary" disabled={busy} onClick={() => void refresh()}>
              {t("import.refresh")}
            </Button>
            <Button variant="primary" busy={busy} disabled={stale} onClick={() => void generate()}>
              {t(status.active ? "include.regenerate" : "include.generate")}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-5 text-sm">
        {complete || error ? (
          <div ref={feedback} tabIndex={-1} className="space-y-2 outline-none">
            {complete ? (
              <div role="status" className="space-y-3">
                <p className="m-0 font-medium">
                  {generated ? t("include.generated", { count: generated.hosts }) : t("include.cleared")}
                </p>
                <IncludeLine status={generated?.status ?? cleared!} />
              </div>
            ) : null}
            {error ? (
              <p role="alert" className="m-0 break-all text-attention">
                {error}
              </p>
            ) : null}
          </div>
        ) : null}
        {confirmClear ? (
          <p className="m-0">{t("include.clearBody")}</p>
        ) : !complete ? (
          <>
            <IncludeLine status={status} />
            <p className="m-0 text-muted-foreground">{t("export.secrets")}</p>
            <p className="m-0 font-medium">
              {t("export.summary", {
                count: preview.report.entries.length,
                skipped: preview.report.skipped.length,
                trust: preview.report.trustRecords,
              })}
            </p>
            {preview.report.entries.length === 0 ? <p className="m-0">{t("include.empty")}</p> : null}
            <section aria-labelledby={`${id}-aliases`}>
              <h3 id={`${id}-aliases`} className="m-0 font-medium">
                {t("include.aliases")}
              </h3>
              <ul className="mt-2 mb-0 list-none space-y-3 p-0">
                {preview.aliases.map((alias) => (
                  <li key={alias.hostId} className="space-y-1">
                    <p className="m-0 break-all font-medium">{alias.hostName}</p>
                    {alias.alias ? <p className="m-0 break-all font-mono text-xs">{`ssh ${alias.alias}`}</p> : null}
                    {alias.problem ? (
                      <p className="m-0 text-muted-foreground">{t(`include.alias.${alias.problem}`)}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
            <OpenSshExportReport
              preview={preview.report}
              choices={choices}
              busy={busy}
              onChooseIdentity={chooseIdentity}
            />
            {busy ? (
              <p role="status" className="m-0 text-muted-foreground">
                {t("export.working")}
              </p>
            ) : null}
            {stale && !busy ? <p className="m-0 text-attention">{t("import.reviewAgain")}</p> : null}
            <div className="border-t border-border pt-4">
              <Button
                variant="secondary"
                disabled={busy}
                onClick={() => {
                  setError(null);
                  setConfirmClear(true);
                }}
              >
                {t("include.clear")}
              </Button>
            </div>
          </>
        ) : null}
      </div>
    </Dialog>
  );
}

export function generatedConfigErrorText(t: ReturnType<typeof useI18n>["t"], error: OpenSshGeneratedError): string {
  if (error.kind === "writeFailed") {
    return error.directory ? t("include.error.partial", { path: error.directory }) : t("include.error.writeFailed");
  }
  if (error.kind === "clearFailed") return t("include.error.clearFailed", { path: error.directory });
  return t(`include.error.${error.kind}`);
}
