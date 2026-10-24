// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useCallback, useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type RemoteFileEntry, type RemoteTextPreview, type RemoteTextPreviewIssue } from "./ipc/bindings";

type PreviewState =
  | { kind: "loading" }
  | { kind: "ready"; preview: RemoteTextPreview }
  | { kind: "error"; issue: RemoteTextPreviewIssue };

/** Only this mounted dialog retains text from one explicit request. */
export function SessionFilePreview({
  sessionId,
  transportId,
  connectionLabel,
  entry,
  onClose,
}: {
  sessionId: string;
  transportId: string;
  connectionLabel: string;
  entry: RemoteFileEntry;
  onClose: () => void;
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<PreviewState>({ kind: "loading" });
  const operation = useRef<string | null>(null);
  const pendingCancellation = useRef<Promise<unknown>>(Promise.resolve());
  const closing = useRef(false);

  const cancel = useCallback(() => {
    const id = operation.current;
    operation.current = null;
    if (id)
      pendingCancellation.current = commands
        .sessionCancelFileOperation(sessionId, transportId, id)
        .catch(() => undefined);
    return pendingCancellation.current;
  }, [sessionId, transportId]);

  useEffect(() => {
    let current = true;
    void (async () => {
      await pendingCancellation.current;
      if (!current || closing.current) return;
      setState({ kind: "loading" });
      const id = crypto.randomUUID();
      operation.current = id;
      try {
        const result = await commands.sessionPreviewFile(sessionId, transportId, id, entry.path);
        if (!current || operation.current !== id) return;
        setState(
          result.status === "ok" ? { kind: "ready", preview: result.data } : { kind: "error", issue: result.error },
        );
      } catch {
        if (current && operation.current === id) setState({ kind: "error", issue: "failed" });
      } finally {
        if (operation.current === id) operation.current = null;
      }
    })();
    return () => {
      current = false;
      void cancel();
    };
  }, [sessionId, transportId, entry.path, attempt, cancel]);

  const close = () => {
    if (closing.current) return;
    closing.current = true;
    setState({ kind: "loading" });
    setOpen(false);
    void cancel().finally(onClose);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) close();
      }}
      title={t("session.files.preview.title", { name: entry.name })}
      description={t("session.files.preview.description", { connection: connectionLabel })}
      closeLabel={t("session.files.preview.close")}
      footer={
        <>
          {state.kind === "error" ? (
            <Button variant="ghost" onClick={() => setAttempt((value) => value + 1)}>
              {t("session.files.retry")}
            </Button>
          ) : null}
          <Button variant="primary" onClick={close}>
            {t("session.files.preview.close")}
          </Button>
        </>
      }
    >
      {state.kind === "loading" ? (
        <p role="status" className="m-0 text-sm">
          {t("session.files.preview.loading")}
        </p>
      ) : null}
      {state.kind === "error" ? (
        <div role="alert" className="text-sm text-attention">
          <p className="m-0">{t(`session.files.preview.issue.${state.issue}`)}</p>
          <p className="mb-0 mt-2 text-muted-foreground">{t("session.files.preview.downloadHint")}</p>
        </div>
      ) : null}
      {state.kind === "ready" ? (
        <>
          <p className="mt-0 mb-3 text-xs text-muted-foreground">
            {t("session.files.preview.bytes", { bytes: state.preview.sizeBytes })}
          </p>
          {state.preview.text === "" ? (
            <p role="status" className="m-0 text-sm">
              {t("session.files.preview.empty")}
            </p>
          ) : (
            <pre
              aria-label={t("session.files.preview.content")}
              tabIndex={0}
              dir="auto"
              style={{ unicodeBidi: "plaintext" }}
              className="m-0 max-h-[42vh] overflow-auto rounded border border-border bg-inset p-3 font-mono text-xs whitespace-pre focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
            >
              {state.preview.text}
            </pre>
          )}
        </>
      ) : null}
    </Dialog>
  );
}
