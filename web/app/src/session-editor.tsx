// SPDX-License-Identifier: Apache-2.0
import { Button } from "@scoplen/ui";
import { useI18n } from "./i18n";
import type { useSessionEditor } from "./use-session-editor";

export function SessionEditor({
  editor,
  transportId,
  active,
  queueAvailable,
}: {
  editor: ReturnType<typeof useSessionEditor>;
  transportId: string | null;
  active: boolean;
  queueAvailable: boolean;
}) {
  const { t, locale } = useI18n();
  const { snapshot, pending, loading } = editor;
  if (!snapshot && !editor.issue) return null;
  const issue = editor.issue ?? snapshot?.issue;
  const busy = pending !== null || loading;
  const connected = !!snapshot && transportId === snapshot.transportId;
  const uploadable =
    snapshot?.state === "changesDetected" || snapshot?.state === "uploaded" || snapshot?.state === "watching";
  return (
    <section aria-label={t("session.editor.title")} className="shrink-0 border-b border-border px-3 py-3 text-xs">
      <h3 className="m-0 text-sm font-semibold">{t("session.editor.title")}</h3>
      {snapshot ? (
        <>
          <p className="my-2 min-w-0 break-words" title={snapshot.remoteName}>
            {t("session.editor.target", { name: snapshot.remoteName })}
          </p>
          {snapshot.localName ? (
            <p className="my-2 min-w-0 break-words text-muted-foreground" title={snapshot.localName}>
              {t("session.editor.copy", { name: snapshot.localName })}
            </p>
          ) : null}
          <p role="status" className="my-2">
            {t(`session.editor.state.${snapshot.state}`)}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="ghost"
              className="px-2"
              disabled={!active || busy || !snapshot.canOpen}
              busy={pending === "open"}
              onClick={() => void editor.open()}
            >
              {t("session.editor.open")}
            </Button>
            <Button
              variant="primary"
              className="px-2"
              disabled={!active || busy || !connected || !queueAvailable || !uploadable}
              busy={pending === "upload"}
              onClick={() => void editor.upload(locale === "zh-Hans" ? "zh-Hans" : "en")}
            >
              {t("session.editor.upload")}
            </Button>
            <Button
              variant="ghost"
              className="px-2"
              disabled={!active || busy}
              busy={pending === "stop"}
              onClick={() => void editor.stop()}
            >
              {t("session.editor.stop")}
            </Button>
          </div>
          <p className="mb-0 mt-2 text-muted-foreground">{t("session.editor.keepCopy")}</p>
        </>
      ) : null}
      {issue ? (
        <div role="alert" className="mt-2 text-attention">
          <p className="m-0">{t(`session.editor.issue.${issue}`)}</p>
          {!snapshot ? (
            <Button variant="ghost" disabled={!active || busy} onClick={editor.retry}>
              {t("session.files.retry")}
            </Button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
