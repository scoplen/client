// SPDX-License-Identifier: Apache-2.0
import { Button, IconButton } from "@scoplen/ui";
import { Download, File, Folder, RefreshCw, Upload, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type RemoteFileEntry, type SessionUploadResult } from "./ipc/bindings";

type Location = { name: string; path: number[] };
type Activity = "listing" | "downloading" | "uploading" | "cancelling" | "waiting" | null;
type FileError = { message: string; listing: boolean };
type UploadFeedback = Pick<SessionUploadResult, "status" | "stagingMayRemain">;

export type UploadOutcome = UploadFeedback & {
  transportId: string;
  operationId: string;
};

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/** File access stays attached to one authenticated terminal transport. */
export function SessionFiles({
  sessionId,
  transportId,
  onClose,
  onUploadOutcome,
}: {
  sessionId: string;
  transportId: string;
  onClose: () => void;
  onUploadOutcome: (outcome: UploadOutcome) => void;
}) {
  const { t, locale } = useI18n();
  const [locations, setLocations] = useState<Location[]>([{ name: "", path: [46] }]);
  const [entries, setEntries] = useState<RemoteFileEntry[]>([]);
  const [activity, setActivity] = useState<Activity>("listing");
  const [error, setError] = useState<FileError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [uploadFeedback, setUploadFeedback] = useState<UploadFeedback | null>(null);
  const [reload, setReload] = useState(0);
  const operation = useRef<string | null>(null);
  const cancelled = useRef<string | null>(null);
  const pendingCancellation = useRef<Promise<unknown>>(Promise.resolve());
  const mounted = useRef(true);
  const translator = useRef(t);
  const currentPath = locations[locations.length - 1]!.path;

  useEffect(() => {
    translator.current = t;
  }, [t]);

  const cancelCurrent = useCallback(() => {
    const id = operation.current;
    if (!id) return;
    operation.current = null;
    pendingCancellation.current = commands
      .sessionCancelFileOperation(sessionId, transportId, id)
      .catch(() => undefined);
  }, [sessionId, transportId]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelCurrent();
    };
  }, [cancelCurrent]);

  useEffect(() => {
    let current = true;
    let id: string | null = null;
    void (async () => {
      await pendingCancellation.current;
      if (!current || !mounted.current) return;
      setActivity("listing");
      setError(null);
      setNotice(null);
      setEntries([]);
      id = crypto.randomUUID();
      operation.current = id;
      try {
        const result = await commands.sessionListFiles(sessionId, transportId, id, currentPath);
        if (!current || !mounted.current || operation.current !== id) return;
        if (result.status === "error") {
          if (cancelled.current === id) setNotice(translator.current("session.files.cancelled"));
          else setError({ message: result.error, listing: true });
        } else setEntries(result.data.entries);
      } catch (cause) {
        if (!current || !mounted.current || operation.current !== id) return;
        if (cancelled.current === id) setNotice(translator.current("session.files.cancelled"));
        else setError({ message: message(cause), listing: true });
      } finally {
        if (current && mounted.current && operation.current === id) {
          operation.current = null;
          cancelled.current = null;
          setActivity(null);
        }
      }
    })();
    return () => {
      current = false;
      if (operation.current === id) cancelCurrent();
    };
  }, [cancelCurrent, sessionId, transportId, currentPath, reload]);

  const download = (entry: RemoteFileEntry) => {
    if (activity || operation.current || entry.kind !== "file") return;
    const id = crypto.randomUUID();
    operation.current = id;
    setActivity("downloading");
    setError(null);
    setNotice(null);
    setUploadFeedback(null);
    void commands
      .sessionDownloadFile(sessionId, transportId, id, entry.path)
      .then((result) => {
        if (!mounted.current || operation.current !== id) return;
        if (result.status === "error") {
          if (cancelled.current === id) setNotice(translator.current("session.files.cancelled"));
          else setError({ message: result.error, listing: false });
        } else setNotice(translator.current(result.data ? "session.files.saved" : "session.files.saveCancelled"));
      })
      .catch((cause: unknown) => {
        if (!mounted.current || operation.current !== id) return;
        if (cancelled.current === id) setNotice(translator.current("session.files.cancelled"));
        else setError({ message: message(cause), listing: false });
      })
      .finally(() => {
        if (!mounted.current || operation.current !== id) return;
        operation.current = null;
        cancelled.current = null;
        setActivity(null);
      });
  };

  const upload = () => {
    if (activity || operation.current) return;
    const id = crypto.randomUUID();
    operation.current = id;
    setActivity("uploading");
    setError(null);
    setNotice(null);
    setUploadFeedback(null);
    const report = (result: SessionUploadResult) => {
      const current = mounted.current && operation.current === id;
      if (result.status === "unknown" || result.stagingMayRemain) {
        onUploadOutcome({
          transportId,
          operationId: id,
          status: result.status,
          stagingMayRemain: result.stagingMayRemain,
        });
      }
      if (!current || result.status === "unknown") return;
      setUploadFeedback({ status: result.status, stagingMayRemain: result.stagingMayRemain });
      if (result.status === "saved") setReload((value) => value + 1);
    };
    void commands
      .sessionUploadFile(sessionId, transportId, id, currentPath, locale === "zh-Hans" ? "zh-Hans" : "en")
      .then((result) =>
        report(result.status === "ok" ? result.data : { status: "failed", message: null, stagingMayRemain: false }),
      )
      .catch(() => report({ status: "unknown", message: null, stagingMayRemain: true }))
      .finally(() => {
        if (!mounted.current || operation.current !== id) return;
        operation.current = null;
        cancelled.current = null;
        setActivity(null);
      });
  };

  const cancel = () => {
    const id = operation.current;
    if (!id || activity === "cancelling" || activity === "waiting") return;
    cancelled.current = id;
    setActivity("cancelling");
    void commands
      .sessionCancelFileOperation(sessionId, transportId, id)
      .then((result) => {
        if (result.status === "error" && mounted.current && operation.current === id) setActivity("waiting");
      })
      .catch(() => {
        if (mounted.current && operation.current === id) setActivity("waiting");
      });
  };

  return (
    <section
      aria-label={t("session.files.title")}
      className="flex h-56 min-h-0 min-w-0 shrink-0 flex-col border-t border-border bg-background lg:h-auto lg:w-80 lg:border-t-0 lg:border-l"
    >
      <header className="flex shrink-0 items-center justify-between gap-2 px-3 py-2">
        <h2 className="m-0 text-sm font-semibold">{t("session.files.title")}</h2>
        <div className="flex min-w-0 items-center gap-1">
          <Button variant="ghost" className="gap-1 px-2" disabled={activity !== null} onClick={upload}>
            <Upload aria-hidden="true" className="size-4" />
            {t("session.files.upload.action")}
          </Button>
          <IconButton
            label={t("session.files.refresh")}
            disabled={activity !== null}
            onClick={() => setReload((value) => value + 1)}
          >
            <RefreshCw aria-hidden="true" className="size-4" />
          </IconButton>
          <IconButton label={t("session.files.close")} onClick={onClose}>
            <X aria-hidden="true" className="size-4" />
          </IconButton>
        </div>
      </header>
      <nav
        aria-label={t("session.files.location")}
        className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-border px-2 pb-2"
      >
        {locations.map((item, index) => {
          const name = index === 0 ? t("session.files.home") : item.name;
          return index === locations.length - 1 ? (
            <span
              key={`${index}-${item.path.join(",")}`}
              aria-current="location"
              title={name}
              className="max-w-40 shrink-0 truncate px-2 text-sm font-medium"
            >
              {name}
            </span>
          ) : (
            <Button
              key={`${index}-${item.path.join(",")}`}
              variant="ghost"
              disabled={activity !== null}
              title={name}
              className="max-w-40 shrink-0 px-2"
              onClick={() => {
                setUploadFeedback(null);
                setLocations((current) => current.slice(0, index + 1));
              }}
            >
              <span className="truncate">{name}</span>
            </Button>
          );
        })}
      </nav>
      {activity ? (
        <div className="flex shrink-0 items-center justify-between gap-2 px-3 py-2 text-xs" role="status">
          <span>{t(`session.files.${activity}`)}</span>
          <Button variant="ghost" disabled={activity === "cancelling" || activity === "waiting"} onClick={cancel}>
            {t("session.files.cancel")}
          </Button>
        </div>
      ) : null}
      {error ? (
        <div role="alert" className="px-3 py-2 text-xs text-attention">
          <p className="m-0">{t("session.files.error")}</p>
          <p className="m-0 mt-1 break-words">{error.message}</p>
          {error.listing ? (
            <Button variant="ghost" onClick={() => setReload((current) => current + 1)}>
              {t("session.files.retry")}
            </Button>
          ) : null}
        </div>
      ) : null}
      {notice ? (
        <p role="status" className="m-0 px-3 py-2 text-xs">
          {notice}
        </p>
      ) : null}
      {uploadFeedback ? (
        <div
          role={uploadFeedback.status === "saved" || uploadFeedback.status === "cancelled" ? "status" : "alert"}
          className={`px-3 py-2 text-xs ${uploadFeedback.status === "saved" || uploadFeedback.status === "cancelled" ? "" : "text-attention"}`}
        >
          <p className="m-0">{t(`session.files.upload.${uploadFeedback.status}`)}</p>
          {uploadFeedback.stagingMayRemain ? <p className="m-0 mt-1">{t("session.files.upload.staging")}</p> : null}
        </div>
      ) : null}
      <div className="min-h-0 flex-1 overflow-auto px-2 pb-2">
        {!activity && !error && entries.length === 0 ? (
          <p className="m-0 px-1 py-2 text-xs text-muted-foreground">{t("session.files.empty")}</p>
        ) : null}
        <ul className="m-0 list-none p-0">
          {entries.map((entry) => (
            <li
              key={entry.path.join(",")}
              className="flex min-w-0 items-center gap-2 border-b border-border/50 px-1 py-1.5 last:border-0"
            >
              {entry.kind === "directory" ? (
                <Folder aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
              ) : (
                <File aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
              )}
              {entry.kind === "directory" ? (
                <button
                  type="button"
                  disabled={activity !== null}
                  title={entry.name}
                  className="min-w-0 flex-1 truncate text-left text-sm text-foreground underline-offset-2 hover:underline focus-visible:rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:opacity-50"
                  onClick={() => {
                    setUploadFeedback(null);
                    setLocations((current) => [...current, { name: entry.name, path: entry.path }]);
                  }}
                >
                  {entry.name}
                </button>
              ) : (
                <span className="min-w-0 flex-1 truncate text-sm" title={entry.name}>
                  {entry.name}
                </span>
              )}
              {entry.kind === "file" ? (
                <IconButton
                  label={t("session.files.download", { name: entry.name })}
                  disabled={activity !== null}
                  onClick={() => download(entry)}
                >
                  <Download aria-hidden="true" className="size-4" />
                </IconButton>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
