// SPDX-License-Identifier: Apache-2.0
import { useProfileCommands } from "./account-profiles";
import { Button, Dialog, Field, IconButton } from "@scoplen/ui";
import { Download, Eye, File, Folder, FolderPlus, Pencil, RefreshCw, Trash2, Upload, X } from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useI18n } from "./i18n";
import {
  type RemoteFileEntry,
  type SessionFileMutationResult,
  type SessionTransferIssue,
  type SessionTransferQueueSnapshot,
} from "./ipc/bindings";
import { SessionTransferQueue } from "./session-transfer-queue";
import { SessionFilePreview } from "./session-file-preview";
import { useSessionFileDrop } from "./use-session-file-drop";
import { SessionEditor } from "./session-editor";
import { useSessionEditor } from "./use-session-editor";

type Location = { name: string; path: number[] };
type Activity = "listing" | "creating" | "renaming" | "deleting" | "cancelling" | "waiting" | null;
type FileError = { message: string; listing: boolean };
type MutationKind = "create" | "rename" | "delete";
type MutationFeedback = { kind: MutationKind; status: SessionFileMutationResult["status"] };
type NameDialog = { kind: "create" } | { kind: "rename"; entry: RemoteFileEntry };
export type FileOperationOutcome = {
  transportId: string;
  operationId: string;
  status: SessionFileMutationResult["status"];
  stagingMayRemain: boolean;
};
export type EnqueueFeedback = {
  requestId: string;
  phase: "started" | "settled";
  issue: SessionTransferIssue | null;
};

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

/** File access stays attached to one authenticated terminal transport. */
export function SessionFiles({
  sessionId,
  transportId,
  connectionLabel,
  active,
  onClose,
  onFileOutcome,
  onEnqueueFeedback,
  queue,
  queueIssue,
}: {
  sessionId: string;
  transportId: string | null;
  connectionLabel: string;
  active: boolean;
  queue: SessionTransferQueueSnapshot | null;
  queueIssue: SessionTransferIssue | null;
  onClose: () => void;
  onFileOutcome: (outcome: FileOperationOutcome) => void;
  onEnqueueFeedback: (feedback: EnqueueFeedback) => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const formId = useId();
  const [locations, setLocations] = useState<Location[]>([{ name: "", path: [46] }]);
  const [entries, setEntries] = useState<RemoteFileEntry[]>([]);
  const [loadedLocation, setLoadedLocation] = useState<string | null>(null);
  const [activity, setActivity] = useState<Activity>(null);
  const [error, setError] = useState<FileError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enqueueIssue, setEnqueueIssue] = useState<SessionTransferIssue | null>(null);
  const [selecting, setSelecting] = useState(false);
  const selectionPending = useRef(false);
  const [mutationFeedback, setMutationFeedback] = useState<MutationFeedback | null>(null);
  const [nameDialog, setNameDialog] = useState<NameDialog | null>(null);
  const [name, setName] = useState("");
  const [reload, setReload] = useState(0);
  const [preview, setPreview] = useState<{ id: string; owner: string; entry: RemoteFileEntry } | null>(null);
  const [editDialog, setEditDialog] = useState<{ owner: string; entry: RemoteFileEntry } | null>(null);
  const operation = useRef<string | null>(null);
  const cancelled = useRef<string | null>(null);
  const pendingCancellation = useRef<Promise<unknown>>(Promise.resolve());
  const mounted = useRef(true);
  const previewFocus = useRef<{ owner: string; path: string } | null>(null);
  const previewButtons = useRef(new Map<string, HTMLButtonElement>());
  const dropList = useRef<HTMLDivElement>(null);
  const translator = useRef(t);
  const currentPath = locations[locations.length - 1]!.path;
  const previewOwner = `${sessionId}:${transportId}:${currentPath.join(",")}`;
  if (preview && (!active || preview.owner !== previewOwner)) setPreview(null);
  if (editDialog && (!active || editDialog.owner !== previewOwner)) setEditDialog(null);
  const previewOpen = active && preview?.owner === previewOwner;
  const editDialogOpen = active && editDialog?.owner === previewOwner;
  const editor = useSessionEditor(sessionId, transportId, active);
  const queueReady = queue !== null;
  const queueBlocked = !queueReady || !!queue?.blocksFileOperations;
  const fileOperationsDisabled =
    activity !== null || queueBlocked || !transportId || selecting || previewOpen || editDialogOpen;
  const selectionDisabled =
    activity !== null ||
    previewOpen ||
    editDialogOpen ||
    editor.pending === "start" ||
    !transportId ||
    !queueReady ||
    selecting ||
    !!queue?.pickerBusy ||
    (queue !== null && queue.outstanding >= queue.capacity);
  const dropEnabled =
    active &&
    loadedLocation === previewOwner &&
    activity === null &&
    !error &&
    !selecting &&
    !nameDialog &&
    !previewOpen &&
    !editDialogOpen &&
    editor.pending !== "start";
  const drop = useSessionFileDrop({
    sessionId,
    transportId,
    queueId: queue?.sessionId === sessionId ? queue.queueId : null,
    directoryPath: currentPath,
    enabled: dropEnabled,
    pickerBusy: queue?.pickerBusy ?? true,
    list: dropList,
    locale: locale === "zh-Hans" ? "zh-Hans" : "en",
    onEnqueueFeedback,
  });

  useEffect(() => {
    translator.current = t;
  }, [t]);

  useEffect(() => {
    if (!active || previewFocus.current?.owner !== previewOwner) {
      previewFocus.current = null;
      return;
    }
    if (previewOpen || activity !== null) return;
    const frame = requestAnimationFrame(() => {
      const target = previewFocus.current;
      const element = target ? previewButtons.current.get(target.path) : null;
      if (element?.isConnected && !element.disabled) {
        element.focus();
        previewFocus.current = null;
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [active, previewOwner, previewOpen, activity]);

  const cancelCurrent = useCallback(() => {
    const id = operation.current;
    if (!id || !transportId) return;
    operation.current = null;
    pendingCancellation.current = commands
      .sessionCancelFileOperation(sessionId, transportId, id)
      .catch(() => undefined);
  }, [sessionId, transportId, commands]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      cancelCurrent();
    };
  }, [cancelCurrent]);

  useEffect(() => {
    if (queueBlocked || !transportId || previewOpen) return;
    let current = true;
    let id: string | null = null;
    void (async () => {
      await pendingCancellation.current;
      if (!current || !mounted.current) return;
      setActivity("listing");
      setLoadedLocation(null);
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
        } else {
          setEntries(result.data.entries);
          setLoadedLocation(previewOwner);
        }
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
  }, [cancelCurrent, sessionId, transportId, currentPath, reload, queueBlocked, previewOpen, previewOwner, commands]);

  const enqueue = (entry?: RemoteFileEntry) => {
    if (selectionDisabled || selectionPending.current || !transportId || (entry && entry.kind !== "file")) return;
    selectionPending.current = true;
    setSelecting(true);
    setEnqueueIssue(null);
    const requestId = crypto.randomUUID();
    onEnqueueFeedback({ requestId, phase: "started", issue: null });
    const language = locale === "zh-Hans" ? "zh-Hans" : "en";
    const pending = entry
      ? commands.sessionEnqueueDownload(sessionId, transportId, entry.path, language)
      : commands.sessionEnqueueUpload(sessionId, transportId, currentPath, language);
    void pending
      .then((result) => {
        onEnqueueFeedback({ requestId, phase: "settled", issue: result.status === "error" ? result.error : null });
        if (!mounted.current) return;
        if (result.status === "error") setEnqueueIssue(result.error);
        else if (result.data.status === "cancelled")
          setNotice(translator.current("session.transfers.selectionCancelled"));
      })
      .catch(() => {
        onEnqueueFeedback({ requestId, phase: "settled", issue: "transferFailed" });
        if (mounted.current) setEnqueueIssue("transferFailed");
      })
      .finally(() => {
        selectionPending.current = false;
        if (mounted.current) setSelecting(false);
      });
  };

  const mutate = (
    kind: MutationKind,
    execute: (
      id: string,
    ) => Promise<{ status: "ok"; data: SessionFileMutationResult } | { status: "error"; error: string }>,
  ) => {
    if (fileOperationsDisabled || operation.current || !transportId) return;
    const id = crypto.randomUUID();
    operation.current = id;
    setActivity(kind === "create" ? "creating" : kind === "rename" ? "renaming" : "deleting");
    setError(null);
    setNotice(null);
    setMutationFeedback(null);
    const report = (result: SessionFileMutationResult) => {
      if (result.status === "unknown") {
        onFileOutcome({ transportId, operationId: id, status: "unknown", stagingMayRemain: false });
      }
      if (!mounted.current || operation.current !== id || result.status === "unknown") return;
      setMutationFeedback({ kind, status: result.status });
      if (result.status === "saved") setReload((value) => value + 1);
    };
    void execute(id)
      .then((result) => report(result.status === "ok" ? result.data : { status: "failed", message: null }))
      .catch(() => report({ status: "unknown", message: null }))
      .finally(() => {
        if (!mounted.current || operation.current !== id) return;
        operation.current = null;
        cancelled.current = null;
        setActivity(null);
      });
  };

  const submitName = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!nameDialog || !name.trim() || fileOperationsDisabled || operation.current || !transportId) return;
    const target = nameDialog;
    const newName = name;
    setNameDialog(null);
    setName("");
    const language = locale === "zh-Hans" ? "zh-Hans" : "en";
    if (target.kind === "create") {
      mutate("create", (id) =>
        commands.sessionCreateRemoteDirectory(sessionId, transportId, id, currentPath, newName, language),
      );
    } else {
      mutate("rename", (id) =>
        commands.sessionRenameRemoteEntry(
          sessionId,
          transportId,
          id,
          currentPath,
          target.entry.path,
          newName,
          language,
        ),
      );
    }
  };

  const deleteEntry = (entry: RemoteFileEntry) => {
    if (!transportId || (entry.kind !== "file" && entry.kind !== "directory")) return;
    mutate("delete", (id) =>
      commands.sessionDeleteRemoteEntry(
        sessionId,
        transportId,
        id,
        currentPath,
        entry.path,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      ),
    );
  };

  const cancel = () => {
    const id = operation.current;
    if (!id || !transportId || activity === "cancelling" || activity === "waiting") return;
    cancelled.current = id;
    setActivity("cancelling");
    void commands
      .sessionCancelFileOperation(sessionId, transportId, id)
      .then((result) => {
        if (result.status === "error" && mounted.current && operation.current === id) {
          cancelled.current = null;
          setActivity("waiting");
        }
      })
      .catch(() => {
        if (mounted.current && operation.current === id) {
          cancelled.current = null;
          setActivity("waiting");
        }
      });
  };

  return (
    <section
      aria-label={t("session.files.title")}
      className="flex h-[min(28rem,60vh)] min-h-0 min-w-0 shrink-0 flex-col overflow-y-auto border-t border-border bg-background lg:h-auto lg:w-80 lg:border-t-0 lg:border-l"
    >
      <header className="flex shrink-0 items-center justify-between gap-2 px-3 py-2">
        <h2 className="m-0 text-sm font-semibold">{t("session.files.title")}</h2>
        <div className="flex min-w-0 items-center gap-1">
          <Button variant="ghost" className="gap-1 px-2" disabled={selectionDisabled} onClick={() => enqueue()}>
            <Upload aria-hidden="true" className="size-4" />
            {t("session.files.upload.action")}
          </Button>
          <IconButton
            label={t("session.files.create.action")}
            disabled={fileOperationsDisabled}
            onClick={() => {
              setName("");
              setNameDialog({ kind: "create" });
            }}
          >
            <FolderPlus aria-hidden="true" className="size-4" />
          </IconButton>
          <IconButton
            label={t("session.files.refresh")}
            disabled={fileOperationsDisabled}
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
              disabled={fileOperationsDisabled}
              title={name}
              className="max-w-40 shrink-0 px-2"
              onClick={() => {
                setMutationFeedback(null);
                setLocations((current) => current.slice(0, index + 1));
              }}
            >
              <span className="truncate">{name}</span>
            </Button>
          );
        })}
      </nav>
      <SessionEditor editor={editor} transportId={transportId} active={active} queueAvailable={!selectionDisabled} />
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
            <Button
              variant="ghost"
              disabled={fileOperationsDisabled}
              onClick={() => setReload((current) => current + 1)}
            >
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
      {mutationFeedback ? (
        <p
          role={mutationFeedback.status === "saved" || mutationFeedback.status === "cancelled" ? "status" : "alert"}
          className={`m-0 px-3 py-2 text-xs ${mutationFeedback.status === "saved" || mutationFeedback.status === "cancelled" ? "" : "text-attention"}`}
        >
          {t(
            mutationFeedback.status === "saved"
              ? `session.files.operation.saved.${mutationFeedback.kind}`
              : `session.files.operation.${mutationFeedback.status}`,
          )}
        </p>
      ) : null}
      <div
        ref={dropList}
        role="region"
        aria-label={t("session.files.drop.list")}
        className={`min-h-16 flex-1 overflow-auto px-2 pb-2 ${drop?.phase === "over" ? "ring-2 ring-primary ring-inset" : ""}`}
      >
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
                  disabled={fileOperationsDisabled}
                  title={entry.name}
                  className="min-w-0 flex-1 truncate text-left text-sm text-foreground underline-offset-2 hover:underline focus-visible:rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary disabled:opacity-50"
                  onClick={() => {
                    setMutationFeedback(null);
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
                  ref={(element) => {
                    const path = entry.path.join(",");
                    if (element) previewButtons.current.set(path, element);
                    else previewButtons.current.delete(path);
                  }}
                  label={t("session.files.preview.action", { name: entry.name })}
                  disabled={fileOperationsDisabled}
                  onClick={() => {
                    previewFocus.current = { owner: previewOwner, path: entry.path.join(",") };
                    setPreview({ id: crypto.randomUUID(), owner: previewOwner, entry });
                  }}
                >
                  <Eye aria-hidden="true" className="size-4" />
                </IconButton>
              ) : null}
              {entry.kind === "file" ? (
                <IconButton
                  label={t("session.editor.action", { name: entry.name })}
                  disabled={selectionDisabled || !active || editor.loading || editor.snapshot !== null}
                  onClick={() => setEditDialog({ owner: previewOwner, entry })}
                >
                  <Pencil aria-hidden="true" className="size-4" />
                </IconButton>
              ) : null}
              {entry.kind === "file" ? (
                <IconButton
                  label={t("session.files.download", { name: entry.name })}
                  disabled={selectionDisabled}
                  onClick={() => enqueue(entry)}
                >
                  <Download aria-hidden="true" className="size-4" />
                </IconButton>
              ) : null}
              {entry.kind === "file" || entry.kind === "directory" ? (
                <>
                  <IconButton
                    label={t("session.files.rename.action", { name: entry.name })}
                    disabled={fileOperationsDisabled}
                    onClick={() => {
                      setName("");
                      setNameDialog({ kind: "rename", entry });
                    }}
                  >
                    <Pencil aria-hidden="true" className="size-4" />
                  </IconButton>
                  <IconButton
                    label={t("session.files.delete.action", { name: entry.name })}
                    disabled={fileOperationsDisabled}
                    className="hover:bg-[color-mix(in_srgb,var(--attention)_10%,transparent)] hover:text-attention"
                    onClick={() => deleteEntry(entry)}
                  >
                    <Trash2 aria-hidden="true" className="size-4" />
                  </IconButton>
                </>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
      <div
        role="status"
        aria-live="polite"
        className="h-16 shrink-0 overflow-y-auto px-3 py-2 text-xs text-muted-foreground"
      >
        {drop
          ? t(
              drop.count === null
                ? drop.phase === "over"
                  ? "session.files.drop.overUnknown"
                  : "session.files.drop.invalid"
                : `session.files.drop.${drop.phase}`,
              {
                count: drop.count ?? 0,
              },
            )
          : queueBlocked || !transportId
            ? t(!transportId ? "session.transfers.disconnected" : "session.transfers.browsingBlocked")
            : dropEnabled
              ? t("session.files.drop.hint")
              : null}
      </div>
      <SessionTransferQueue
        snapshot={queue}
        issue={drop?.issue ?? enqueueIssue ?? queueIssue}
        admittingDrop={drop?.phase === "checking"}
      />
      {previewOpen && preview && transportId ? (
        <SessionFilePreview
          key={preview.id}
          sessionId={sessionId}
          transportId={transportId}
          connectionLabel={connectionLabel}
          entry={preview.entry}
          onClose={() => setPreview((current) => (current?.id === preview.id ? null : current))}
        />
      ) : null}
      <Dialog
        open={!!editDialogOpen}
        onOpenChange={(open) => {
          if (!open) setEditDialog(null);
        }}
        title={t("session.editor.confirmTitle", { name: editDialog?.entry.name ?? "" })}
        description={t("session.editor.description", { connection: connectionLabel })}
        closeLabel={t("session.files.cancel")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setEditDialog(null)}>
              {t("session.files.cancel")}
            </Button>
            <Button
              variant="primary"
              disabled={!transportId || !active || editor.pending !== null || editor.snapshot !== null}
              onClick={() => {
                if (!editDialog || !transportId || !active) return;
                const selected = editDialog.entry;
                setEditDialog(null);
                void editor.start(selected.path, locale === "zh-Hans" ? "zh-Hans" : "en").then((result) => {
                  if (mounted.current && result?.status === "ok" && result.data.kind === "cancelled")
                    setNotice(translator.current("session.transfers.selectionCancelled"));
                });
              }}
            >
              {t("session.editor.chooseCopy")}
            </Button>
          </>
        }
      >
        <p className="m-0 text-sm">{t("session.editor.localDisclosure")}</p>
        <p className="mb-0 mt-3 text-sm text-muted-foreground">{t("session.editor.manualUpload")}</p>
      </Dialog>
      <Dialog
        open={nameDialog !== null}
        onOpenChange={(open) => {
          if (!open) setNameDialog(null);
        }}
        title={t(nameDialog?.kind === "rename" ? "session.files.rename.title" : "session.files.create.title")}
        description={
          nameDialog?.kind === "rename"
            ? t("session.files.rename.description", { name: nameDialog.entry.name })
            : undefined
        }
        closeLabel={t("session.files.cancel")}
        footer={
          <>
            <Button variant="ghost" onClick={() => setNameDialog(null)}>
              {t("session.files.cancel")}
            </Button>
            <Button variant="primary" type="submit" form={formId} disabled={!name.trim() || fileOperationsDisabled}>
              {t(nameDialog?.kind === "rename" ? "session.files.rename.submit" : "session.files.create.submit")}
            </Button>
          </>
        }
      >
        <form id={formId} onSubmit={submitName}>
          <Field
            label={t("session.files.name")}
            autoFocus
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </form>
      </Dialog>
    </section>
  );
}
