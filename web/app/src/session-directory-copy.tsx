// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field } from "@scoplen/ui";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  SessionDirectoryCopyIssue,
  SessionDirectoryCopySelection,
  SessionTransferDirection,
} from "./ipc/bindings";

type Review = {
  phase: "preparing" | "ready" | "enqueueing" | "failed" | "unknown";
  selection: SessionDirectoryCopySelection | null;
  issue: SessionDirectoryCopyIssue | null;
  name: string;
};

/** Native selections stay with their original owner until consumed or discarded. */
export function SessionDirectoryCopy({
  sessionId,
  transportId,
  remotePath,
  direction,
  connectionLabel,
  onClose,
  onQueued,
}: {
  sessionId: string;
  transportId: string;
  remotePath: number[];
  direction: SessionTransferDirection;
  connectionLabel: string;
  onClose: () => void;
  onQueued: () => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const formId = useId();
  const owner = useMemo(
    () => ({ commands, sessionId, transportId, remotePath, direction }),
    [commands, sessionId, transportId, remotePath, direction],
  );
  const live = useRef<typeof owner | null>(null);
  const pending = useRef<symbol | null>(null);
  const retained = useRef<{ owner: typeof owner; id: string } | null>(null);
  const closing = useRef(false);
  const [state, setState] = useState<Review>({ phase: "preparing", selection: null, issue: null, name: "" });

  const prepare = async () => {
    if (live.current !== owner || pending.current || closing.current) return;
    const token = Symbol();
    pending.current = token;
    setState({ phase: "preparing", selection: null, issue: null, name: "" });
    try {
      const result = await owner.commands.sessionPrepareDirectoryCopy(
        sessionId,
        transportId,
        remotePath,
        direction,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      );
      if (live.current !== owner || pending.current !== token || closing.current) {
        if (result.status === "ok" && result.data.kind === "prepared")
          void owner.commands
            .sessionDiscardDirectoryCopy(sessionId, result.data.selection.selectionId)
            .catch(() => undefined);
        return;
      }
      if (result.status === "error") {
        setState({ phase: "failed", selection: null, issue: result.error, name: "" });
      } else if (result.data.kind === "cancelled") {
        setState({ phase: "failed", selection: null, issue: "cancelled", name: "" });
      } else {
        const selection = result.data.selection;
        if (
          selection.sessionId !== sessionId ||
          selection.transportId !== transportId ||
          selection.direction !== direction
        ) {
          void owner.commands.sessionDiscardDirectoryCopy(sessionId, selection.selectionId).catch(() => undefined);
          setState({ phase: "failed", selection: null, issue: "unavailable", name: "" });
          return;
        }
        retained.current = { owner, id: selection.selectionId };
        setState({ phase: "ready", selection, issue: null, name: selection.defaultRootName ?? "" });
      }
    } catch {
      if (live.current === owner && pending.current === token && !closing.current)
        setState({ phase: "failed", selection: null, issue: "failed", name: "" });
    } finally {
      if (pending.current === token) pending.current = null;
    }
  };

  const prepareRef = useRef(prepare);
  useEffect(() => {
    prepareRef.current = prepare;
  });
  useEffect(() => {
    live.current = owner;
    let current = true;
    void Promise.resolve().then(() => {
      if (current) void prepareRef.current();
    });
    return () => {
      current = false;
      if (live.current === owner) live.current = null;
      if (retained.current?.owner === owner) {
        const id = retained.current.id;
        retained.current = null;
        void owner.commands.sessionDiscardDirectoryCopy(owner.sessionId, id).catch(() => undefined);
      }
    };
  }, [owner]);

  const validName =
    state.name.trim().length > 0 && state.name !== "." && state.name !== ".." && !/[/\0]/.test(state.name);
  const enqueue = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (
      live.current !== owner ||
      closing.current ||
      pending.current ||
      state.phase !== "ready" ||
      !state.selection ||
      !validName
    )
      return;
    const token = Symbol();
    pending.current = token;
    const selection = state.selection;
    setState({ ...state, phase: "enqueueing", issue: null });
    try {
      const result = await owner.commands.sessionEnqueueDirectoryCopy(
        sessionId,
        transportId,
        selection.selectionId,
        state.name,
      );
      if (live.current !== owner || closing.current) return;
      if (result.status === "error") {
        if (result.error === "unsupportedName") {
          setState({ ...state, phase: "ready", issue: result.error });
        } else {
          retained.current = null;
          setState({
            ...state,
            phase: result.error === "publicationUnknown" ? "unknown" : "failed",
            selection: null,
            issue: result.error,
          });
        }
      } else {
        retained.current = null;
        if (result.data.status === "queued") {
          onQueued();
          onClose();
        } else {
          setState({ ...state, phase: "failed", selection: null, issue: "cancelled" });
        }
      }
    } catch {
      if (live.current === owner && !closing.current)
        setState({ ...state, phase: "unknown", selection: null, issue: null });
    } finally {
      if (pending.current === token) pending.current = null;
    }
  };
  const close = () => {
    if (closing.current) return;
    closing.current = true;
    onClose();
  };
  const busy = state.phase === "preparing" || state.phase === "enqueueing";

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
      title={t(`session.directoryCopy.title.${direction}`)}
      description={t("session.directoryCopy.description", { connection: connectionLabel })}
      closeLabel={t("session.directoryCopy.close")}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {t("session.directoryCopy.close")}
          </Button>
          {state.phase === "failed" ? (
            <Button variant="primary" onClick={() => void prepare()}>
              {t("session.directoryCopy.chooseAgain")}
            </Button>
          ) : null}
          {state.selection ? (
            <Button
              variant="primary"
              type="submit"
              form={formId}
              disabled={busy || !validName}
              busy={state.phase === "enqueueing"}
            >
              {t("session.directoryCopy.enqueue")}
            </Button>
          ) : null}
        </>
      }
    >
      <p className="mt-0 text-sm">{t("session.directoryCopy.newRoot")}</p>
      <p className="text-sm text-muted-foreground">{t("session.directoryCopy.partialDisclosure")}</p>
      {state.phase === "preparing" ? (
        <p role="status" className="text-sm">
          {t("session.directoryCopy.preparing")}
        </p>
      ) : null}
      {state.issue && state.phase !== "unknown" ? (
        <p role="alert" className="text-sm text-attention">
          {t(`session.directoryCopy.issue.${state.issue}`)}
        </p>
      ) : null}
      {state.selection ? (
        <form id={formId} onSubmit={(event) => void enqueue(event)} className="flex min-w-0 flex-col gap-4">
          <p className="m-0 break-words text-sm font-medium">{t(`session.directoryCopy.direction.${direction}`)}</p>
          <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
            <dt>{t("session.directoryCopy.source")}</dt>
            <dd className="m-0 break-all">{state.selection.sourceName}</dd>
            <dt>{t("session.directoryCopy.destination")}</dt>
            <dd className="m-0 break-all">{state.selection.destinationParentName}</dd>
          </dl>
          <Field
            autoFocus
            label={t("session.directoryCopy.name")}
            hint={t("session.directoryCopy.nameHint")}
            value={state.name}
            disabled={busy}
            error={state.name && !validName ? t("session.directoryCopy.invalidName") : undefined}
            onChange={(event) => setState({ ...state, issue: null, name: event.target.value })}
          />
        </form>
      ) : null}
      {state.phase === "unknown" ? (
        <p role="alert" className="text-sm text-attention">
          {t("session.directoryCopy.unknown")}
        </p>
      ) : null}
    </Dialog>
  );
}
