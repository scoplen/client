// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useEffect, useMemo, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { SessionDirectorySyncIssue, SessionDirectorySyncPlan, SessionTransferDirection } from "./ipc/bindings";

type Comparison = {
  phase: "choose" | "preparing" | "ready" | "applying" | "unknown";
  plan: SessionDirectorySyncPlan | null;
  issue: SessionDirectorySyncIssue | null;
};

/** A preview owns unapplied authority; admitted work belongs to the session queue. */
export function SessionDirectorySync({
  sessionId,
  transportId,
  remotePath,
  connectionLabel,
  availableSlots,
  onClose,
  onQueued,
}: {
  sessionId: string;
  transportId: string;
  remotePath: number[];
  connectionLabel: string;
  availableSlots: number;
  onClose: () => void;
  onQueued: (count: number) => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const owner = useMemo(
    () => ({ commands, sessionId, transportId, remotePath }),
    [commands, sessionId, transportId, remotePath],
  );
  const live = useRef<typeof owner | null>(null);
  const operation = useRef<{ owner: typeof owner; id: string } | null>(null);
  const retained = useRef<{ owner: typeof owner; id: string } | null>(null);
  const applying = useRef<typeof owner | null>(null);
  const closing = useRef(false);
  const [stored, setStored] = useState<{ owner: typeof owner; state: Comparison } | null>(null);
  const state: Comparison = stored?.owner === owner ? stored.state : { phase: "choose", plan: null, issue: null };

  useEffect(() => {
    live.current = owner;
    return () => {
      if (live.current === owner) live.current = null;
      if (operation.current?.owner === owner) {
        const id = operation.current.id;
        operation.current = null;
        void owner.commands.sessionCancelFileOperation(owner.sessionId, owner.transportId, id).catch(() => undefined);
      }
      if (retained.current?.owner === owner) {
        const id = retained.current.id;
        retained.current = null;
        void owner.commands.sessionDiscardDirectorySync(owner.sessionId, id).catch(() => undefined);
      }
    };
  }, [owner]);

  const discard = (planId: string) => {
    if (retained.current?.id === planId) retained.current = null;
    void commands.sessionDiscardDirectorySync(sessionId, planId).catch(() => undefined);
  };

  const prepare = async (direction: SessionTransferDirection) => {
    if (live.current !== owner || operation.current?.owner === owner || applying.current === owner) return;
    if (retained.current?.owner === owner) discard(retained.current.id);
    const id = crypto.randomUUID();
    operation.current = { owner, id };
    setStored({ owner, state: { phase: "preparing", plan: null, issue: null } });
    try {
      const result = await commands.sessionPrepareDirectorySync(
        sessionId,
        transportId,
        id,
        remotePath,
        direction,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      );
      if (live.current !== owner || operation.current?.id !== id || closing.current) {
        if (result.status === "ok" && result.data.kind === "prepared")
          void commands.sessionDiscardDirectorySync(sessionId, result.data.plan.planId).catch(() => undefined);
        return;
      }
      if (result.status === "error") {
        setStored({ owner, state: { phase: "choose", plan: null, issue: result.error } });
      } else if (result.data.kind === "cancelled") {
        setStored({ owner, state: { phase: "choose", plan: null, issue: "cancelled" } });
      } else {
        const plan = result.data.plan;
        if (plan.sessionId !== sessionId || plan.transportId !== transportId || plan.direction !== direction) {
          discard(plan.planId);
          setStored({ owner, state: { phase: "choose", plan: null, issue: "unavailable" } });
          return;
        }
        retained.current = { owner, id: plan.planId };
        setStored({ owner, state: { phase: "ready", plan, issue: null } });
      }
    } catch {
      if (live.current === owner && operation.current?.id === id && !closing.current)
        setStored({ owner, state: { phase: "choose", plan: null, issue: "failed" } });
    } finally {
      if (operation.current?.id === id) operation.current = null;
    }
  };

  const apply = async () => {
    const plan = state.plan;
    if (live.current !== owner || !plan || state.phase !== "ready" || applying.current === owner) return;
    applying.current = owner;
    setStored({ owner, state: { phase: "applying", plan, issue: null } });
    try {
      const result = await commands.sessionApplyDirectorySync(
        sessionId,
        transportId,
        plan.planId,
        locale === "zh-Hans" ? "zh-Hans" : "en",
      );
      if (live.current !== owner || closing.current) return;
      if (result.status === "error") {
        if (result.error === "queueFull") {
          setStored({ owner, state: { phase: "ready", plan, issue: result.error } });
        } else {
          discard(plan.planId);
          setStored({ owner, state: { phase: "choose", plan: null, issue: result.error } });
        }
      } else {
        retained.current = null;
        onQueued(result.data.kind === "queued" ? result.data.items.length : 0);
        onClose();
      }
    } catch {
      if (live.current === owner && !closing.current)
        setStored({ owner, state: { phase: "unknown", plan, issue: null } });
    } finally {
      if (applying.current === owner) applying.current = null;
    }
  };

  const close = () => {
    if (closing.current) return;
    closing.current = true;
    onClose();
  };
  const changed = state.plan?.entries.filter((entry) => entry.change !== "same").length ?? 0;
  const busy = state.phase === "preparing" || state.phase === "applying";
  const full = changed > availableSlots;

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
      title={t("session.directorySync.title")}
      description={t("session.directorySync.description", { connection: connectionLabel })}
      closeLabel={t("session.directorySync.close")}
      footer={
        <>
          {state.phase === "ready" && state.plan ? (
            <Button variant="ghost" onClick={() => void prepare(state.plan!.direction)}>
              {t("session.directorySync.compareAgain")}
            </Button>
          ) : null}
          <Button variant="ghost" onClick={close}>
            {t(state.phase === "preparing" ? "session.directorySync.cancel" : "session.directorySync.close")}
          </Button>
          {state.plan && state.phase !== "unknown" ? (
            <Button
              variant="primary"
              busy={state.phase === "applying"}
              disabled={busy || changed === 0 || full}
              onClick={() => void apply()}
            >
              {t("session.directorySync.apply", { count: changed })}
            </Button>
          ) : null}
        </>
      }
    >
      <p className="mt-0 text-sm">{t("session.directorySync.scope")}</p>
      <p className="text-sm text-muted-foreground">{t("session.directorySync.localDisclosure")}</p>
      {state.issue ? (
        <p role="alert" className="text-sm text-attention">
          {t(`session.directorySync.issue.${state.issue}`)}
        </p>
      ) : null}
      {state.phase === "choose" ? (
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => void prepare("upload")}>
            {t("session.directorySync.compareUpload")}
          </Button>
          <Button variant="ghost" onClick={() => void prepare("download")}>
            {t("session.directorySync.compareDownload")}
          </Button>
        </div>
      ) : null}
      {state.phase === "preparing" ? (
        <p role="status" className="text-sm">
          {t("session.directorySync.preparing")}
        </p>
      ) : null}
      {state.plan ? (
        <>
          <p className="break-words text-sm font-medium">
            {t(`session.directorySync.direction.${state.plan.direction}`)}
          </p>
          <dl className="m-0 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
            <dt>{t("session.directorySync.remote")}</dt>
            <dd className="m-0 break-words">{state.plan.remoteName}</dd>
            <dt>{t("session.directorySync.local")}</dt>
            <dd className="m-0 break-words">{state.plan.localName}</dd>
          </dl>
          <p className="text-xs text-muted-foreground">
            {t("session.directorySync.excluded", { count: state.plan.excludedDirectories })}
          </p>
          {state.plan.entries.length === 0 ? (
            <p role="status" className="text-sm">
              {t("session.directorySync.empty")}
            </p>
          ) : (
            <ul
              aria-label={t("session.directorySync.changes")}
              className="m-0 max-h-[36vh] list-none overflow-auto p-0"
            >
              {state.plan.entries.map((entry, index) => (
                <li
                  key={index}
                  className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 border-b border-border py-2 text-sm"
                >
                  <span className="min-w-0 flex-1 break-words" title={entry.name}>
                    {entry.name}
                  </span>
                  <span>{t(`session.directorySync.change.${entry.change}`)}</span>
                  <span className="w-full text-xs text-muted-foreground">
                    {t("session.directorySync.sizes", {
                      source: t("session.directorySync.bytes", { bytes: entry.sourceSizeBytes }),
                      target:
                        entry.targetSizeBytes === null
                          ? t("session.directorySync.missing")
                          : t("session.directorySync.bytes", { bytes: entry.targetSizeBytes }),
                    })}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {changed === 0 && state.plan.entries.length > 0 ? (
            <p role="status" className="text-sm">
              {t("session.directorySync.same")}
            </p>
          ) : null}
          {full ? (
            <p role="status" className="text-sm text-attention">
              {t("session.directorySync.capacity", { count: changed, available: availableSlots })}
            </p>
          ) : null}
          <p className="mb-0 text-xs text-muted-foreground">{t("session.directorySync.review")}</p>
        </>
      ) : null}
      {state.phase === "unknown" ? (
        <p role="alert" className="text-sm text-attention">
          {t("session.directorySync.unknown")}
        </p>
      ) : null}
    </Dialog>
  );
}
