// SPDX-License-Identifier: Apache-2.0
import { useProfileCommands } from "./account-profiles";
import { Button } from "@scoplen/ui";
import { Download, Upload } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { type SessionTransferIssue, type SessionTransferItem, type SessionTransferQueueSnapshot } from "./ipc/bindings";

function byteCount(value: string): bigint | null {
  if (!/^(0|[1-9]\d{0,19})$/.test(value)) return null;
  const count = BigInt(value);
  return count <= 18_446_744_073_709_551_615n ? count : null;
}

type TransferAction = "cancel" | "pause" | "resume" | "acknowledge";
type ActionIdentity = {
  queueId: string;
  itemId: string;
  executionId: string;
  kind: TransferAction;
};

function actionAvailable(item: SessionTransferItem, action: TransferAction) {
  switch (action) {
    case "cancel":
      return item.canCancel;
    case "pause":
      return item.state === "transferring" && item.canPause;
    case "resume":
      return item.state === "paused" && item.canResume;
    case "acknowledge":
      return item.canAcknowledge;
  }
}

function actionStillCurrent(snapshot: SessionTransferQueueSnapshot | null, action: ActionIdentity) {
  return (
    action.queueId === snapshot?.queueId &&
    snapshot.items.some(
      (item) =>
        item.itemId === action.itemId && item.executionId === action.executionId && actionAvailable(item, action.kind),
    )
  );
}

/** A bounded projection of the queue; every state transition remains owned by Rust. */
export function SessionTransferQueue({
  snapshot,
  issue,
  admittingDrop = false,
}: {
  snapshot: SessionTransferQueueSnapshot | null;
  issue: SessionTransferIssue | null;
  admittingDrop?: boolean;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const headingId = useId();
  const unknownId = useId();
  const actionPending = useRef<(ActionIdentity & { token: symbol }) | null>(null);
  const [action, setAction] = useState<
    (ActionIdentity & { pending: boolean; issue: SessionTransferIssue | null }) | null
  >(null);
  const visibleAction = action !== null && actionStillCurrent(snapshot, action) ? action : null;
  const currentIssue = visibleAction?.issue ?? issue;
  const rows = snapshot ? [...snapshot.items, ...snapshot.recent.slice().reverse()] : [];
  const hasUnknown = snapshot?.items.some((item) => item.state === "unknown") ?? false;
  const hasPaused = snapshot?.items.some((item) => item.state === "paused") ?? false;
  const format = new Intl.NumberFormat(locale);

  const request = async (item: SessionTransferItem, kind: TransferAction) => {
    if (!snapshot || !actionAvailable(item, kind)) return;
    const pending = actionPending.current;
    if (
      pending &&
      actionStillCurrent(snapshot, pending) &&
      !(
        kind === "cancel" &&
        (pending.kind === "pause" || pending.kind === "resume") &&
        pending.itemId === item.itemId &&
        pending.executionId === item.executionId
      )
    )
      return;
    const { sessionId, queueId } = snapshot;
    const identity = { queueId, itemId: item.itemId, executionId: item.executionId, kind };
    const token = Symbol();
    actionPending.current = { ...identity, token };
    setAction({ ...identity, pending: true, issue: null });
    let failure: SessionTransferIssue | null = null;
    try {
      const command = {
        cancel: commands.sessionCancelTransfer,
        pause: commands.sessionPauseTransfer,
        resume: commands.sessionResumeTransfer,
        acknowledge: commands.sessionAcknowledgeTransfer,
      }[kind];
      const result = await command(sessionId, queueId, item.itemId, item.executionId);
      if (result.status === "error") failure = result.error;
    } catch {
      failure = "transferFailed";
    } finally {
      if (actionPending.current?.token === token) {
        actionPending.current = null;
        setAction({ ...identity, pending: false, issue: failure });
      }
    }
  };

  return (
    <section aria-labelledby={headingId} className="min-h-0 shrink-0 border-t border-border">
      <div className="flex items-center justify-between gap-2 px-3 pt-3">
        <h3 id={headingId} className="m-0 text-xs font-semibold">
          {t("session.transfers.title")}
        </h3>
        {snapshot ? (
          <span className="shrink-0 text-xs tabular-nums text-muted">
            {t("session.transfers.capacity", { count: snapshot.outstanding, capacity: snapshot.capacity })}
          </span>
        ) : null}
      </div>
      <p className="m-0 px-3 py-2 text-xs text-muted">{t("session.transfers.background")}</p>
      {hasPaused ? <p className="m-0 px-3 pb-2 text-xs text-muted">{t("session.transfers.pausedHelp")}</p> : null}
      {currentIssue ? (
        <p role="alert" className="m-0 px-3 pb-2 text-xs text-attention">
          {t(`session.transfers.issue.${currentIssue}`)}
        </p>
      ) : null}
      {!snapshot && !currentIssue ? (
        <p role="status" className="m-0 px-3 pb-3 text-xs text-muted">
          {t("session.transfers.loading")}
        </p>
      ) : null}
      {snapshot?.pickerBusy && !admittingDrop ? (
        <p role="status" className="m-0 px-3 pb-2 text-xs">
          {t("session.transfers.nativeDialog")}
        </p>
      ) : null}
      {snapshot && rows.length === 0 ? (
        <p className="m-0 px-3 pb-3 text-xs text-muted">{t("session.transfers.empty")}</p>
      ) : null}
      {hasUnknown ? (
        <p id={unknownId} className="m-0 px-3 pb-2 text-xs text-attention">
          {t("session.transfers.unknownHelp")}
        </p>
      ) : null}
      <ol className="m-0 max-h-64 list-none overflow-y-auto p-0 px-3 text-xs">
        {rows.map((item) => {
          const transferred = byteCount(item.transferredBytes);
          const total = item.totalBytes === null ? null : byteCount(item.totalBytes);
          const countsValid =
            transferred !== null && (item.totalBytes === null || (total !== null && transferred <= total));
          const moving =
            item.state === "transferring" ||
            item.state === "finalizing" ||
            item.state === "pausing" ||
            item.state === "paused" ||
            item.state === "validating" ||
            (item.state === "queued" && transferred !== null && transferred > 0n);
          const percent =
            !countsValid || total === null ? null : total === 0n ? 100 : Number((transferred! * 100n) / total);
          const progress = !countsValid
            ? null
            : total === null
              ? t("session.files.transfer.unknownTotal", { transferred: format.format(transferred!) })
              : t("session.files.transfer.knownTotal", {
                  transferred: format.format(transferred!),
                  total: format.format(total),
                  percent: percent ?? 0,
                });
          const Direction = item.direction === "upload" ? Upload : Download;
          return (
            <li key={item.itemId} className="min-w-0 border-t border-border py-2">
              <div className="flex min-w-0 items-start gap-2">
                <Direction aria-hidden className="mt-0.5 size-3.5 shrink-0 text-muted" />
                <div className="min-w-0 flex-1">
                  <p className="m-0 break-all font-medium">{item.name}</p>
                  <p className="m-0 mt-1 text-muted">
                    <span>{t(`session.transfers.direction.${item.direction}`)}</span>
                    {" · "}
                    <span>{t(`session.transfers.state.${item.state}`)}</span>
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap justify-end gap-1">
                {actionAvailable(item, "pause") ? (
                  <Button
                    variant="ghost"
                    disabled={visibleAction?.pending}
                    onClick={() => void request(item, "pause")}
                    aria-label={t("session.transfers.pauseNamed", { name: item.name })}
                  >
                    {t("session.transfers.pause")}
                  </Button>
                ) : null}
                {actionAvailable(item, "resume") ? (
                  <Button
                    variant="ghost"
                    disabled={visibleAction?.pending}
                    onClick={() => void request(item, "resume")}
                    aria-label={t("session.transfers.resumeNamed", { name: item.name })}
                  >
                    {t("session.transfers.resume")}
                  </Button>
                ) : null}
                {actionAvailable(item, "cancel") ? (
                  <Button
                    variant="ghost"
                    disabled={
                      visibleAction?.pending &&
                      !(
                        (visibleAction.kind === "pause" || visibleAction.kind === "resume") &&
                        visibleAction.itemId === item.itemId &&
                        visibleAction.executionId === item.executionId
                      )
                    }
                    onClick={() => void request(item, "cancel")}
                    aria-label={t("session.transfers.cancelNamed", { name: item.name })}
                  >
                    {t("session.files.cancel")}
                  </Button>
                ) : null}
                {actionAvailable(item, "acknowledge") ? (
                  <Button
                    variant="ghost"
                    disabled={visibleAction?.pending}
                    onClick={() => void request(item, "acknowledge")}
                    aria-describedby={unknownId}
                    aria-label={t("session.transfers.dismissNamed", { name: item.name })}
                  >
                    {t("session.transfers.dismiss")}
                  </Button>
                ) : null}
              </div>
              {moving && progress ? (
                <div className="mt-2">
                  <p className="m-0 break-all tabular-nums">{progress}</p>
                  <progress
                    className="mt-1 block h-1.5 w-full min-w-0 accent-primary"
                    max={100}
                    value={percent ?? undefined}
                    aria-label={t("session.transfers.progressNamed", { name: item.name })}
                    aria-valuetext={progress}
                  />
                </div>
              ) : null}
              {item.issue ? (
                <p className="m-0 mt-1 break-words text-attention">{t(`session.transfers.issue.${item.issue}`)}</p>
              ) : null}
              {item.stagingMayRemain && item.issue !== "cleanupIncomplete" ? (
                <p className="m-0 mt-1 text-attention">{t("session.transfers.issue.cleanupIncomplete")}</p>
              ) : null}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
