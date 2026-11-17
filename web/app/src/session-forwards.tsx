// SPDX-License-Identifier: Apache-2.0
import { Button } from "@scoplen/ui";
import { useCallback, useContext, useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { ForwardIssue, SessionForwardSnapshot } from "./ipc/bindings";
import { ForwardsContext, tunnelIssueKey, type ForwardController } from "./use-forwards";

export function useSessionForwards(sessionId: string) {
  const commands = useProfileCommands();
  const [entries, setEntries] = useState<SessionForwardSnapshot[]>([]);
  const [issue, setIssue] = useState<ForwardIssue | null>(null);
  const [stopIssue, setStopIssue] = useState<{ forwardId: string; issue: ForwardIssue } | null>(null);
  const [stopping, setStopping] = useState<string | null>(null);
  const transport = useRef<string | null>(null);
  const revision = useRef(0);
  const lifetime = useRef(0);
  const pendingStop = useRef<string | null>(null);

  useEffect(
    () => () => {
      transport.current = null;
      lifetime.current++;
    },
    [],
  );

  const begin = useCallback((transportId: string | null) => {
    transport.current = transportId;
    lifetime.current++;
    revision.current++;
    pendingStop.current = null;
    setStopping(null);
    setIssue(null);
    setStopIssue(null);
    if (transportId) setEntries([]);
  }, []);

  const receive = useCallback((transportId: string, next: SessionForwardSnapshot[]) => {
    if (transport.current !== transportId) return;
    revision.current++;
    setEntries(next);
    setIssue(null);
  }, []);

  const load = useCallback(
    async (transportId: string) => {
      if (transport.current !== transportId) return;
      const epoch = lifetime.current;
      const version = ++revision.current;
      const current = () =>
        transport.current === transportId && lifetime.current === epoch && revision.current === version;
      try {
        const result = await commands.sessionForwardList(sessionId, transportId);
        if (!current()) return;
        if (result.status === "ok") {
          setEntries(result.data);
          setIssue(null);
        } else setIssue(result.error);
      } catch {
        if (current()) setIssue("unavailable");
      }
    },
    [commands, sessionId],
  );

  const stop = async (forwardId: string) => {
    const transportId = transport.current;
    if (!transportId || pendingStop.current) return;
    const epoch = lifetime.current;
    pendingStop.current = forwardId;
    setStopping(forwardId);
    setStopIssue(null);
    const current = () => transport.current === transportId && lifetime.current === epoch;
    try {
      const result = await commands.sessionForwardStop(sessionId, transportId, forwardId);
      if (!current()) return;
      if (result.status === "error") setStopIssue({ forwardId, issue: result.error });
      else await load(transportId);
    } catch {
      if (current()) setStopIssue({ forwardId, issue: "unavailable" });
    } finally {
      if (current()) {
        pendingStop.current = null;
        setStopping(null);
      }
    }
  };

  return { entries, issue, stopIssue, stopping, begin, receive, load, stop };
}

export function SessionForwards({
  controller,
  connected,
  runtime: providedRuntime,
}: {
  controller: ReturnType<typeof useSessionForwards>;
  connected: boolean;
  runtime?: ForwardController;
}) {
  const { t } = useI18n();
  const observedRuntime = useContext(ForwardsContext);
  const runtime = providedRuntime ?? observedRuntime;
  if (!controller.entries.length && !controller.issue) return null;
  return (
    <section aria-label={t("tunnels.attached.title")} className="mx-4 mb-2 shrink-0 border-t border-border pt-2">
      <h3 className="m-0 text-xs font-medium">{t("tunnels.attached.title")}</h3>
      <p className="mt-1 mb-2 text-xs text-muted-foreground">{t("tunnels.attached.lifetime")}</p>
      {controller.issue ? (
        <p role="alert" className="my-1 text-xs text-attention">
          {t(tunnelIssueKey(controller.issue, true))}
        </p>
      ) : null}
      <ul aria-label={t("tunnels.attached.title")} className="m-0 max-h-36 list-none space-y-2 overflow-y-auto p-0">
        {controller.entries.map((entry) => {
          const observed = runtime?.snapshots.find((run) => run.runId === entry.run?.runId);
          const run =
            observed && entry.run && BigInt(observed.revision) > BigInt(entry.run.revision) ? observed : entry.run;
          const issue = entry.issue ?? run?.lastIssue;
          return (
            <li key={entry.forwardId} className="min-w-0 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <span className="min-w-0 flex-1 break-words font-medium">
                  {entry.name ?? t("tunnels.attached.missing", { id: entry.forwardId })}
                </span>
                <span className={issue && !entry.stopped ? "text-attention" : "text-muted-foreground"}>
                  {entry.stopped
                    ? t("tunnels.attached.stopped")
                    : run
                      ? t(`tunnels.phase.${run.phase}`)
                      : t("tunnels.phase.failed")}
                </span>
                <Button
                  variant="ghost"
                  disabled={!connected || entry.stopped || controller.stopping !== null || run?.phase === "stopping"}
                  onClick={() => void controller.stop(entry.forwardId)}
                >
                  {t("tunnels.stop")}
                </Button>
              </div>
              {!entry.stopped && issue ? (
                <p className="mt-1 mb-0 break-words text-attention">{t(tunnelIssueKey(issue, true))}</p>
              ) : null}
              {controller.stopIssue?.forwardId === entry.forwardId ? (
                <p role="alert" className="mt-1 mb-0 text-attention">
                  {t(tunnelIssueKey(controller.stopIssue.issue, true))}
                </p>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
