// SPDX-License-Identifier: Apache-2.0
import { createContext, useCallback, useEffect, useRef, useState } from "react";
import {
  commands,
  events,
  type ForwardIssue,
  type ForwardSnapshot,
  type SessionPreparationIntent,
} from "./ipc/bindings";

export interface ForwardController {
  snapshots: ForwardSnapshot[];
  loading: boolean;
  issue: ForwardIssue | null;
  refresh: () => void;
  start: (forwardId: string, profileId: string) => Promise<ForwardSnapshot | null>;
  stop: (runId: string) => Promise<ForwardIssue | null>;
  respond: (runId: string, promptId: string, intent: SessionPreparationIntent) => Promise<ForwardIssue | null>;
}

export const ForwardsContext = createContext<ForwardController | null>(null);

export function isLiveForward(snapshot: ForwardSnapshot): boolean {
  return snapshot.phase === "preparing" || snapshot.phase === "listening" || snapshot.phase === "stopping";
}

function merge(current: ForwardSnapshot[], next: ForwardSnapshot): ForwardSnapshot[] {
  const previous = current.find((run) => run.runId === next.runId);
  if (previous && BigInt(previous.revision) >= BigInt(next.revision)) return current;
  const updated = [...current.filter((run) => run.runId !== next.runId), next];
  const ended = updated.filter((run) => !isLiveForward(run));
  const retained = new Set(ended.slice(-32).map((run) => run.runId));
  return updated.filter((run) => isLiveForward(run) || retained.has(run.runId));
}

/** Observes native owners for the Shell lifetime; detaching never sends Stop. */
export function useForwards(): ForwardController {
  const [snapshots, setSnapshots] = useState<ForwardSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [issue, setIssue] = useState<ForwardIssue | null>(null);
  const [reload, setReload] = useState(0);
  const mounted = useRef(false);
  const ready = useRef(false);
  const generation = useRef(0);
  const current = useRef<ForwardSnapshot[]>([]);
  const receive = useCallback((snapshot: ForwardSnapshot) => {
    if (!mounted.current) return;
    current.current = merge(current.current, snapshot);
    setSnapshots(current.current);
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);

  useEffect(() => {
    let active = true;
    const epoch = ++generation.current;
    let unlisten: (() => void) | undefined;
    const received = new Set<string>();
    ready.current = false;
    void (async () => {
      try {
        const stop = await events.forwardChanged.listen((event) => {
          if (active && generation.current === epoch) {
            received.add(event.payload.snapshot.runId);
            receive(event.payload.snapshot);
          }
        });
        if (!active || generation.current !== epoch) {
          stop();
          return;
        }
        unlisten = stop;
        const result = await commands.forwardList();
        if (!active || generation.current !== epoch) return;
        if (result.status === "error") {
          setIssue(result.error);
          return;
        }
        const retained = new Set([...received, ...result.data.map((run) => run.runId)]);
        current.current = current.current.filter((run) => retained.has(run.runId));
        result.data.forEach((run) => {
          current.current = merge(current.current, run);
        });
        setSnapshots(current.current);
        ready.current = true;
        setIssue(null);
      } catch {
        if (active && generation.current === epoch) setIssue("unavailable");
      } finally {
        if (active && generation.current === epoch) setLoading(false);
      }
    })();
    return () => {
      active = false;
      ready.current = false;
      unlisten?.();
    };
  }, [receive, reload]);

  return {
    snapshots,
    loading,
    issue,
    refresh: () => {
      if (!mounted.current) return;
      generation.current++;
      ready.current = false;
      current.current = [];
      setSnapshots([]);
      setIssue(null);
      setLoading(true);
      setReload((value) => value + 1);
    },
    start: async (forwardId, profileId) => {
      if (!mounted.current) return null;
      if (!ready.current) {
        setIssue("unavailable");
        return null;
      }
      const epoch = generation.current;
      try {
        const result = await commands.forwardStart(forwardId, profileId);
        if (!mounted.current || generation.current !== epoch) return null;
        if (result.status === "error") {
          setIssue(result.error);
          return null;
        }
        receive(result.data);
        setIssue(null);
        return result.data;
      } catch {
        if (mounted.current && generation.current === epoch) setIssue("unavailable");
        return null;
      }
    },
    stop: async (runId) => {
      const epoch = generation.current;
      if (!mounted.current || !ready.current || !current.current.some((run) => run.runId === runId)) return "expired";
      try {
        const result = await commands.forwardStop(runId);
        if (!mounted.current || generation.current !== epoch) return "expired";
        return result.status === "error" ? result.error : null;
      } catch {
        return mounted.current && generation.current === epoch ? "unavailable" : "expired";
      }
    },
    respond: async (runId, promptId, intent) => {
      const epoch = generation.current;
      const run = current.current.find((snapshot) => snapshot.runId === runId);
      if (
        !mounted.current ||
        !ready.current ||
        run?.phase !== "preparing" ||
        !run.preparation ||
        !("promptId" in run.preparation) ||
        run.preparation.promptId !== promptId
      )
        return "expired";
      try {
        const result = await commands.forwardRespond(runId, promptId, intent);
        if (!mounted.current || generation.current !== epoch) return "expired";
        return result.status === "error" ? result.error : null;
      } catch {
        return mounted.current && generation.current === epoch ? "unavailable" : "expired";
      }
    },
  };
}
