// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { commands, type SessionTransferIssue, type SessionTransferQueueSnapshot } from "./ipc/bindings";

const POLL_INTERVAL = 250;
const MAX_U64 = 18_446_744_073_709_551_615n;

function revision(value: string): bigint | null {
  if (!/^(0|[1-9]\d{0,19})$/.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= MAX_U64 ? parsed : null;
}

type QueueState = {
  sessionId: string;
  snapshot: SessionTransferQueueSnapshot | null;
  issue: SessionTransferIssue | null;
};

/** Observing Files never owns, cancels, or restarts a Rust transfer. */
export function useSessionTransfers(sessionId: string, visible: boolean) {
  const [state, setState] = useState<QueueState>({ sessionId, snapshot: null, issue: null });
  const inFlight = useRef(false);
  const accepted = useRef<{ sessionId: string; queueId: string; revision: bigint } | null>(null);

  useEffect(() => {
    if (!visible) return;
    let current = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const schedule = () => {
      if (current) timer = setTimeout(() => void poll(), POLL_INTERVAL);
    };

    const poll = async () => {
      if (!current) return;
      if (inFlight.current) {
        schedule();
        return;
      }
      inFlight.current = true;
      try {
        const result = await commands.sessionTransferQueue(sessionId);
        if (!current) return;
        if (result.status === "error") {
          setState((previous) => ({
            sessionId,
            snapshot: previous.sessionId === sessionId ? previous.snapshot : null,
            issue: result.error,
          }));
          return;
        }
        const snapshot = result.data;
        const nextRevision = revision(snapshot.revision);
        if (snapshot.sessionId !== sessionId || nextRevision === null) return;
        const previous = accepted.current;
        if (
          previous?.sessionId === sessionId &&
          previous.queueId === snapshot.queueId &&
          nextRevision < previous.revision
        )
          return;
        accepted.current = { sessionId, queueId: snapshot.queueId, revision: nextRevision };
        setState({ sessionId, snapshot, issue: null });
      } catch {
        if (current)
          setState((previous) => ({
            sessionId,
            snapshot: previous.sessionId === sessionId ? previous.snapshot : null,
            issue: "transferFailed",
          }));
      } finally {
        inFlight.current = false;
        schedule();
      }
    };

    void poll();
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [sessionId, visible]);

  return state.sessionId === sessionId ? state : { sessionId, snapshot: null, issue: null };
}
