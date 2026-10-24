// SPDX-License-Identifier: Apache-2.0
import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from "react";
import { commands, events, type SessionFileDrag, type SessionTransferIssue } from "./ipc/bindings";

type DropFeedback = {
  owner: string;
  phase: "over" | "checking" | "accepted" | "refused";
  count: number | null;
  issue: SessionTransferIssue | null;
};

type EnqueueFeedback = {
  requestId: string;
  phase: "started" | "settled";
  issue: SessionTransferIssue | null;
};

// Arm and revoke share one window's intent boundary, including StrictMode remounts.
let contextWork: Promise<unknown> = Promise.resolve();

function serializeContext<T>(work: () => Promise<T>): Promise<T> {
  const pending = contextWork.then(work, work);
  contextWork = pending.catch(() => undefined);
  return pending;
}

function blocked() {
  return (
    document.visibilityState !== "visible" || document.querySelector('[role="dialog"], [role="alertdialog"]') !== null
  );
}

function geometry(element: HTMLElement) {
  const bounds = element.getBoundingClientRect();
  const viewport = window.visualViewport;
  return [
    bounds.left,
    bounds.top,
    bounds.width,
    bounds.height,
    window.innerWidth,
    window.innerHeight,
    window.devicePixelRatio,
    viewport?.width,
    viewport?.height,
    viewport?.offsetLeft,
    viewport?.offsetTop,
    viewport?.scale,
    blocked(),
  ].join(":");
}

function count(value: number): number | null {
  return Number.isInteger(value) && value >= 1 && value <= 16 ? value : null;
}

function hitsList(element: HTMLElement, event: SessionFileDrag) {
  if (blocked() || event.x === null || event.y === null) return false;
  if (!Number.isFinite(event.x) || !Number.isFinite(event.y)) return false;
  if (event.x < 0 || event.x >= 1 || event.y < 0 || event.y >= 1) return false;
  if (
    !Number.isFinite(window.innerWidth) ||
    !Number.isFinite(window.innerHeight) ||
    window.innerWidth <= 0 ||
    window.innerHeight <= 0
  )
    return false;
  const x = event.x * window.innerWidth;
  const y = event.y * window.innerHeight;
  const bounds = element.getBoundingClientRect();
  if (
    ![bounds.left, bounds.top, bounds.width, bounds.height].every(Number.isFinite) ||
    bounds.width <= 0 ||
    bounds.height <= 0 ||
    x < bounds.left ||
    x >= bounds.right ||
    y < bounds.top ||
    y >= bounds.bottom
  )
    return false;
  const target = document.elementFromPoint(x, y);
  return target !== null && element.contains(target);
}

/** Native selection paths stay in Rust; this view returns only a ticket after hit testing. */
export function useSessionFileDrop({
  sessionId,
  transportId,
  queueId,
  directoryPath,
  enabled,
  pickerBusy,
  list,
  locale,
  onEnqueueFeedback,
}: {
  sessionId: string;
  transportId: string | null;
  queueId: string | null;
  directoryPath: number[];
  enabled: boolean;
  pickerBusy: boolean;
  list: RefObject<HTMLDivElement | null>;
  locale: "en" | "zh-Hans";
  onEnqueueFeedback: (feedback: EnqueueFeedback) => void;
}) {
  const [revision, setRevision] = useState(0);
  const [feedback, setFeedback] = useState<DropFeedback | null>(null);
  const path = directoryPath.join(",");
  const owner = `${sessionId}:${transportId}:${queueId}:${path}`;
  if (feedback && (!enabled || feedback.owner !== owner)) setFeedback(null);
  const busy = pickerBusy && !(feedback?.owner === owner && feedback.phase === "checking");
  const latest = useRef({ owner, enabled, locale, onEnqueueFeedback });
  useLayoutEffect(() => {
    latest.current = { owner, enabled, locale, onEnqueueFeedback };
  });

  useEffect(() => {
    const element = list.current;
    if (!enabled || busy || !transportId || !queueId || !element) return;
    if (
      typeof ResizeObserver !== "function" ||
      typeof window.matchMedia !== "function" ||
      typeof document.elementFromPoint !== "function"
    )
      return;
    const contextId = crypto.randomUUID();
    const originalGeometry = geometry(element);
    let current = true;
    let stop: (() => void) | undefined;
    let latestTicket: string | null = null;
    let pendingTicket: string | null = null;
    let lastDroppedTicket: string | null = null;
    let finishArming!: (ready: boolean) => void;
    const armReady = new Promise<boolean>((resolve) => {
      finishArming = resolve;
    });
    const valid = () => current && latest.current.enabled && latest.current.owner === owner;
    const revoke = () => serializeContext(() => commands.sessionRevokeFileDrop(contextId));
    const invalidate = () => {
      if (!current) return;
      current = false;
      finishArming(false);
      setFeedback((previous) =>
        previous?.owner === owner && (previous.phase === "over" || previous.phase === "checking") ? null : previous,
      );
      void revoke();
      setRevision((value) => value + 1);
    };
    const checkGeometry = () => {
      if (geometry(element) !== originalGeometry) invalidate();
    };
    const refuse = (event: SessionFileDrag) => {
      latestTicket = event.ticketId;
      pendingTicket = null;
      if (event.ticketId) void commands.sessionCancelFileDrop(contextId, event.ticketId).catch(() => undefined);
      setFeedback({ owner, phase: "refused", count: count(event.count), issue: null });
    };
    const receive = (event: SessionFileDrag) => {
      if (!valid() || event.contextId !== contextId) return;
      if (geometry(element) !== originalGeometry) {
        invalidate();
        return;
      }
      if (event.phase === "leave") {
        setFeedback((previous) => (previous?.phase === "over" ? null : previous));
        return;
      }
      if (event.phase === "refused") {
        refuse(event);
        return;
      }
      const acceptedCount = count(event.count);
      const hit = hitsList(element, event);
      if (event.phase === "over") {
        if (pendingTicket !== null) return;
        setFeedback(hit ? { owner, phase: "over", count: acceptedCount, issue: null } : null);
        return;
      }
      if (!event.ticketId || lastDroppedTicket === event.ticketId) return;
      lastDroppedTicket = event.ticketId;
      if (!hit || acceptedCount === null) {
        refuse(event);
        return;
      }
      const ticket = event.ticketId;
      latestTicket = ticket;
      pendingTicket = ticket;
      setFeedback({ owner, phase: "checking", count: acceptedCount, issue: null });
      latest.current.onEnqueueFeedback({ requestId: ticket, phase: "started", issue: null });
      void armReady
        .then((ready) => {
          if (
            !ready ||
            !valid() ||
            latestTicket !== ticket ||
            geometry(element) !== originalGeometry ||
            !hitsList(element, event)
          ) {
            void commands.sessionCancelFileDrop(contextId, ticket).catch(() => undefined);
            return { status: "error" as const, error: "staleItem" as const };
          }
          return commands.sessionConsumeFileDrop(contextId, ticket, latest.current.locale);
        })
        .then((result) => {
          const issue = result.status === "error" ? result.error : null;
          latest.current.onEnqueueFeedback({ requestId: ticket, phase: "settled", issue });
          if (!valid() || latestTicket !== ticket) return;
          pendingTicket = null;
          if (result.status === "error") setFeedback({ owner, phase: "refused", count: acceptedCount, issue });
          else setFeedback({ owner, phase: "accepted", count: count(result.data.accepted), issue: null });
        })
        .catch(() => {
          latest.current.onEnqueueFeedback({ requestId: ticket, phase: "settled", issue: "transferFailed" });
          if (valid() && latestTicket === ticket) {
            pendingTicket = null;
            setFeedback({ owner, phase: "refused", count: acceptedCount, issue: "transferFailed" });
          }
        });
    };
    if (!blocked()) {
      void events.sessionFileDrag
        .listen((event) => receive(event.payload))
        .then(async (unlisten) => {
          if (!valid()) {
            finishArming(false);
            unlisten();
            return;
          }
          stop = unlisten;
          const result = await serializeContext(async () => {
            if (!valid()) return;
            return commands.sessionArmFileDrop(sessionId, transportId, queueId, path.split(",").map(Number), contextId);
          });
          finishArming(result?.status === "ok");
          if (valid() && result?.status === "error")
            setFeedback({ owner, phase: "refused", count: null, issue: result.error });
        })
        .catch(() => {
          finishArming(false);
          if (valid()) setFeedback({ owner, phase: "refused", count: null, issue: "transferFailed" });
        });
    }

    const observer = new MutationObserver(checkGeometry);
    observer.observe(document.body, { subtree: true, childList: true, attributes: true, characterData: true });
    const resize = new ResizeObserver(checkGeometry);
    resize.observe(element);
    resize.observe(document.documentElement);
    const resolution = window.matchMedia(`(resolution: ${window.devicePixelRatio}dppx)`);
    resolution.addEventListener("change", invalidate);
    window.addEventListener("resize", invalidate);
    window.addEventListener("scroll", invalidate, true);
    document.addEventListener("visibilitychange", invalidate);
    window.visualViewport?.addEventListener("resize", invalidate);
    window.visualViewport?.addEventListener("scroll", invalidate);
    return () => {
      current = false;
      finishArming(false);
      stop?.();
      observer.disconnect();
      resize.disconnect();
      resolution.removeEventListener("change", invalidate);
      window.removeEventListener("resize", invalidate);
      window.removeEventListener("scroll", invalidate, true);
      document.removeEventListener("visibilitychange", invalidate);
      window.visualViewport?.removeEventListener("resize", invalidate);
      window.visualViewport?.removeEventListener("scroll", invalidate);
      void revoke();
    };
  }, [sessionId, transportId, queueId, path, owner, enabled, busy, list, revision]);

  return enabled && feedback?.owner === owner ? feedback : null;
}
