// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import type { Locale, SessionEditorIssue, SessionEditorSnapshot } from "./ipc/bindings";

type Action = "start" | "open" | "upload" | "stop";
type Outcome<T> = { status: "ok"; data: T } | { status: "error"; error: SessionEditorIssue };

/** Observing a working copy never owns its editor, file, or transfer. */
export function useSessionEditor(sessionId: string, transportId: string | null, active: boolean) {
  const commands = useProfileCommands();
  const [snapshot, setSnapshot] = useState<SessionEditorSnapshot | null>(null);
  const [issue, setIssue] = useState<SessionEditorIssue | null>(null);
  const [pollIssue, setPollIssue] = useState<SessionEditorIssue | null>(null);
  const [loading, setLoading] = useState(true);
  const context = useMemo(() => ({ commands, sessionId, transportId }), [commands, sessionId, transportId]);
  const [actionState, setActionState] = useState<{ context: typeof context; kind: Action } | null>(null);
  const [reload, setReload] = useState(0);
  const owner = useRef<typeof context | null>(null);
  const action = useRef<{ context: typeof context; token: symbol } | null>(null);
  const reading = useRef(false);

  useEffect(() => {
    owner.current = context;
    return () => {
      if (owner.current === context) owner.current = null;
    };
  }, [context]);

  useEffect(() => {
    if (!active) return;
    let current = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const token = owner.current;
    const schedule = () => {
      if (current) timer = setTimeout(() => void poll(), 500);
    };
    const poll = async () => {
      if (!current) return;
      if (reading.current) {
        schedule();
        return;
      }
      reading.current = true;
      try {
        const result = await commands.sessionEditorSnapshot(sessionId);
        if (!current || owner.current !== token) return;
        if (result.status === "error") setPollIssue(result.error);
        else if (result.data === null || result.data.sessionId === sessionId) {
          setSnapshot(result.data);
          setPollIssue(null);
        }
      } catch {
        if (current && owner.current === token) setPollIssue("transferFailed");
      } finally {
        reading.current = false;
        if (current && owner.current === token) setLoading(false);
        schedule();
      }
    };
    void poll();
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [commands, sessionId, transportId, active, reload]);

  const request = async <T>(kind: Action, execute: () => Promise<Outcome<T>>) => {
    const capturedOwner = owner.current;
    if (!active || !capturedOwner || action.current?.context === capturedOwner) return null;
    const token = Symbol();
    action.current = { context: capturedOwner, token };
    setActionState({ context: capturedOwner, kind });
    setIssue(null);
    try {
      const result = await execute();
      if (owner.current !== capturedOwner || action.current?.token !== token) return null;
      if (result.status === "error") setIssue(result.error);
      return result;
    } catch {
      if (owner.current === capturedOwner && action.current?.token === token) setIssue("transferFailed");
      return null;
    } finally {
      if (action.current?.token === token) action.current = null;
      if (owner.current === capturedOwner) {
        setActionState(null);
        setLoading(true);
        setReload((value) => value + 1);
      }
    }
  };

  return {
    snapshot,
    issue: issue ?? pollIssue,
    loading,
    pending: actionState?.context === context ? actionState.kind : null,
    retry: () => {
      setIssue(null);
      setReload((value) => value + 1);
    },
    start: (remotePath: number[], locale: Locale) =>
      transportId
        ? request("start", () => commands.sessionEditFile(sessionId, transportId, remotePath, locale))
        : Promise.resolve(null),
    open: () =>
      snapshot
        ? request("open", () => commands.sessionEditorOpen(sessionId, snapshot.editorId))
        : Promise.resolve(null),
    upload: (locale: Locale) =>
      snapshot && transportId === snapshot.transportId
        ? request("upload", () => commands.sessionEditorUpload(sessionId, transportId, snapshot.editorId, locale))
        : Promise.resolve(null),
    stop: () =>
      snapshot
        ? request("stop", () => commands.sessionEditorStop(sessionId, snapshot.editorId))
        : Promise.resolve(null),
  };
}
