// SPDX-License-Identifier: Apache-2.0
import { useProfileCommands } from "./account-profiles";
import {
  Button,
  Dialog,
  HostEgg,
  IconButton,
  Mark,
  shortcutModifier,
  useContextMenu,
  type MarkMood,
} from "@scoplen/ui";
import type { ScoplenTerminalElement, TerminalSnapshot, TerminalSplitDirection } from "@scoplen/terminal";
import { FolderOpen, Palette } from "lucide-react";
import { Channel } from "@tauri-apps/api/core";
import { Terminal, type TerminalSink, type TerminalSource } from "@scoplen/terminal/react";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useI18n } from "./i18n";
import {
  type SessionEvent,
  type PreparationEvent,
  type PreparationContext,
  type SessionTransferIssue,
  type SessionPreparationIntent,
} from "./ipc/bindings";
import { useTerminalColors, xtermTheme } from "./terminal-colors";
import { SessionFiles, type EnqueueFeedback, type FileOperationOutcome } from "./session-files";
import { dismissUploadAttention, initialUploadAttention, recordUploadAttention } from "./session-upload-attention";
import { useSessionTransfers } from "./use-session-transfers";
import { SessionSnippetsButton } from "./session-snippets";
import {
  TrustDialog,
  PassphraseDialog,
  InteractiveDialog,
  TrustSourceDetails,
  HopIdentity,
} from "./preparation-dialogs";

export type SessionState =
  | "verifying"
  | "trusting"
  | "passphrase"
  | "keyboardInteractive"
  | "connecting"
  | "reconnecting"
  | "connected"
  | "closed"
  | "failed";

/** The face the host's egg makes in each state. */
const sessionFaces: Record<SessionState, { mood: MarkMood; active: boolean; attention: boolean }> = {
  verifying: { mood: "awake", active: true, attention: false },
  trusting: { mood: "awake", active: true, attention: true },
  passphrase: { mood: "awake", active: true, attention: true },
  keyboardInteractive: { mood: "awake", active: true, attention: true },
  connecting: { mood: "awake", active: true, attention: false },
  reconnecting: { mood: "awake", active: true, attention: false },
  connected: { mood: "rest", active: true, attention: false },
  closed: { mood: "closed", active: false, attention: false },
  failed: { mood: "low", active: false, attention: true },
};

/** A small output surface for the first live SSH session slice. */
export function SessionTerminal({
  profileId,
  label,
  active = true,
  onClose,
  onStateChange,
  onLabelChange,
  onOpenColors,
  savedOutput,
  registerClose,
  sessionId: restoredSessionId,
  onSplit,
  splitIssue,
  registerFocus,
}: {
  profileId: string;
  label: string;
  /** Only the selected session may display its pending prompt. */
  active?: boolean;
  onClose: (discardOutput?: boolean) => void;
  savedOutput?: TerminalSnapshot;
  /** Fresh runtime identity supplied by an explicit saved-Workspace Open. */
  sessionId?: string;
  registerClose?: (close: (discard?: boolean) => Promise<boolean>) => () => void;
  /** Explicitly start one independent ordinary terminal beside this pane. */
  onSplit?: (direction: TerminalSplitDirection) => void;
  splitIssue?: string;
  /** Register actual input focus without transferring session ownership. */
  registerFocus?: (focus: () => void) => () => void;
  /** Told whenever the connection state changes, so the window can show it on the tab. */
  onStateChange?: (state: SessionState) => void;
  /** Current target label resolved through ordinary Login preparation. */
  onLabelChange?: (label: string) => void;
  /** Opens the terminal color settings. */
  onOpenColors?: () => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const titleId = useId();
  const [state, setState] = useState<SessionState>(savedOutput ? "closed" : "verifying");
  const [offline, setOffline] = useState(!!savedOutput);
  const [restored, setRestored] = useState(!savedOutput);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [closeFailed, setCloseFailed] = useState(false);
  const [closingView, setClosingView] = useState(false);
  const closing = useRef(false);
  const checkpointTransport = useRef<string | null>(null);
  const checkpointSequence = useRef(0);
  const outputRevision = useRef(0);
  const savedRevision = useRef(0);
  const quietWaiters = useRef(new Set<() => void>());
  const checkpointTail = useRef<Promise<void>>(Promise.resolve());
  const [error, setError] = useState<string | null>(null);
  const [hostPrompt, setHostPrompt] = useState<Extract<PreparationEvent, { kind: "trust" }> | null>(null);
  const hostKey = hostPrompt?.hostKey ?? null;
  const [verified, setVerified] = useState<Array<Extract<PreparationEvent, { kind: "verified" }>>>([]);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [filesOpen, setFilesOpen] = useState(false);
  const [enqueueIssue, setEnqueueIssue] = useState<SessionTransferIssue | null>(null);
  const latestEnqueue = useRef<string | null>(null);
  const [uploadAttention, setUploadAttention] = useState(initialUploadAttention);
  const filesToggle = useRef<HTMLButtonElement>(null);
  const [context, setContext] = useState<PreparationContext | null>(null);
  const [passphrasePrompt, setPassphrasePrompt] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<Extract<PreparationEvent, { kind: "keyboardInteractive" }> | null>(null);
  const [challengeError, setChallengeError] = useState<string | null>(null);
  const currentPrompt = useRef<string | null>(null);
  const [trustError, setTrustError] = useState<string | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [passphraseError, setPassphraseError] = useState<string | null>(null);
  const [source, setSource] = useState<TerminalSource | null>(null);
  const [hasOutput, setHasOutput] = useState(!!savedOutput);
  const [transportPending, setTransportPending] = useState(false);
  const [sessionId] = useState(() => restoredSessionId ?? crypto.randomUUID());
  const [runRevision, setRunRevision] = useState(0);
  const transfers = useSessionTransfers(sessionId, active && !offline);
  const [transportId, setTransportId] = useState<string | null>(null);
  const currentTransport = useRef<string | null>(null);
  const [automatic, setAutomatic] = useState(false);
  const [retry, setRetry] = useState<{ attempt: number; delaySeconds: number } | null>(null);
  const mounted = useRef(true);
  const generation = useRef(0);
  const connecting = useRef(false);
  const retrying = useRef(false);
  const connectionEnded = useRef(false);
  const localEnd = useRef<{ state: "closed" | "failed"; message: string | null } | null>(null);
  const trusting = useRef(false);
  const reportState = useRef(onStateChange);
  const reportLabel = useRef(onLabelChange);
  const translate = useRef(t);
  useEffect(() => {
    reportState.current = onStateChange;
    reportLabel.current = onLabelChange;
    translate.current = t;
  });
  useEffect(() => {
    reportState.current?.(state);
  }, [state]);

  const reportFileOutcome = useCallback((outcome: FileOperationOutcome) => {
    setUploadAttention((current) => recordUploadAttention(current, outcome));
  }, []);
  const reportEnqueue = useCallback((feedback: EnqueueFeedback) => {
    if (feedback.phase === "started") latestEnqueue.current = feedback.requestId;
    if (latestEnqueue.current === feedback.requestId) setEnqueueIssue(feedback.issue);
  }, []);

  const connectSession = useCallback(() => {
    if (!mounted.current || connecting.current) return;
    const current = generation.current;
    connecting.current = true;
    connectionEnded.current = false;
    localEnd.current = null;
    setTransportPending(true);
    setState("connecting");
    setError(null);
    setSource({
      subscribe(onChunk, { signal }) {
        let active = true;
        let ended = false;
        const stop = () => {
          if (!active) return;
          active = false;
          if (!ended) void commands.sessionCloseTransport(sessionId).catch(() => undefined);
        };
        signal.addEventListener("abort", stop, { once: true });

        const clearPreparation = () => {
          trusting.current = false;
          setTrustBusy(false);
          setTrustError(null);
          setHostPrompt(null);
          setPassphrasePrompt(null);
          setChallenge(null);
          setChallengeError(null);
          currentPrompt.current = null;
          setPassphraseError(null);
        };
        const messages = new Channel<SessionEvent | ArrayBuffer>((event) => {
          if (!active || ended || !mounted.current || current !== generation.current) return;
          if (event instanceof ArrayBuffer) {
            const chunk = new Uint8Array(event);
            const transport = currentTransport.current;
            if (connectionEnded.current || !transport || chunk.length < 16) return;
            const expected = transport.replaceAll("-", "");
            for (let index = 0; index < 16; index++) {
              if (chunk[index] !== Number.parseInt(expected.slice(index * 2, index * 2 + 2), 16)) return;
            }
            const data = chunk.subarray(16);
            if (data.length) outputRevision.current++;
            if (data.length) setHasOutput(true);
            onChunk(data);
            return;
          }
          if (localEnd.current && event.kind !== "closed" && event.kind !== "failed") return;
          if (
            connectionEnded.current &&
            event.kind !== "starting" &&
            event.kind !== "closed" &&
            event.kind !== "failed"
          )
            return;
          switch (event.kind) {
            case "starting":
              checkpointTransport.current = event.transportId;
              setFilesOpen(false);
              clearPreparation();
              currentTransport.current = event.transportId;
              setTransportId(event.transportId);
              connectionEnded.current = false;
              setTransportPending(true);
              setAutomatic(event.automatic);
              setRetry(null);
              setContext(null);
              setVerified([]);
              setDetailsOpen(false);
              setError(null);
              setState(event.automatic ? "reconnecting" : "connecting");
              break;
            case "preparation": {
              if (currentTransport.current !== event.transportId) return;
              clearPreparation();
              const preparation = event.event;
              setContext(preparation.context);
              if (preparation.context.target)
                reportLabel.current?.(`${preparation.context.host} · ${preparation.context.login}`);
              if (preparation.kind === "verified") {
                setVerified((current) => [
                  ...current.filter((item) => item.context.position !== preparation.context.position),
                  preparation,
                ]);
                break;
              }
              setHostPrompt(preparation.kind === "trust" ? preparation : null);
              setPassphrasePrompt(preparation.kind === "passphrase" ? preparation.promptId : null);
              setChallenge(preparation.kind === "keyboardInteractive" ? preparation : null);
              currentPrompt.current = preparation.kind === "progress" ? null : preparation.promptId;
              setPassphraseError(
                preparation.kind === "passphrase" && preparation.incorrect
                  ? translate.current("session.passphrase.incorrect")
                  : null,
              );
              setState(
                preparation.kind === "trust"
                  ? "trusting"
                  : preparation.kind === "keyboardInteractive"
                    ? "keyboardInteractive"
                    : preparation.kind === "passphrase"
                      ? "passphrase"
                      : "connecting",
              );
              break;
            }
            case "ready":
              if (currentTransport.current !== event.transportId) return;
              clearPreparation();
              setState("connected");
              setTransportPending(false);
              setAutomatic(false);
              setRetry(null);
              setError(null);
              break;
            case "retrying":
              clearPreparation();
              currentTransport.current = null;
              setTransportId(null);
              setRetry({ attempt: event.attempt, delaySeconds: event.delaySeconds });
              setAutomatic(true);
              setState("reconnecting");
              setError(event.error);
              break;
            case "closed":
            case "failed":
              clearPreparation();
              connectionEnded.current = true;
              for (const resolve of quietWaiters.current) resolve();
              quietWaiters.current.clear();
              currentTransport.current = null;
              setTransportId(null);
              setTransportPending(false);
              setAutomatic(false);
              setRetry(null);
              setState(localEnd.current?.state ?? event.kind);
              setError(localEnd.current?.message ?? (event.kind === "failed" ? event.error : null));
              break;
          }
        });
        void commands
          .sessionReserveTransport(sessionId, true)
          .then((reservation) => {
            if (reservation.status === "error") return reservation;
            if (
              !active ||
              closing.current ||
              connectionEnded.current ||
              !mounted.current ||
              current !== generation.current
            ) {
              void commands.sessionCloseTransport(sessionId).catch(() => undefined);
              return { status: "ok" as const, data: null };
            }
            return commands.sessionConnect(profileId, null, true, sessionId, messages);
          })
          .then((result) => {
            if (!active || !mounted.current || current !== generation.current) return;
            ended = true;
            clearPreparation();
            currentTransport.current = null;
            setTransportId(null);
            if (connectionEnded.current) return;
            if (result.status === "ok") {
              setState("closed");
            } else {
              setState("failed");
              setError(result.error);
            }
          })
          .catch((cause: unknown) => {
            if (!active || !mounted.current || current !== generation.current) return;
            ended = true;
            clearPreparation();
            currentTransport.current = null;
            setTransportId(null);
            if (connectionEnded.current) return;
            setState("failed");
            setError(cause instanceof Error ? cause.message : String(cause));
          })
          .finally(() => {
            if (!active || !mounted.current || current !== generation.current) return;
            connectionEnded.current = true;
            for (const resolve of quietWaiters.current) resolve();
            quietWaiters.current.clear();
            connecting.current = false;
            setTransportPending(false);
          });

        return { unsubscribe: stop };
      },
    });
  }, [profileId, sessionId, commands]);

  const inputSink = useMemo<TerminalSink>(
    () => ({
      async write(bytes) {
        if (!transportId) return;
        const result = await commands.sessionInput(sessionId, transportId, Array.from(bytes));
        if (result.status === "error") throw new Error(result.error);
      },
    }),
    [sessionId, transportId, commands],
  );
  const { colors } = useTerminalColors();
  const terminal = useRef<ScoplenTerminalElement>(null);
  const selected = useRef(active);
  useEffect(() => {
    selected.current = active;
  }, [active]);
  const returnInputFocus = () => {
    if (selected.current) terminal.current?.focusInput();
    return false;
  };
  useEffect(
    () =>
      registerFocus?.(() => {
        if (!["trusting", "passphrase", "keyboardInteractive"].includes(state) && !detailsOpen)
          terminal.current?.focusInput();
      }),
    [registerFocus, state, detailsOpen],
  );
  const menu = useContextMenu();

  // The remote terminal follows the window: the size is sent once the session
  // is connected, and again whenever the grid changes.
  const size = useRef<{ columns: number; rows: number } | null>(null);
  const sendSize = useCallback(() => {
    if (!size.current || !transportId) return;
    void commands.sessionResize(sessionId, transportId, size.current.columns, size.current.rows).catch(() => undefined);
  }, [sessionId, transportId, commands]);
  useEffect(() => {
    if (state === "connected") sendSize();
  }, [state, sendSize]);
  const terminalProfile = useMemo(
    () => ({ cursorBlink: true, scrollback: 2_000, theme: xtermTheme(colors) }),
    [colors],
  );

  const closeTransport = useCallback(() => {
    void commands.sessionCloseTransport(sessionId).catch(() => undefined);
  }, [sessionId, commands]);

  const checkpoint = useCallback(
    (force = false) => {
      const ownerGeneration = generation.current;
      const transport = checkpointTransport.current;
      const operation = checkpointTail.current
        .catch(() => undefined)
        .then(async () => {
          if (!mounted.current || ownerGeneration !== generation.current || checkpointTransport.current !== transport)
            return;
          if (
            !transport ||
            !terminal.current ||
            !outputRevision.current ||
            (!force && savedRevision.current === outputRevision.current)
          )
            return;
          const revision = outputRevision.current;
          const snapshot = await terminal.current.serialize();
          if (!mounted.current || ownerGeneration !== generation.current || checkpointTransport.current !== transport)
            return;
          const result = await commands.sessionSaveOutput(sessionId, transport, ++checkpointSequence.current, snapshot);
          if (mounted.current && ownerGeneration === generation.current && checkpointTransport.current === transport) {
            if (result.status === "error") throw new Error(result.error);
            savedRevision.current = revision;
            setSaveError(null);
          }
        });
      checkpointTail.current = operation;
      return operation;
    },
    [sessionId, commands],
  );

  const prepareClose = useCallback(
    async (discard = false) => {
      if (closing.current) return false;
      if (discard) return true;
      closing.current = true;
      setClosingView(true);
      try {
        if (!offline && connecting.current && !connectionEnded.current) {
          let timer: ReturnType<typeof setTimeout> | undefined;
          let resolveQuiet!: () => void;
          const quiet = new Promise<void>((resolve, reject) => {
            resolveQuiet = resolve;
            quietWaiters.current.add(resolve);
            timer = setTimeout(() => reject(new Error("terminal close timed out")), 10_000);
          });
          try {
            await Promise.all([
              quiet,
              commands.sessionStopReconnecting(sessionId).then((result) => {
                if (result.status === "error" && checkpointTransport.current) throw new Error(result.error);
              }),
            ]);
          } finally {
            clearTimeout(timer);
            quietWaiters.current.delete(resolveQuiet);
          }
        }
        if (!offline) await checkpoint(true);
        return true;
      } catch {
        setSaveError(translate.current("session.output.saveFailed"));
        setCloseFailed(true);
        return false;
      } finally {
        closing.current = false;
        setClosingView(false);
      }
    },
    [offline, sessionId, checkpoint, commands],
  );
  useEffect(() => registerClose?.(prepareClose), [registerClose, prepareClose]);

  useEffect(() => {
    if (offline) return;
    const timer = setInterval(() => {
      if (closing.current) return;
      const current = generation.current;
      const transport = checkpointTransport.current;
      void checkpoint().catch(() => {
        if (mounted.current && current === generation.current && checkpointTransport.current === transport)
          setSaveError(translate.current("session.output.saveFailed"));
      });
    }, 5_000);
    return () => clearInterval(timer);
  }, [offline, checkpoint]);

  useEffect(() => {
    if (!savedOutput) return;
    let active = true;
    void Promise.resolve()
      .then(async () => {
        if (active) await terminal.current?.restore(savedOutput);
      })
      .then(() => {
        if (active) setRestored(true);
      })
      .catch(() => {
        if (active) setSaveError(translate.current("session.output.restoreFailed"));
      });
    return () => {
      active = false;
    };
  }, [savedOutput]);

  useEffect(() => {
    if (offline) return;
    return () => {
      void commands.sessionCloseTransport(sessionId).catch(() => undefined);
    };
  }, [offline, profileId, sessionId, commands]);

  useEffect(() => {
    if (offline) return;
    let active = true;
    const current = ++generation.current;
    mounted.current = true;

    void (async () => {
      try {
        await Promise.resolve();
        if (!active || !mounted.current || current !== generation.current) return;
        setState("verifying");
        setError(null);
        setHostPrompt(null);
        setTrustError(null);
        setPassphraseError(null);
        connectSession();
      } catch (cause) {
        if (!active || !mounted.current || current !== generation.current) return;
        setState("failed");
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (active && mounted.current && current === generation.current) retrying.current = false;
      }
    })();

    return () => {
      active = false;
      mounted.current = false;
    };
  }, [connectSession, profileId, sessionId, offline, runRevision]);

  const interruptTransport = (failure: boolean, message: string | null) => {
    const current = generation.current;
    localEnd.current = { state: failure ? "failed" : "closed", message };
    connectionEnded.current = true;
    currentTransport.current = null;
    setTransportId(null);
    currentPrompt.current = null;
    trusting.current = false;
    setTrustBusy(false);
    setHostPrompt(null);
    setPassphrasePrompt(null);
    setChallenge(null);
    setChallengeError(null);
    setTransportPending(true);
    setAutomatic(false);
    setRetry(null);
    setState(failure ? "failed" : "closed");
    setError(message);
    const command = failure ? commands.sessionFailTransport : commands.sessionStopReconnecting;
    void command(sessionId)
      .then((result) => {
        if (result.status === "error") throw new Error(result.error);
      })
      .catch((cause: unknown) => {
        if (!mounted.current || current !== generation.current) return;
        setState("failed");
        setError(cause instanceof Error ? cause.message : String(cause));
        setTransportPending(false);
      });
  };
  const cancelTrust = () => interruptTransport(false, t("session.trust.cancelled"));

  const respond = async (promptId: string, intent: SessionPreparationIntent) => {
    if (trusting.current || !mounted.current || currentPrompt.current !== promptId) return;
    const transport = currentTransport.current;
    if (!transport) return;
    const current = generation.current;
    trusting.current = true;
    setTrustBusy(true);
    setTrustError(null);
    try {
      const result = await commands.sessionRespond(sessionId, transport, promptId, intent);
      if (!mounted.current || current !== generation.current || currentPrompt.current !== promptId) return;
      if (result.status === "error") {
        if (intent.kind === "keyboardInteractive") setChallengeError(result.error);
        else if (intent.kind === "passphrase") setPassphraseError(result.error);
        else setTrustError(result.error);
        return;
      }
      trusting.current = false;
      setTrustBusy(false);
      currentPrompt.current = null;
      setHostPrompt(null);
      setPassphrasePrompt(null);
      setChallenge(null);
      setChallengeError(null);
      setState("connecting");
    } catch (cause) {
      if (!mounted.current || current !== generation.current || currentPrompt.current !== promptId) return;
      const message = cause instanceof Error ? cause.message : String(cause);
      if (intent.kind === "keyboardInteractive") setChallengeError(message);
      else if (intent.kind === "passphrase") setPassphraseError(message);
      else setTrustError(message);
    } finally {
      if (mounted.current && current === generation.current && currentPrompt.current === promptId) {
        trusting.current = false;
        setTrustBusy(false);
      }
    }
  };
  const trustAndConnect = () => {
    if (hostPrompt) void respond(hostPrompt.promptId, { kind: "acceptHostKey" });
  };

  const reconnect = () => {
    if (closing.current || !restored) return;
    if (offline) {
      setOffline(false);
      setSaveError(null);
      return;
    }
    if (!mounted.current || transportPending || retrying.current || (state !== "closed" && state !== "failed")) return;
    if (!connecting.current) {
      retrying.current = true;
      setTransportPending(true);
      setRunRevision((revision) => revision + 1);
      return;
    }
    retrying.current = true;
    localEnd.current = null;
    connectionEnded.current = false;
    setTransportPending(true);
    trusting.current = false;
    setTrustBusy(false);
    setHostPrompt(null);
    setError(null);
    currentPrompt.current = null;
    setPassphrasePrompt(null);
    setChallenge(null);
    setChallengeError(null);
    setContext(null);
    setState("verifying");
    void commands
      .sessionRetryTransport(sessionId)
      .then((result) => {
        if (!mounted.current || result.status !== "error") return;
        setState("failed");
        setError(result.error);
        setTransportPending(false);
      })
      .catch((cause: unknown) => {
        if (!mounted.current) return;
        setState("failed");
        setError(cause instanceof Error ? cause.message : String(cause));
        setTransportPending(false);
      })
      .finally(() => {
        retrying.current = false;
      });
  };

  const cancelPassphrase = () => interruptTransport(false, t("session.passphrase.cancelled"));

  const status =
    state === "verifying"
      ? t("session.verifying")
      : state === "trusting"
        ? t(
            hostKey?.changed
              ? "session.trust.changedTitle"
              : hostKey?.review
                ? "session.trust.reviewTitle"
                : "session.firstConnection",
          )
        : state === "keyboardInteractive"
          ? t("session.interactive.status")
          : state === "passphrase"
            ? t("session.passphrase.status")
            : state === "reconnecting"
              ? retry
                ? t("session.reconnecting.wait", { attempt: retry.attempt, seconds: retry.delaySeconds })
                : t("session.reconnecting")
              : state === "connecting"
                ? t("session.connecting")
                : state === "connected"
                  ? t("session.connected")
                  : state === "closed"
                    ? t("session.closed")
                    : t("session.failed");

  const face = sessionFaces[state];
  const unknownTransfer = transfers.snapshot?.items.some((item) => item.state === "unknown") ?? false;
  const transferCleanup =
    transfers.snapshot?.items.some((item) => item.stagingMayRemain) ||
    transfers.snapshot?.recent.some((item) => item.stagingMayRemain);
  return (
    <section className="flex h-full min-h-0 flex-col bg-background text-foreground" aria-labelledby={titleId}>
      <header className="flex shrink-0 flex-col gap-2 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-3">
          <HostEgg seed={profileId} size="1.75rem" mood={face.mood} active={face.active} attention={face.attention} />
          <div className="min-w-0">
            <h2 id={titleId} className="ui-display truncate text-base">
              {label}
            </h2>
            <p className="m-0 flex items-center gap-1.5 text-xs text-muted-foreground" role="status">
              <span
                aria-hidden="true"
                className={`size-1.5 rounded-full ${state === "connected" ? "bg-primary" : state === "failed" ? "bg-attention" : "bg-muted-foreground"}`}
              />
              {offline ? t("session.output.offline") : status}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1">
          {onSplit ? (
            <span className="flex flex-wrap gap-1" title={splitIssue ?? (closingView ? t("panes.closing") : undefined)}>
              <Button
                variant="ghost"
                disabled={!active || !!splitIssue || offline || closingView}
                onClick={() => onSplit("horizontal")}
              >
                {t("panes.right")}
              </Button>
              <Button
                variant="ghost"
                disabled={!active || !!splitIssue || offline || closingView}
                onClick={() => onSplit("vertical")}
              >
                {t("panes.below")}
              </Button>
            </span>
          ) : null}
          {verified.length ? (
            <Button variant="ghost" onClick={() => setDetailsOpen(true)}>
              {t("session.details.open")}
            </Button>
          ) : null}
          {automatic ? (
            <Button variant="ghost" onClick={() => interruptTransport(false, null)}>
              {t("session.reconnecting.stop")}
            </Button>
          ) : null}
          {state === "closed" || state === "failed" ? (
            <Button variant="primary" disabled={transportPending || !restored || closingView} onClick={reconnect}>
              {t("session.reconnect")}
            </Button>
          ) : null}
          {active && !offline && !closingView && state === "connected" && transportId ? (
            <SessionSnippetsButton
              key={transportId}
              sessionId={sessionId}
              transportId={transportId}
              target={label}
              canSend={() => currentTransport.current === transportId && !connectionEnded.current && !closing.current}
            />
          ) : null}
          {!offline &&
          !closingView &&
          (state === "connected" || !!transfers.snapshot?.items.length || !!transfers.snapshot?.recent.length) ? (
            <IconButton
              ref={filesToggle}
              label={t(filesOpen ? "session.files.close" : "session.files.open")}
              pressed={filesOpen}
              onClick={() => setFilesOpen((open) => !open)}
            >
              <FolderOpen aria-hidden="true" className="size-4" />
            </IconButton>
          ) : null}
          {onOpenColors ? (
            <IconButton label={t("session.colors")} onClick={onOpenColors}>
              <Palette aria-hidden="true" className="size-4" />
            </IconButton>
          ) : null}
          <Button
            variant="ghost"
            disabled={closingView}
            onClick={() => {
              if (registerClose) onClose();
              else
                void prepareClose().then((saved) => {
                  if (saved) {
                    closeTransport();
                    onClose();
                  }
                });
            }}
          >
            {t("session.close")}
          </Button>
        </div>
      </header>
      {onSplit && active && (splitIssue || offline || closingView) ? (
        <p className="mx-4 mt-0 mb-2 text-xs text-muted-foreground">
          {splitIssue ?? t(offline ? "panes.offline" : "panes.closing")}
        </p>
      ) : null}
      {saveError ? (
        <div className="mx-4 mb-2 flex flex-wrap items-center gap-2">
          <p role="alert" className="m-0 text-sm text-attention">
            {saveError}
          </p>
          {closeFailed ? (
            <Button variant="ghost" disabled={closingView} onClick={() => onClose(true)}>
              {t("session.output.closeWithoutSaving")}
            </Button>
          ) : null}
        </div>
      ) : null}
      {automatic ? (
        <p className="mx-4 mt-0 mb-2 text-xs text-muted-foreground">{t("session.reconnecting.newShell")}</p>
      ) : null}
      {hasOutput && error ? (
        <p role="alert" className="mx-4 mt-0 mb-2 text-sm whitespace-pre-wrap text-attention">
          {error}
        </p>
      ) : null}
      {!filesOpen && enqueueIssue ? (
        <div role="alert" className="mx-3 mb-2 flex flex-wrap items-center gap-2 text-xs text-attention">
          <p className="m-0 min-w-0 flex-1">{t(`session.transfers.issue.${enqueueIssue}`)}</p>
          <Button variant="ghost" onClick={() => setFilesOpen(true)}>
            {t("session.transfers.review")}
          </Button>
          <Button variant="ghost" onClick={() => setEnqueueIssue(null)}>
            {t("session.files.upload.dismiss")}
          </Button>
        </div>
      ) : null}
      {!filesOpen && transfers.snapshot && (transfers.snapshot.outstanding > 0 || transferCleanup) ? (
        <div
          role={unknownTransfer || transferCleanup ? "alert" : "status"}
          className="mx-3 mb-2 flex flex-wrap items-center gap-2 text-xs"
        >
          <p className="m-0 min-w-0 flex-1">
            {t(
              unknownTransfer
                ? "session.transfers.attentionUnknown"
                : transferCleanup
                  ? "session.transfers.attentionCleanup"
                  : "session.transfers.pending",
              { count: transfers.snapshot.outstanding },
            )}
          </p>
          <Button variant="ghost" onClick={() => setFilesOpen(true)}>
            {t("session.transfers.review")}
          </Button>
        </div>
      ) : null}
      {uploadAttention.unknown || uploadAttention.stagingMayRemain ? (
        <div
          role="alert"
          className={`mx-3 mb-2 flex flex-wrap items-start gap-2 rounded-md border-(length:--scoplen-border-width) p-3 ${uploadAttention.unknown ? "border-attention" : "border-border"}`}
        >
          <div className="min-w-0 flex-1 text-xs">
            {uploadAttention.unknown ? (
              <p className="m-0 text-attention">{t("session.files.operation.attentionUnknown")}</p>
            ) : null}
            {uploadAttention.stagingMayRemain ? (
              <p className="m-0 mt-1 text-attention">
                {t(uploadAttention.unknown ? "session.files.upload.staging" : "session.files.upload.attentionStaging")}
              </p>
            ) : null}
          </div>
          {state === "connected" && !offline && !closingView && !filesOpen ? (
            <Button variant="ghost" className="shrink-0 px-2" onClick={() => setFilesOpen(true)}>
              {t("session.files.open")}
            </Button>
          ) : null}
          <Button variant="ghost" className="shrink-0 px-2" onClick={() => setUploadAttention(dismissUploadAttention)}>
            {t("session.files.upload.dismiss")}
          </Button>
        </div>
      ) : null}
      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="min-h-0 min-w-0 flex-1 px-3 pb-3">
          <div
            onContextMenu={(event) =>
              menu(event, [
                {
                  label: t("menu.copy"),
                  shortcut: `${shortcutModifier}C`,
                  onSelect: () => void terminal.current?.copySelection(),
                },
                {
                  label: t("menu.paste"),
                  shortcut: `${shortcutModifier}V`,
                  disabled: state !== "connected",
                  onSelect: () => void terminal.current?.paste(),
                },
                "separator",
                { label: t("menu.copyAll"), onSelect: () => void terminal.current?.copyAll() },
                { label: t("menu.clear"), onSelect: () => terminal.current?.clearOutput() },
                ...(onOpenColors ? ["separator" as const, { label: t("session.colors"), onSelect: onOpenColors }] : []),
              ])
            }
            className="relative h-full min-h-0 overflow-hidden rounded-xl border-(length:--scoplen-border-width) border-border p-3 shadow-(--scoplen-shadow-card) transition-colors duration-(--duration-state)"
            style={{ background: colors.background }}
          >
            <Terminal
              ref={terminal}
              source={source}
              sink={state === "connected" ? inputSink : null}
              readOnly={offline || closingView || state !== "connected"}
              aria-label={t("session.output")}
              className={`h-full min-h-0 transition-opacity duration-(--duration-overlay) ${state === "connected" || hasOutput ? "opacity-100" : "opacity-40"}`}
              profile={terminalProfile}
              onTerminalResize={(next) => {
                size.current = next;
                if (state === "connected") sendSize();
              }}
              onTerminalError={(terminalError) => {
                if (!mounted.current) return;
                interruptTransport(true, terminalError.message);
              }}
            />
            {state !== "connected" && !hasOutput ? (
              <Stage state={state} seed={profileId} label={label} status={status} error={error} context={context} />
            ) : null}
          </div>
        </div>
        {filesOpen && !offline && !closingView ? (
          <SessionFiles
            key={transportId ?? "disconnected"}
            sessionId={sessionId}
            transportId={state === "connected" ? transportId : null}
            connectionLabel={label}
            active={active}
            queue={transfers.snapshot}
            queueIssue={enqueueIssue ?? transfers.issue}
            onEnqueueFeedback={reportEnqueue}
            onClose={() => {
              setFilesOpen(false);
              filesToggle.current?.focus();
            }}
            onFileOutcome={reportFileOutcome}
          />
        ) : null}
      </div>
      <TrustDialog
        finalFocus={returnInputFocus}
        active={active}
        prompt={hostPrompt}
        busy={trustBusy}
        error={trustError}
        onAccept={trustAndConnect}
        onCancel={cancelTrust}
      />
      <Dialog
        open={active && detailsOpen}
        onOpenChange={setDetailsOpen}
        title={t("session.details.title")}
        closeLabel={t("session.details.close")}
        footer={null}
      >
        <div className="space-y-6">
          {verified.map((hop) => (
            <section key={hop.context.position} aria-label={hop.context.host}>
              <HopIdentity context={hop.context} />
              <dl className="mb-4 grid gap-3 text-sm">
                <div>
                  <dt className="text-muted-foreground">{t("session.trust.algorithm")}</dt>
                  <dd className="m-0 mt-1 font-mono">{hop.algorithm}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">{t("session.trust.fingerprint")}</dt>
                  <dd className="m-0 mt-1 break-all font-mono select-text">{hop.fingerprint}</dd>
                </div>
              </dl>
              <TrustSourceDetails source={hop.source} />
            </section>
          ))}
        </div>
      </Dialog>
      {challenge ? (
        <InteractiveDialog
          finalFocus={returnInputFocus}
          key={challenge.promptId}
          active={active}
          challenge={challenge}
          busy={trustBusy}
          error={challengeError}
          onCancel={() => interruptTransport(false, t("session.interactive.cancelled"))}
          onAnswer={(answers) => void respond(challenge.promptId, { kind: "keyboardInteractive", answers })}
        />
      ) : null}
      <PassphraseDialog
        finalFocus={returnInputFocus}
        active={active}
        promptId={passphrasePrompt}
        context={context}
        busy={trustBusy}
        error={passphraseError}
        onCancel={cancelPassphrase}
        onPassphrase={(value) => {
          if (!value) {
            setPassphraseError(t("session.passphrase.required"));
            return;
          }
          if (passphrasePrompt) void respond(passphrasePrompt, { kind: "passphrase", value });
        }}
      />
    </section>
  );
}

/**
 * What covers the terminal until it is in use: while connecting, the mark
 * and the host's egg at either end of a route with a dot traveling along it;
 * once the session is closed, the egg asleep; when it failed, the egg in the
 * attention color with the reason. The terminal stays mounted underneath.
 */
function Stage({
  state,
  seed,
  label,
  status,
  error,
  context,
}: {
  state: Exclude<SessionState, "connected">;
  seed: string;
  label: string;
  status: string;
  error: string | null;
  context: PreparationContext | null;
}) {
  const working =
    state === "verifying" ||
    state === "connecting" ||
    state === "reconnecting" ||
    state === "trusting" ||
    state === "passphrase" ||
    state === "keyboardInteractive";
  return (
    <div className="absolute inset-0 grid place-items-center bg-[color-mix(in_srgb,var(--background)_78%,transparent)] px-6 backdrop-blur-[3px]">
      <div className="scoplen-rise flex w-full min-w-0 max-w-md flex-col items-center text-center">
        {working ? (
          <div aria-hidden="true" className="flex items-center gap-3">
            <Mark size="2.5rem" mood="awake" look={{ x: 1, y: 0 }} className="text-foreground" />
            <span className="scoplen-route relative h-0.5 w-28 rounded-full bg-border-strong sm:w-40" />
            <HostEgg seed={seed} size="2.5rem" mood="awake" active />
          </div>
        ) : (
          <HostEgg
            seed={seed}
            size="3.5rem"
            mood={state === "failed" ? "low" : "closed"}
            attention={state === "failed"}
            className={state === "failed" ? "" : "text-egg"}
          />
        )}
        <p className="mt-5 mb-0 font-mono text-sm text-foreground">{label}</p>
        <p className="mt-1 mb-0 text-sm text-muted-foreground">{status}</p>
        {state === "connecting" && context && context.total > 1 ? (
          <div className="mt-4 w-full">
            <HopIdentity context={context} />
          </div>
        ) : null}
        {error ? (
          <p role="alert" className="mt-4 mb-0 text-sm whitespace-pre-wrap text-attention">
            {error}
          </p>
        ) : null}
      </div>
    </div>
  );
}
