// SPDX-License-Identifier: Apache-2.0
import {
  Button,
  Dialog,
  Field,
  HostEgg,
  IconButton,
  Mark,
  shortcutModifier,
  useContextMenu,
  type MarkMood,
} from "@scoplen/ui";
import type { ScoplenTerminalElement } from "@scoplen/terminal";
import { Palette } from "lucide-react";
import { Channel } from "@tauri-apps/api/core";
import { Terminal, type TerminalSink, type TerminalSource } from "@scoplen/terminal/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type PreparationEvent, type PreparationContext } from "./ipc/bindings";
import { frameChannel } from "./ipc/frames";
import { useTerminalColors, xtermTheme } from "./terminal-colors";

export type SessionState = "verifying" | "trusting" | "passphrase" | "connecting" | "connected" | "closed" | "failed";

/** The face the host's egg makes in each state. */
const sessionFaces: Record<SessionState, { mood: MarkMood; active: boolean; attention: boolean }> = {
  verifying: { mood: "awake", active: true, attention: false },
  trusting: { mood: "awake", active: true, attention: false },
  passphrase: { mood: "awake", active: true, attention: false },
  connecting: { mood: "awake", active: true, attention: false },
  connected: { mood: "rest", active: true, attention: false },
  closed: { mood: "closed", active: false, attention: false },
  failed: { mood: "low", active: false, attention: true },
};

/** A small output surface for the first live SSH session slice. */
export function SessionTerminal({
  profileId,
  label,
  onClose,
  onStateChange,
  onOpenColors,
}: {
  profileId: string;
  label: string;
  onClose: () => void;
  /** Told whenever the connection state changes, so the window can show it on the tab. */
  onStateChange?: (state: SessionState) => void;
  /** Opens the terminal color settings. */
  onOpenColors?: () => void;
}) {
  const { t } = useI18n();
  const [state, setState] = useState<SessionState>("verifying");
  const [error, setError] = useState<string | null>(null);
  const [hostPrompt, setHostPrompt] = useState<Extract<PreparationEvent, { kind: "trust" }> | null>(null);
  const hostKey = hostPrompt?.hostKey ?? null;
  const [context, setContext] = useState<PreparationContext | null>(null);
  const [passphrasePrompt, setPassphrasePrompt] = useState<string | null>(null);
  const currentPrompt = useRef<string | null>(null);
  const [trustError, setTrustError] = useState<string | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [passphraseError, setPassphraseError] = useState<string | null>(null);
  const [source, setSource] = useState<TerminalSource | null>(null);
  const [hasOutput, setHasOutput] = useState(false);
  const [transportPending, setTransportPending] = useState(false);
  const [sessionId, setSessionId] = useState(() => crypto.randomUUID());
  const mounted = useRef(true);
  const generation = useRef(0);
  const connecting = useRef(false);
  const retrying = useRef(false);
  const connectionEnded = useRef(false);
  const trusting = useRef(false);
  const passphraseInput = useRef<HTMLInputElement>(null);
  const reportState = useRef(onStateChange);
  const translate = useRef(t);
  useEffect(() => {
    reportState.current = onStateChange;
    translate.current = t;
  });
  useEffect(() => {
    reportState.current?.(state);
  }, [state]);

  const connectSession = useCallback(() => {
    if (!mounted.current || connecting.current) return;
    const current = generation.current;
    connecting.current = true;
    connectionEnded.current = false;
    setTransportPending(true);
    setState("connecting");
    setError(null);
    setSource({
      subscribe(onChunk, { signal }) {
        let active = true;
        let ended = false;
        const frames = frameChannel((chunk) => {
          if (!active || !mounted.current || current !== generation.current) return;
          if (chunk.length) setHasOutput(true);
          onChunk(chunk);
        });
        const ready = new Channel<null>(() => {
          if (!active || ended || connectionEnded.current || !mounted.current || current !== generation.current) return;
          setState("connected");
        });

        const stop = () => {
          if (!active) return;
          active = false;
          void commands.sessionCloseTransport(sessionId).catch(() => undefined);
        };
        signal.addEventListener("abort", stop, { once: true });

        const preparation = new Channel<PreparationEvent>((event) => {
          if (!active || ended || connectionEnded.current || !mounted.current || current !== generation.current) return;
          setContext(event.context);
          trusting.current = false;
          setTrustBusy(false);
          setTrustError(null);
          setHostPrompt(event.kind === "trust" ? event : null);
          setPassphrasePrompt(event.kind === "passphrase" ? event.promptId : null);
          currentPrompt.current = event.kind === "progress" ? null : event.promptId;
          if (passphraseInput.current) passphraseInput.current.value = "";
          setPassphraseError(
            event.kind === "passphrase" && event.incorrect ? translate.current("session.passphrase.incorrect") : null,
          );
          setState(event.kind === "trust" ? "trusting" : event.kind === "passphrase" ? "passphrase" : "connecting");
        });
        void commands
          .sessionReserveTransport(sessionId, true)
          .then((reservation) => {
            if (reservation.status === "error") return reservation;
            if (!active || connectionEnded.current || !mounted.current || current !== generation.current) {
              void commands.sessionCloseTransport(sessionId).catch(() => undefined);
              return { status: "ok" as const, data: null };
            }
            return commands.sessionConnect(profileId, null, true, sessionId, frames, ready, preparation);
          })
          .then((result) => {
            if (!active || !mounted.current || current !== generation.current) return;
            ended = true;
            setHostPrompt(null);
            setPassphrasePrompt(null);
            currentPrompt.current = null;
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
            setHostPrompt(null);
            setPassphrasePrompt(null);
            currentPrompt.current = null;
            if (connectionEnded.current) return;
            setState("failed");
            setError(cause instanceof Error ? cause.message : String(cause));
          })
          .finally(() => {
            if (!mounted.current || current !== generation.current) return;
            connecting.current = false;
            setTransportPending(false);
          });

        return { unsubscribe: stop };
      },
    });
  }, [profileId, sessionId]);

  const inputSink = useMemo<TerminalSink>(
    () => ({
      async write(bytes) {
        const result = await commands.sessionInput(sessionId, Array.from(bytes));
        if (result.status === "error") throw new Error(result.error);
      },
    }),
    [sessionId],
  );
  const { colors } = useTerminalColors();
  const terminal = useRef<ScoplenTerminalElement>(null);
  const menu = useContextMenu();

  // The remote terminal follows the window: the size is sent once the session
  // is connected, and again whenever the grid changes.
  const size = useRef<{ columns: number; rows: number } | null>(null);
  const sendSize = useCallback(() => {
    if (!size.current) return;
    void commands.sessionResize(sessionId, size.current.columns, size.current.rows).catch(() => undefined);
  }, [sessionId]);
  useEffect(() => {
    if (state === "connected") sendSize();
  }, [state, sendSize]);
  const terminalProfile = useMemo(
    () => ({ cursorBlink: true, scrollback: 2_000, theme: xtermTheme(colors) }),
    [colors],
  );

  const closeTransport = useCallback(() => {
    void commands.sessionCloseTransport(sessionId).catch(() => undefined);
  }, [sessionId]);

  useEffect(() => {
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
      void commands.sessionCloseTransport(sessionId).catch(() => undefined);
    };
  }, [connectSession, profileId, sessionId]);

  const cancelPreparation = (message: string) => {
    connectionEnded.current = true;
    currentPrompt.current = null;
    setHostPrompt(null);
    setPassphrasePrompt(null);
    if (passphraseInput.current) passphraseInput.current.value = "";
    closeTransport();
    setState("failed");
    setError(message);
  };
  const cancelTrust = () => cancelPreparation(t("session.trust.cancelled"));

  const respond = async (
    promptId: string,
    intent: { kind: "acceptHostKey" } | { kind: "passphrase"; value: string },
  ) => {
    if (trusting.current || !mounted.current || currentPrompt.current !== promptId) return;
    const current = generation.current;
    trusting.current = true;
    setTrustBusy(true);
    setTrustError(null);
    try {
      const result = await commands.sessionRespond(sessionId, promptId, intent);
      if (!mounted.current || current !== generation.current || currentPrompt.current !== promptId) return;
      if (result.status === "error") {
        if (intent.kind === "passphrase") setPassphraseError(result.error);
        else setTrustError(result.error);
        return;
      }
      trusting.current = false;
      setTrustBusy(false);
      currentPrompt.current = null;
      setHostPrompt(null);
      setPassphrasePrompt(null);
      setState("connecting");
    } catch (cause) {
      if (!mounted.current || current !== generation.current || currentPrompt.current !== promptId) return;
      const message = cause instanceof Error ? cause.message : String(cause);
      if (intent.kind === "passphrase") setPassphraseError(message);
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
    if (!mounted.current || connecting.current || retrying.current || (state !== "closed" && state !== "failed"))
      return;
    retrying.current = true;
    generation.current++;
    connectionEnded.current = true;
    trusting.current = false;
    setTrustBusy(false);
    setHostPrompt(null);
    setError(null);
    setSource(null);
    currentPrompt.current = null;
    setPassphrasePrompt(null);
    setContext(null);
    setState("verifying");
    setSessionId(crypto.randomUUID());
  };

  const cancelPassphrase = () => cancelPreparation(t("session.passphrase.cancelled"));

  const submitPassphrase = () => {
    if (trusting.current) return;
    const value = passphraseInput.current?.value ?? "";
    if (!value) {
      setPassphraseError(t("session.passphrase.required"));
      return;
    }
    if (passphraseInput.current) passphraseInput.current.value = "";
    if (passphrasePrompt) void respond(passphrasePrompt, { kind: "passphrase", value });
  };

  const status =
    state === "verifying"
      ? t("session.verifying")
      : state === "trusting"
        ? t(hostKey?.changed ? "session.trust.changedTitle" : "session.firstConnection")
        : state === "passphrase"
          ? t("session.passphrase.status")
          : state === "connecting"
            ? t("session.connecting")
            : state === "connected"
              ? t("session.connected")
              : state === "closed"
                ? t("session.closed")
                : t("session.failed");

  const face = sessionFaces[state];

  return (
    <main className="flex h-full min-h-0 flex-col bg-background text-foreground" aria-labelledby="session-title">
      <header className="flex shrink-0 flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <HostEgg seed={profileId} size="1.75rem" mood={face.mood} active={face.active} attention={face.attention} />
          <div className="min-w-0">
            <h1 id="session-title" className="ui-display truncate text-base">
              {label}
            </h1>
            <p className="m-0 flex items-center gap-1.5 text-xs text-muted-foreground" role="status">
              <span
                aria-hidden="true"
                className={`size-1.5 rounded-full ${state === "connected" ? "bg-primary" : state === "failed" ? "bg-attention" : "bg-muted-foreground"}`}
              />
              {status}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center justify-end gap-1">
          {state === "closed" || state === "failed" ? (
            <Button variant="primary" disabled={transportPending} onClick={reconnect}>
              {t("session.reconnect")}
            </Button>
          ) : null}
          {onOpenColors ? (
            <IconButton label={t("session.colors")} onClick={onOpenColors}>
              <Palette aria-hidden="true" className="size-4" />
            </IconButton>
          ) : null}
          <Button
            variant="ghost"
            onClick={() => {
              mounted.current = false;
              generation.current++;
              if (passphraseInput.current) passphraseInput.current.value = "";
              closeTransport();
              onClose();
            }}
          >
            {t("session.close")}
          </Button>
        </div>
      </header>
      {hasOutput && error ? (
        <p role="alert" className="mx-4 mt-0 mb-2 text-sm whitespace-pre-wrap text-attention">
          {error}
        </p>
      ) : null}
      <div className="min-h-0 flex-1 px-3 pb-3">
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
            aria-label={t("session.output")}
            className={`h-full min-h-0 transition-opacity duration-(--duration-overlay) ${state === "connected" || hasOutput ? "opacity-100" : "opacity-40"}`}
            profile={terminalProfile}
            onTerminalResize={(next) => {
              size.current = next;
              if (state === "connected") sendSize();
            }}
            onTerminalError={(terminalError) => {
              if (!mounted.current) return;
              connectionEnded.current = true;
              closeTransport();
              setState("failed");
              setError(terminalError.message);
            }}
          />
          {state !== "connected" && !hasOutput ? (
            <Stage state={state} seed={profileId} label={label} status={status} error={error} context={context} />
          ) : null}
        </div>
      </div>
      <Dialog
        open={hostKey !== null}
        onOpenChange={(open) => {
          if (!open) cancelTrust();
        }}
        title={hostKey?.changed ? t("session.trust.changedTitle") : t("session.trust.title")}
        description={hostKey?.changed ? t("session.trust.changedBody") : t("session.trust.firstBody")}
        closeLabel={t("session.trust.cancel")}
        mark={
          hostKey?.changed ? (
            <Mark
              size="2.5rem"
              mood="low"
              className="text-attention"
              gesture={{ name: "shake", at: hostKey.fingerprint }}
            />
          ) : (
            <Mark size="2.5rem" mood="awake" look={{ x: 0.3, y: 1 }} />
          )
        }
        footer={
          <>
            <Button variant="ghost" onClick={cancelTrust}>
              {t("session.trust.cancel")}
            </Button>
            <Button variant="primary" busy={trustBusy} onClick={() => void trustAndConnect()}>
              {t("session.trust.connect")}
            </Button>
          </>
        }
      >
        {hostKey ? (
          <div className="space-y-4 text-sm">
            {context ? <HopIdentity context={context} /> : null}
            <dl className="grid gap-3">
              <div>
                <dt className="text-muted-foreground">{t("session.trust.algorithm")}</dt>
                <dd className="m-0 mt-1 font-mono select-text">{hostKey.algorithm}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("session.trust.fingerprint")}</dt>
                <dd className="m-0 mt-1 break-all font-mono select-text">{hostKey.fingerprint}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("session.trust.publicKey")}</dt>
                <dd className="m-0 mt-1 break-all rounded-md bg-inset p-3 font-mono text-xs leading-5 select-text">
                  {hostKey.key}
                </dd>
              </div>
            </dl>
            {trustError ? (
              <p role="alert" className="m-0 text-sm text-attention">
                {trustError}
              </p>
            ) : null}
          </div>
        ) : null}
      </Dialog>
      <Dialog
        open={passphrasePrompt !== null}
        onOpenChange={(open) => {
          if (!open) cancelPassphrase();
        }}
        title={t("session.passphrase.title")}
        description={t("session.passphrase.body")}
        closeLabel={t("session.passphrase.cancel")}
        footer={
          <>
            <Button variant="ghost" onClick={cancelPassphrase}>
              {t("session.passphrase.cancel")}
            </Button>
            <Button variant="primary" busy={trustBusy} onClick={submitPassphrase}>
              {t("session.passphrase.connect")}
            </Button>
          </>
        }
      >
        {context ? <HopIdentity context={context} /> : null}
        <form
          onSubmit={(event) => {
            event.preventDefault();
            submitPassphrase();
          }}
        >
          <Field
            ref={passphraseInput}
            label={t("session.passphrase.field")}
            type="password"
            autoComplete="off"
            autoFocus
            error={passphraseError ?? undefined}
          />
        </form>
      </Dialog>
    </main>
  );
}

function HopIdentity({ context }: { context: PreparationContext }) {
  const { t } = useI18n();
  const endpoint = context.address.includes(":")
    ? `[${context.address}]:${context.port}`
    : `${context.address}:${context.port}`;
  return (
    <div className="mb-4 min-w-0 space-y-1 text-sm">
      <p className="m-0 text-muted-foreground">
        {context.target ? t("session.route.target") : t("session.route.hop")} · {context.position} / {context.total}
      </p>
      <p className="m-0 break-words font-medium">
        {context.host} · {context.login}
      </p>
      <p className="m-0 break-all font-mono select-text">
        {context.username}@{endpoint}
      </p>
    </div>
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
  const working = state === "verifying" || state === "connecting" || state === "trusting" || state === "passphrase";
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
