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
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { useI18n } from "./i18n";
import {
  commands,
  type SessionEvent,
  type PreparationEvent,
  type PreparationContext,
  type HostKeyTrustSource,
} from "./ipc/bindings";
import { useTerminalColors, xtermTheme } from "./terminal-colors";

export type SessionState =
  "verifying" | "trusting" | "passphrase" | "connecting" | "reconnecting" | "connected" | "closed" | "failed";

/** The face the host's egg makes in each state. */
const sessionFaces: Record<SessionState, { mood: MarkMood; active: boolean; attention: boolean }> = {
  verifying: { mood: "awake", active: true, attention: false },
  trusting: { mood: "awake", active: true, attention: true },
  passphrase: { mood: "awake", active: true, attention: true },
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
  onOpenColors,
}: {
  profileId: string;
  label: string;
  /** Only the selected session may display its pending prompt. */
  active?: boolean;
  onClose: () => void;
  /** Told whenever the connection state changes, so the window can show it on the tab. */
  onStateChange?: (state: SessionState) => void;
  /** Opens the terminal color settings. */
  onOpenColors?: () => void;
}) {
  const { t } = useI18n();
  const titleId = useId();
  const [state, setState] = useState<SessionState>("verifying");
  const [error, setError] = useState<string | null>(null);
  const [hostPrompt, setHostPrompt] = useState<Extract<PreparationEvent, { kind: "trust" }> | null>(null);
  const hostKey = hostPrompt?.hostKey ?? null;
  const [verified, setVerified] = useState<Array<Extract<PreparationEvent, { kind: "verified" }>>>([]);
  const [detailsOpen, setDetailsOpen] = useState(false);
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
  useEffect(() => {
    if (!active && passphraseInput.current) passphraseInput.current.value = "";
  }, [active]);

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
          void commands.sessionCloseTransport(sessionId).catch(() => undefined);
        };
        signal.addEventListener("abort", stop, { once: true });

        const clearPreparation = () => {
          trusting.current = false;
          setTrustBusy(false);
          setTrustError(null);
          setHostPrompt(null);
          setPassphrasePrompt(null);
          currentPrompt.current = null;
          if (passphraseInput.current) passphraseInput.current.value = "";
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
              if (preparation.kind === "verified") {
                setVerified((current) => [
                  ...current.filter((item) => item.context.position !== preparation.context.position),
                  preparation,
                ]);
                break;
              }
              setHostPrompt(preparation.kind === "trust" ? preparation : null);
              setPassphrasePrompt(preparation.kind === "passphrase" ? preparation.promptId : null);
              currentPrompt.current = preparation.kind === "progress" ? null : preparation.promptId;
              setPassphraseError(
                preparation.kind === "passphrase" && preparation.incorrect
                  ? translate.current("session.passphrase.incorrect")
                  : null,
              );
              setState(
                preparation.kind === "trust"
                  ? "trusting"
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
            if (!active || connectionEnded.current || !mounted.current || current !== generation.current) {
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
        if (!transportId) return;
        const result = await commands.sessionInput(sessionId, transportId, Array.from(bytes));
        if (result.status === "error") throw new Error(result.error);
      },
    }),
    [sessionId, transportId],
  );
  const { colors } = useTerminalColors();
  const terminal = useRef<ScoplenTerminalElement>(null);
  const menu = useContextMenu();

  // The remote terminal follows the window: the size is sent once the session
  // is connected, and again whenever the grid changes.
  const size = useRef<{ columns: number; rows: number } | null>(null);
  const sendSize = useCallback(() => {
    if (!size.current || !transportId) return;
    void commands.sessionResize(sessionId, transportId, size.current.columns, size.current.rows).catch(() => undefined);
  }, [sessionId, transportId]);
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
    if (passphraseInput.current) passphraseInput.current.value = "";
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
    if (!mounted.current || transportPending || retrying.current || (state !== "closed" && state !== "failed")) return;
    if (!connecting.current) {
      retrying.current = true;
      setTransportPending(true);
      setSessionId(crypto.randomUUID());
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
        ? t(
            hostKey?.changed
              ? "session.trust.changedTitle"
              : hostKey?.review
                ? "session.trust.reviewTitle"
                : "session.firstConnection",
          )
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

  return (
    <main className="flex h-full min-h-0 flex-col bg-background text-foreground" aria-labelledby={titleId}>
      <header className="flex shrink-0 flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <HostEgg seed={profileId} size="1.75rem" mood={face.mood} active={face.active} attention={face.attention} />
          <div className="min-w-0">
            <h1 id={titleId} className="ui-display truncate text-base">
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
      {automatic ? (
        <p className="mx-4 mt-0 mb-2 text-xs text-muted-foreground">{t("session.reconnecting.newShell")}</p>
      ) : null}
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
              interruptTransport(true, terminalError.message);
            }}
          />
          {state !== "connected" && !hasOutput ? (
            <Stage state={state} seed={profileId} label={label} status={status} error={error} context={context} />
          ) : null}
        </div>
      </div>
      <Dialog
        open={active && hostKey !== null}
        onOpenChange={(open) => {
          if (!open && active) cancelTrust();
        }}
        title={
          hostKey?.changed
            ? t("session.trust.changedTitle")
            : hostKey?.review
              ? t("session.trust.reviewTitle")
              : t("session.trust.title")
        }
        description={
          hostKey?.changed
            ? t("session.trust.changedBody")
            : hostKey?.review === "revokedDevice"
              ? t("session.trust.revokedBody")
              : hostKey?.review
                ? t("session.trust.unverifiedBody")
                : t("session.trust.firstBody")
        }
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
            {hostKey.previousSource ? <TrustSourceDetails source={hostKey.previousSource} /> : null}
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
      <Dialog
        open={active && passphrasePrompt !== null}
        onOpenChange={(open) => {
          if (!open && active) cancelPassphrase();
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

function TrustSourceDetails({ source }: { source: HostKeyTrustSource }) {
  const { t, locale } = useI18n();
  return (
    <dl className="grid gap-3 text-sm">
      <div>
        <dt className="text-muted-foreground">{t("session.details.source")}</dt>
        <dd className="m-0 mt-1 break-words">
          {source.current ? t("session.details.currentDevice") : (source.deviceName ?? source.deviceId)}
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">{t("session.details.method")}</dt>
        <dd className="m-0 mt-1">{t(source.imported ? "session.details.imported" : "session.details.manual")}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground">{t("session.details.acceptedAt")}</dt>
        <dd className="m-0 mt-1">
          {source.acceptedAt ? (
            <time dateTime={new Date(Number(source.acceptedAt)).toISOString()}>
              {new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(
                new Date(Number(source.acceptedAt)),
              )}
            </time>
          ) : (
            t("session.details.timeUnavailable")
          )}
        </dd>
      </div>
    </dl>
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
  const working =
    state === "verifying" ||
    state === "connecting" ||
    state === "reconnecting" ||
    state === "trusting" ||
    state === "passphrase";
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
