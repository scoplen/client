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
import { commands, type HostKeyDetails } from "./ipc/bindings";
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
  const [hostKey, setHostKey] = useState<HostKeyDetails | null>(null);
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

  const connectSession = useCallback(
    (passphrase: string | null = null) => {
      if (!mounted.current || connecting.current) return;
      const current = generation.current;
      connecting.current = true;
      connectionEnded.current = false;
      setTransportPending(true);
      let pendingPassphrase = passphrase;
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
            if (!active || ended || connectionEnded.current || !mounted.current || current !== generation.current)
              return;
            setState("connected");
          });

          const stop = () => {
            if (!active) return;
            active = false;
            void commands.sessionCloseTransport(sessionId).catch(() => undefined);
          };
          signal.addEventListener("abort", stop, { once: true });

          const oneTimePassphrase = pendingPassphrase;
          pendingPassphrase = null;
          void commands
            .sessionConnect(profileId, null, true, sessionId, oneTimePassphrase, frames, ready)
            .then((result) => {
              if (!active || !mounted.current || current !== generation.current) return;
              ended = true;
              if (connectionEnded.current) return;
              if (result.status === "ok") {
                setState("closed");
              } else {
                if (result.error.kind === "invalidPrivateKeyPassphrase" || result.error.kind === "passphraseRequired") {
                  setState("passphrase");
                  setPassphraseError(
                    translate.current(
                      result.error.kind === "invalidPrivateKeyPassphrase"
                        ? "session.passphrase.incorrect"
                        : "session.passphrase.required",
                    ),
                  );
                  setSource(null);
                } else {
                  setState("failed");
                  setError(result.error.kind === "failed" ? result.error.message : String(result.error));
                }
              }
            })
            .catch((cause: unknown) => {
              if (!active || !mounted.current || current !== generation.current) return;
              ended = true;
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
    },
    [profileId, sessionId],
  );

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
        setHostKey(null);
        setTrustError(null);
        setPassphraseError(null);
        const result = await commands.sessionHostKey(profileId);
        if (!active || !mounted.current || current !== generation.current) return;
        if (result.status === "error") {
          setState("failed");
          setError(result.error);
          return;
        }
        if (result.data.status === "trusted") {
          if (result.data.passphraseRequired) setState("passphrase");
          else connectSession();
        } else {
          setHostKey(result.data);
          setState("trusting");
        }
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

  const cancelTrust = () => {
    if (trusting.current) return;
    setHostKey(null);
    setState("failed");
    setError(t("session.trust.cancelled"));
  };

  const trustAndConnect = async () => {
    if (!hostKey || trusting.current || !mounted.current) return;
    const current = generation.current;
    trusting.current = true;
    setTrustBusy(true);
    setTrustError(null);
    try {
      const result = await commands.sessionTrustHostKey(profileId, hostKey.algorithm, hostKey.key, hostKey.fingerprint);
      if (!mounted.current || current !== generation.current) return;
      if (result.status === "error") {
        setTrustError(result.error);
        return;
      }
      setHostKey(null);
      if (hostKey.passphraseRequired) setState("passphrase");
      else connectSession();
    } catch (cause) {
      if (!mounted.current || current !== generation.current) return;
      setTrustError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (mounted.current && current === generation.current) {
        trusting.current = false;
        setTrustBusy(false);
      }
    }
  };

  const reconnect = () => {
    if (!mounted.current || connecting.current || retrying.current || (state !== "closed" && state !== "failed"))
      return;
    retrying.current = true;
    generation.current++;
    connectionEnded.current = true;
    trusting.current = false;
    setTrustBusy(false);
    setHostKey(null);
    setError(null);
    setSource(null);
    setState("verifying");
    setSessionId(crypto.randomUUID());
  };

  const cancelPassphrase = () => {
    if (passphraseInput.current) passphraseInput.current.value = "";
    setPassphraseError(null);
    setState("failed");
    setError(t("session.passphrase.cancelled"));
  };

  const submitPassphrase = () => {
    const value = passphraseInput.current?.value ?? "";
    if (!value) {
      setPassphraseError(t("session.passphrase.required"));
      return;
    }
    if (new TextEncoder().encode(value).length > 4096) {
      setPassphraseError(t("session.passphrase.tooLong"));
      return;
    }
    if (passphraseInput.current) passphraseInput.current.value = "";
    setPassphraseError(null);
    connectSession(value);
  };

  const status =
    state === "verifying"
      ? t("session.verifying")
      : state === "trusting"
        ? t("session.firstConnection")
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
            <Stage state={state} seed={profileId} label={label} status={status} error={error} />
          ) : null}
        </div>
      </div>
      <Dialog
        open={hostKey !== null}
        onOpenChange={(open) => {
          if (!open) cancelTrust();
        }}
        title={hostKey?.status === "changed" ? t("session.trust.changedTitle") : t("session.trust.title")}
        description={hostKey?.status === "changed" ? t("session.trust.changedBody") : t("session.trust.firstBody")}
        closeLabel={t("session.trust.cancel")}
        mark={
          hostKey?.status === "changed" ? (
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
            <Button variant="ghost" onClick={cancelTrust} disabled={trustBusy}>
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
        open={state === "passphrase"}
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
            <Button variant="primary" onClick={submitPassphrase}>
              {t("session.passphrase.connect")}
            </Button>
          </>
        }
      >
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
}: {
  state: Exclude<SessionState, "connected">;
  seed: string;
  label: string;
  status: string;
  error: string | null;
}) {
  const working = state === "verifying" || state === "connecting" || state === "trusting" || state === "passphrase";
  return (
    <div className="absolute inset-0 grid place-items-center bg-[color-mix(in_srgb,var(--background)_78%,transparent)] px-6 backdrop-blur-[3px]">
      <div className="scoplen-rise flex max-w-md flex-col items-center text-center">
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
        {error ? (
          <p role="alert" className="mt-4 mb-0 text-sm whitespace-pre-wrap text-attention">
            {error}
          </p>
        ) : null}
      </div>
    </div>
  );
}
