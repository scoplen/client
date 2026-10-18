// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, HostEgg, Mark, type MarkMood } from "@scoplen/ui";
import { Terminal, type TerminalSink, type TerminalSource } from "@scoplen/terminal/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useI18n } from "./i18n";
import { commands, type HostKeyDetails } from "./ipc/bindings";
import { frameChannel } from "./ipc/frames";

export type SessionState = "verifying" | "trusting" | "connecting" | "connected" | "closed" | "failed";

/** The face the host's egg makes in each state. */
const sessionFaces: Record<SessionState, { mood: MarkMood; active: boolean; attention: boolean }> = {
  verifying: { mood: "awake", active: true, attention: false },
  trusting: { mood: "awake", active: true, attention: false },
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
}: {
  profileId: string;
  label: string;
  onClose: () => void;
  /** Told whenever the connection state changes, so the window can show it on the tab. */
  onStateChange?: (state: SessionState) => void;
}) {
  const { t } = useI18n();
  const [state, setState] = useState<SessionState>("verifying");
  const [error, setError] = useState<string | null>(null);
  const [hostKey, setHostKey] = useState<HostKeyDetails | null>(null);
  const [trustError, setTrustError] = useState<string | null>(null);
  const [trustBusy, setTrustBusy] = useState(false);
  const [source, setSource] = useState<TerminalSource | null>(null);
  const mounted = useRef(true);
  const sessionId = useMemo(() => crypto.randomUUID(), []);
  const reportState = useRef(onStateChange);
  useEffect(() => {
    reportState.current = onStateChange;
  });
  useEffect(() => {
    reportState.current?.(state);
  }, [state]);

  const connectSession = useCallback(() => {
    if (!mounted.current) return;
    setState("connecting");
    setError(null);
    setSource({
      subscribe(onChunk, { signal }) {
        let active = true;
        const frames = frameChannel((chunk) => {
          if (!active || !mounted.current) return;
          setState("connected");
          onChunk(chunk);
        });

        const stop = () => {
          if (!active) return;
          active = false;
          void commands.sessionCloseTransport(sessionId).catch(() => undefined);
        };
        signal.addEventListener("abort", stop, { once: true });

        void commands
          .sessionConnect(profileId, null, true, sessionId, frames)
          .then((result) => {
            if (!active || !mounted.current) return;
            if (result.status === "ok") {
              setState("closed");
            } else {
              setState("failed");
              setError(result.error);
            }
          })
          .catch((cause: unknown) => {
            if (!active || !mounted.current) return;
            setState("failed");
            setError(cause instanceof Error ? cause.message : String(cause));
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
  const terminalProfile = useMemo(() => ({ cursorBlink: true, scrollback: 2_000 }), []);

  const closeTransport = useCallback(() => {
    void commands.sessionCloseTransport(sessionId).catch(() => undefined);
  }, [sessionId]);

  useEffect(() => {
    let active = true;
    mounted.current = true;

    void (async () => {
      try {
        await Promise.resolve();
        if (!active || !mounted.current) return;
        setState("verifying");
        setError(null);
        setHostKey(null);
        setTrustError(null);
        const result = await commands.sessionHostKey(profileId);
        if (!active || !mounted.current) return;
        if (result.status === "error") {
          setState("failed");
          setError(result.error);
          return;
        }
        if (result.data.status === "trusted") connectSession();
        else {
          setHostKey(result.data);
          setState("trusting");
        }
      } catch (cause) {
        if (!active || !mounted.current) return;
        setState("failed");
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    })();

    return () => {
      active = false;
      mounted.current = false;
      void commands.sessionCloseTransport(sessionId).catch(() => undefined);
    };
  }, [connectSession, profileId, sessionId]);

  const cancelTrust = () => {
    if (trustBusy) return;
    setHostKey(null);
    setState("failed");
    setError(t("session.trust.cancelled"));
  };

  const trustAndConnect = async () => {
    if (!hostKey || trustBusy) return;
    setTrustBusy(true);
    setTrustError(null);
    const result = await commands.sessionTrustHostKey(profileId, hostKey.algorithm, hostKey.key, hostKey.fingerprint);
    if (!mounted.current) return;
    setTrustBusy(false);
    if (result.status === "error") {
      setTrustError(result.error);
      return;
    }
    setHostKey(null);
    void connectSession();
  };

  const status =
    state === "verifying"
      ? t("session.verifying")
      : state === "trusting"
        ? t("session.firstConnection")
        : state === "connecting"
          ? t("session.connecting")
          : state === "connected"
            ? t("session.connected")
            : state === "closed"
              ? t("session.closed")
              : t("session.failed");

  const face = sessionFaces[state];

  return (
    <main className="flex h-full min-h-0 flex-col bg-terminal text-terminal-foreground" aria-labelledby="session-title">
      <header className="flex shrink-0 items-center justify-between gap-3 border-b-(length:--scoplen-border-width) border-terminal-border px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-3">
          <HostEgg
            seed={profileId}
            size="1.75rem"
            mood={face.mood}
            active={face.active}
            attention={face.attention}
            className={face.active ? "text-[color-mix(in_srgb,var(--primary)_80%,white)]" : "text-terminal-muted"}
          />
          <div className="min-w-0">
            <h1 id="session-title" className="ui-display truncate text-base">
              {label}
            </h1>
            <p className="m-0 flex items-center gap-1.5 text-xs text-terminal-muted" role="status">
              <span
                aria-hidden="true"
                className={`size-1.5 rounded-full ${state === "connected" ? "bg-[color-mix(in_srgb,var(--primary)_80%,white)]" : state === "failed" ? "bg-attention" : "bg-terminal-muted"}`}
              />
              {status}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          className="shrink-0 text-terminal-foreground hover:bg-terminal-raised"
          onClick={() => {
            closeTransport();
            onClose();
          }}
        >
          {t("session.close")}
        </Button>
      </header>
      <div className="relative min-h-0 flex-1 overflow-hidden px-4 py-3">
        <Terminal
          source={source}
          sink={inputSink}
          aria-label={t("session.output")}
          className={`h-full min-h-0 rounded-md transition-opacity duration-(--duration-overlay) ${state === "connected" ? "opacity-100" : "opacity-40"}`}
          profile={terminalProfile}
          onTerminalError={(terminalError) => {
            if (!mounted.current) return;
            setState("failed");
            setError(terminalError.message);
          }}
        />
        {state !== "connected" ? (
          <Stage state={state} seed={profileId} label={label} status={status} error={error} />
        ) : null}
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
                <dd className="m-0 mt-1 font-mono">{hostKey.algorithm}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("session.trust.fingerprint")}</dt>
                <dd className="m-0 mt-1 break-all font-mono">{hostKey.fingerprint}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t("session.trust.publicKey")}</dt>
                <dd className="m-0 mt-1 break-all rounded-md bg-inset p-3 font-mono text-xs leading-5">
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
  const working = state === "verifying" || state === "connecting" || state === "trusting";
  return (
    <div className="absolute inset-0 grid place-items-center bg-[color-mix(in_srgb,var(--terminal)_82%,transparent)] px-6 backdrop-blur-[2px]">
      <div className="scoplen-rise flex max-w-md flex-col items-center text-center">
        {working ? (
          <div aria-hidden="true" className="flex items-center gap-3">
            <Mark size="2.5rem" mood="awake" look={{ x: 1, y: 0 }} className="text-terminal-foreground" />
            <span className="scoplen-route relative h-0.5 w-28 rounded-full bg-terminal-border sm:w-40" />
            <HostEgg
              seed={seed}
              size="2.5rem"
              mood="awake"
              active
              className="text-[color-mix(in_srgb,var(--primary)_80%,white)]"
            />
          </div>
        ) : (
          <HostEgg
            seed={seed}
            size="3.5rem"
            mood={state === "failed" ? "low" : "closed"}
            attention={state === "failed"}
            className={state === "failed" ? "" : "text-terminal-muted"}
          />
        )}
        <p className="mt-5 mb-0 font-mono text-sm text-terminal-foreground">{label}</p>
        <p className="mt-1 mb-0 text-sm text-terminal-muted">{status}</p>
        {error ? (
          <p
            role="alert"
            className="mt-4 mb-0 text-sm whitespace-pre-wrap text-[color-mix(in_srgb,var(--attention)_70%,white)]"
          >
            {error}
          </p>
        ) : null}
      </div>
    </div>
  );
}
