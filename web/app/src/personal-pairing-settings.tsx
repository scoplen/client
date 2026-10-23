// SPDX-License-Identifier: Apache-2.0
import { Button, Field } from "@scoplen/ui";
import { Channel } from "@tauri-apps/api/core";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useI18n } from "./i18n";
import { commands, type PairingError, type PairingQrDisplay, type PairingStatus } from "./ipc/bindings";

type Outcome = { status: "ok"; data: PairingStatus | null } | { status: "error"; error: PairingError };

const progresses = (phase: PairingStatus["phase"]) =>
  phase === "waiting" || phase === "exchanging" || phase === "waiting_acceptance";

function PairingQr({ qr, label }: { qr: PairingQrDisplay; label: string }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext("2d");
    if (!element || !context) return;
    const scale = 4;
    element.width = element.height = (qr.size + 8) * scale;
    context.fillStyle = "white";
    context.fillRect(0, 0, element.width, element.height);
    context.fillStyle = "black";
    qr.modules.forEach((module, index) => {
      if (module === 1)
        context.fillRect(((index % qr.size) + 4) * scale, (Math.floor(index / qr.size) + 4) * scale, scale, scale);
    });
    return () => {
      context.clearRect(0, 0, element.width, element.height);
      element.width = element.height = 1;
    };
  }, [qr]);
  return (
    <canvas
      ref={canvas}
      role="img"
      aria-label={label}
      className="mt-3 block aspect-square w-72 max-w-full [image-rendering:pixelated]"
    />
  );
}

export function PersonalPairingSettings({
  configured,
  authenticated,
  disabled,
  onBusyChange,
}: {
  configured: boolean;
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const { t } = useI18n();
  const [status, setStatus] = useState<PairingStatus | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [qr, setQr] = useState<PairingQrDisplay | null>(null);
  const secretQr = useRef<PairingQrDisplay | null>(null);
  const [failed, setFailed] = useState<PairingError | "unavailable" | null>(null);
  const [mode, setMode] = useState<"new" | "old" | null>(null);
  const [working, setWorking] = useState(false);
  const [watching, setWatching] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const origin = useRef<HTMLInputElement>(null);
  const device = useRef<HTMLInputElement>(null);
  const link = useRef<HTMLInputElement>(null);
  const inputPassword = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const opener = useRef<HTMLButtonElement>(null);
  const restoreFocus = useRef(false);
  const pending = useRef(false);
  const observer = useRef<string | null>(null);
  const nativeObserver = useRef<string | null>(null);
  const observerDone = useRef<Promise<void> | null>(null);
  const mounted = useRef(false);
  const focusStep = useRef(false);

  useEffect(() => {
    mounted.current = true;
    void commands.personalPairingStatus().then(
      (result) => {
        if (!mounted.current) return;
        if (result.status === "ok") setStatus(result.data);
        else setFailed(result.error);
      },
      () => {
        if (mounted.current) setFailed("unavailable");
      },
    );
    const passwordInput = inputPassword.current;
    return () => {
      mounted.current = false;
      secretQr.current?.modules.fill(0);
      secretQr.current = null;
      if (passwordInput) passwordInput.value = "";
      const id = nativeObserver.current;
      observer.current = null;
      nativeObserver.current = null;
      if (id) void commands.stopPersonalPairingWatch(id).catch(() => undefined);
    };
  }, []);

  useEffect(() => {
    if (focusStep.current) {
      focusStep.current = false;
      heading.current?.focus();
    }
  }, [status?.phase]);

  useEffect(() => {
    if (mode === "new") origin.current?.focus();
    if (mode === "old") link.current?.focus();
    if (mode === null && restoreFocus.current) {
      restoreFocus.current = false;
      opener.current?.focus();
    }
    const secret = inputPassword.current;
    return () => {
      if (secret) secret.value = "";
    };
  }, [mode]);

  const clearDisplay = () => {
    setPassword(null);
    secretQr.current?.modules.fill(0);
    secretQr.current = null;
    setQr(null);
  };

  const update = (next: PairingStatus) => {
    if (!mounted.current) return;
    if (next.phase !== status?.phase) focusStep.current = true;
    setStatus(next);
    if (!progresses(next.phase)) clearDisplay();
    setCopied(false);
  };

  const refreshLocal = async (current: () => boolean) => {
    try {
      const result = await commands.personalPairingStatus();
      if (mounted.current && current() && result.status === "ok") update(result.data);
    } catch {
      /* Retain the original error until the local checkpoint is available. */
    }
  };

  const stopWatching = async () => {
    const id = nativeObserver.current;
    const done = observerDone.current;
    observer.current = null;
    nativeObserver.current = null;
    setWatching(false);
    if (id) {
      const result = await commands.stopPersonalPairingWatch(id);
      if (result.status === "error") throw new Error("Could not detach pairing observer");
    }
    // The bounded core tick releases its operation lock when the watcher resolves.
    await done;
    if (observerDone.current === done) observerDone.current = null;
  };

  const watch = async () => {
    const id = crypto.randomUUID();
    observer.current = id;
    setWatching(true);
    onBusyChange(true);
    const messages = new Channel<PairingStatus>();
    messages.onmessage = (next) => {
      if (mounted.current && observer.current === id) update(next);
    };
    try {
      const registration = await commands.preparePersonalPairingWatch();
      if (registration.status === "error") throw new Error("Could not register pairing observer");
      if (!mounted.current || observer.current !== id) {
        await commands.stopPersonalPairingWatch(registration.data);
        return;
      }
      nativeObserver.current = registration.data;
      const result = await commands.watchPersonalPairing(registration.data, messages);
      if (!mounted.current || observer.current !== id) return;
      if (result.status === "error") {
        setFailed(result.error);
        clearDisplay();
        await refreshLocal(() => observer.current === id);
      }
    } catch {
      if (mounted.current && observer.current === id) {
        setFailed("unavailable");
        clearDisplay();
        await refreshLocal(() => observer.current === id);
      }
    } finally {
      if (mounted.current && observer.current === id) {
        observer.current = null;
        nativeObserver.current = null;
        setWatching(false);
        onBusyChange(false);
      }
    }
  };

  const run = async (operation: () => Promise<Outcome>, resume = true) => {
    if (pending.current) return;
    pending.current = true;
    setWorking(true);
    setFailed(null);
    setCopyFailed(false);
    onBusyChange(true);
    let next: PairingStatus | null = null;
    try {
      await stopWatching();
      if (!mounted.current) return;
      const result = await operation();
      if (!mounted.current) return;
      if (result.status === "ok") {
        if (!result.data) return;
        next = result.data;
        update(next);
        setMode(null);
      } else {
        setFailed(result.error);
        clearDisplay();
        await refreshLocal(() => pending.current);
      }
    } catch {
      if (mounted.current) {
        setFailed("unavailable");
        clearDisplay();
        await refreshLocal(() => pending.current);
      }
    } finally {
      pending.current = false;
      if (mounted.current) {
        setWorking(false);
        if (next && resume && progresses(next.phase)) observerDone.current = watch();
        else onBusyChange(false);
      }
    }
  };

  const create = (event: FormEvent) => {
    event.preventDefault();
    if (pending.current || !origin.current || !device.current) return;
    const server = origin.current.value;
    const name = device.current.value;
    void run(async () => {
      const result = await commands.createPersonalPairing(server, name);
      if (result.status === "error") return result;
      if (mounted.current) {
        secretQr.current?.modules.fill(0);
        secretQr.current = result.data.qr;
        setQr(result.data.qr);
        setPassword(result.data.password);
      } else result.data.qr?.modules.fill(0);
      result.data.password = "";
      result.data.qr = null;
      return { status: "ok", data: result.data.status };
    });
  };

  const join = (event: FormEvent) => {
    event.preventDefault();
    if (pending.current || !link.current || !inputPassword.current) return;
    const publicLink = link.current.value;
    const secret = inputPassword.current.value;
    inputPassword.current.value = "";
    void run(() => commands.joinPersonalPairing(publicLink, secret));
  };

  const joinImage = () => {
    if (inputPassword.current) inputPassword.current.value = "";
    void run(async () => {
      const registration = await commands.preparePersonalPairingWatch();
      if (registration.status === "error") return registration;
      const id = registration.data;
      if (!mounted.current) {
        await commands.stopPersonalPairingWatch(id);
        return { status: "ok", data: null };
      }
      nativeObserver.current = id;
      try {
        return await commands.joinPersonalPairingImage(id);
      } finally {
        await commands.stopPersonalPairingWatch(id);
        if (nativeObserver.current === id) nativeObserver.current = null;
      }
    });
  };

  const copy = async () => {
    if (!status?.publicLink) return;
    setCopyFailed(false);
    try {
      await navigator.clipboard.writeText(status.publicLink);
      if (mounted.current) setCopied(true);
    } catch {
      if (mounted.current) setCopyFailed(true);
    }
  };

  const idle =
    status?.phase === "idle" ||
    status?.phase === "cancelled" ||
    status?.phase === "restart_required" ||
    status?.phase === "completed";
  const active = status && !idle && status.phase !== "completed";
  const blocked = working || (disabled && !watching);
  const failureKey =
    failed && typeof failed === "object"
      ? (`settings.personal.error.${failed.personal}` as const)
      : (`settings.personal.pairing.error.${failed ?? "unavailable"}` as const);

  return (
    <section aria-labelledby="personal-pairing-title" className="mt-6 border-t border-border pt-6">
      <h3 ref={heading} tabIndex={-1} id="personal-pairing-title" className="text-sm font-medium">
        {t("settings.personal.pairing.title")}
      </h3>
      <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.pairing.body")}</p>
      {failed ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {t(failureKey)}
        </p>
      ) : null}
      <p role="status" className="mt-3 text-sm text-muted-foreground">
        {t(
          status?.phase === "completed" && status.side === "old_device"
            ? "settings.personal.pairing.admissionConfirmed"
            : status
              ? `settings.personal.pairing.phase.${status.phase}`
              : "settings.personal.pairing.loading",
        )}
      </p>
      {status?.origin ? <p className="mt-3 break-all select-text text-sm">{status.origin}</p> : null}
      {status?.side === "new_device" && status.publicLink && active ? (
        <div className="mt-4 space-y-3">
          <Field label={t("settings.personal.pairing.link")} value={status.publicLink} readOnly autoComplete="off" />
          <Button variant="secondary" onClick={() => void copy()}>
            {t(copied ? "settings.personal.pairing.copied" : "settings.personal.pairing.copy")}
          </Button>
          {copyFailed ? (
            <p role="alert" className="text-sm text-attention">
              {t("settings.personal.pairing.copyFailed")}
            </p>
          ) : null}
          {password ? (
            <div>
              <p className="text-sm font-medium">{t("settings.personal.pairing.qr")}</p>
              {qr ? (
                <PairingQr qr={qr} label={t("settings.personal.pairing.qr")} />
              ) : (
                <p className="mt-2 text-sm text-muted-foreground">
                  {t("settings.personal.pairing.error.qr_unavailable")}
                </p>
              )}
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.pairing.qrHint")}</p>
              <p className="mt-4 text-sm font-medium">{t("settings.personal.pairing.password")}</p>
              <output
                aria-label={t("settings.personal.pairing.password")}
                className="mt-2 block select-text font-mono text-2xl"
              >
                {password}
              </output>
              <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.pairing.passwordHint")}</p>
            </div>
          ) : null}
        </div>
      ) : null}
      {status?.phase === "confirm_device" ? (
        <div className="mt-4">
          <p className="text-sm">{t("settings.personal.pairing.review")}</p>
          <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">{t("settings.personal.deviceName")}</dt>
            <dd className="m-0 break-words [overflow-wrap:anywhere]">{status.peerName}</dd>
            <dt className="text-muted-foreground">{t("settings.personal.pairing.platform")}</dt>
            <dd className="m-0 break-words [overflow-wrap:anywhere]">{status.peerPlatform}</dd>
          </dl>
          <Button className="mt-4" disabled={blocked} onClick={() => void run(commands.confirmPersonalPairing)}>
            {t("settings.personal.pairing.confirm")}
          </Button>
        </div>
      ) : null}
      {idle && !mode ? (
        <div className="mt-4">
          {!configured ? (
            <Button ref={opener} variant="secondary" disabled={blocked} onClick={() => setMode("new")}>
              {t("settings.personal.pairing.create")}
            </Button>
          ) : authenticated ? (
            <Button ref={opener} variant="secondary" disabled={blocked} onClick={() => setMode("old")}>
              {t("settings.personal.pairing.join")}
            </Button>
          ) : (
            <p className="text-sm text-muted-foreground">{t("settings.personal.pairing.authenticate")}</p>
          )}
        </div>
      ) : null}
      {mode ? (
        <form onSubmit={mode === "new" ? create : join} className="mt-4 flex flex-col gap-4">
          {mode === "new" ? (
            <>
              {status?.side === "new_device" ? (
                <p className="text-sm text-muted-foreground">{t("settings.personal.pairing.retained")}</p>
              ) : null}
              <Field
                ref={origin}
                label={t("settings.personal.pairing.origin")}
                hint={t("settings.personal.pairing.originHint")}
                type="url"
                maxLength={2048}
                defaultValue={status?.side === "new_device" ? (status.origin ?? "") : ""}
                readOnly={status?.side === "new_device"}
                required
                disabled={blocked}
                autoComplete="off"
                spellCheck={false}
              />
              <Field
                ref={device}
                label={t("settings.personal.deviceName")}
                maxLength={128}
                defaultValue={status?.side === "new_device" ? (status.deviceName ?? "") : ""}
                readOnly={status?.side === "new_device"}
                required
                disabled={blocked}
                autoComplete="off"
              />
            </>
          ) : (
            <>
              <div>
                <Button variant="secondary" disabled={blocked} onClick={joinImage}>
                  {t("settings.personal.pairing.readImage")}
                </Button>
                <p className="mt-2 text-sm text-muted-foreground">{t("settings.personal.pairing.imageHint")}</p>
              </div>
              <Field
                ref={link}
                label={t("settings.personal.pairing.link")}
                hint={t("settings.personal.pairing.linkHint")}
                type="url"
                maxLength={4096}
                required
                disabled={blocked}
                autoComplete="off"
                spellCheck={false}
                autoCapitalize="none"
              />
              <Field
                ref={inputPassword}
                label={t("settings.personal.pairing.password")}
                hint={t("settings.personal.pairing.inputHint")}
                type="password"
                minLength={8}
                maxLength={8}
                required
                disabled={blocked}
                autoComplete="off"
                spellCheck={false}
                autoCapitalize="characters"
              />
            </>
          )}
          <div className="flex flex-wrap gap-3">
            <Button type="submit" disabled={blocked}>
              {t(
                working
                  ? "settings.personal.working"
                  : mode === "new"
                    ? "settings.personal.pairing.start"
                    : "settings.personal.pairing.verify",
              )}
            </Button>
            <Button
              variant="secondary"
              disabled={working}
              onClick={() => {
                if (inputPassword.current) inputPassword.current.value = "";
                restoreFocus.current = true;
                setMode(null);
              }}
            >
              {t("settings.personal.pairing.close")}
            </Button>
          </div>
        </form>
      ) : null}
      {active ? (
        <div className="mt-4 flex flex-wrap gap-3">
          {!watching && status.phase !== "confirm_device" ? (
            <Button disabled={blocked} onClick={() => void run(commands.recoverPersonalPairing)}>
              {t(working ? "settings.personal.working" : "settings.personal.pairing.recover")}
            </Button>
          ) : null}
          <Button
            variant="secondary"
            disabled={working}
            onClick={() => {
              clearDisplay();
              void run(commands.cancelPersonalPairing, false);
            }}
          >
            {t("settings.personal.pairing.cancel")}
          </Button>
        </div>
      ) : null}
      {!status && failed ? (
        <Button
          className="mt-4"
          variant="secondary"
          disabled={blocked}
          onClick={() => void run(commands.personalPairingStatus, false)}
        >
          {t("settings.personal.pairing.reload")}
        </Button>
      ) : null}
    </section>
  );
}
