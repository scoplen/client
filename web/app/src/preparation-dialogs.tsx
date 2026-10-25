// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field, Mark } from "@scoplen/ui";
import { useEffect, useId, useMemo, useRef } from "react";
import { useI18n } from "./i18n";
import type { PreparationEvent, PreparationContext, HostKeyTrustSource } from "./ipc/bindings";

export function TrustDialog({
  active,
  prompt,
  busy: trustBusy,
  error: trustError,
  onAccept: trustAndConnect,
  onCancel: cancelTrust,
}: {
  active: boolean;
  prompt: Extract<PreparationEvent, { kind: "trust" }> | null;
  busy: boolean;
  error: string | null;
  onAccept: () => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const hostKey = prompt?.hostKey ?? null;
  const context = prompt?.context ?? null;
  return (
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
  );
}

export function PassphraseDialog({
  active,
  promptId: passphrasePrompt,
  context,
  busy: trustBusy,
  error: passphraseError,
  onPassphrase,
  onCancel: cancelPassphrase,
}: {
  active: boolean;
  promptId: string | null;
  context: PreparationContext | null;
  busy: boolean;
  error: string | null;
  onPassphrase: (value: string) => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const passphraseInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const input = passphraseInput.current;
    if (input) input.value = "";
    return () => {
      if (input) input.value = "";
    };
  }, [active, passphrasePrompt]);
  const submitPassphrase = () => {
    if (trustBusy || !active || !passphrasePrompt) return;
    const value = passphraseInput.current?.value ?? "";
    if (passphraseInput.current) passphraseInput.current.value = "";
    onPassphrase(value);
  };
  return (
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
  );
}

export function InteractiveDialog({
  active,
  challenge,
  busy,
  error,
  onAnswer,
  onCancel,
}: {
  active: boolean;
  challenge: Extract<PreparationEvent, { kind: "keyboardInteractive" }>;
  busy: boolean;
  error: string | null;
  onAnswer: (answers: string[]) => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const form = useId();
  const inputs = useRef<Array<HTMLInputElement | null>>([]);
  const inputRefs = useMemo(
    () =>
      challenge.prompts.map((_, index) => (input: HTMLInputElement | null) => {
        if (!input && inputs.current[index]) inputs.current[index]!.value = "";
        inputs.current[index] = input;
      }),
    [challenge.prompts],
  );
  const cancel = () => {
    inputs.current.forEach((field) => {
      if (field) field.value = "";
    });
    onCancel();
  };
  useEffect(() => {
    const fields = inputs.current;
    if (!active)
      fields.forEach((field) => {
        if (field) field.value = "";
      });
    return () =>
      fields.forEach((field) => {
        if (field) field.value = "";
      });
  }, [active]);
  return (
    <Dialog
      open={active}
      onOpenChange={(open) => {
        if (!open && active) cancel();
      }}
      title={t("session.interactive.title")}
      description={t("session.interactive.body")}
      closeLabel={t("session.interactive.cancel")}
      footer={
        <>
          <Button variant="ghost" onClick={cancel}>
            {t("session.interactive.cancel")}
          </Button>
          <Button variant="primary" type="submit" form={form} busy={busy}>
            {t("session.interactive.continue")}
          </Button>
        </>
      }
    >
      <HopIdentity context={challenge.context} />
      <div className="mb-4 min-w-0 space-y-2 whitespace-pre-wrap text-sm wrap-anywhere">
        {challenge.name ? <p className="m-0">{challenge.name}</p> : null}
        {challenge.instruction ? <p className="m-0">{challenge.instruction}</p> : null}
      </div>
      <form
        id={form}
        className="flex min-w-0 flex-col gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          if (busy || !active) return;
          const answers = challenge.prompts.map((_, index) => inputs.current[index]?.value ?? "");
          inputs.current.forEach((field) => {
            if (field) field.value = "";
          });
          onAnswer(answers);
        }}
      >
        {challenge.prompts.map((prompt, index) => (
          <Field
            key={index}
            ref={inputRefs[index]}
            label={prompt.text || t("session.interactive.response", { count: index + 1 })}
            type={prompt.echo ? "text" : "password"}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            autoFocus={index === 0}
            maxLength={65536}
            className="min-w-0 [&_label]:whitespace-pre-wrap [&_label]:wrap-anywhere"
          />
        ))}
        {error ? (
          <p role="alert" className="m-0 text-sm text-attention">
            {error}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}

export function TrustSourceDetails({ source }: { source: HostKeyTrustSource }) {
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

export function HopIdentity({ context }: { context: PreparationContext }) {
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
