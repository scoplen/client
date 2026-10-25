// SPDX-License-Identifier: Apache-2.0
import { Button, Confirm, Dialog, Field, IconButton } from "@scoplen/ui";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useContext, useEffect, useId, useRef, useState } from "react";
import { useI18n } from "../i18n";
import type { ForwardIssue, ForwardSnapshot, PreparationEvent, SessionPreparationIntent } from "../ipc/bindings";
import { InteractiveDialog, PassphraseDialog, TrustDialog } from "../preparation-dialogs";
import { ForwardsContext, isLiveForward } from "../use-forwards";
import {
  useInventory,
  type AccessProfileSummary,
  type Failure,
  type ForwardInput,
  type ForwardSummary,
  type ObjectEditError,
  type Outcome,
} from "./api";
import { useLoad } from "./use-load";

function loadObjects<T>(promise: Promise<Outcome<T, ObjectEditError>>): Promise<Outcome<T, Failure>> {
  return promise.then((result) =>
    result.status === "ok"
      ? result
      : {
          status: "error",
          error: {
            kind: "failed",
            reference: result.error.kind === "failed" ? result.error.reference : result.error.kind,
          },
        },
  );
}

function endpoint(host: string | null, port: number | null): string {
  if (!host || !port) return "—";
  return `${host.includes(":") ? `[${host}]` : host}:${port}`;
}

function isLoopback(address: string): boolean {
  const normalized = address.trim().toLowerCase();
  return (
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized) || normalized === "::1" || normalized === "0:0:0:0:0:0:0:1"
  );
}

export function TunnelsHome() {
  const { t, locale } = useI18n();
  const api = useInventory();
  const runtime = useContext(ForwardsContext);
  const forwards = useLoad(() => loadObjects(api.forwards()), "forwards");
  const profiles = useLoad(() => loadObjects(api.accessProfiles()), "access-profiles");
  const [editing, setEditing] = useState<ForwardSummary | "new" | null>(null);
  const [deleting, setDeleting] = useState<ForwardSummary | null>(null);
  const [starting, setStarting] = useState<ForwardSummary | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<ObjectEditError | null>(null);
  const [stopIssue, setStopIssue] = useState<ForwardIssue | null>(null);
  const [stopping, setStopping] = useState<string | null>(null);
  const addTrigger = useRef<HTMLButtonElement | null>(null);
  const editorTrigger = useRef<HTMLButtonElement | null>(null);
  const runs = runtime?.snapshots ?? [];
  const profileList = profiles.state === "ready" ? profiles.data : [];
  const selectedRun = runs.find((run) => run.runId === selected);
  const numberFormat = new Intl.NumberFormat(locale);
  const number = (value: string | number) => numberFormat.format(typeof value === "string" ? BigInt(value) : value);

  const stop = async (runId: string) => {
    if (!runtime || stopping) return;
    setStopping(runId);
    setSelected(null);
    setStopIssue(null);
    try {
      setStopIssue(await runtime.stop(runId));
    } finally {
      setStopping(null);
    }
  };
  const remove = async () => {
    if (!deleting || deleteBusy) return;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      const result = await api.deleteForward(deleting.id);
      if (result.status === "ok") setDeleting(null);
      else setDeleteError(result.error);
    } catch {
      setDeleteError({ kind: "failed", reference: "tunnel inventory unavailable" });
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div className="h-full min-h-0 overflow-y-auto px-6 py-6">
      <div className="mx-auto max-w-4xl">
        <header className="flex flex-wrap items-start gap-4 pb-6">
          <div className="min-w-0 flex-1">
            <h1 className="ui-display text-3xl">{t("tunnels.title")}</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{t("tunnels.description")}</p>
          </div>
          <Button
            ref={addTrigger}
            variant="primary"
            onClick={(event) => {
              editorTrigger.current = event.currentTarget;
              setEditing("new");
            }}
            className="gap-1.5"
          >
            <Plus aria-hidden="true" className="size-4" />
            {t("tunnels.add")}
          </Button>
        </header>

        <section aria-labelledby="tunnel-runs-title" className="pb-8">
          <h2 id="tunnel-runs-title" className="m-0 text-sm font-semibold">
            {t("tunnels.runs")}
          </h2>
          {!runtime ? (
            <p className="text-sm text-muted-foreground">{t("tunnels.desktopOnly")}</p>
          ) : runtime.loading ? (
            <p role="status" className="text-sm text-muted-foreground">
              {t("tunnels.loading")}
            </p>
          ) : null}
          {runtime?.issue ? (
            <div role="alert" className="mt-3 text-sm text-attention">
              <p>{t(`tunnels.issue.${runtime.issue}`)}</p>
              <Button variant="ghost" onClick={runtime.refresh}>
                {t("tunnels.refresh")}
              </Button>
            </div>
          ) : null}
          {stopIssue ? (
            <p role="alert" className="text-sm text-attention">
              {t(`tunnels.issue.${stopIssue}`)}
            </p>
          ) : null}
          {runtime && !runtime.loading && !runtime.issue && runs.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("tunnels.runs.empty")}</p>
          ) : null}
          <ul className="m-0 mt-3 list-none divide-y divide-border p-0" aria-label={t("tunnels.runs")}>
            {runs.map((run) => {
              const configuration = run.configuration;
              const prompt = run.phase === "preparing" && run.preparation && "promptId" in run.preparation;
              return (
                <li key={run.runId} className="min-w-0 py-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="m-0 min-w-0 flex-1 break-words text-sm font-medium">{configuration.name}</h3>
                    <span
                      className={run.phase === "failed" ? "text-xs text-attention" : "text-xs text-muted-foreground"}
                    >
                      {prompt ? t("tunnels.attention") : t(`tunnels.phase.${run.phase}`)}
                    </span>
                    {prompt ? (
                      <Button variant="secondary" onClick={() => setSelected(run.runId)}>
                        {t("tunnels.continue")}
                      </Button>
                    ) : null}
                    {isLiveForward(run) ? (
                      <Button
                        variant="ghost"
                        onClick={() => void stop(run.runId)}
                        disabled={run.phase === "stopping" || stopping === run.runId}
                      >
                        {t("tunnels.stop")}
                      </Button>
                    ) : null}
                  </div>
                  {configuration.kind === "remote" ? (
                    <RemoteEndpoints {...configuration} />
                  ) : (
                    <p className="mt-1 mb-0 break-all font-mono text-xs text-muted-foreground select-text">
                      {run.boundAddress ?? endpoint(configuration.bindAddress, configuration.bindPort)}
                      {configuration.kind === "local"
                        ? ` → ${endpoint(configuration.targetHost, configuration.targetPort)}`
                        : null}
                    </p>
                  )}
                  {configuration.kind === "remote" ? <RemoteScope address={configuration.bindAddress} /> : null}
                  {configuration.kind === "dynamic" ? (
                    <>
                      <p className="mt-1 mb-0 text-xs text-muted-foreground">{t("tunnels.dynamicBody")}</p>
                      {!isLoopback(configuration.bindAddress) ? (
                        <p role="note" className="mt-2 mb-0 text-sm text-attention">
                          {t("tunnels.dynamicNonLoopback")}
                        </p>
                      ) : null}
                    </>
                  ) : null}
                  <p className="mt-1 mb-0 break-words text-xs text-muted-foreground">
                    {configuration.login.host} · {configuration.login.login}
                  </p>
                  <p className="mt-1 mb-0 break-all font-mono text-xs text-muted-foreground select-text">
                    {configuration.login.username}@{endpoint(configuration.login.address, configuration.login.port)}
                  </p>
                  <dl className="mt-3 mb-0 flex flex-wrap gap-x-6 gap-y-2 text-xs tabular-nums">
                    {[
                      [t("tunnels.connections"), number(run.activeConnections)],
                      [t("tunnels.uploaded"), `${number(run.uploadedBytes)} B`],
                      [t("tunnels.downloaded"), `${number(run.downloadedBytes)} B`],
                      [t("tunnels.rejected"), number(run.rejectedConnections)],
                    ].map(([label, value]) => (
                      <div key={label} className="flex gap-2">
                        <dt className="text-muted-foreground">{label}</dt>
                        <dd className="m-0">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  {run.lastIssue ? (
                    <p className="mt-2 mb-0 text-sm text-attention">{t(`tunnels.issue.${run.lastIssue}`)}</p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </section>

        <section aria-labelledby="tunnel-saved-title">
          <h2 id="tunnel-saved-title" className="m-0 text-sm font-semibold">
            {t("tunnels.saved")}
          </h2>
          {forwards.state === "loading" ? (
            <p role="status" className="text-sm text-muted-foreground">
              {t("tunnels.loading")}
            </p>
          ) : forwards.state === "failed" ? (
            <p role="alert" className="text-sm text-attention">
              {t("failed.body")} {t("startup.error.reference", { reference: forwards.reference })}
            </p>
          ) : forwards.data.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("tunnels.saved.empty")}</p>
          ) : (
            <ul aria-label={t("tunnels.saved")} className="m-0 mt-3 list-none divide-y divide-border p-0">
              {forwards.data.map((forward) => {
                const live = runs.some((run) => run.configuration.forwardId === forward.id && isLiveForward(run));
                return (
                  <li key={forward.id} className="flex min-w-0 flex-wrap items-center gap-3 py-4">
                    <div className="min-w-0 flex-1 basis-52">
                      <h3 className="m-0 break-words text-sm font-medium">{forward.name}</h3>
                      {forward.kind === "remote" ? (
                        <RemoteEndpoints {...forward} />
                      ) : (
                        <p className="mt-1 mb-0 break-all font-mono text-xs text-muted-foreground">
                          {endpoint(forward.bindAddress, forward.bindPort)}
                          {forward.kind === "dynamic" ? null : ` → ${endpoint(forward.targetHost, forward.targetPort)}`}
                        </p>
                      )}
                      {forward.kind === "dynamic" ? (
                        <p className="mt-1 mb-0 text-xs text-muted-foreground">{t("tunnels.dynamicSocks")}</p>
                      ) : null}
                      {forward.restored ? (
                        <p className="mt-1 mb-0 text-xs text-attention">{t("hosts.restored")}</p>
                      ) : null}
                    </div>
                    <div className="ml-auto flex shrink-0 items-center gap-1">
                      <Button
                        variant="secondary"
                        onClick={() => setStarting(forward)}
                        disabled={
                          !runtime ||
                          runtime.loading ||
                          runtime.issue === "unavailable" ||
                          live ||
                          profiles.state !== "ready"
                        }
                      >
                        {live ? t("tunnels.running") : t("tunnels.start")}
                      </Button>
                      <IconButton
                        label={t("tunnels.edit", { name: forward.name })}
                        onClick={(event) => {
                          editorTrigger.current = event.currentTarget;
                          setEditing(forward);
                        }}
                      >
                        <Pencil aria-hidden="true" className="size-4" />
                      </IconButton>
                      <IconButton
                        label={t("tunnels.delete", { name: forward.name })}
                        onClick={() => {
                          setDeleting(forward);
                          setDeleteError(null);
                        }}
                      >
                        <Trash2 aria-hidden="true" className="size-4" />
                      </IconButton>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
          {profiles.state === "failed" ? (
            <p role="alert" className="text-sm text-attention">
              {t("tunnels.profilesFailed")}
            </p>
          ) : null}
        </section>
      </div>
      {editing ? (
        <TunnelEditor
          key={editing === "new" ? "new" : editing.id}
          existing={editing === "new" ? null : editing}
          profiles={profileList}
          finalFocus={() => (editorTrigger.current?.isConnected ? editorTrigger.current : addTrigger.current)}
          onClose={() => setEditing(null)}
          onSaved={() => setEditing(null)}
        />
      ) : null}
      {starting && runtime ? (
        <StartDialog
          forward={starting}
          profiles={profileList}
          onClose={() => setStarting(null)}
          onStart={async (profileId) => {
            const run = await runtime.start(starting.id, profileId);
            if (run) {
              setStarting(null);
              setSelected(run.runId);
            }
            return run !== null;
          }}
          issue={runtime.issue}
        />
      ) : null}
      {selectedRun ? (
        <RunPreparation
          key={`${selectedRun.runId}:${selectedRun.preparation && "promptId" in selectedRun.preparation ? selectedRun.preparation.promptId : selectedRun.phase}`}
          run={selectedRun}
          onCancel={() => void stop(selectedRun.runId)}
        />
      ) : null}
      <Confirm
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open && !deleteBusy) setDeleting(null);
        }}
        title={t("tunnels.deleteTitle", { name: deleting?.name ?? "" })}
        body={
          <>
            <p>{t("tunnels.deleteBody")}</p>
            {deleteError ? (
              <p role="alert" className="text-attention">
                {editError(t, deleteError)}
              </p>
            ) : null}
          </>
        }
        confirmLabel={t("tunnels.delete", { name: deleting?.name ?? "" })}
        cancelLabel={t("objects.cancel")}
        onConfirm={() => void remove()}
        busy={deleteBusy}
        destructive
      />
    </div>
  );
}

function loginLabel(profile: AccessProfileSummary): string {
  return `${profile.hostName ?? profile.host} · ${profile.name ?? profile.username}`;
}

function RemoteEndpoints({
  bindAddress,
  bindPort,
  targetHost,
  targetPort,
}: Pick<ForwardSummary, "bindAddress" | "bindPort" | "targetHost" | "targetPort">) {
  const { t } = useI18n();
  return (
    <dl className="mt-1 mb-0 text-xs text-muted-foreground">
      {[
        [t("tunnels.remoteListener"), endpoint(bindAddress, bindPort)],
        [t("tunnels.localTarget"), endpoint(targetHost, targetPort)],
      ].map(([label, value]) => (
        <div key={label} className="flex flex-wrap gap-x-2">
          <dt>{label}</dt>
          <dd className="m-0 break-all font-mono select-text">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function RemoteScope({ address }: { address: string }) {
  const { t } = useI18n();
  return (
    <>
      <p className="mt-2 mb-0 text-xs text-muted-foreground">{t("tunnels.remoteScope")}</p>
      {address && !isLoopback(address) ? (
        <p role="note" className="mt-2 mb-0 text-sm text-attention">
          {t("tunnels.remoteNonLoopback")}
        </p>
      ) : null}
    </>
  );
}

function RunPreparation({ run, onCancel }: { run: ForwardSnapshot; onCancel: () => void }) {
  const { t } = useI18n();
  const runtime = useContext(ForwardsContext);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const event = run.phase === "preparing" ? run.preparation : null;
  const promptId = event && "promptId" in event ? event.promptId : null;
  const pending = useRef<string | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const answer = async (intent: SessionPreparationIntent) => {
    if (!runtime || !promptId || pending.current === promptId) return;
    pending.current = promptId;
    setBusy(true);
    setError(null);
    const issue = await runtime.respond(run.runId, promptId, intent);
    if (!mounted.current) return;
    if (issue) {
      pending.current = null;
      setBusy(false);
      setError(t(`tunnels.issue.${issue}`));
    }
  };
  return (
    <PreparationPrompt
      key={promptId}
      event={event}
      busy={busy}
      error={error}
      onAnswer={(intent) => void answer(intent)}
      onCancel={onCancel}
    />
  );
}

function PreparationPrompt({
  event,
  busy,
  error,
  onAnswer,
  onCancel,
}: {
  event: PreparationEvent | null;
  busy: boolean;
  error: string | null;
  onAnswer: (intent: SessionPreparationIntent) => void;
  onCancel: () => void;
}) {
  const { t } = useI18n();
  const [required, setRequired] = useState(false);
  if (event?.kind === "trust")
    return (
      <TrustDialog
        active
        prompt={event}
        busy={busy}
        error={error}
        onAccept={() => onAnswer({ kind: "acceptHostKey" })}
        onCancel={onCancel}
      />
    );
  if (event?.kind === "keyboardInteractive")
    return (
      <InteractiveDialog
        active
        challenge={event}
        busy={busy}
        error={error}
        onAnswer={(answers) => onAnswer({ kind: "keyboardInteractive", answers })}
        onCancel={onCancel}
      />
    );
  if (event?.kind === "passphrase")
    return (
      <PassphraseDialog
        active
        promptId={event.promptId}
        context={event.context}
        busy={busy}
        error={
          error ??
          (required ? t("session.passphrase.required") : event.incorrect ? t("session.passphrase.incorrect") : null)
        }
        onPassphrase={(value) => {
          setRequired(!value);
          if (value) onAnswer({ kind: "passphrase", value });
        }}
        onCancel={onCancel}
      />
    );
  return null;
}

function StartDialog({
  forward,
  profiles,
  onClose,
  onStart,
  issue,
}: {
  forward: ForwardSummary;
  profiles: AccessProfileSummary[];
  onClose: () => void;
  onStart: (profile: string) => Promise<boolean>;
  issue: ForwardIssue | null;
}) {
  const { t } = useI18n();
  const [profile, setProfile] = useState(
    profiles.some((candidate) => candidate.id === forward.profile && !candidate.orphaned) ? forward.profile! : "",
  );
  const [busy, setBusy] = useState(false);
  const id = useId();
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
      title={t("tunnels.startTitle", { name: forward.name })}
      description={t("tunnels.startBody")}
      closeLabel={t("objects.cancel")}
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            {t("objects.cancel")}
          </Button>
          <Button
            variant="primary"
            disabled={!profile}
            busy={busy}
            onClick={() => {
              if (busy || !profile) return;
              setBusy(true);
              void onStart(profile).finally(() => setBusy(false));
            }}
          >
            {t("tunnels.start")}
          </Button>
        </>
      }
    >
      <label htmlFor={id} className="block text-sm font-medium">
        {t("tunnels.login")}
      </label>
      <select
        id={id}
        value={profile}
        disabled={busy}
        onChange={(event) => setProfile(event.target.value)}
        className={selectStyle}
      >
        <option value="">{t("tunnels.chooseLogin")}</option>
        {profiles.map((item) => (
          <option key={item.id} value={item.id} disabled={item.orphaned}>
            {loginLabel(item)}
          </option>
        ))}
      </select>
      {profiles.every((item) => item.orphaned) ? (
        <p className="text-sm text-attention">{t("tunnels.noLogins")}</p>
      ) : null}
      {issue ? (
        <p role="alert" className="text-sm text-attention">
          {t(`tunnels.issue.${issue}`)}
        </p>
      ) : null}
    </Dialog>
  );
}

function TunnelEditor({
  existing,
  profiles,
  finalFocus,
  onClose,
  onSaved,
}: {
  existing: ForwardSummary | null;
  profiles: AccessProfileSummary[];
  finalFocus: () => HTMLElement | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const form = useId();
  const select = useId();
  const mode = useId();
  const [kind, setKind] = useState<ForwardInput["kind"]>(existing?.kind ?? "local");
  const [value, setValue] = useState({
    name: existing?.name ?? "",
    bindAddress: existing?.bindAddress ?? "127.0.0.1",
    bindPort: existing?.bindPort?.toString() ?? "",
    targetHost: existing?.kind !== "dynamic" ? (existing?.targetHost ?? "") : "",
    targetPort: existing?.kind !== "dynamic" ? (existing?.targetPort?.toString() ?? "") : "",
    profile: existing?.profile ?? "",
  });
  const [error, setError] = useState<ObjectEditError | null>(null);
  const [busy, setBusy] = useState(false);
  const field = (name: keyof typeof value) => ({
    value: value[name],
    disabled: busy,
    onChange: (event: React.ChangeEvent<HTMLInputElement>) =>
      setValue((current) => ({ ...current, [name]: event.target.value })),
  });
  const invalid = error?.kind === "invalidForward" ? error.field : null;
  const address = value.bindAddress.trim();
  const save = async () => {
    if (busy) return;
    setError(null);
    setBusy(true);
    const input: ForwardInput = {
      ...value,
      kind,
      bindPort: Number(value.bindPort),
      targetHost: kind !== "dynamic" ? value.targetHost : null,
      targetPort: kind !== "dynamic" ? Number(value.targetPort) : null,
      profile: value.profile || null,
    };
    try {
      const result = existing ? await api.updateForward(existing.id, input) : await api.createForward(input);
      if (result.status === "ok") onSaved();
      else setError(result.error);
    } catch {
      setError({ kind: "failed", reference: "tunnel inventory unavailable" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
      title={existing ? t("tunnels.editTitle") : t("tunnels.newTitle")}
      description={t("tunnels.editorBody")}
      finalFocus={finalFocus}
      closeLabel={t("objects.cancel")}
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            {t("objects.cancel")}
          </Button>
          <Button variant="primary" type="submit" form={form} busy={busy}>
            {t("objects.save")}
          </Button>
        </>
      }
    >
      <form
        id={form}
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Field
          label={t("tunnels.name")}
          {...field("name")}
          required
          autoFocus
          error={error?.kind === "emptyName" ? t("objects.error.emptyName") : undefined}
        />
        <div>
          <label htmlFor={mode} className="block text-sm font-medium">
            {t("tunnels.mode")}
          </label>
          <select
            id={mode}
            value={kind}
            disabled={busy}
            onChange={(event) => {
              setKind(event.target.value as ForwardInput["kind"]);
              setError(null);
            }}
            className={selectStyle}
          >
            <option value="local">{t("tunnels.localTcp")}</option>
            <option value="remote">{t("tunnels.remoteTcp")}</option>
            <option value="dynamic">{t("tunnels.dynamicSocks")}</option>
          </select>
        </div>
        {kind === "dynamic" ? <p className="text-sm text-muted-foreground">{t("tunnels.dynamicBody")}</p> : null}
        {kind === "remote" ? <p className="text-sm text-muted-foreground">{t("tunnels.remoteBody")}</p> : null}
        <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_7rem]">
          <Field
            label={t(kind === "remote" ? "tunnels.remoteBindAddress" : "tunnels.bindAddress")}
            {...field("bindAddress")}
            required
            error={invalid === "bindAddress" ? t("tunnels.error.bindAddress") : undefined}
          />
          <Field
            label={t(kind === "remote" ? "tunnels.remoteBindPort" : "tunnels.bindPort")}
            {...field("bindPort")}
            type="number"
            min={1}
            max={65535}
            required
            error={invalid === "bindPort" ? t("tunnels.error.port") : undefined}
          />
        </div>
        {kind === "remote" ? (
          <RemoteScope address={address} />
        ) : !isLoopback(address) && address ? (
          <p role="note" className="text-sm text-attention">
            {t(kind === "dynamic" ? "tunnels.dynamicNonLoopback" : "tunnels.nonLoopback")}
          </p>
        ) : null}
        {kind !== "dynamic" ? (
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_7rem]">
            <Field
              label={t(kind === "remote" ? "tunnels.localTargetHost" : "tunnels.targetHost")}
              {...field("targetHost")}
              required
              error={invalid === "targetHost" ? t("tunnels.error.targetHost") : undefined}
            />
            <Field
              label={t(kind === "remote" ? "tunnels.localTargetPort" : "tunnels.targetPort")}
              {...field("targetPort")}
              type="number"
              min={1}
              max={65535}
              required
              error={invalid === "targetPort" ? t("tunnels.error.port") : undefined}
            />
          </div>
        ) : null}
        <div>
          <label htmlFor={select} className="block text-sm font-medium">
            {t("tunnels.defaultLogin")}
          </label>
          <select
            id={select}
            value={value.profile}
            disabled={busy}
            onChange={(event) => setValue((current) => ({ ...current, profile: event.target.value }))}
            className={selectStyle}
          >
            <option value="">{t("tunnels.chooseAtStart")}</option>
            {value.profile && !profiles.some((profile) => profile.id === value.profile) ? (
              <option value={value.profile}>{t("tunnels.loginUnavailable")}</option>
            ) : null}
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id} disabled={profile.orphaned}>
                {loginLabel(profile)}
              </option>
            ))}
          </select>
        </div>
        {error && !invalid && error.kind !== "emptyName" ? (
          <p role="alert" className="text-sm text-attention">
            {editError(t, error)}
          </p>
        ) : null}
      </form>
    </Dialog>
  );
}

const selectStyle = "mt-2 h-10 w-full min-w-0 rounded-md border border-border bg-inset px-3 text-sm text-foreground";

function editError(t: ReturnType<typeof useI18n>["t"], error: ObjectEditError): string {
  if (error.kind === "inUse") return t("tunnels.error.inUse");
  if (error.kind === "failed") return t("startup.error.reference", { reference: error.reference });
  if (error.kind === "invalidForward") return t("tunnels.error.invalidField");
  if (error.kind === "notFound" || error.kind === "invalidId") return t("tunnels.error.missingReference");
  if (error.kind === "textTooLong") return t("objects.error.textTooLong", { field: error.field });
  return t("failed.body");
}
