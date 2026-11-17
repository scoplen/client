// SPDX-License-Identifier: Apache-2.0
import { Button, Select } from "@scoplen/ui";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  SessionTarget,
  TeamError,
  TeamImportDiagnostic,
  TeamImportError,
  TeamImportFields,
  TeamImportPending,
  TeamImportPreview,
  TeamImportSource,
  TeamSummary,
} from "./ipc/bindings";
import { TeamAssets } from "./team-assets";

type Translate = ReturnType<typeof useI18n>["t"];

/** Account-owned migration tools stay in Settings > Data. Roles never grant UI authority. */
export function TeamInventoryImportSettings({ onConnect }: { onConnect?: (target: SessionTarget) => void }) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const id = useId();
  const [teams, setTeams] = useState<TeamSummary[]>([]);
  const [saved, setSaved] = useState<string[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [savedCursor, setSavedCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const active = useRef(true);
  const reading = useRef(false);
  const [names, setNames] = useState<Record<string, string>>({});

  const load = useCallback(
    (more: boolean, next: string | null = null, retained: string | null = null) => {
      if (reading.current) return;
      reading.current = true;
      return Promise.all([
        !more || next ? commands.teamsPage(next) : null,
        !more || retained ? commands.retainedTeamInventoryImports(retained) : null,
      ])
        .then(([memberships, imports]) => {
          if (!active.current) return;
          if (memberships?.status === "ok") {
            setNames((previous) => ({
              ...previous,
              ...Object.fromEntries(memberships.data.teams.map((team) => [team.id, team.name])),
            }));
            setTeams((previous) => (more ? [...previous, ...memberships.data.teams] : memberships.data.teams));
            setCursor(memberships.data.nextCursor);
          } else if (memberships) {
            if (!more) setTeams([]);
            setFailed(teamError(t, memberships.error));
          }
          if (imports?.status === "ok") {
            setSaved((previous) => [...new Set([...(more ? previous : []), ...imports.data.organizationIds])]);
            setSavedCursor(imports.data.nextCursor);
          } else if (imports) setFailed(importError(t, imports.error));
        })
        .catch(() => {
          if (active.current) setFailed(t("teamImport.error.connection"));
        })
        .finally(() => {
          reading.current = false;
          if (active.current) setLoading(false);
        });
    },
    [commands, t],
  );

  useEffect(() => {
    active.current = true;
    void load(false);
    return () => {
      active.current = false;
    };
  }, [load]);

  const retainedChanged = useCallback((organization: string, exists: boolean) => {
    setSaved((previous) =>
      exists ? [...new Set([...previous, organization])] : previous.filter((id) => id !== organization),
    );
  }, []);
  const currentTeam = teams.find((team) => team.id === selected);
  const selectedName =
    currentTeam?.name ?? names[selected] ?? t("teamImport.unavailableTeam", { id: selected.slice(-8) });
  const recoveryOnly = saved.filter((id) => !teams.some((team) => team.id === id));
  const options = [
    { value: "", label: t("teamImport.chooseTeam") },
    ...teams.map((team) => ({ value: team.id, label: team.name, group: t("teamImport.currentTeams") })),
    ...recoveryOnly.map((id) => ({
      value: id,
      label: names[id] ?? t("teamImport.unavailableTeam", { id: id.slice(-8) }),
      group: t("teamImport.savedTeams"),
    })),
  ];

  return (
    <section aria-labelledby={`${id}-title`} className="mt-8 border-t border-border pt-8">
      <h2 id={`${id}-title`} className="ui-display text-lg">
        {t("teamImport.title")}
      </h2>
      <p className="mt-2 max-w-lg text-sm text-muted-foreground">{t("teamImport.body")}</p>
      <div className="mt-4 flex flex-wrap items-end gap-3">
        <Select
          label={t("teamImport.team")}
          value={selected}
          options={options}
          disabled={busy || loading}
          onValueChange={setSelected}
          size="field"
          className="min-w-0 max-w-full"
        />
        <Button
          disabled={busy || loading}
          busy={loading}
          onClick={() => {
            setLoading(true);
            setFailed(null);
            void load(false);
          }}
        >
          {t("teamImport.refreshTeams")}
        </Button>
        {cursor || savedCursor ? (
          <Button
            disabled={busy || loading}
            onClick={() => {
              setLoading(true);
              setFailed(null);
              void load(true, cursor, savedCursor);
            }}
          >
            {t("teamImport.moreTeams")}
          </Button>
        ) : null}
      </div>
      {failed ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {failed}
        </p>
      ) : null}
      {!loading && !failed && options.length === 1 ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {t("teamImport.noTeams")}
        </p>
      ) : null}
      {selected ? (
        <SelectedTeamImport
          key={`${selected}:${!!currentTeam}`}
          team={{ id: selected, name: selectedName, roles: currentTeam?.roles ?? [] }}
          available={!!currentTeam}
          onBusyChange={setBusy}
          onRetainedChange={retainedChanged}
          onConnect={onConnect}
        />
      ) : null}
    </section>
  );
}

function SelectedTeamImport({
  team,
  available,
  onBusyChange,
  onRetainedChange,
  onConnect,
}: {
  team: TeamSummary;
  available: boolean;
  onBusyChange: (busy: boolean) => void;
  onRetainedChange: (organization: string, exists: boolean) => void;
  onConnect?: (target: SessionTarget) => void;
}) {
  const commands = useProfileCommands();
  const { t, locale } = useI18n();
  const [source, setSource] = useState<TeamImportSource>("csv");
  const [preview, setPreview] = useState<TeamImportPreview | null>(null);
  const [chosen, setChosen] = useState<number[]>([]);
  const [pending, setPending] = useState<TeamImportPending | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [refreshed, setRefreshed] = useState(false);
  const [assetsOpen, setAssetsOpen] = useState(false);
  const active = useRef(true);
  const inFlight = useRef(false);
  const reviewId = useRef<string | null>(null);

  const clearPreview = useCallback(() => {
    const current = reviewId.current;
    reviewId.current = null;
    if (current) void commands.clearTeamInventoryImportPreview(current).catch(() => undefined);
    setPreview(null);
    setChosen([]);
  }, [commands]);

  const readPending = useCallback(
    () =>
      commands.pendingTeamInventoryImport(team.id).then((result) => {
        if (!active.current) return;
        if (result.status === "error") {
          setLoaded(false);
          setFailed(importError(t, result.error));
          return;
        }
        if (result.data) clearPreview();
        setPending(result.data);
        setLoaded(true);
        onRetainedChange(team.id, !!result.data);
      }),
    [commands, team.id, onRetainedChange, t, clearPreview],
  );

  useEffect(() => {
    active.current = true;
    void readPending().catch(() => {
      if (active.current) setFailed(t("teamImport.error.connection"));
    });
    return () => {
      active.current = false;
      const current = reviewId.current;
      reviewId.current = null;
      if (current) void commands.clearTeamInventoryImportPreview(current).catch(() => undefined);
      onBusyChange(false);
    };
  }, [commands, onBusyChange, readPending, t]);

  const run = async (action: () => Promise<void>, recover = false) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setFailed(null);
    onBusyChange(true);
    try {
      await action();
    } catch {
      if (active.current) {
        setFailed(t("teamImport.error.connection"));
        if (recover) {
          setLoaded(false);
          try {
            await readPending();
          } catch {
            /* Keep sending disabled until an explicit reload succeeds. */
          }
        }
      }
    } finally {
      inFlight.current = false;
      if (active.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  };

  const choose = () =>
    void run(async () => {
      clearPreview();
      const result = await commands.chooseTeamInventoryImport(team.id, source, locale === "zh-Hans" ? "zh-Hans" : "en");
      if (!active.current) {
        if (result.status === "ok" && result.data)
          void commands.clearTeamInventoryImportPreview(result.data.previewId).catch(() => undefined);
        return;
      }
      if (result.status === "error") setFailed(importError(t, result.error));
      else {
        reviewId.current = result.data?.previewId ?? null;
        setPreview(result.data);
      }
    });

  const prepare = () => {
    if (!preview || !available) return;
    const original = preview;
    void run(async () => {
      const result = await commands.prepareTeamInventoryImport(team.id, original.previewId, chosen);
      if (!active.current) return;
      if (result.status === "error") setFailed(importError(t, result.error));
      else {
        setPending(result.data);
        onRetainedChange(team.id, true);
        clearPreview();
      }
    }, true);
  };

  const refresh = async (original: TeamImportPending) => {
    const result = await commands.reviewTeamInventoryImport(team.id, original.operationId);
    if (!active.current) return;
    if (result.status === "error") {
      setRefreshed(false);
      setFailed(importError(t, result.error));
    } else {
      setPending(result.data.pending);
      setRefreshed(result.data.inventory?.phase === "ready" && result.data.inventory.acknowledged);
      if (result.data.error) setFailed(teamError(t, result.data.error));
    }
  };

  const submit = () => {
    if (!pending) return;
    const original = pending;
    void run(async () => {
      setLoaded(false);
      try {
        const result = await commands.submitTeamInventoryImport(team.id, original.operationId);
        if (!active.current) return;
        if (result.status === "error") setFailed(importError(t, result.error));
        else {
          setPending(result.data);
          if (result.data.phase === "confirmed") await refresh(result.data);
        }
      } finally {
        await readPending();
      }
    }, true);
  };

  const discard = () => {
    if (!pending) return;
    const original = pending;
    void run(async () => {
      const result = await commands.discardTeamInventoryImport(team.id, original.operationId);
      if (!active.current) return;
      if (result.status === "error") setFailed(importError(t, result.error));
      else {
        setPending(null);
        setRefreshed(false);
        onRetainedChange(team.id, false);
      }
    }, true);
  };

  const ready = preview?.candidates.filter((candidate) => candidate.status === "ready") ?? [];
  return (
    <div className="mt-5" aria-busy={busy || !loaded}>
      {!loaded ? (
        <>
          <p role="status" className="text-sm">
            {t("teamImport.loading")}
          </p>
          <Button disabled={busy} onClick={() => void run(readPending)}>
            {t("teamImport.reload")}
          </Button>
        </>
      ) : null}
      {!available ? <p className="text-sm text-muted-foreground">{t("teamImport.recoveryOnly")}</p> : null}
      {pending ? (
        <>
          <h3 className="text-sm font-medium">{t("teamImport.saved")}</h3>
          <p role="status" className="mt-2 max-w-lg text-sm">
            {t(`teamImport.phase.${pending.phase}`)}
          </p>
          <p className="mt-2 break-all text-sm text-muted-foreground select-text">{pending.origin}</p>
          <p className="mt-1 break-all text-sm text-muted-foreground select-text">
            {t("teamImport.account", { id: pending.accountId })}
          </p>
          <p className="mt-3 text-sm">{t("teamImport.disclosure", { team: team.name, count: pending.rows.length })}</p>
          <ul
            aria-label={t("teamImport.selectedRows")}
            className="mt-3 max-h-96 list-none divide-y divide-border overflow-y-auto p-0"
          >
            {pending.rows.map((row) => (
              <li key={row.hostId} className="py-3">
                <ImportFields fields={row.fields} />
              </li>
            ))}
          </ul>
          {refreshed ? (
            <p role="status" className="mt-3 text-sm">
              {t("teamImport.refreshed")}
            </p>
          ) : null}
          <div className="mt-4 flex flex-wrap gap-3">
            {pending.phase === "prepared" || pending.phase === "unknown" ? (
              <Button variant="primary" disabled={busy || !loaded} busy={busy} onClick={submit}>
                {t(pending.phase === "prepared" ? "teamImport.submit" : "teamImport.confirm")}
              </Button>
            ) : null}
            {pending.phase !== "prepared" ? (
              <Button disabled={busy || !loaded} onClick={() => void run(() => refresh(pending))}>
                {t("teamImport.reviewInventory")}
              </Button>
            ) : null}
            {pending.phase === "confirmed" ? (
              <Button disabled={busy} onClick={() => setAssetsOpen(true)}>
                {t("teamImport.viewInventory")}
              </Button>
            ) : null}
            {pending.phase !== "unknown" ? (
              <Button
                variant="ghost"
                disabled={busy || !loaded || (pending.phase === "expired" && !pending.canArchive)}
                onClick={discard}
              >
                {t(
                  pending.phase === "confirmed"
                    ? "teamImport.done"
                    : pending.phase === "expired"
                      ? "teamImport.archive"
                      : "teamImport.cancel",
                )}
              </Button>
            ) : null}
          </div>
        </>
      ) : loaded && available ? (
        <>
          <Select
            label={t("teamImport.source")}
            value={source}
            size="field"
            disabled={busy}
            options={[
              { value: "csv", label: t("teamImport.csv") },
              { value: "openSsh", label: t("teamImport.openSsh") },
            ]}
            onValueChange={(value) => {
              clearPreview();
              setSource(value);
              setFailed(null);
            }}
          />
          <p className="mt-2 max-w-lg text-sm text-muted-foreground">
            {t(source === "csv" ? "teamImport.csvHint" : "teamImport.openSshHint")}
          </p>
          <Button className="mt-3" disabled={busy} busy={busy} onClick={choose}>
            {t("teamImport.chooseFile")}
          </Button>
        </>
      ) : null}
      {preview ? (
        <>
          <p className="mt-4 break-all text-sm text-muted-foreground select-text">{preview.origin}</p>
          <p className="mt-1 break-all text-sm text-muted-foreground select-text">
            {t("teamImport.account", { id: preview.accountId })}
          </p>
          <p className="mt-3 text-sm">
            {t("teamImport.previewSummary", { ready: ready.length, blocked: preview.candidates.length - ready.length })}
          </p>
          <div className="mt-3 flex flex-wrap gap-3">
            <Button
              disabled={busy || !ready.length}
              onClick={() => setChosen(ready.map((candidate) => candidate.ordinal))}
            >
              {t("teamImport.selectAll")}
            </Button>
            <Button variant="ghost" disabled={busy || !chosen.length} onClick={() => setChosen([])}>
              {t("teamImport.selectNone")}
            </Button>
          </div>
          <ul
            aria-label={t("teamImport.preview")}
            className="mt-3 max-h-96 list-none divide-y divide-border overflow-y-auto p-0"
          >
            {preview.candidates.map((candidate) => (
              <li key={candidate.ordinal} className="py-3">
                {candidate.status === "ready" ? (
                  <>
                    <label className="flex items-start gap-2 text-sm font-medium">
                      <input
                        type="checkbox"
                        disabled={busy}
                        checked={chosen.includes(candidate.ordinal)}
                        onChange={(event) =>
                          setChosen((previous) =>
                            event.target.checked
                              ? [...previous, candidate.ordinal]
                              : previous.filter((id) => id !== candidate.ordinal),
                          )
                        }
                      />
                      <span className="min-w-0 whitespace-pre-wrap wrap-anywhere">
                        {t("teamImport.readyRow", { ordinal: candidate.ordinal, name: candidate.fields.name })}
                      </span>
                    </label>
                    <ImportFields fields={candidate.fields} name={false} />
                  </>
                ) : (
                  <>
                    <p className="text-sm font-medium">{t("teamImport.blockedRow", { ordinal: candidate.ordinal })}</p>
                    <p className="mt-1 text-sm text-muted-foreground">{diagnosticText(t, candidate.diagnostic)}</p>
                  </>
                )}
              </li>
            ))}
          </ul>
          <Button className="mt-4" variant="primary" disabled={busy || !chosen.length || !loaded} onClick={prepare}>
            {t("teamImport.reviewSelection", { count: chosen.length })}
          </Button>
        </>
      ) : null}
      {failed ? (
        <p role="alert" className="mt-3 max-w-lg text-sm text-attention">
          {failed}
        </p>
      ) : null}
      {assetsOpen ? <TeamAssets team={team} onClose={() => setAssetsOpen(false)} onConnect={onConnect} /> : null}
    </div>
  );
}

function ImportFields({ fields, name = true }: { fields: TeamImportFields; name?: boolean }) {
  const { t } = useI18n();
  return (
    <>
      {name ? <p className="whitespace-pre-wrap text-sm font-medium wrap-anywhere">{fields.name}</p> : null}
      <dl className="mt-2 grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("teamImport.field.address")}</dt>
        <dd className="m-0 whitespace-pre-wrap font-mono wrap-anywhere select-text">{fields.address}</dd>
        <dt className="text-muted-foreground">{t("teamImport.field.port")}</dt>
        <dd className="m-0 font-mono select-text">{fields.port}</dd>
        <dt className="text-muted-foreground">{t("teamImport.field.username")}</dt>
        <dd className="m-0 whitespace-pre-wrap font-mono wrap-anywhere select-text">{fields.username}</dd>
        {fields.loginName !== null ? (
          <>
            <dt className="text-muted-foreground">{t("teamImport.field.login_name")}</dt>
            <dd className="m-0 whitespace-pre-wrap wrap-anywhere select-text">{fields.loginName}</dd>
          </>
        ) : null}
      </dl>
    </>
  );
}

const diagnosticCodes = [
  "invalid_utf8",
  "invalid_csv",
  "invalid_header",
  "invalid_cell",
  "empty_input",
  "too_many_records",
  "too_large",
  "raw_too_large",
  "invalid_syntax",
  "unsupported_scope",
  "no_candidates",
  "too_many_candidates",
  "unsupported_option",
  "unsupported_value",
  "invalid_field",
  "missing_username",
] as const;
const fieldNames = ["name", "address", "port", "username", "login_name"] as const;

function diagnosticText(t: Translate, diagnostic: TeamImportDiagnostic): string {
  const code = diagnosticCodes.find((code) => code === diagnostic.code);
  const field = fieldNames.find((field) => field === diagnostic.field);
  return [
    t(code ? `teamImport.diagnostic.${code}` : "teamImport.error.invalidRequest"),
    diagnostic.record !== null ? t("teamImport.record", { record: diagnostic.record }) : null,
    diagnostic.line !== null ? t("teamImport.line", { line: diagnostic.line }) : null,
    field ? t(`teamImport.field.${field}`) : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

function teamError(t: Translate, error: TeamError): string {
  if (error === "permissionDenied") return t("teamImport.denied");
  if (error === "teamNotFound") return t("teamImport.unavailable");
  if (
    error === "notConfigured" ||
    error === "authenticationRequired" ||
    error === "admissionUnverified" ||
    error === "membershipScopeRequired"
  )
    return t("teamImport.accountRequired");
  if (error === "connectionBeforeRequest") return t("teamImport.notSent");
  return t("teamImport.error.connection");
}

function importError(t: Translate, error: TeamImportError): string {
  if (error.kind === "source") return diagnosticText(t, error.detail);
  if (error.kind === "team") return teamError(t, error.detail);
  return t(`teamImport.error.${error.kind}`);
}
