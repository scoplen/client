// SPDX-License-Identifier: Apache-2.0
import { Button, Field } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { TeamCreationView, TeamPageView, TeamSettingsView, TeamSummary } from "./ipc/bindings";

export function TeamSettings({
  authenticated,
  disabled,
  onBusyChange,
}: {
  authenticated: boolean;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [creation, setCreation] = useState<TeamCreationView | null>(null);
  const [page, setPage] = useState<TeamPageView | null>(null);
  const [name, setName] = useState("");
  const [failed, setFailed] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reviewedExpired, setReviewedExpired] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [edit, setEdit] = useState<TeamSettingsView | null>(null);
  const [editName, setEditName] = useState("");
  const [editFailure, setEditFailure] = useState<string | null>(null);
  const [reviewRequired, setReviewRequired] = useState(false);
  const [nameSaved, setNameSaved] = useState(false);
  const editRevision = useRef(0);
  const editField = useRef<HTMLInputElement>(null);
  const editOpener = useRef<HTMLButtonElement | null>(null);
  const returnEditFocus = useRef(false);
  const mounted = useRef(false);
  const inFlight = useRef(false);

  useEffect(() => {
    let active = true;
    mounted.current = true;
    void commands.pendingTeamCreation().then(
      (result) => {
        if (!active) return;
        if (result.status === "ok") setCreation(result.data);
        else setFailed(result.error);
        setLoading(false);
      },
      () => {
        if (active) {
          setFailed("storage");
          setLoading(false);
        }
      },
    );
    return () => {
      active = false;
      mounted.current = false;
    };
  }, [commands]);

  useEffect(() => {
    if (edit) editField.current?.focus();
  }, [edit]);
  useEffect(() => {
    if (!busy && editingId === null && returnEditFocus.current) {
      returnEditFocus.current = false;
      editOpener.current?.focus();
    }
  }, [busy, editingId]);

  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current || disabled || loading) return;
    inFlight.current = true;
    setBusy(true);
    setFailed(null);
    onBusyChange(true);
    try {
      await operation();
    } catch {
      if (mounted.current) {
        setFailed("storage");
        await readPending().catch(() => {
          if (mounted.current) setFailed("storage");
        });
      }
    } finally {
      inFlight.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusyChange(false);
      }
    }
  };

  const readPending = async () => {
    const result = await commands.pendingTeamCreation();
    if (!mounted.current) return;
    if (result.status === "ok") setCreation(result.data);
    else setFailed(result.error);
  };

  const query = (cursor: string | null) => {
    if (!authenticated) return;
    void run(async () => {
      const result = await commands.teamsPage(cursor);
      if (!mounted.current) return;
      if (result.status === "error") setFailed(result.error);
      else {
        setPage((previous) => ({
          ...result.data,
          teams: cursor ? [...(previous?.teams ?? []), ...result.data.teams] : result.data.teams,
        }));
        if (!cursor && creation?.phase === "expired") setReviewedExpired(true);
      }
    });
  };

  const submit = async (operation: TeamCreationView) => {
    const result = await commands.submitTeamCreation(operation.operationId);
    if (!mounted.current) return;
    if (result.status === "ok") setCreation(result.data);
    else {
      setFailed(result.error);
      await readPending();
    }
  };

  const create = () => {
    if (!authenticated || creation || !name) return;
    void run(async () => {
      const result = await commands.prepareTeamCreation(name);
      if (!mounted.current) return;
      if (result.status === "error") setFailed(result.error);
      else {
        setCreation(result.data);
        await submit(result.data);
      }
    });
  };

  const discard = () => {
    if (!creation || creation.phase === "unknown" || (creation.phase === "expired" && !reviewedExpired)) return;
    void run(async () => {
      const result = await commands.discardTeamCreation(creation.operationId);
      if (!mounted.current) return;
      if (result.status === "error") setFailed(result.error);
      else {
        setCreation(null);
        setName("");
        setReviewedExpired(false);
      }
    });
  };

  const closeEdit = () => {
    returnEditFocus.current = true;
    editRevision.current++;
    setEditingId(null);
    setEdit(null);
    setEditName("");
    setEditFailure(null);
    setReviewRequired(false);
  };
  const readEdit = (id: string) => {
    if (!authenticated) return;
    const revision = ++editRevision.current;
    setEditingId(id);
    setEdit(null);
    setEditFailure(null);
    setNameSaved(false);
    void run(async () => {
      const result = await commands.teamSettings(id).catch(() => ({ status: "error" as const, error: "storage" }));
      if (!mounted.current || revision !== editRevision.current) return;
      if (result.status === "error") setEditFailure(result.error);
      else {
        setEdit(result.data);
        setEditName(result.data.team.name);
        setReviewRequired(false);
      }
    });
  };
  const saveName = () => {
    if (!authenticated || !edit || reviewRequired || !editName) return;
    const revision = editRevision.current;
    const captured = edit;
    void run(async () => {
      const result = await commands
        .updateTeamName(captured.team.id, captured.etag, editName)
        .catch(() => ({ status: "error" as const, error: "settingsUnknown" }));
      if (!mounted.current || revision !== editRevision.current) return;
      if (result.status === "error") {
        setEditFailure(result.error);
        if (["settingsConflict", "settingsUnknown", "teamNotFound"].includes(result.error)) setReviewRequired(true);
      } else {
        setPage((previous) =>
          previous
            ? {
                ...previous,
                teams: previous.teams.map((team) => (team.id === captured.team.id ? result.data.team : team)),
              }
            : previous,
        );
        closeEdit();
        setNameSaved(true);
      }
    });
  };
  const editErrorKey =
    editFailure === "invalidName"
      ? "teams.error.name"
      : editFailure === "permissionDenied"
        ? "teams.settings.permission"
        : editFailure === "settingsConflict"
          ? "teams.settings.conflict"
          : editFailure === "updateScopeRequired"
            ? "teams.settings.scope"
            : editFailure === "settingsUnknown"
              ? "teams.settings.unknown"
              : editFailure === "teamNotFound"
                ? "teams.settings.notFound"
                : editFailure === "authenticationRequired" || editFailure === "authentication"
                  ? "teams.error.authentication"
                  : "teams.settings.failed";
  const errorKey =
    failed === "invalidName"
      ? "teams.error.name"
      : failed === "permissionDenied"
        ? "teams.error.permission"
        : failed === "authenticationRequired" || failed === "authentication" || failed === "notConfigured"
          ? "teams.error.authentication"
          : failed === "network" || failed === "connectionBeforeRequest" || failed === "serviceUnavailable"
            ? "teams.error.network"
            : failed === "outcomeUnknown" || failed === "operationExpired"
              ? "teams.error.pending"
              : "teams.error.generic";
  const locked = busy || disabled || loading;
  const role = (value: string) => {
    switch (value) {
      case "owner":
        return t("teams.role.owner");
      case "administrator":
        return t("teams.role.administrator");
      case "security_auditor":
        return t("teams.role.securityAuditor");
      case "approver":
        return t("teams.role.approver");
      case "member":
        return t("teams.role.member");
      default:
        return value;
    }
  };
  const summary = (team: TeamSummary) => (
    <div className="min-w-0">
      <p className="break-words text-sm font-medium [overflow-wrap:anywhere]">{team.name}</p>
      <p className="mt-1 break-words text-sm text-muted-foreground [overflow-wrap:anywhere]">
        {t("teams.roles", { roles: team.roles.map(role).join(", ") })}
      </p>
      <p className="mt-1 break-all select-text font-mono text-xs text-muted-foreground">{team.id}</p>
    </div>
  );

  return (
    <section aria-labelledby="teams-title" className="mt-6 border-t border-border pt-6" aria-busy={busy || loading}>
      <h3 id="teams-title" className="text-sm font-medium">
        {t("teams.title")}
      </h3>
      <p className="mt-2 text-sm text-muted-foreground">{t("teams.body")}</p>
      {loading || busy ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {t(loading ? "teams.loading" : "teams.working")}
        </p>
      ) : null}
      {failed ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {t(errorKey)}
        </p>
      ) : null}
      {!authenticated ? <p className="mt-3 text-sm text-muted-foreground">{t("teams.error.authentication")}</p> : null}
      {nameSaved ? (
        <p role="status" className="mt-3 text-sm">
          {t("teams.settings.saved")}
        </p>
      ) : null}
      <Button className="mt-4" variant="secondary" disabled={locked || !authenticated} onClick={() => query(null)}>
        {t("teams.refresh")}
      </Button>
      {page ? (
        page.teams.length ? (
          <ul aria-label={t("teams.list")} className="mt-4 list-none divide-y divide-border p-0">
            {page.teams.map((team) => (
              <li key={team.id} className="py-3">
                {summary(team)}
                <Button
                  className="mt-3"
                  variant="secondary"
                  disabled={locked || !authenticated}
                  onClick={(event) => {
                    editOpener.current = event.currentTarget;
                    readEdit(team.id);
                  }}
                >
                  {t("teams.settings.edit", { name: team.name })}
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <p role="status" className="mt-3 text-sm text-muted-foreground">
            {t("teams.empty")}
          </p>
        )
      ) : (
        <p className="mt-3 text-sm text-muted-foreground">{t("teams.notQueried")}</p>
      )}
      {page?.nextCursor ? (
        <Button variant="secondary" disabled={locked || !authenticated} onClick={() => query(page.nextCursor)}>
          {t("teams.more")}
        </Button>
      ) : null}
      {editingId ? (
        <form
          className="mt-6 flex max-w-sm flex-col gap-3"
          aria-label={t("teams.settings.title")}
          onSubmit={(event) => {
            event.preventDefault();
            saveName();
          }}
        >
          <h4 className="text-sm font-medium">{t("teams.settings.title")}</h4>
          <p className="break-all font-mono text-xs text-muted-foreground select-text">{editingId}</p>
          {edit ? (
            <Field
              ref={editField}
              label={t("teams.settings.name")}
              hint={t("teams.settings.hint")}
              value={editName}
              onChange={(event) => setEditName(event.target.value)}
              maxLength={128}
              required
              disabled={locked || !authenticated || reviewRequired || editFailure === "updateScopeRequired"}
              error={editFailure === "invalidName" ? t("teams.error.name") : undefined}
            />
          ) : null}
          {editFailure ? (
            <p role="alert" className="text-sm text-attention">
              {t(editErrorKey)}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              disabled={
                locked ||
                !authenticated ||
                !edit ||
                !editName ||
                reviewRequired ||
                editFailure === "updateScopeRequired"
              }
            >
              {t("teams.settings.save")}
            </Button>
            <Button variant="secondary" disabled={locked || !authenticated} onClick={() => readEdit(editingId)}>
              {t("teams.settings.refresh")}
            </Button>
            <Button variant="ghost" onClick={closeEdit}>
              {t("teams.settings.close")}
            </Button>
          </div>
        </form>
      ) : null}
      {creation ? (
        <div className="mt-6">
          <p className="break-words text-sm font-medium [overflow-wrap:anywhere]">{creation.name}</p>
          <p role="status" className="mt-2 text-sm text-muted-foreground">
            {t(`teams.phase.${creation.phase}`)}
          </p>
          {creation.organization ? <div className="mt-3">{summary(creation.organization)}</div> : null}
          <div className="mt-4 flex flex-wrap gap-2">
            {creation.phase === "prepared" || creation.phase === "unknown" ? (
              <Button disabled={locked || !authenticated} onClick={() => void run(() => submit(creation))}>
                {t(creation.phase === "unknown" ? "teams.retry" : "teams.create")}
              </Button>
            ) : null}
            {creation.phase !== "unknown" ? (
              <Button
                variant="secondary"
                disabled={locked || (creation.phase === "expired" && !reviewedExpired)}
                onClick={discard}
              >
                {t(creation.phase === "confirmed" ? "teams.done" : "teams.clear")}
              </Button>
            ) : null}
          </div>
        </div>
      ) : (
        <form
          className="mt-6 flex max-w-sm flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            create();
          }}
        >
          <Field
            label={t("teams.name")}
            name="team-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={128}
            required
            disabled={locked || !authenticated}
            error={failed === "invalidName" ? t("teams.error.name") : undefined}
          />
          <Button type="submit" disabled={locked || !authenticated || !name}>
            {t("teams.create")}
          </Button>
        </form>
      )}
    </section>
  );
}
