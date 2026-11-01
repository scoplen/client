// SPDX-License-Identifier: Apache-2.0
import { Button, Confirm, Field } from "@scoplen/ui";
import { useEffect, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  TeamInvitationPageView,
  TeamInvitationView,
  TeamMemberPageView,
  TeamMemberView,
  TeamOperationView,
  TeamPageView,
  TeamSettingsView,
} from "./ipc/bindings";

const roleNames = ["owner", "administrator", "security_auditor", "approver", "member"] as const;
const roleKeys = {
  owner: "owner",
  administrator: "administrator",
  security_auditor: "securityAuditor",
  approver: "approver",
  member: "member",
} as const;

function RoleSelection({
  value,
  onChange,
  disabled,
  owner,
}: {
  value: string[];
  onChange: (roles: string[]) => void;
  disabled: boolean;
  owner: boolean;
}) {
  const { t } = useI18n();
  return (
    <fieldset disabled={disabled} className="flex flex-wrap gap-x-4 gap-y-2">
      <legend className="mb-2 text-sm font-medium">{t("teams.membership.roles")}</legend>
      {roleNames
        .filter((role) => owner || role !== "owner")
        .map((role) => (
          <label key={role} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={value.includes(role)}
              onChange={(event) =>
                onChange(event.target.checked ? [...value, role] : value.filter((item) => item !== role))
              }
            />
            {t(`teams.role.${roleKeys[role]}`)}
          </label>
        ))}
    </fieldset>
  );
}

/// The secret is placed only in this explicit uncontrolled field, never React state.
function InvitationPassword({
  operation,
  disabled,
  run,
}: {
  operation: TeamOperationView;
  disabled: boolean;
  run: (work: () => Promise<void>) => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const field = useRef<HTMLInputElement>(null);
  const visible = useRef(false);
  const revision = useRef(0);
  const [shown, setShown] = useState(false);
  const clear = () => {
    revision.current++;
    visible.current = false;
    if (field.current) field.current.value = "";
    setShown(false);
  };
  useEffect(() => {
    const input = field.current;
    return () => {
      revision.current = -1;
      visible.current = false;
      if (input) input.value = "";
    };
  }, []);
  return (
    <div className="mt-3 flex flex-col gap-3">
      <Field
        label={t("teams.membership.password")}
        ref={field}
        type={shown ? "text" : "password"}
        readOnly
        autoComplete="off"
        spellCheck={false}
        defaultValue=""
      />
      <div className="flex flex-wrap gap-2">
        <Button
          variant="secondary"
          disabled={disabled}
          onClick={() => {
            if (visible.current) {
              clear();
              return;
            }
            const captured = ++revision.current;
            run(async () => {
              const result = await commands.revealTeamInvitationPassword(operation.operationId);
              if (captured !== revision.current || !field.current) return;
              if (result.status === "error") throw new Error(result.error);
              field.current.value = result.data;
              visible.current = true;
              setShown(true);
              field.current.focus();
            });
          }}
        >
          {t(shown ? "teams.membership.hidePassword" : "teams.membership.revealPassword")}
        </Button>
        <Button
          variant="secondary"
          disabled={disabled}
          onClick={() => {
            clear();
            run(async () => {
              const result = await commands.copyTeamInvitationPassword(operation.operationId);
              if (result.status === "error") throw new Error(result.error);
            });
          }}
        >
          {t("teams.membership.copyPassword")}
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">{t("teams.membership.passwordHint")}</p>
    </div>
  );
}

export function TeamMembership({
  initialTeamId,
  disabled,
  onBusyChange,
  onClose,
  onMembershipChanged,
}: {
  initialTeamId: string | null;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  onClose: () => void;
  onMembershipChanged: (page?: TeamPageView) => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [pending, setPending] = useState<TeamOperationView[]>([]);
  const [team, setTeam] = useState<TeamSettingsView | null>(null);
  const [invitations, setInvitations] = useState<TeamInvitationPageView | null>(null);
  const [members, setMembers] = useState<TeamMemberPageView | null>(null);
  const [link, setLink] = useState("");
  const [preview, setPreview] = useState<TeamInvitationView | null>(null);
  const [username, setUsername] = useState("");
  const [roles, setRoles] = useState<string[]>(["member"]);
  const [editing, setEditing] = useState<TeamMemberView | null>(null);
  const [editRoles, setEditRoles] = useState<string[]>([]);
  const [editStatus, setEditStatus] = useState("active");
  const [reviewed, setReviewed] = useState<string[]>([]);
  const [teamReviewRequired, setTeamReviewRequired] = useState(false);
  const [invitationReviewRequired, setInvitationReviewRequired] = useState(false);
  const [memberReviewRequired, setMemberReviewRequired] = useState(false);
  const [confirmation, setConfirmation] = useState<
    | { kind: "revoke"; item: TeamInvitationView }
    | { kind: "remove"; item: TeamMemberView }
    | { kind: "leave"; item: TeamSettingsView }
    | { kind: "dissolve"; item: TeamSettingsView }
    | null
  >(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [notice, setNotice] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [secretRevision, setSecretRevision] = useState(0);
  const mounted = useRef(false);
  const inFlight = useRef(false);
  const password = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const panel = useRef<HTMLElement>(null);
  const clearPassword = () => {
    if (password.current) password.current.value = "";
    setSecretRevision((value) => value + 1);
  };
  useEffect(() => {
    const surface = panel.current;
    mounted.current = true;
    heading.current?.focus();
    void commands
      .pendingTeamOperations()
      .then((result) => {
        if (!mounted.current) return;
        if (result.status === "ok") setPending(result.data);
        else setFailed(result.error);
        setLoading(false);
      })
      .catch(() => {
        if (mounted.current) {
          setFailed("storage");
          setLoading(false);
        }
      });
    return () => {
      mounted.current = false;
      surface?.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach((input) => {
        input.value = "";
      });
    };
  }, [commands]);
  const refreshPending = async () => {
    const result = await commands.pendingTeamOperations();
    if (!mounted.current) return;
    if (result.status === "ok") setPending(result.data);
    else setFailed(result.error);
  };
  const run = (work: () => Promise<void>) => {
    if (inFlight.current || disabled || loading) return;
    inFlight.current = true;
    setBusy(true);
    setFailed(null);
    setNotice(false);
    onBusyChange(true);
    void work()
      .catch((error: unknown) => {
        if (mounted.current) setFailed(error instanceof Error ? error.message : "storage");
      })
      .finally(() => {
        inFlight.current = false;
        if (mounted.current) {
          setBusy(false);
          onBusyChange(false);
        }
      });
  };
  const locked = disabled || loading || busy;
  const owner = team?.team.roles.includes("owner") ?? false;
  const administrative = owner || (team?.team.roles.includes("administrator") ?? false);
  const roleText = (values: string[]) =>
    values
      .map((value) =>
        roleNames.includes(value as (typeof roleNames)[number])
          ? t(`teams.role.${roleKeys[value as (typeof roleNames)[number]]}`)
          : value,
      )
      .join(", ");
  const handle = <T,>(result: { status: "ok"; data: T } | { status: "error"; error: string }): T | null => {
    if (!mounted.current) return null;
    if (result.status === "error") {
      setFailed(result.error);
      return null;
    }
    return result.data;
  };
  const readTeam = () => {
    if (!initialTeamId) return;
    run(async () => {
      const current = handle(await commands.teamSettings(initialTeamId));
      if (current) {
        setTeam(current);
        setTeamReviewRequired(false);
        setEditing(null);
      }
    });
  };
  const listInvitations = async (cursor: string | null = null, organization = team?.team.id) => {
    if (!organization) return false;
    const result = await commands.teamInvitations(organization, cursor);
    if (!mounted.current) return false;
    if (result.status === "error") {
      setFailed(result.error);
      return ["teamNotFound", "permissionDenied"].includes(result.error);
    }
    setInvitations((previous) => ({
      ...result.data,
      items: cursor ? [...(previous?.items ?? []), ...result.data.items] : result.data.items,
    }));
    if (!cursor) setInvitationReviewRequired(false);
    return true;
  };
  const listMembers = async (cursor: string | null = null) => {
    if (!team) return;
    const current = handle(await commands.teamMembers(team.team.id, cursor));
    if (current) {
      setMembers((previous) => ({
        ...current,
        items: cursor ? [...(previous?.items ?? []), ...current.items] : current.items,
      }));
      setEditing(null);
      if (!cursor) setMemberReviewRequired(false);
    }
  };
  const submit = async (operation: TeamOperationView) => {
    clearPassword();
    const result = await commands.submitTeamOperation(operation.kind, operation.operationId);
    const current = handle(result);
    if (current?.phase === "confirmed") {
      setNotice(true);
      if (current.kind === "acceptance") {
        const page = handle(await commands.teamsPage(null));
        if (mounted.current) onMembershipChanged(page ?? undefined);
      } else if (current.kind === "dissolution") {
        setTeam(null);
        setMembers(null);
        setInvitations(null);
        onMembershipChanged();
      }
    }
    await refreshPending();
  };
  const invite = () => {
    if (!team) return;
    run(async () => {
      const operation = handle(await commands.prepareTeamInvitation(team.team.id, username, roles));
      if (operation) await submit(operation);
    });
  };
  const accept = () => {
    if (!preview || !password.current) return;
    const input = password.current;
    run(async () => {
      const request = (() => {
        try {
          return commands.prepareTeamAcceptance(link, preview.etag, input.value);
        } finally {
          input.value = "";
        }
      })();
      const operation = handle(await request);
      if (operation) await submit(operation);
    });
  };
  const review = async (operation: TeamOperationView) => {
    clearPassword();
    if (operation.kind === "invitation") {
      if (!(await listInvitations(null, operation.organizationId))) return;
    } else {
      const current = handle(await commands.teamsPage(null));
      if (!current) return;
      onMembershipChanged();
    }
    if (mounted.current) setReviewed((previous) => [...previous, operation.operationId]);
  };
  const mutate = async () => {
    if (!confirmation) return;
    clearPassword();
    const captured = confirmation;
    if (captured.kind === "dissolve") {
      const operation = handle(await commands.prepareTeamDissolution(captured.item.team.id, captured.item.etag));
      setConfirmation(null);
      if (operation) await submit(operation);
      return;
    }
    const result =
      captured.kind === "revoke"
        ? await commands.revokeTeamInvitation(captured.item.organizationId, captured.item.id, captured.item.etag)
        : captured.kind === "remove"
          ? await commands.removeTeamMember(captured.item.organizationId, captured.item.id, captured.item.etag)
          : await commands.removeTeamMember(captured.item.team.id, captured.item.membershipId, captured.item.etag);
    if (!mounted.current) return;
    setConfirmation(null);
    if (result.status === "error") {
      setFailed(result.error);
      if (captured.kind === "revoke") setInvitationReviewRequired(true);
      else if (captured.kind === "leave") setTeamReviewRequired(true);
      else setMemberReviewRequired(true);
      setEditing(null);
    } else {
      setNotice(true);
      setInvitations(null);
      setMembers(null);
      if (captured.kind === "leave" || (captured.kind === "remove" && captured.item.isSelf)) {
        setTeam(null);
        onMembershipChanged();
      }
    }
  };
  const errorKey =
    failed === "clipboardUnavailable"
      ? "teams.membership.clipboard"
      : failed === "invitationOriginMismatch"
        ? "teams.membership.origin"
        : failed === "teamNotFound"
          ? "teams.membership.notFound"
          : failed === "invitationDenied"
            ? "teams.membership.denied"
            : failed === "invalidInvitation"
              ? "teams.membership.invalid"
              : failed === "permissionDenied"
                ? "teams.membership.permission"
                : failed === "membershipScopeRequired"
                  ? "teams.membership.scope"
                  : failed === "membershipConflict" || failed === "conflict"
                    ? "teams.membership.conflict"
                    : failed === "membershipUnknown" || failed === "outcomeUnknown"
                      ? "teams.membership.unknown"
                      : "teams.membership.failed";
  return (
    <section
      ref={panel}
      className="mt-6 border-t border-border pt-6"
      aria-labelledby="team-membership-title"
      aria-busy={busy || loading}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 id="team-membership-title" ref={heading} tabIndex={-1} className="text-base font-medium">
          {t(initialTeamId ? "teams.membership.manage" : "teams.membership.join")}
        </h4>
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => {
            clearPassword();
            onClose();
          }}
        >
          {t("teams.membership.close")}
        </Button>
      </div>
      {loading || busy ? (
        <p role="status" className="mt-3 text-sm text-muted-foreground">
          {t("teams.working")}
        </p>
      ) : null}
      {failed ? (
        <p role="alert" className="mt-3 text-sm text-attention">
          {t(errorKey)}
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="mt-3 text-sm">
          {t("teams.membership.confirmed")}
        </p>
      ) : null}
      {initialTeamId ? (
        <div className="mt-4">
          <Button variant="secondary" disabled={locked} onClick={readTeam}>
            {t("teams.membership.reviewTeam")}
          </Button>
          {team ? (
            <>
              <h5 className="mt-4 break-words text-base font-medium">{team.team.name}</h5>
              <p className="mt-1 text-sm text-muted-foreground">
                {t("teams.roles", { roles: roleText(team.team.roles) })}
              </p>
              {administrative ? (
                <>
                  <form
                    className="mt-5 flex max-w-md flex-col gap-3"
                    aria-label={t("teams.membership.invite")}
                    onSubmit={(event) => {
                      event.preventDefault();
                      invite();
                    }}
                  >
                    <Field
                      label={t("teams.membership.username")}
                      value={username}
                      maxLength={64}
                      required
                      autoComplete="off"
                      disabled={locked || pending.some((item) => item.kind === "invitation")}
                      onChange={(event) => setUsername(event.target.value)}
                    />
                    <RoleSelection value={roles} onChange={setRoles} disabled={locked} owner={owner} />
                    <Button
                      type="submit"
                      disabled={
                        locked || !username || !roles.length || pending.some((item) => item.kind === "invitation")
                      }
                    >
                      {t("teams.membership.invite")}
                    </Button>
                  </form>
                  <div className="mt-5 flex flex-wrap gap-2">
                    <Button
                      variant="secondary"
                      disabled={locked}
                      onClick={() =>
                        run(async () => {
                          await listInvitations();
                        })
                      }
                    >
                      {t("teams.membership.refreshInvitations")}
                    </Button>
                    <Button variant="secondary" disabled={locked} onClick={() => run(() => listMembers())}>
                      {t("teams.membership.refreshMembers")}
                    </Button>
                  </div>
                </>
              ) : null}
              <div className="mt-5 flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  disabled={locked || teamReviewRequired}
                  onClick={() => setConfirmation({ kind: "leave", item: team })}
                >
                  {t("teams.membership.leave")}
                </Button>
                {owner ? (
                  <Button
                    variant="secondary"
                    disabled={locked || teamReviewRequired || pending.some((item) => item.kind === "dissolution")}
                    onClick={() => setConfirmation({ kind: "dissolve", item: team })}
                  >
                    {t("teams.membership.dissolve")}
                  </Button>
                ) : null}
              </div>
            </>
          ) : null}
        </div>
      ) : (
        <form
          className="mt-4 flex max-w-md flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            accept();
          }}
        >
          <Field
            label={t("teams.membership.link")}
            value={link}
            maxLength={2200}
            disabled={locked}
            onChange={(event) => {
              clearPassword();
              setLink(event.target.value);
              setPreview(null);
            }}
          />
          <Button
            variant="secondary"
            disabled={locked || !link}
            onClick={() => {
              clearPassword();
              setPreview(null);
              run(async () => {
                const current = handle(await commands.previewTeamInvitation(link));
                if (current) setPreview(current);
              });
            }}
          >
            {t("teams.membership.preview")}
          </Button>
          {preview ? (
            <>
              <div className="border-l-2 border-primary pl-3 text-sm">
                <p className="break-words font-medium">{preview.organizationName}</p>
                <p className="mt-1 break-words">
                  {t("teams.membership.recipient", { username: preview.recipientUsername })}
                </p>
                <p className="mt-1">
                  {roleText(preview.roles)} · {t(`teams.membership.status.${preview.status as "pending"}`)}
                </p>
                <p className="mt-1 text-muted-foreground">{preview.expiresAt}</p>
              </div>
              <Field
                ref={password}
                label={t("teams.membership.password")}
                type="password"
                autoComplete="off"
                spellCheck={false}
                minLength={8}
                maxLength={8}
                required
                disabled={locked || preview.status !== "pending" || pending.some((item) => item.kind === "acceptance")}
              />
              <Button
                type="submit"
                disabled={locked || preview.status !== "pending" || pending.some((item) => item.kind === "acceptance")}
              >
                {t("teams.membership.accept")}
              </Button>
            </>
          ) : null}
        </form>
      )}
      {pending.map((operation) => (
        <div key={operation.operationId} className="mt-5 border-t border-border pt-4">
          <h5 className="text-sm font-medium">{t(`teams.membership.kind.${operation.kind}`)}</h5>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground select-text">
            {operation.organizationId}
          </p>
          {operation.recipientUsername ? (
            <p className="mt-1 break-words text-sm">
              {t("teams.membership.recipient", { username: operation.recipientUsername })} · {roleText(operation.roles)}
            </p>
          ) : null}
          <p role="status" className="mt-2 text-sm text-muted-foreground">
            {t(`teams.membership.phase.${operation.phase}`)}
          </p>
          {operation.kind === "invitation" && operation.phase === "confirmed" ? (
            <>
              <Field className="mt-3" label={t("teams.membership.link")} value={operation.link ?? ""} readOnly />
              <Button
                className="mt-2"
                variant="secondary"
                disabled={locked}
                onClick={() =>
                  run(async () => {
                    const result = await commands.copyTeamInvitationLink(operation.operationId);
                    if (result.status === "error") setFailed(result.error);
                  })
                }
              >
                {t("teams.membership.copyLink")}
              </Button>
              <InvitationPassword
                key={`${operation.operationId}:${secretRevision}`}
                operation={operation}
                disabled={locked}
                run={run}
              />
            </>
          ) : null}
          <div className="mt-3 flex flex-wrap gap-2">
            {operation.phase === "prepared" || operation.phase === "unknown" ? (
              <Button disabled={locked} onClick={() => run(() => submit(operation))}>
                {t(operation.phase === "unknown" ? "teams.membership.retry" : "teams.membership.submit")}
              </Button>
            ) : null}
            {operation.phase === "expired" ? (
              <Button variant="secondary" disabled={locked} onClick={() => run(() => review(operation))}>
                {t("teams.membership.reviewStatus")}
              </Button>
            ) : null}
            {operation.phase !== "unknown" ? (
              <Button
                variant="secondary"
                disabled={locked || (operation.phase === "expired" && !reviewed.includes(operation.operationId))}
                onClick={() => {
                  clearPassword();
                  run(async () => {
                    const result = await commands.discardTeamOperation(operation.kind, operation.operationId);
                    if (result.status === "error") setFailed(result.error);
                    else await refreshPending();
                  });
                }}
              >
                {t(
                  operation.phase === "expired"
                    ? "teams.membership.archive"
                    : operation.phase === "confirmed"
                      ? "teams.membership.dismiss"
                      : "teams.clear",
                )}
              </Button>
            ) : null}
          </div>
        </div>
      ))}
      {invitations ? (
        <div className="mt-5">
          <h5 className="text-sm font-medium">{t("teams.membership.invitations")}</h5>
          {!invitations.items.length ? (
            <p className="mt-2 text-sm text-muted-foreground">{t("teams.membership.emptyInvitations")}</p>
          ) : null}
          <ul className="mt-2 list-none divide-y divide-border p-0">
            {invitations.items.map((item) => (
              <li key={item.id} className="py-3">
                <p className="break-words text-sm font-medium">{item.recipientUsername}</p>
                <p className="mt-1 break-words text-sm text-muted-foreground">{item.organizationName}</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  {roleText(item.roles)} · {t(`teams.membership.status.${item.status as "pending"}`)}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">{item.expiresAt}</p>
                {item.status === "pending" || item.status === "locked" ? (
                  <Button
                    className="mt-2"
                    variant="secondary"
                    disabled={locked || invitationReviewRequired}
                    onClick={() => setConfirmation({ kind: "revoke", item })}
                  >
                    {t("teams.membership.revoke")}
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
          {invitations.nextCursor ? (
            <Button
              variant="secondary"
              disabled={locked}
              onClick={() =>
                run(async () => {
                  await listInvitations(invitations.nextCursor);
                })
              }
            >
              {t("teams.membership.moreInvitations")}
            </Button>
          ) : null}
        </div>
      ) : null}
      {members ? (
        <div className="mt-5">
          <h5 className="text-sm font-medium">{t("teams.membership.members")}</h5>
          {!members.items.length ? (
            <p className="mt-2 text-sm text-muted-foreground">{t("teams.membership.emptyMembers")}</p>
          ) : null}
          <ul className="mt-2 list-none divide-y divide-border p-0">
            {members.items.map((item) => (
              <li key={item.id} className="py-3">
                <p className="break-words text-sm font-medium">
                  {item.username}
                  {item.isSelf ? ` (${t("teams.membership.you")})` : ""}
                </p>
                <p className="mt-1 text-sm text-muted-foreground">
                  {roleText(item.roles)} · {t(`teams.membership.status.${item.status as "active"}`)}
                </p>
                {item.status !== "removed" && (owner || !item.roles.includes("owner")) ? (
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button
                      variant="secondary"
                      disabled={locked || memberReviewRequired}
                      onClick={() => {
                        setEditing(item);
                        setEditRoles(item.roles);
                        setEditStatus(item.status);
                      }}
                    >
                      {t("teams.membership.editMember")}
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={locked || memberReviewRequired}
                      onClick={() => setConfirmation({ kind: "remove", item })}
                    >
                      {t("teams.membership.remove")}
                    </Button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
          {members.nextCursor ? (
            <Button variant="secondary" disabled={locked} onClick={() => run(() => listMembers(members.nextCursor))}>
              {t("teams.membership.moreMembers")}
            </Button>
          ) : null}
        </div>
      ) : null}
      {editing ? (
        <form
          className="mt-5 flex max-w-md flex-col gap-3"
          aria-label={t("teams.membership.editMember")}
          onSubmit={(event) => {
            event.preventDefault();
            clearPassword();
            const captured = editing;
            run(async () => {
              const result = await commands.updateTeamMember(
                captured.organizationId,
                captured.id,
                captured.etag,
                editRoles,
                editStatus,
              );
              if (!mounted.current) return;
              setEditing(null);
              if (result.status === "error") {
                setFailed(result.error);
                setMemberReviewRequired(true);
              } else {
                if (result.data.isSelf) {
                  setTeam(null);
                  setMembers(null);
                  setInvitations(null);
                } else
                  setMembers((previous) =>
                    previous
                      ? {
                          ...previous,
                          items: previous.items.map((item) => (item.id === captured.id ? result.data : item)),
                        }
                      : previous,
                  );
                setNotice(true);
                onMembershipChanged();
              }
            });
          }}
        >
          <h5 className="break-words text-sm font-medium">{editing.username}</h5>
          <RoleSelection
            value={editRoles}
            onChange={setEditRoles}
            disabled={locked || memberReviewRequired}
            owner={owner}
          />
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              disabled={locked || memberReviewRequired}
              checked={editStatus === "suspended"}
              onChange={(event) => setEditStatus(event.target.checked ? "suspended" : "active")}
            />
            {t("teams.membership.suspend")}
          </label>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={locked || memberReviewRequired || !editRoles.length}>
              {t("teams.membership.saveMember")}
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => setEditing(null)}>
              {t("teams.membership.cancel")}
            </Button>
          </div>
        </form>
      ) : null}
      {confirmation ? (
        <Confirm
          open
          onOpenChange={(open) => {
            if (!open && !busy) setConfirmation(null);
          }}
          title={t(`teams.membership.${confirmation.kind}`)}
          body={
            confirmation.kind === "dissolve"
              ? t("teams.membership.dissolveBody", { name: confirmation.item.team.name })
              : confirmation.kind === "leave"
                ? t("teams.membership.leaveBody", { name: confirmation.item.team.name })
                : confirmation.kind === "remove"
                  ? t("teams.membership.removeBody", { username: confirmation.item.username })
                  : t("teams.membership.revokeBody", { username: confirmation.item.recipientUsername })
          }
          confirmLabel={t(`teams.membership.${confirmation.kind}`)}
          cancelLabel={t("teams.membership.cancel")}
          destructive
          busy={busy}
          onConfirm={() => run(mutate)}
        />
      ) : null}
    </section>
  );
}
