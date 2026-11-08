// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog } from "@scoplen/ui";
import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  TeamAuthoringCollection,
  TeamAuthoringCreateView,
  TeamAuthoringData,
  TeamAuthoringPageView,
  TeamAuthoringResourceView,
  TeamMemberPageView,
  TeamSummary,
} from "./ipc/bindings";
import {
  assetCollections,
  collectionLabel,
  emptyTeamData,
  resourceName,
  TeamAuthoringFields,
  TeamSelect,
} from "./team-authoring-fields";
import { TeamRuleForm } from "./team-rule-form";

type Editor = {
  data: TeamAuthoringData;
  resource: TeamAuthoringResourceView | null;
  deleting: boolean;
  review: boolean;
};

export function TeamAuthoring({
  team,
  section = "assets",
  onClose,
}: {
  team: TeamSummary;
  section?: "assets" | "access";
  onClose: () => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const formId = useId();
  const [collection, setCollection] = useState<TeamAuthoringCollection>(section === "assets" ? "host" : "policy");
  const [pages, setPages] = useState<Partial<Record<TeamAuthoringCollection, TeamAuthoringPageView>>>({});
  const pagesRef = useRef(pages);
  const [loading, setLoading] = useState<Partial<Record<TeamAuthoringCollection, boolean>>>({});
  const loadingRef = useRef(new Set<TeamAuthoringCollection>());
  const [members, setMembers] = useState<TeamMemberPageView | null>(null);
  const membersRef = useRef(members);
  const [editor, setEditor] = useState<Editor | null>(null);
  const [rule, setRule] = useState(false);
  const [pending, setPending] = useState<TeamAuthoringCreateView | null>(null);
  const [pendingLoaded, setPendingLoaded] = useState(false);
  const [reviewedExpired, setReviewedExpired] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [invalidFields, setInvalidFields] = useState<Set<string>>(new Set());
  const active = useRef(true);
  const inFlight = useRef(false);
  const memberLoading = useRef(false);
  const content = useRef<HTMLElement>(null);
  const editorOpener = useRef<string | null>(null);
  const restoreFocus = useRef(false);
  const editorKey = editor ? `${editor.data.kind}:${editor.resource?.etag ?? "new"}` : rule ? "rule" : null;

  useEffect(() => {
    if (editorKey) content.current?.querySelector<HTMLElement>("input,select,textarea")?.focus();
    else if (restoreFocus.current) {
      restoreFocus.current = false;
      content.current?.querySelector<HTMLElement>(`[data-team-authoring-opener="${editorOpener.current}"]`)?.focus();
    }
  }, [editorKey]);

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);

  const load = useCallback(
    async (kind: TeamAuthoringCollection, more = false) => {
      if (loadingRef.current.has(kind)) return false;
      loadingRef.current.add(kind);
      setLoading((old) => ({ ...old, [kind]: true }));
      const cursor = more ? (pagesRef.current[kind]?.nextCursor ?? null) : null;
      try {
        const result = await commands.teamAuthoringPage(team.id, kind, cursor);
        if (!active.current) return false;
        if (result.status === "error") {
          setFailed(result.error);
          const next = Object.fromEntries(Object.entries(pagesRef.current).filter(([key]) => key !== kind));
          pagesRef.current = next;
          setPages(next);
          return false;
        }
        const page = {
          ...result.data,
          items: cursor ? [...(pagesRef.current[kind]?.items ?? []), ...result.data.items] : result.data.items,
        };
        pagesRef.current = { ...pagesRef.current, [kind]: page };
        setPages(pagesRef.current);
        return true;
      } catch {
        if (active.current) setFailed("network");
        return false;
      } finally {
        loadingRef.current.delete(kind);
        if (active.current) setLoading((old) => ({ ...old, [kind]: false }));
      }
    },
    [commands, team.id],
  );

  const readPending = useCallback(async () => {
    const result = await commands.pendingTeamAuthoring(team.id);
    if (!active.current) return;
    if (result.status === "ok") {
      setPending(result.data);
      setPendingLoaded(true);
      return true;
    } else {
      setFailed(result.error);
      setPendingLoaded(false);
      return false;
    }
  }, [commands, team.id]);

  const loadMembers = useCallback(
    async (more = false) => {
      if (memberLoading.current) return;
      memberLoading.current = true;
      try {
        const cursor = more ? (membersRef.current?.nextCursor ?? null) : null;
        const result = await commands.teamMembers(team.id, cursor);
        if (!active.current) return;
        if (result.status === "error") setFailed(result.error);
        else {
          membersRef.current = {
            ...result.data,
            items: cursor ? [...(membersRef.current?.items ?? []), ...result.data.items] : result.data.items,
          };
          setMembers(membersRef.current);
        }
      } catch {
        if (active.current) setFailed("network");
      } finally {
        memberLoading.current = false;
      }
    },
    [commands, team.id],
  );

  useEffect(() => {
    void commands.pendingTeamAuthoring(team.id).then(
      (result) => {
        if (!active.current) return;
        if (result.status === "ok") {
          setPending(result.data);
          setPendingLoaded(true);
        } else {
          setFailed(result.error);
          setPendingLoaded(false);
        }
      },
      () => {
        if (active.current) {
          setFailed("storage");
          setPendingLoaded(false);
        }
      },
    );
  }, [commands, team.id]);
  useEffect(() => {
    void load(collection);
  }, [collection, load]);

  const run = async (action: () => Promise<void>, mutation: "edit" | "create" | null = null) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setFailed(null);
    setNotice(null);
    try {
      await action();
    } catch {
      if (active.current) {
        setFailed(mutation ? "authoringUnknown" : "network");
        if (mutation === "edit") setEditor((old) => (old ? { ...old, review: true } : old));
        if (mutation === "create")
          await readPending().catch(() => {
            if (active.current) setPendingLoaded(false);
          });
      }
    } finally {
      inFlight.current = false;
      if (active.current) setBusy(false);
    }
  };

  const prepareReferences = (kind: TeamAuthoringCollection) => {
    const needed: Partial<Record<TeamAuthoringCollection, TeamAuthoringCollection[]>> = {
      host: ["login", "hostGroup"],
      login: ["host", "route"],
      route: ["login", "gatewayNetwork"],
      hostGroup: ["hostGroup"],
      trustRecord: ["host"],
    };
    for (const reference of needed[kind] ?? []) if (!pagesRef.current[reference]) void load(reference);
    if (kind === "group" && !membersRef.current) void loadMembers();
  };

  const create = (kind: TeamAuthoringCollection) => {
    if (pending || !pendingLoaded || busy) return;
    setInvalidFields(new Set());
    setFailed(null);
    setRule(false);
    setEditor({ data: emptyTeamData(kind), resource: null, deleting: false, review: false });
    prepareReferences(kind);
  };

  const edit = (resource: TeamAuthoringResourceView, deleting = false) => {
    void run(async () => {
      const result = await commands.teamAuthoringResource(team.id, resource.data.kind, resource.id);
      if (!active.current) return;
      if (result.status === "error") {
        setFailed(result.error);
        return;
      }
      setInvalidFields(new Set());
      setEditor({ data: result.data.data, resource: result.data, deleting, review: false });
      prepareReferences(result.data.data.kind);
    });
  };

  const submitPending = async (operation: TeamAuthoringCreateView) => {
    const result = await commands.submitTeamAuthoring(team.id, operation.operationId);
    if (!active.current) return;
    if (result.status === "error") {
      setFailed(result.error);
      await readPending();
    } else {
      setPending(result.data);
      if (result.data.phase === "confirmed") {
        setNotice(t("teams.authoring.saved"));
        await load(result.data.data.kind);
      }
    }
  };

  const prepareCreate = async (data: TeamAuthoringData) => {
    if (pending || !pendingLoaded) return;
    const result = await commands.prepareTeamAuthoring(team.id, data);
    if (!active.current) return;
    if (result.status === "error") {
      setFailed(result.error);
      await readPending();
    } else {
      setPending(result.data);
      setEditor(null);
      setRule(false);
      await submitPending(result.data);
    }
  };

  const save = (event: FormEvent) => {
    event.preventDefault();
    if (!editor || editor.review || editor.resource?.readOnly || invalidFields.size || busy) return;
    const captured = editor;
    void run(
      async () => {
        if (captured.resource) {
          const result = captured.deleting
            ? await commands.deleteTeamAuthoring(
                team.id,
                captured.resource.data.kind,
                captured.resource.id,
                captured.resource.etag,
              )
            : await commands.updateTeamAuthoring(team.id, captured.resource.id, captured.resource.etag, captured.data);
          if (!active.current) return;
          if (result.status === "error") {
            setFailed(result.error);
            if (["authoringConflict", "authoringUnknown", "teamNotFound", "invalidTeamResponse"].includes(result.error))
              setEditor((old) => (old ? { ...old, review: true } : old));
          } else {
            setEditor(null);
            setNotice(t(captured.deleting ? "teams.authoring.deleted" : "teams.authoring.saved"));
            await load(captured.data.kind);
          }
        } else {
          await prepareCreate(captured.data);
        }
      },
      captured.resource ? "edit" : "create",
    );
  };

  const closeEditor = () => {
    restoreFocus.current = true;
    setEditor(null);
    setRule(false);
    setFailed(null);
    setInvalidFields(new Set());
  };
  const refresh = () =>
    void run(async () => {
      const pendingRead = await readPending();
      if (await load(collection)) {
        if (pendingRead) setFailed(null);
        if (pending?.phase === "expired" && pending.data.kind === collection) setReviewedExpired(true);
      }
    });
  const discard = () => {
    if (!pending || pending.phase === "unknown" || (pending.phase === "expired" && !reviewedExpired)) return;
    const captured = pending;
    void run(async () => {
      const result = await commands.discardTeamAuthoring(team.id, captured.operationId);
      if (!active.current) return;
      if (result.status === "error") setFailed(result.error);
      else {
        setPending(null);
        setReviewedExpired(false);
      }
    });
  };
  const references = Object.fromEntries(
    Object.entries(pages).map(([kind, page]) => [kind, { items: page.items, more: page.nextCursor !== null }]),
  );
  const page = pages[collection];
  const kindLabel = collectionLabel(t, editor?.data.kind ?? collection);
  const errorKey =
    failed === "invalidAuthoringData"
      ? "teams.authoring.invalid"
      : failed === "authoringConflict"
        ? "teams.authoring.conflict"
        : failed === "authoringUnknown"
          ? "teams.authoring.unknown"
          : failed === "authoringPending"
            ? "teams.authoring.pending"
            : failed === "permissionDenied"
              ? "teams.error.accessDenied"
              : failed === "authenticationRequired" || failed === "membershipScopeRequired"
                ? "teams.error.authentication"
                : failed === "teamNotFound"
                  ? "teams.assets.unavailable"
                  : "teams.authoring.failed";
  const title = editor
    ? t(
        editor.deleting ? "teams.authoring.delete" : editor.resource ? "teams.authoring.edit" : "teams.authoring.add",
        editor.resource ? { name: resourceName(editor.resource) } : { kind: kindLabel },
      )
    : t(section === "assets" ? "teams.authoring.title" : "teams.authoring.accessTitle", { name: team.name });

  return (
    <Dialog
      open
      title={title}
      description={t(section === "assets" ? "teams.authoring.body" : "teams.authoring.accessBody")}
      closeLabel={t("teams.authoring.close")}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      footer={
        editor ? (
          <>
            <Button variant="ghost" disabled={busy} onClick={closeEditor}>
              {t("teams.authoring.cancel")}
            </Button>
            {editor.review ? (
              <Button variant="secondary" disabled={busy} onClick={() => edit(editor.resource!, editor.deleting)}>
                {t("teams.authoring.refresh")}
              </Button>
            ) : null}
            <Button
              variant="primary"
              type="submit"
              form={formId}
              disabled={busy || editor.review || editor.resource?.readOnly || invalidFields.size > 0}
              className={editor.deleting ? "bg-attention! text-white!" : undefined}
            >
              {t(
                editor.deleting
                  ? "teams.authoring.delete"
                  : editor.resource
                    ? "teams.authoring.save"
                    : "teams.authoring.create",
                { name: editor.resource ? resourceName(editor.resource) : "" },
              )}
            </Button>
          </>
        ) : (
          <>
            {rule ? (
              <Button variant="ghost" disabled={busy} onClick={closeEditor}>
                {t("teams.authoring.cancel")}
              </Button>
            ) : (
              <Button variant="ghost" onClick={onClose}>
                {t("teams.authoring.close")}
              </Button>
            )}
            <Button variant="secondary" disabled={busy || loading[collection]} onClick={refresh}>
              {t("teams.authoring.refresh")}
            </Button>
          </>
        )
      }
    >
      <section ref={content} aria-busy={busy || loading[collection]} className="min-w-0 space-y-4">
        {page ? <p className="break-all text-xs text-muted-foreground select-text">{page.origin}</p> : null}
        {failed ? (
          <p role="alert" className="text-sm text-attention">
            {t(errorKey)}
          </p>
        ) : null}
        {notice ? (
          <p role="status" className="text-sm text-muted-foreground">
            {notice}
          </p>
        ) : null}
        {editor ? (
          <form id={formId} onSubmit={save} className="space-y-5">
            {editor.deleting ? (
              <p className="text-sm">{t("teams.authoring.deleteBody")}</p>
            ) : (
              <fieldset
                disabled={busy || editor.review || editor.resource?.readOnly}
                className="min-w-0 space-y-5 border-0 p-0"
              >
                <TeamAuthoringFields
                  key={editor.resource?.etag ?? `new-${editor.data.kind}`}
                  data={editor.data}
                  onChange={(data) => setEditor((old) => (old ? { ...old, data } : old))}
                  references={references}
                  loadMore={(kind) => void load(kind, true)}
                  members={members?.items ?? []}
                  moreMembers={members?.nextCursor !== null && members !== null}
                  loadMembers={() => void loadMembers(true)}
                  onValid={(field, valid) =>
                    setInvalidFields((old) => {
                      const next = new Set(old);
                      if (valid) next.delete(field);
                      else next.add(field);
                      return next;
                    })
                  }
                />
              </fieldset>
            )}
            {editor.resource?.readOnly ? (
              <p role="status" className="text-sm text-muted-foreground">
                {t("teams.authoring.readOnly")}
              </p>
            ) : null}
            {editor.review ? (
              <p role="status" className="text-sm text-attention">
                {t("teams.authoring.conflict")}
              </p>
            ) : null}
          </form>
        ) : (
          <>
            {pending ? (
              <section className="space-y-3 border-y border-border py-4" aria-label={t("teams.authoring.pending")}>
                <p role="status" className="text-sm">
                  {t(
                    pending.phase === "confirmed"
                      ? "teams.authoring.confirmed"
                      : pending.phase === "expired"
                        ? "teams.authoring.expired"
                        : pending.phase === "prepared"
                          ? "teams.authoring.prepared"
                          : "teams.authoring.pending",
                  )}
                </p>
                <p className="break-all text-xs text-muted-foreground select-text">
                  {collectionLabel(t, pending.data.kind)} · {pending.resourceId}
                </p>
                <details>
                  <summary className="cursor-pointer text-sm">{t("teams.authoring.savedFields")}</summary>
                  <fieldset disabled className="mt-4 min-w-0 space-y-4 border-0 p-0">
                    <TeamAuthoringFields
                      key={pending.operationId}
                      data={pending.data}
                      onChange={() => {}}
                      references={references}
                      loadMore={() => {}}
                      members={members?.items ?? []}
                      moreMembers={false}
                      loadMembers={() => {}}
                      onValid={() => {}}
                    />
                  </fieldset>
                </details>
                <div className="flex flex-wrap gap-2">
                  {pending.phase === "prepared" || pending.phase === "unknown" ? (
                    <Button
                      variant="primary"
                      disabled={busy}
                      onClick={() => void run(() => submitPending(pending), "create")}
                    >
                      {t(pending.phase === "unknown" ? "teams.authoring.confirm" : "teams.authoring.send")}
                    </Button>
                  ) : null}
                  {pending.phase !== "unknown" ? (
                    <Button
                      variant="secondary"
                      disabled={busy || (pending.phase === "expired" && !reviewedExpired)}
                      onClick={discard}
                    >
                      {t(
                        pending.phase === "confirmed"
                          ? "teams.authoring.done"
                          : pending.phase === "expired"
                            ? "teams.authoring.archive"
                            : "teams.authoring.discard",
                      )}
                    </Button>
                  ) : null}
                </div>
              </section>
            ) : null}
            {rule ? (
              <TeamRuleForm
                team={team}
                references={references}
                members={members?.items ?? []}
                moreMembers={members?.nextCursor !== null && members !== null}
                loadMembers={() => void loadMembers(true)}
                loadMore={(kind) => void load(kind, true)}
                disabled={busy || pending !== null}
                onSave={(data) => void run(() => prepareCreate(data), "create")}
              />
            ) : (
              <>
                <TeamSelect
                  label={t("teams.authoring.collection")}
                  value={collection}
                  onChange={(value) => {
                    setCollection(value as TeamAuthoringCollection);
                    setFailed(null);
                    setNotice(null);
                  }}
                  options={(section === "assets" ? assetCollections : (["policy", "group"] as const)).map((kind) => ({
                    value: kind,
                    label: collectionLabel(t, kind),
                  }))}
                  disabled={busy}
                />
                <div className="flex flex-wrap gap-2">
                  {section === "access" && collection === "policy" ? (
                    <Button
                      variant="primary"
                      data-team-authoring-opener="rule"
                      disabled={busy || !pendingLoaded || pending !== null}
                      onClick={() => {
                        editorOpener.current = "rule";
                        setRule(true);
                        setFailed(null);
                        void loadMembers();
                        for (const kind of [...assetCollections, "group"] as const)
                          if (!pagesRef.current[kind]) void load(kind);
                      }}
                    >
                      {t("teams.authoring.addRule")}
                    </Button>
                  ) : null}
                  <Button
                    variant={section === "access" && collection === "policy" ? "secondary" : "primary"}
                    data-team-authoring-opener={`create:${collection}`}
                    disabled={busy || !pendingLoaded || pending !== null}
                    onClick={() => {
                      editorOpener.current = `create:${collection}`;
                      create(collection);
                    }}
                  >
                    {section === "access" && collection === "policy"
                      ? t("teams.authoring.advanced")
                      : t("teams.authoring.add", { kind: collectionLabel(t, collection) })}
                  </Button>
                </div>
                {loading[collection] ? (
                  <p role="status" className="text-sm text-muted-foreground">
                    {t("teams.authoring.loading")}
                  </p>
                ) : null}
                {page?.items.length === 0 && !loading[collection] ? (
                  <p className="text-sm text-muted-foreground">{t("teams.authoring.empty")}</p>
                ) : null}
                <ul className="m-0 list-none divide-y divide-border p-0" aria-label={kindLabel}>
                  {page?.items.map((resource) => (
                    <li key={resource.id} className="space-y-2 py-3">
                      <p className="break-words text-sm font-medium [overflow-wrap:anywhere]">
                        {resourceName(resource)}
                      </p>
                      {resource.readOnly ? (
                        <p className="text-xs text-muted-foreground">{t("teams.authoring.readOnly")}</p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        <Button
                          variant="ghost"
                          data-team-authoring-opener={`edit:${resource.id}`}
                          disabled={busy}
                          onClick={() => {
                            editorOpener.current = `edit:${resource.id}`;
                            edit(resource);
                          }}
                        >
                          {t("teams.authoring.edit", { name: resourceName(resource) })}
                        </Button>
                        {!resource.readOnly ? (
                          <Button
                            variant="ghost"
                            className="text-attention!"
                            data-team-authoring-opener={`delete:${resource.id}`}
                            disabled={busy}
                            onClick={() => {
                              editorOpener.current = `delete:${resource.id}`;
                              edit(resource, true);
                            }}
                          >
                            {t("teams.authoring.delete", { name: resourceName(resource) })}
                          </Button>
                        ) : null}
                      </div>
                    </li>
                  ))}
                </ul>
                {page?.nextCursor ? (
                  <Button
                    variant="secondary"
                    disabled={busy || loading[collection]}
                    onClick={() => void load(collection, true)}
                  >
                    {t("teams.authoring.more")}
                  </Button>
                ) : null}
              </>
            )}
          </>
        )}
      </section>
    </Dialog>
  );
}
