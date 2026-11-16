// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field, Select } from "@scoplen/ui";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  OpenedWorkspace,
  WorkspaceInput,
  WorkspaceIssue,
  WorkspaceView,
  WorkspaceTreeInput,
  AccessProfileSummary,
  ForwardSummary,
} from "./ipc/bindings";
import { useStoreChanges } from "./ipc/store-events";

/** The shell supplies current visible intent; Rust validates and saves the complete set. */
export function WorkspacesDialog({
  tabs,
  active,
  onOpen,
  onClose,
  teamSessions = false,
}: {
  tabs: WorkspaceInput["tabs"];
  active: number | null;
  onOpen: (workspace: OpenedWorkspace) => void;
  onClose: () => void;
  teamSessions?: boolean;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [items, setItems] = useState<WorkspaceView[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState<WorkspaceIssue | null>(null);
  const [name, setName] = useState("");
  const [deleting, setDeleting] = useState<WorkspaceView | null>(null);
  const [choices, setChoices] = useState<{ forwards: ForwardSummary[]; profiles: AccessProfileSummary[] } | null>(null);
  const [choicesFailed, setChoicesFailed] = useState(false);
  const [selected, setSelected] = useState<WorkspaceInput["forwards"]>([]);
  const alive = useRef(false);
  const inFlight = useRef(false);
  const revision = useRef(0);
  const formId = useId();
  const containsOutput = (tree: WorkspaceTreeInput): boolean =>
    tree.kind === "savedOutput" ||
    (tree.kind === "split" && (containsOutput(tree.first) || containsOutput(tree.second)));
  const offline = tabs.some((tab) => containsOutput(tab.tree));
  const hasTerminal = tabs.length > 0;
  const hasSessions = hasTerminal || selected.length > 0;

  const reload = useCallback(() => {
    const request = ++revision.current;
    return Promise.allSettled([
      commands.workspacesList(),
      commands.inventoryForwards(),
      commands.inventoryAccessProfiles(),
    ])
      .then(
        ([listed, forwards, profiles]) => {
          if (!alive.current || request !== revision.current) return;
          if (listed.status === "fulfilled") {
            if (listed.value.status === "ok") setItems(listed.value.data);
            else setIssue(listed.value.error);
          } else setIssue({ kind: "storage" });
          if (
            forwards.status === "fulfilled" &&
            forwards.value.status === "ok" &&
            profiles.status === "fulfilled" &&
            profiles.value.status === "ok"
          ) {
            setChoices({ forwards: forwards.value.data, profiles: profiles.value.data });
            setChoicesFailed(false);
          } else setChoicesFailed(true);
        },
        () => {
          if (alive.current && request === revision.current) setIssue({ kind: "storage" });
        },
      )
      .finally(() => {
        if (alive.current && request === revision.current) setLoading(false);
      });
  }, [commands]);
  useEffect(() => {
    alive.current = true;
    void reload();
    return () => {
      alive.current = false;
    };
  }, [reload]);
  useStoreChanges(
    ["workspace", "accessProfile", "host", "credential", "route", "hostGroup", "forward"],
    () => void reload(),
  );

  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setIssue(null);
    try {
      await operation();
    } catch {
      if (alive.current) setIssue({ kind: "storage" });
    } finally {
      inFlight.current = false;
      if (alive.current) setBusy(false);
    }
  };
  const save = () => {
    if (teamSessions || !hasSessions || offline) return;
    void run(async () => {
      const result = await commands.workspacesCreate({ name, tabs, active, forwards: selected });
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setName("");
        setSelected([]);
        await reload();
      }
    });
  };
  const open = (item: WorkspaceView) =>
    void run(async () => {
      const result = await commands.workspacesOpen(item.id);
      if (!alive.current) return;
      if (result.status === "error") {
        setIssue(result.error);
        await reload();
      } else {
        onOpen(result.data);
        onClose();
      }
    });
  const remove = () => {
    if (!deleting) return;
    void run(async () => {
      const result = await commands.workspacesDelete(deleting.id);
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setDeleting(null);
        await reload();
      }
    });
  };
  const list = (unavailable: boolean) => {
    const group = items.filter((item) => Boolean(item.issue) === unavailable);
    if (group.length === 0) return null;
    return (
      <section aria-labelledby={`${formId}-${unavailable ? "unavailable" : "saved"}`}>
        <h2 id={`${formId}-${unavailable ? "unavailable" : "saved"}`} className="text-sm font-medium">
          {t(unavailable ? "workspaces.unavailable" : "workspaces.saved")}
        </h2>
        <ul className="m-0 list-none divide-y divide-border p-0">
          {group.map((item) => (
            <li key={item.id} className="flex flex-wrap items-center gap-3 py-3">
              <div className="min-w-0 flex-1 basis-48">
                <p className="m-0 break-words font-medium">{item.name || t("workspaces.unnamed")}</p>
                <p className="mt-1 mb-0 text-xs text-muted-foreground">
                  {item.issue
                    ? t(`workspaces.issue.${item.issue.kind}`)
                    : `${t("workspaces.tabs", { count: item.tabCount })} · ${t("workspaces.forwards", { count: item.forwardCount })}`}
                </p>
              </div>
              <Button variant="ghost" disabled={busy || !!item.issue} onClick={() => open(item)}>
                {t("workspaces.open")}
              </Button>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setDeleting(item);
                  setIssue(null);
                }}
              >
                {t("workspaces.delete")}
              </Button>
            </li>
          ))}
        </ul>
      </section>
    );
  };
  return (
    <Dialog
      open
      onOpenChange={(value) => !value && !busy && onClose()}
      title={t("workspaces.title")}
      closeLabel={t("workspaces.close")}
      footer={
        <Button variant="ghost" disabled={busy} onClick={onClose}>
          {t("workspaces.close")}
        </Button>
      }
    >
      <div className="space-y-5 text-sm">
        {deleting ? (
          <div className="space-y-3">
            <p>{t("workspaces.deleteBody", { name: deleting.name || t("workspaces.unnamed") })}</p>
            <div className="flex flex-wrap justify-end gap-2">
              <Button variant="ghost" disabled={busy} onClick={() => setDeleting(null)}>
                {t("workspaces.cancel")}
              </Button>
              <Button variant="destructive" busy={busy} onClick={remove}>
                {t("workspaces.delete")}
              </Button>
            </div>
          </div>
        ) : (
          <>
            <p className="m-0 text-muted-foreground">{t("workspaces.description")}</p>
            <form
              id={formId}
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                save();
              }}
            >
              <Field
                label={t("workspaces.name")}
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={busy || offline || teamSessions}
              />
              <fieldset disabled={busy || offline || teamSessions} className="m-0 min-w-0 space-y-3 border-0 p-0">
                <legend className="mb-2 font-medium">{t("workspaces.selectForwards")}</legend>
                <p className="m-0 text-muted-foreground">{t("workspaces.forwardHelp")}</p>
                {!choices && !choicesFailed ? <p role="status">{t("workspaces.loadingForwards")}</p> : null}
                {choicesFailed ? (
                  <p role="alert" className="text-attention">
                    {t("workspaces.forwardsFailed")}
                  </p>
                ) : null}
                {choices?.forwards.length === 0 ? <p>{t("workspaces.noForwards")}</p> : null}
                {choices?.forwards.map((forward) => {
                  const chosen = selected.find((entry) => entry.forwardId === forward.id);
                  return (
                    <div key={forward.id} className="space-y-1">
                      <label htmlFor={`${formId}-forward-${forward.id}`} className="block break-words font-medium">
                        {t("workspaces.forwardLogin", { name: forward.name })}
                      </label>
                      <Select
                        id={`${formId}-forward-${forward.id}`}
                        label={t("workspaces.forwardLogin", { name: forward.name })}
                        size="field"
                        value={chosen?.profileId ?? ""}
                        disabled={busy || offline || teamSessions || (!chosen && selected.length >= 16)}
                        options={[
                          { value: "", label: t("workspaces.omitForward") },
                          ...(chosen && !choices.profiles.some((profile) => profile.id === chosen.profileId)
                            ? [{ value: chosen.profileId, label: t("workspaces.missingLogin"), disabled: true }]
                            : []),
                          ...choices.profiles.map((profile) => ({
                            value: profile.id,
                            label: `${profile.hostName ?? profile.host} · ${profile.name ?? profile.username}`,
                          })),
                        ]}
                        onValueChange={(profileId) =>
                          setSelected((current) => {
                            const other = current.filter((entry) => entry.forwardId !== forward.id);
                            return profileId ? [...other, { forwardId: forward.id, profileId }] : other;
                          })
                        }
                      />
                    </div>
                  );
                })}
                {selected
                  .filter((entry) => choices && !choices.forwards.some((forward) => forward.id === entry.forwardId))
                  .map((entry) => (
                    <div key={entry.forwardId} className="flex flex-wrap items-center gap-2">
                      <p role="alert" className="m-0 min-w-0 flex-1 break-all text-attention">
                        {t("workspaces.missingForward", { id: entry.forwardId })}
                      </p>
                      <Button
                        variant="ghost"
                        onClick={() =>
                          setSelected((current) => current.filter((item) => item.forwardId !== entry.forwardId))
                        }
                      >
                        {t("workspaces.omitForward")}
                      </Button>
                    </div>
                  ))}
                <p className="m-0 text-xs text-muted-foreground">{t("workspaces.forwardLimit")}</p>
              </fieldset>
              {!hasSessions || offline ? (
                <p className="m-0 text-muted-foreground">
                  {t(offline ? "workspaces.issue.savedOutputUnsupported" : "workspaces.issue.emptyTabs")}
                </p>
              ) : null}
              <div className="flex justify-end">
                <Button
                  type="submit"
                  variant="primary"
                  busy={busy}
                  disabled={!hasSessions || offline || teamSessions || name.trim() === ""}
                >
                  {t("workspaces.save")}
                </Button>
              </div>
            </form>
            {teamSessions ? <p role="status">{t("workspaces.teamUnavailable")}</p> : null}
            {loading ? (
              <p role="status">{t("workspaces.loading")}</p>
            ) : items.length === 0 && !issue ? (
              <p>{t("workspaces.empty")}</p>
            ) : (
              <>
                {list(false)}
                {list(true)}
              </>
            )}
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => {
                setIssue(null);
                setLoading(true);
                void reload();
              }}
            >
              {t("workspaces.refresh")}
            </Button>
          </>
        )}
        {issue ? (
          <p role="alert" className="m-0 text-attention">
            {t(`workspaces.issue.${issue.kind}`)}
          </p>
        ) : null}
      </div>
    </Dialog>
  );
}
