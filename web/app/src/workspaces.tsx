// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field } from "@scoplen/ui";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  OpenedWorkspace,
  WorkspaceInput,
  WorkspaceIssue,
  WorkspaceView,
  WorkspaceTreeInput,
} from "./ipc/bindings";
import { useStoreChanges } from "./ipc/store-events";

/** The shell supplies current visible intent; Rust validates and saves the complete set. */
export function WorkspacesDialog({
  tabs,
  active,
  onOpen,
  onClose,
}: {
  tabs: WorkspaceInput["tabs"];
  active: number | null;
  onOpen: (workspace: OpenedWorkspace) => void;
  onClose: () => void;
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [items, setItems] = useState<WorkspaceView[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState<WorkspaceIssue | null>(null);
  const [name, setName] = useState("");
  const [deleting, setDeleting] = useState<WorkspaceView | null>(null);
  const alive = useRef(false);
  const inFlight = useRef(false);
  const revision = useRef(0);
  const formId = useId();
  const containsOutput = (tree: WorkspaceTreeInput): boolean =>
    tree.kind === "savedOutput" ||
    (tree.kind === "split" && (containsOutput(tree.first) || containsOutput(tree.second)));
  const offline = tabs.some((tab) => containsOutput(tab.tree));
  const hasTerminal = tabs.length > 0;

  const reload = useCallback(() => {
    const request = ++revision.current;
    return commands
      .workspacesList()
      .then(
        (result) => {
          if (!alive.current || request !== revision.current) return;
          if (result.status === "ok") setItems(result.data);
          else setIssue(result.error);
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
  const save = () =>
    void run(async () => {
      const result = await commands.workspacesCreate({ name, tabs, active });
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setName("");
        await reload();
      }
    });
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
                    : t("workspaces.tabs", { count: item.tabCount })}
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
                disabled={busy || !hasTerminal || offline}
              />
              {!hasTerminal || offline ? (
                <p className="m-0 text-muted-foreground">
                  {t(offline ? "workspaces.issue.savedOutputUnsupported" : "workspaces.issue.emptyTabs")}
                </p>
              ) : null}
              <div className="flex justify-end">
                <Button
                  type="submit"
                  variant="primary"
                  busy={busy}
                  disabled={!hasTerminal || offline || name.trim() === ""}
                >
                  {t("workspaces.save")}
                </Button>
              </div>
            </form>
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
