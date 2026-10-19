// SPDX-License-Identifier: Apache-2.0
import { Button, Confirm, Dialog, Field, IconButton, Mark, Notice, TextAreaField } from "@scoplen/ui";
import { Pencil, Plus, RotateCcw, Trash2 } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type AccessProfileInput,
  type AccessProfileSummary,
  type CredentialBindingInput,
  type CredentialInput,
  type CredentialKindInput,
  type CredentialSummary,
  type Failure,
  type ForwardSummary,
  type HostSummary,
  type Id,
  type ObjectEditError,
  type Outcome,
  type RouteDefinition,
  type RouteSummary,
} from "./api";
import { routeText } from "./labels";
import { useLoad, type Loaded } from "./use-load";

export type ObjectSection = "logins" | "keys" | "routes";

type Editing = { kind: ObjectSection; id?: Id } | null;
type Deleting = { kind: ObjectSection; id: Id; name: string } | null;

function objectLoad<T>(promise: Promise<Outcome<T, ObjectEditError>>): Promise<Outcome<T, Failure>> {
  return promise.then((result) => {
    if (result.status === "ok") return result;
    const reference = result.error.kind === "failed" ? result.error.reference : result.error.kind;
    return { status: "error", error: { kind: "failed", reference } };
  });
}

/** The independent object editors reached from the Hosts inventory. */
export function InventoryObjects({
  section: initialSection,
  onBack,
  embedded = false,
}: {
  section: ObjectSection;
  onBack: () => void;
  /** Shown beside the hosts sidebar, which already offers the way back and the other sections. */
  embedded?: boolean;
}) {
  // Beside the sidebar the editor is part of the Hosts page, not a page of its own.
  const Root = embedded ? "div" : "main";
  const { t } = useI18n();
  const api = useInventory();
  const [section, setSection] = useState<ObjectSection>(initialSection);
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<Deleting>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<ObjectEditError | null>(null);
  const [restoreBusy, setRestoreBusy] = useState<Id | null>(null);
  const [restoreError, setRestoreError] = useState<{ id: Id; message: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const profiles = useLoad(() => objectLoad(api.accessProfiles()), "access-profiles");
  const credentials = useLoad(() => objectLoad(api.credentials()), "credentials");
  const routes = useLoad(() => objectLoad(api.routes()), "routes");
  const forwards = useLoad(() => objectLoad(api.forwards()), "forwards");
  const hosts = useLoad(() => api.hosts({ kind: "all" }, ""), "all-hosts");

  const title =
    section === "logins"
      ? t("objects.logins.title")
      : section === "keys"
        ? t("objects.keys.title")
        : t("objects.routes.title");
  const description =
    section === "logins"
      ? t("objects.logins.description")
      : section === "keys"
        ? t("objects.keys.description")
        : t("objects.routes.description");
  const addLabel =
    section === "logins" ? t("objects.add.login") : section === "keys" ? t("objects.add.key") : t("objects.add.route");

  const confirmDelete = async () => {
    if (!deleting || deleteBusy) return;
    setDeleteBusy(true);
    setDeleteError(null);
    const result =
      deleting.kind === "logins"
        ? await api.deleteAccessProfile(deleting.id)
        : deleting.kind === "keys"
          ? await api.deleteCredential(deleting.id)
          : await api.deleteRoute(deleting.id);
    setDeleteBusy(false);
    if (result.status === "ok") {
      setDeleting(null);
      setNotice(t("objects.delete", { name: deleting.name }));
    } else {
      setDeleteError(result.error);
    }
  };

  const onSaved = (message: string) => {
    setEditing(null);
    setNotice(message);
  };

  const restoreOrphanedObject = async (objectId: Id, rowId: Id) => {
    if (restoreBusy) return;
    setRestoreBusy(rowId);
    setRestoreError(null);
    const result = await api.restoreOrphanedObject(objectId);
    setRestoreBusy(null);
    if (result.status === "ok") setNotice(t("objects.orphaned.restored"));
    else setRestoreError({ id: rowId, message: objectErrorText(t, result.error) });
  };

  return (
    <Root
      {...(embedded ? {} : { id: "main", tabIndex: -1 })}
      className="h-full min-h-0 overflow-y-auto px-6 py-6 focus:outline-none"
    >
      <div className="mx-auto max-w-4xl">
        <header className="flex flex-wrap items-start gap-4 pb-2">
          {embedded ? null : (
            <Button variant="ghost" onClick={onBack} className="-ml-3">
              {t("objects.back")}
            </Button>
          )}
          <div className="min-w-0 flex-1">
            <h1 className="ui-display text-3xl">{title}</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{description}</p>
          </div>
          <Button variant="primary" onClick={() => setEditing({ kind: section })} className="gap-1.5">
            <Plus aria-hidden="true" className="size-4" />
            {addLabel}
          </Button>
        </header>

        {embedded ? null : (
          <nav
            aria-label={
              section === "logins"
                ? t("objects.list.logins")
                : section === "keys"
                  ? t("objects.list.keys")
                  : t("objects.list.routes")
            }
            className="mt-5"
          >
            <div role="tablist" className="inline-flex gap-1 rounded-full bg-inset p-1" aria-label={t("frame.tabs")}>
              {(["logins", "keys", "routes"] as ObjectSection[]).map((value) => {
                const selected = value === section;
                const label =
                  value === "logins" ? t("frame.logins") : value === "keys" ? t("frame.keys") : t("frame.routes");
                return (
                  <button
                    key={value}
                    type="button"
                    role="tab"
                    aria-selected={selected}
                    onClick={() => setSection(value)}
                    className="relative rounded-full border-(length:--scoplen-border-width) border-transparent px-4 py-1.5 text-sm text-muted-foreground transition-[background-color,color,box-shadow] duration-(--duration-state) hover:text-foreground aria-selected:border-border aria-selected:bg-raised aria-selected:font-medium aria-selected:text-foreground aria-selected:shadow-(--scoplen-shadow-control)"
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </nav>
        )}

        <section aria-labelledby="objects-list-title" className="mt-5">
          <h2 id="objects-list-title" className="sr-only">
            {section === "logins"
              ? t("objects.list.logins")
              : section === "keys"
                ? t("objects.list.keys")
                : t("objects.list.routes")}
          </h2>
          {section === "logins" ? (
            <ProfileList
              data={profiles}
              routes={routes}
              forwards={forwards}
              onEdit={(id) => setEditing({ kind: "logins", id })}
              onDelete={setDeleting}
              onRestore={(objectId, rowId) => void restoreOrphanedObject(objectId, rowId)}
              restoreBusy={restoreBusy}
              restoreError={restoreError}
            />
          ) : section === "keys" ? (
            <CredentialList
              data={credentials}
              onEdit={(id) => setEditing({ kind: "keys", id })}
              onDelete={setDeleting}
            />
          ) : (
            <RouteList
              data={routes}
              profiles={profiles}
              credentials={credentials}
              onEdit={(id) => setEditing({ kind: "routes", id })}
              onDelete={setDeleting}
              onRestore={(objectId, rowId) => void restoreOrphanedObject(objectId, rowId)}
              restoreBusy={restoreBusy}
              restoreError={restoreError}
            />
          )}
        </section>
      </div>

      {editing?.kind === "logins" ? (
        <ProfileEditor
          key={editing.id ?? "new"}
          id={editing.id}
          profiles={profiles}
          hosts={hosts}
          credentials={credentials}
          routes={routes}
          forwards={forwards}
          onClose={() => setEditing(null)}
          onSaved={onSaved}
        />
      ) : null}
      {editing?.kind === "keys" ? (
        <CredentialEditor
          key={editing.id ?? "new"}
          id={editing.id}
          credentials={credentials}
          onClose={() => setEditing(null)}
          onSaved={onSaved}
        />
      ) : null}
      {editing?.kind === "routes" ? (
        <RouteEditor
          key={editing.id ?? "new"}
          id={editing.id}
          profiles={profiles}
          routes={routes}
          credentials={credentials}
          onClose={() => setEditing(null)}
          onSaved={onSaved}
        />
      ) : null}

      <Confirm
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open && !deleteBusy) {
            setDeleting(null);
            setDeleteError(null);
          }
        }}
        title={t("objects.deleteTitle", { name: deleting?.name ?? "" })}
        body={
          <>
            <p className="m-0">{t("objects.deleteBody")}</p>
            {deleteError ? (
              <p role="alert" className="mt-3 mb-0 text-attention">
                {objectErrorText(t, deleteError)}
              </p>
            ) : null}
          </>
        }
        confirmLabel={deleting ? t("objects.delete", { name: deleting.name }) : t("objects.cancel")}
        cancelLabel={t("objects.cancel")}
        onConfirm={() => void confirmDelete()}
        busy={deleteBusy}
        destructive
      />
      {notice ? <Notice message={notice} onDismiss={() => setNotice(null)} /> : null}
    </Root>
  );
}

function ProfileList({
  data,
  routes,
  forwards,
  onEdit,
  onDelete,
  onRestore,
  restoreBusy,
  restoreError,
}: {
  data: Loaded<AccessProfileSummary[]>;
  routes: Loaded<RouteSummary[]>;
  forwards: Loaded<ForwardSummary[]>;
  onEdit: (id: Id) => void;
  onDelete: (item: Deleting) => void;
  onRestore: (objectId: Id, rowId: Id) => void;
  restoreBusy: Id | null;
  restoreError: { id: Id; message: string } | null;
}) {
  const { t } = useI18n();
  if (data.state === "loading") return <Loading />;
  if (data.state === "failed") return <FailureNotice reference={data.reference} />;
  if (data.data.length === 0) return <Empty text={t("objects.empty.logins")} />;
  const orphaned = data.data.filter((profile) => profile.orphaned || profile.hostName === null);
  const live = data.data.filter((profile) => !profile.orphaned && profile.hostName !== null);
  const list = (profiles: AccessProfileSummary[], orphan = false) => (
    <ul
      aria-label={orphan ? t("objects.orphaned.title") : t("objects.list.logins")}
      className="ui-surface m-0 list-none divide-y divide-border overflow-hidden p-0"
    >
      {profiles.map((profile) => {
        const name = profile.name ?? (orphan ? profile.username : `${profile.username}@${profile.hostName}`);
        const restoreTarget = orphan ? profileOrphanRestoreTarget(profile, routes, forwards) : null;
        const missingLabel =
          profile.hostName === null
            ? t("objects.orphaned.missingHost")
            : profile.credentialId && !profile.credential
              ? t("objects.orphaned.missingCredential")
              : profile.routeId &&
                  routes.state === "ready" &&
                  !routes.data.some((route) => route.id === profile.routeId)
                ? t("objects.orphaned.missingRoute")
                : profile.forwards.some(
                      (forwardId) =>
                        forwards.state === "ready" && !forwards.data.some((forward) => forward.id === forwardId),
                    )
                  ? t("objects.orphaned.missingForward")
                  : t("objects.orphaned.missingObject");
        return (
          <li
            key={profile.id}
            className="flex flex-wrap items-center gap-3 px-4 py-3 transition-colors duration-(--duration-micro) hover:bg-inset/50"
          >
            <div className="min-w-0 flex-1">
              <p className="m-0 truncate text-sm font-medium">{name}</p>
              <p className="m-0 truncate font-mono text-xs text-muted-foreground">
                <span>{orphan ? missingLabel : `${profile.username}@${profile.hostName}`}</span>
                {" · "}
                <span>{routeText(t, profile.route)}</span>
              </p>
              <p className="m-0 text-xs text-muted-foreground">
                {profile.isDefault ? t("objects.profile.default") : ""}
                {profile.forwards.length > 0
                  ? `${profile.isDefault ? " · " : ""}${t("objects.profile.forwardCount", { count: profile.forwards.length })}`
                  : ""}
                {profile.restored ? ` · ${t("hosts.restored")}` : ""}
                {restoreError?.id === profile.id ? ` · ${restoreError.message}` : ""}
              </p>
            </div>
            <RowActions
              name={name}
              editDisabled={orphan}
              onEdit={() => onEdit(profile.id)}
              onDelete={() => onDelete({ kind: "logins", id: profile.id, name })}
              onRestore={restoreTarget ? () => onRestore(restoreTarget, profile.id) : undefined}
              restoreBusy={restoreBusy === profile.id}
            />
          </li>
        );
      })}
    </ul>
  );
  return (
    <div className="space-y-5">
      {orphaned.length > 0 ? (
        <section aria-labelledby="orphaned-logins-title" className="space-y-2">
          <div>
            <h3 id="orphaned-logins-title" className="m-0 text-sm font-medium">
              {t("objects.orphaned.title")}
            </h3>
            <p className="m-0 text-sm text-muted-foreground">{t("objects.orphaned.body")}</p>
          </div>
          {list(orphaned, true)}
        </section>
      ) : null}
      {live.length > 0 ? list(live) : null}
    </div>
  );
}

function profileOrphanRestoreTarget(
  profile: AccessProfileSummary,
  routes: Loaded<RouteSummary[]>,
  forwards: Loaded<ForwardSummary[]>,
): Id | null {
  if (profile.hostName === null) return profile.host;
  if (profile.credentialId && !profile.credential) return profile.credentialId;
  if (profile.routeId && (routes.state !== "ready" || !routes.data.some((route) => route.id === profile.routeId))) {
    return profile.routeId;
  }
  if (forwards.state === "ready") {
    const missing = profile.forwards.find((forward) => !forwards.data.some((item) => item.id === forward));
    if (missing) return missing;
  }
  return null;
}

function CredentialList({
  data,
  onEdit,
  onDelete,
}: {
  data: Loaded<CredentialSummary[]>;
  onEdit: (id: Id) => void;
  onDelete: (item: Deleting) => void;
}) {
  const { t } = useI18n();
  if (data.state === "loading") return <Loading />;
  if (data.state === "failed") return <FailureNotice reference={data.reference} />;
  if (data.data.length === 0) return <Empty text={t("objects.empty.keys")} />;
  return (
    <ul
      aria-label={t("objects.list.keys")}
      className="ui-surface m-0 list-none divide-y divide-border overflow-hidden p-0"
    >
      {data.data.map((credential) => {
        const name = credential.name ?? credentialKindText(t, credential.kind);
        return (
          <li
            key={credential.id}
            className="flex flex-wrap items-center gap-3 px-4 py-3 transition-colors duration-(--duration-micro) hover:bg-inset/50"
          >
            <div className="min-w-0 flex-1">
              <p className="m-0 truncate text-sm font-medium">{name}</p>
              <p className="m-0 text-xs text-muted-foreground">
                {credentialKindText(t, credential.kind)} · {credentialBindingText(t, credential.binding)} ·{" "}
                {credential.hasSecret ? t("objects.credential.hasSecret") : t("objects.credential.noSecret")}
              </p>
              <p className="m-0 text-xs text-muted-foreground">
                {t("objects.references", { count: credential.profileCount + credential.routeCount })}
              </p>
            </div>
            <RowActions
              name={name}
              onEdit={() => onEdit(credential.id)}
              onDelete={() => onDelete({ kind: "keys", id: credential.id, name })}
            />
          </li>
        );
      })}
    </ul>
  );
}

function RouteList({
  data,
  profiles,
  credentials,
  onEdit,
  onDelete,
  onRestore,
  restoreBusy,
  restoreError,
}: {
  data: Loaded<RouteSummary[]>;
  profiles: Loaded<AccessProfileSummary[]>;
  credentials: Loaded<CredentialSummary[]>;
  onEdit: (id: Id) => void;
  onDelete: (item: Deleting) => void;
  onRestore: (objectId: Id, rowId: Id) => void;
  restoreBusy: Id | null;
  restoreError: { id: Id; message: string } | null;
}) {
  const { t } = useI18n();
  if (data.state === "loading") return <Loading />;
  if (data.state === "failed") return <FailureNotice reference={data.reference} />;
  if (data.data.length === 0) return <Empty text={t("objects.empty.routes")} />;
  const orphaned = data.data.filter((route) => route.orphaned);
  const live = data.data.filter((route) => !route.orphaned);
  const list = (routes: RouteSummary[], isOrphaned = false) => (
    <ul
      aria-label={isOrphaned ? t("objects.orphaned.title") : t("objects.list.routes")}
      className="ui-surface m-0 list-none divide-y divide-border overflow-hidden p-0"
    >
      {routes.map((route) => {
        const restoreTarget = isOrphaned ? routeOrphanRestoreTarget(route, profiles, credentials) : null;
        return (
          <li
            key={route.id}
            className="flex flex-wrap items-center gap-3 px-4 py-3 transition-colors duration-(--duration-micro) hover:bg-inset/50"
          >
            <div className="min-w-0 flex-1">
              <p className="m-0 truncate text-sm font-medium">{route.name}</p>
              <p className="m-0 text-xs text-muted-foreground">
                {isOrphaned ? t("objects.orphaned.missingObject") : routeKindText(t, route.definition.kind)}
              </p>
              <p className="m-0 text-xs text-muted-foreground">
                {t("objects.references", { count: route.profileCount })}
                {route.restored ? ` · ${t("hosts.restored")}` : ""}
                {restoreError?.id === route.id ? ` · ${restoreError.message}` : ""}
              </p>
            </div>
            <RowActions
              name={route.name}
              disabled={route.definition.kind === "managed"}
              editDisabled={isOrphaned}
              onEdit={() => onEdit(route.id)}
              onDelete={() => onDelete({ kind: "routes", id: route.id, name: route.name })}
              onRestore={restoreTarget ? () => onRestore(restoreTarget, route.id) : undefined}
              restoreBusy={restoreBusy === route.id}
            />
          </li>
        );
      })}
    </ul>
  );
  return (
    <div className="space-y-5">
      {orphaned.length > 0 ? (
        <section aria-labelledby="orphaned-routes-title" className="space-y-2">
          <div>
            <h3 id="orphaned-routes-title" className="m-0 text-sm font-medium">
              {t("objects.orphaned.title")}
            </h3>
            <p className="m-0 text-sm text-muted-foreground">{t("objects.orphaned.body")}</p>
          </div>
          {list(orphaned, true)}
        </section>
      ) : null}
      {live.length > 0 ? list(live) : null}
    </div>
  );
}

function routeOrphanRestoreTarget(
  route: RouteSummary,
  profiles: Loaded<AccessProfileSummary[]>,
  credentials: Loaded<CredentialSummary[]>,
): Id | null {
  const definition = route.definition;
  if (definition.kind === "jump" && profiles.state === "ready") {
    const missing = definition.hops.find((hop) => !profiles.data.some((profile) => profile.id === hop));
    if (missing) return missing;
  }
  if (
    (definition.kind === "socks5" || definition.kind === "httpConnect") &&
    definition.credential &&
    credentials.state === "ready" &&
    !credentials.data.some((credential) => credential.id === definition.credential)
  ) {
    return definition.credential;
  }
  return null;
}

function RowActions({
  name,
  onEdit,
  onDelete,
  disabled = false,
  editDisabled = false,
  onRestore,
  restoreBusy = false,
}: {
  name: string;
  onEdit: () => void;
  onDelete: () => void;
  disabled?: boolean;
  editDisabled?: boolean;
  onRestore?: () => void;
  restoreBusy?: boolean;
}) {
  const { t } = useI18n();
  return (
    <div className="ml-auto flex shrink-0 gap-0.5">
      <IconButton label={t("objects.edit", { name })} disabled={disabled || editDisabled} onClick={onEdit}>
        <Pencil aria-hidden="true" className="size-4" />
      </IconButton>
      {onRestore ? (
        <Button
          variant="ghost"
          busy={restoreBusy}
          disabled={restoreBusy}
          onClick={onRestore}
          aria-label={t("objects.orphaned.restore")}
          className="gap-1.5"
        >
          <RotateCcw aria-hidden="true" className="size-4" />
          <span className="hidden sm:inline">{t("objects.orphaned.restore")}</span>
        </Button>
      ) : null}
      <IconButton
        label={t("objects.delete", { name })}
        disabled={disabled}
        onClick={onDelete}
        className="hover:bg-[color-mix(in_srgb,var(--attention)_10%,transparent)] hover:text-attention"
      >
        <Trash2 aria-hidden="true" className="size-4" />
      </IconButton>
    </div>
  );
}

function Loading() {
  const { t } = useI18n();
  return (
    <p role="status" className="py-12 text-center text-sm text-muted-foreground">
      {t("objects.loading")}
    </p>
  );
}

function FailureNotice({ reference }: { reference: string }) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col items-center py-12 text-center">
      <Mark size="3rem" mood="low" className="mb-4 text-attention" />
      <p role="alert" className="m-0 max-w-sm text-sm text-attention">
        {t("failed.body")} {t("startup.error.reference", { reference })}
      </p>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="scoplen-rise flex flex-col items-center py-12 text-center text-sm text-muted-foreground">
      <Mark size="3rem" mood="awake" look={{ x: 0, y: -0.6 }} className="mb-4 text-egg" />
      <p className="m-0 max-w-sm">{text}</p>
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
  disabled,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  disabled?: boolean;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-foreground">
        {label}
      </label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        className="ui-input h-10 px-3 text-sm"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {hint ? <p className="m-0 text-sm text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function EditorDialog({
  title,
  description,
  busy,
  error,
  onClose,
  onSave,
  canSave = true,
  children,
}: {
  title: string;
  description?: string;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onSave: () => void;
  canSave?: boolean;
  children: ReactNode;
}) {
  const { t } = useI18n();
  return (
    <Dialog
      open
      onOpenChange={(open) => !open && !busy && onClose()}
      title={title}
      description={description}
      closeLabel={t("objects.cancel")}
      footer={
        <>
          <Button variant="ghost" disabled={busy} onClick={onClose}>
            {t("objects.cancel")}
          </Button>
          <Button variant="primary" busy={busy} disabled={!canSave} onClick={onSave}>
            {t("objects.save")}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {error ? (
          <p role="alert" className="m-0 text-sm text-attention">
            {error}
          </p>
        ) : null}
        {children}
      </div>
    </Dialog>
  );
}

function ProfileEditor({
  id,
  profiles,
  hosts,
  credentials,
  routes,
  forwards,
  onClose,
  onSaved,
}: {
  id?: Id;
  profiles: Loaded<AccessProfileSummary[]>;
  hosts: Loaded<HostSummary[]>;
  credentials: Loaded<CredentialSummary[]>;
  routes: Loaded<RouteSummary[]>;
  forwards: Loaded<ForwardSummary[]>;
  onClose: () => void;
  onSaved: (message: string) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const existing = id && profiles.state === "ready" ? profiles.data.find((profile) => profile.id === id) : undefined;
  const [value, setValue] = useState<AccessProfileInput>(() =>
    existing
      ? {
          host: existing.host,
          name: existing.name,
          username: existing.username,
          credential: existing.credentialId,
          route: existing.routeId,
          terminalProfile: existing.terminalProfile,
          startupCommand: existing.startupCommand,
          agentForwarding: existing.agentForwarding,
          forwards: [...existing.forwards],
          defaultProfile: existing.isDefault,
        }
      : {
          host: "",
          name: null,
          username: "",
          credential: null,
          route: null,
          terminalProfile: null,
          startupCommand: null,
          agentForwarding: false,
          forwards: [],
          defaultProfile: false,
        },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hostOptions =
    hosts.state === "ready"
      ? hosts.data.map((host) => ({ value: host.id, label: `${host.name} (${host.address})` }))
      : [];
  const credentialOptions =
    credentials.state === "ready"
      ? credentials.data.map((credential) => ({
          value: credential.id,
          label: credential.name ?? credentialKindText(t, credential.kind),
        }))
      : [];
  const routeOptions =
    routes.state === "ready"
      ? routes.data.filter((route) => !route.orphaned).map((route) => ({ value: route.id, label: route.name }))
      : [];
  const save = async () => {
    setBusy(true);
    setError(null);
    const result = id ? await api.updateAccessProfile(id, value) : await api.createAccessProfile(value);
    setBusy(false);
    if (result.status === "ok") onSaved(id ? t("objects.save") : t("objects.add.login"));
    else setError(objectErrorText(t, result.error));
  };
  return (
    <EditorDialog
      title={
        id
          ? t("objects.edit", { name: existing?.name ?? existing?.username ?? t("objects.profile.new") })
          : t("objects.profile.new")
      }
      busy={busy}
      error={error}
      onClose={onClose}
      onSave={() => void save()}
      canSave={forwards.state === "ready"}
    >
      <SelectField
        label={t("objects.profile.host")}
        value={value.host}
        onChange={(host) => setValue((current) => ({ ...current, host }))}
        options={[{ value: "", label: t("objects.profile.host") }, ...hostOptions]}
      />
      <Field
        label={t("objects.profile.username")}
        value={value.username}
        onChange={(event) => setValue((current) => ({ ...current, username: event.target.value }))}
        autoComplete="username"
      />
      <Field
        label={t("objects.profile.name")}
        hint={t("objects.profile.nameHint")}
        value={value.name ?? ""}
        onChange={(event) => setValue((current) => ({ ...current, name: event.target.value || null }))}
      />
      <SelectField
        label={t("objects.profile.credential")}
        value={value.credential ?? ""}
        onChange={(credential) => setValue((current) => ({ ...current, credential: credential || null }))}
        options={[{ value: "", label: t("objects.profile.anyCredential") }, ...credentialOptions]}
      />
      <SelectField
        label={t("objects.profile.route")}
        value={value.route ?? ""}
        onChange={(route) => setValue((current) => ({ ...current, route: route || null }))}
        options={[{ value: "", label: t("objects.profile.direct") }, ...routeOptions]}
      />
      <Field
        label={t("objects.profile.terminalProfile")}
        value={value.terminalProfile ?? ""}
        onChange={(event) => setValue((current) => ({ ...current, terminalProfile: event.target.value || null }))}
      />
      <Field
        label={t("objects.profile.startupCommand")}
        value={value.startupCommand ?? ""}
        onChange={(event) => setValue((current) => ({ ...current, startupCommand: event.target.value || null }))}
      />
      <fieldset className="flex flex-col gap-2" disabled={forwards.state !== "ready"}>
        <legend className="text-sm font-medium text-foreground">{t("objects.profile.forwards")}</legend>
        <p className="m-0 text-sm text-muted-foreground">{t("objects.profile.forwardsHint")}</p>
        {forwards.state === "loading" ? (
          <p className="m-0 text-sm text-muted-foreground">{t("objects.loading")}</p>
        ) : null}
        {forwards.state === "failed" ? <FailureNotice reference={forwards.reference} /> : null}
        {forwards.state === "ready" && forwards.data.length === 0 ? (
          <p className="m-0 text-sm text-muted-foreground">{t("objects.profile.noForwards")}</p>
        ) : null}
        {forwards.state === "ready"
          ? forwards.data.map((forward) => {
              const checkboxId = `profile-forward-${forward.id}`;
              return (
                <label key={forward.id} htmlFor={checkboxId} className="flex items-start gap-2 text-sm">
                  <input
                    id={checkboxId}
                    type="checkbox"
                    checked={value.forwards.includes(forward.id)}
                    onChange={(event) =>
                      setValue((current) => ({
                        ...current,
                        forwards: event.target.checked
                          ? [...new Set([...current.forwards, forward.id])]
                          : current.forwards.filter((id) => id !== forward.id),
                      }))
                    }
                    className="mt-0.5 size-4 accent-[var(--primary)]"
                  />
                  <span>
                    <span className="block">{forward.name}</span>
                    <span className="block text-xs text-muted-foreground">{forwardKindText(t, forward.kind)}</span>
                  </span>
                </label>
              );
            })
          : null}
      </fieldset>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={value.agentForwarding}
          onChange={(event) => setValue((current) => ({ ...current, agentForwarding: event.target.checked }))}
          className="size-4 accent-[var(--primary)]"
        />
        {t("objects.profile.agentForwarding")}
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={value.defaultProfile}
          onChange={(event) => setValue((current) => ({ ...current, defaultProfile: event.target.checked }))}
          className="size-4 accent-[var(--primary)]"
        />
        {t("objects.profile.default")}
      </label>
    </EditorDialog>
  );
}

function CredentialEditor({
  id,
  credentials,
  onClose,
  onSaved,
}: {
  id?: Id;
  credentials: Loaded<CredentialSummary[]>;
  onClose: () => void;
  onSaved: (message: string) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const existing =
    id && credentials.state === "ready" ? credentials.data.find((credential) => credential.id === id) : undefined;
  const [value, setValue] = useState<CredentialInput>(() =>
    existing
      ? {
          name: existing.name,
          kind: existing.kind,
          binding: existing.binding,
          secret: null,
          deviceSecret: null,
          publicKey: existing.publicKey,
          provider: existing.provider,
          certificateScope: existing.certificateScope,
        }
      : {
          name: null,
          kind: "key",
          binding: "shared",
          secret: null,
          deviceSecret: null,
          publicKey: null,
          provider: {},
          certificateScope: null,
        },
  );
  const [secret, setSecret] = useState("");
  const [deviceSecret, setDeviceSecret] = useState("");
  const [providerText, setProviderText] = useState(() =>
    existing
      ? Object.entries(existing.provider)
          .map(([key, item]) => `${key}=${item}`)
          .join("\n")
      : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const secretAllowed =
    value.binding === "shared" || (value.binding === "device" && (value.kind === "password" || value.kind === "key"));
  const allowedBindings = credentialBindings(value.kind);
  const save = async () => {
    const provider: Record<string, string> = {};
    for (const line of providerText.split(/\r?\n/)) {
      const index = line.indexOf("=");
      if (index > 0) provider[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
    setBusy(true);
    setError(null);
    const result = id
      ? await api.updateCredential(id, {
          ...value,
          secret: value.binding === "shared" ? secret || null : null,
          deviceSecret: value.binding === "device" && secretAllowed ? deviceSecret || null : null,
          provider,
        })
      : await api.createCredential({
          ...value,
          secret: value.binding === "shared" ? secret || null : null,
          deviceSecret: value.binding === "device" && secretAllowed ? deviceSecret || null : null,
          provider,
        });
    setBusy(false);
    if (result.status === "ok") onSaved(id ? t("objects.save") : t("objects.add.key"));
    else setError(objectErrorText(t, result.error));
  };
  return (
    <EditorDialog
      title={
        id ? t("objects.edit", { name: existing?.name ?? t("objects.credential.new") }) : t("objects.credential.new")
      }
      description={t("objects.keys.description")}
      busy={busy}
      error={error}
      onClose={onClose}
      onSave={() => void save()}
    >
      <Field
        label={t("objects.credential.name")}
        value={value.name ?? ""}
        onChange={(event) => setValue((current) => ({ ...current, name: event.target.value || null }))}
      />
      <SelectField
        label={t("objects.credential.kind")}
        value={value.kind}
        onChange={(kind) => {
          const nextKind = kind as CredentialKindInput;
          const nextBindings = credentialBindings(nextKind);
          setValue((current) => ({
            ...current,
            kind: nextKind,
            binding: nextBindings.includes(current.binding) ? current.binding : nextBindings[0]!,
          }));
        }}
        options={(
          ["password", "key", "certificate", "agent", "securityKey", "deviceKey", "external"] as CredentialKindInput[]
        ).map((kind) => ({ value: kind, label: credentialKindText(t, kind) }))}
      />
      <SelectField
        label={t("objects.credential.binding")}
        value={value.binding}
        onChange={(binding) => setValue((current) => ({ ...current, binding: binding as CredentialBindingInput }))}
        options={allowedBindings.map((binding) => ({
          value: binding,
          label: credentialBindingText(t, binding),
        }))}
      />
      {secretAllowed ? (
        <TextAreaField
          label={value.binding === "device" ? t("objects.credential.deviceSecret") : t("objects.credential.secret")}
          hint={
            id && existing?.hasSecret
              ? t("objects.credential.secretKeep")
              : value.binding === "device"
                ? t("objects.credential.deviceSecretHint")
                : t("objects.credential.secretHint")
          }
          value={value.binding === "device" ? deviceSecret : secret}
          onChange={(event) =>
            value.binding === "device" ? setDeviceSecret(event.target.value) : setSecret(event.target.value)
          }
          autoComplete="new-password"
        />
      ) : null}
      {value.binding === "device" && !secretAllowed ? (
        <p className="m-0 text-sm text-muted-foreground">{t("objects.credential.deviceKeyHint")}</p>
      ) : null}
      {value.kind === "key" || value.kind === "agent" ? (
        <Field
          label={t("objects.credential.publicKey")}
          value={value.publicKey ?? ""}
          onChange={(event) => setValue((current) => ({ ...current, publicKey: event.target.value || null }))}
        />
      ) : null}
      {value.kind === "external" ? (
        <TextAreaField
          label={t("objects.credential.provider")}
          hint={t("objects.credential.providerHint")}
          value={providerText}
          onChange={(event) => setProviderText(event.target.value)}
        />
      ) : null}
      {value.kind === "certificate" ? (
        <Field
          label={t("objects.credential.certificateScope")}
          value={value.certificateScope ?? ""}
          onChange={(event) => setValue((current) => ({ ...current, certificateScope: event.target.value || null }))}
        />
      ) : null}
    </EditorDialog>
  );
}

function RouteEditor({
  id,
  profiles,
  routes,
  credentials,
  onClose,
  onSaved,
}: {
  id?: Id;
  profiles: Loaded<AccessProfileSummary[]>;
  routes: Loaded<RouteSummary[]>;
  credentials: Loaded<CredentialSummary[]>;
  onClose: () => void;
  onSaved: (message: string) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const existing = id && routes.state === "ready" ? routes.data.find((route) => route.id === id) : undefined;
  const initial = existing?.definition;
  const initialKind = initial?.kind ?? "jump";
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<RouteDefinition["kind"]>(initialKind);
  const [hops, setHops] = useState<string[]>(initial?.kind === "jump" ? [...initial.hops] : []);
  const [proxy, setProxy] = useState(
    initial && (initial.kind === "socks5" || initial.kind === "httpConnect") ? initial.proxy : "",
  );
  const [proxyCredential, setProxyCredential] = useState(
    initial && (initial.kind === "socks5" || initial.kind === "httpConnect") ? (initial.credential ?? "") : "",
  );
  const [proxyUsername, setProxyUsername] = useState(
    initial && (initial.kind === "socks5" || initial.kind === "httpConnect") ? (initial.username ?? "") : "",
  );
  const [command, setCommand] = useState(initial?.kind === "command" ? initial.command : "");
  const [gatewayNetwork, setGatewayNetwork] = useState(initial?.kind === "managed" ? initial.gatewayNetwork : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const managed = kind === "managed" || existing?.definition.kind === "managed";
  const save = async () => {
    let definition: RouteDefinition;
    if (kind === "jump")
      definition = {
        kind,
        hops: hops.map((item) => item.trim()).filter(Boolean),
      };
    else if (kind === "socks5" || kind === "httpConnect")
      definition = {
        kind,
        proxy,
        credential: proxyCredential || null,
        username: proxyCredential ? proxyUsername : null,
      };
    else if (kind === "command") definition = { kind, command };
    else definition = { kind: "managed", gatewayNetwork };
    setBusy(true);
    setError(null);
    const result = id ? await api.updateRoute(id, { name, definition }) : await api.createRoute({ name, definition });
    setBusy(false);
    if (result.status === "ok") onSaved(id ? t("objects.save") : t("objects.add.route"));
    else setError(objectErrorText(t, result.error));
  };
  const credentialOptions =
    credentials.state === "ready"
      ? credentials.data
          .filter((credential) => credential.kind === "password")
          .map((credential) => ({
            value: credential.id,
            label: credential.name ?? credentialKindText(t, credential.kind),
          }))
      : [];
  return (
    <EditorDialog
      title={id ? t("objects.edit", { name: existing?.name ?? t("objects.route.new") }) : t("objects.route.new")}
      description={t("objects.routes.description")}
      busy={busy}
      error={error}
      onClose={onClose}
      onSave={() => void save()}
      canSave={!managed}
    >
      <Field label={t("objects.route.name")} value={name} onChange={(event) => setName(event.target.value)} />
      <SelectField
        label={t("objects.route.kind")}
        value={kind}
        disabled={Boolean(existing?.definition.kind === "managed")}
        onChange={(next) => setKind(next as RouteDefinition["kind"])}
        options={(["jump", "socks5", "httpConnect", "command"] as RouteDefinition["kind"][]).map((value) => ({
          value,
          label: routeKindText(t, value),
        }))}
      />
      {kind === "jump" ? (
        <div className="flex flex-col gap-2">
          <p className="m-0 text-sm font-medium text-foreground">{t("objects.route.hops")}</p>
          <p className="m-0 text-sm text-muted-foreground">{t("objects.route.hopsHint")}</p>
          {(hops.length > 0 ? hops : [""]).map((hop, index) => (
            <div key={`${index}-${hop}`} className="flex items-end gap-2">
              <div className="min-w-0 flex-1">
                <SelectField
                  label={t("objects.route.hop", { number: index + 1 })}
                  value={hop}
                  onChange={(next) =>
                    setHops((current) => {
                      const nextHops = current.length > 0 ? [...current] : [""];
                      nextHops[index] = next;
                      return nextHops;
                    })
                  }
                  options={[
                    { value: "", label: t("objects.route.selectHop") },
                    ...(profiles.state === "ready"
                      ? profiles.data
                          .filter((profile) => !profile.orphaned)
                          .map((profile) => ({
                            value: profile.id,
                            label: `${profile.name ?? profile.username} · ${profile.hostName ?? profile.host}`,
                          }))
                      : []),
                  ]}
                />
              </div>
              {hops.length > 0 ? (
                <Button
                  variant="ghost"
                  type="button"
                  onClick={() => setHops((current) => current.filter((_, item) => item !== index))}
                  aria-label={t("objects.route.removeHop", { number: index + 1 })}
                >
                  {t("objects.route.removeHop", { number: index + 1 })}
                </Button>
              ) : null}
            </div>
          ))}
          <Button variant="ghost" type="button" onClick={() => setHops((current) => [...current, ""])}>
            {t("objects.route.addHop")}
          </Button>
        </div>
      ) : null}
      {kind === "socks5" || kind === "httpConnect" ? (
        <>
          <Field
            label={t("objects.route.proxy")}
            value={proxy}
            onChange={(event) => setProxy(event.target.value)}
            placeholder="proxy.example.com:1080"
          />
          <SelectField
            label={t("objects.route.proxyCredential")}
            value={proxyCredential}
            onChange={(next) => {
              setProxyCredential(next);
              if (!next) setProxyUsername("");
            }}
            options={[{ value: "", label: t("objects.route.noCredential") }, ...credentialOptions]}
          />
          {proxyCredential ? (
            <>
              <Field
                label={t("objects.route.proxyUsername")}
                value={proxyUsername}
                onChange={(event) => setProxyUsername(event.target.value)}
                autoComplete="username"
              />
              <p className="m-0 text-xs text-muted-foreground">{t("objects.route.proxyAuthNotice")}</p>
            </>
          ) : null}
        </>
      ) : null}
      {kind === "command" ? (
        <Field
          label={t("objects.route.command")}
          value={command}
          onChange={(event) => setCommand(event.target.value)}
          placeholder="ssh -W %h:%p jump"
        />
      ) : null}
      {kind === "managed" ? (
        <Field
          label={t("objects.route.gatewayNetwork")}
          value={gatewayNetwork}
          onChange={(event) => setGatewayNetwork(event.target.value)}
          hint={t("objects.route.managedHint")}
          disabled
        />
      ) : null}
      {managed ? <p className="m-0 text-sm text-muted-foreground">{t("objects.route.managedHint")}</p> : null}
    </EditorDialog>
  );
}

type Translator = ReturnType<typeof useI18n>["t"];

function credentialKindText(t: Translator, kind: CredentialKindInput): string {
  switch (kind) {
    case "password":
      return t("objects.credential.kind.password");
    case "key":
      return t("objects.credential.kind.key");
    case "certificate":
      return t("objects.credential.kind.certificate");
    case "agent":
      return t("objects.credential.kind.agent");
    case "securityKey":
      return t("objects.credential.kind.securityKey");
    case "deviceKey":
      return t("objects.credential.kind.deviceKey");
    case "external":
      return t("objects.credential.kind.external");
  }
}

function credentialBindingText(t: Translator, binding: CredentialBindingInput): string {
  switch (binding) {
    case "shared":
      return t("objects.credential.binding.shared");
    case "device":
      return t("objects.credential.binding.device");
    case "none":
      return t("objects.credential.binding.none");
  }
}

function credentialBindings(kind: CredentialKindInput): CredentialBindingInput[] {
  switch (kind) {
    case "password":
    case "key":
      return ["shared", "device"];
    case "certificate":
    case "securityKey":
      return ["device", "none"];
    case "deviceKey":
      return ["device", "none"];
    case "agent":
    case "external":
      return ["none"];
  }
}

function routeKindText(t: Translator, kind: RouteDefinition["kind"]): string {
  switch (kind) {
    case "jump":
      return t("objects.route.kind.jump");
    case "socks5":
      return t("objects.route.kind.socks5");
    case "httpConnect":
      return t("objects.route.kind.httpConnect");
    case "command":
      return t("objects.route.kind.command");
    case "managed":
      return t("objects.route.kind.managed");
  }
}

function forwardKindText(t: Translator, kind: ForwardSummary["kind"]): string {
  switch (kind) {
    case "local":
      return t("objects.forward.kind.local");
    case "remote":
      return t("objects.forward.kind.remote");
    case "dynamic":
      return t("objects.forward.kind.dynamic");
  }
}

function objectErrorText(t: Translator, error: ObjectEditError): string {
  switch (error.kind) {
    case "invalidId":
      return t("objects.error.invalidId");
    case "notFound":
      return t("objects.error.notFound");
    case "emptyName":
      return t("objects.error.emptyName");
    case "emptyUsername":
      return t("objects.error.emptyUsername");
    case "textTooLong":
      return t("objects.error.textTooLong", { field: error.field });
    case "invalidCredential":
      return t("objects.error.invalidCredential");
    case "invalidRoute":
      return t("objects.error.invalidRoute");
    case "invalidProxy":
      return t("objects.error.invalidProxy");
    case "invalidProxyAuthentication":
      return t("objects.error.invalidProxyAuthentication");
    case "invalidCommand":
      return t("objects.error.invalidCommand");
    case "invalidCredentialBinding":
      return t("objects.error.invalidCredentialBinding");
    case "secretRequired":
      return t("objects.error.secretRequired");
    case "secretNotAllowed":
      return t("objects.error.secretNotAllowed");
    case "inUse":
      return t("objects.error.inUse");
    case "defaultProfile":
      return t("objects.error.defaultProfile");
    case "managedRoute":
      return t("objects.error.managedRoute");
    case "failed":
      return t("startup.error.reference", { reference: error.reference });
  }
  return t("failed.body");
}
