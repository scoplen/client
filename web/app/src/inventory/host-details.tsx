// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field, HostEgg, IconButton, Tag, TextAreaField } from "@scoplen/ui";
import { Pencil, Plus, X } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { useI18n } from "../i18n";
import {
  useInventory,
  type CredentialLabel,
  type EditHostError,
  type GroupError,
  type GroupInput,
  type GroupSummary,
  type HostDetails,
  type Id,
  type LoginSummary,
} from "./api";
import { credentialText, routeText } from "./labels";
import { useLoad } from "./use-load";

/** Everything about one host, beside the list. */
export function HostDetailsPanel({
  id,
  groups,
  onClose,
  onDelete,
  onConnect,
}: {
  id: Id;
  groups: GroupSummary[];
  onClose: () => void;
  onDelete: (host: HostDetails) => void;
  onConnect?: (profileId: Id, label: string) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const details = useLoad(() => api.host(id), id);
  const [editing, setEditing] = useState(false);

  return (
    <aside
      aria-labelledby="host-details-title"
      className="scoplen-slide-in flex w-[22rem] shrink-0 flex-col border-l-(length:--scoplen-border-width) border-border bg-raised max-lg:absolute max-lg:inset-y-0 max-lg:right-0 max-lg:z-20 max-lg:shadow-(--scoplen-shadow-overlay)"
    >
      <div className="flex items-start gap-3 px-5 pt-6">
        {details.state === "ready" && details.data ? (
          <HostEgg
            key={details.data.id}
            seed={details.data.id}
            active
            size="2.75rem"
            className="scoplen-hop-in -mt-1"
          />
        ) : null}
        <div className="min-w-0 flex-1">
          {details.state === "ready" && details.data ? (
            <>
              <h2 id="host-details-title" className="ui-display m-0 text-xl break-words">
                {details.data.name}
              </h2>
              <p className="mt-0.5 mb-0 font-mono text-xs break-all text-muted-foreground">
                {details.data.address}
                {details.data.port !== 22 ? `:${details.data.port}` : ""}
              </p>
            </>
          ) : (
            <h2 id="host-details-title" className="sr-only">
              {t("hosts.loading")}
            </h2>
          )}
        </div>
        <IconButton label={t("host.close")} onClick={onClose} className="-mr-2">
          <X aria-hidden="true" className="size-4" />
        </IconButton>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
        {details.state === "failed" ? (
          <p role="alert" className="text-sm text-attention">
            {t("failed.body")} {t("startup.error.reference", { reference: details.reference })}
          </p>
        ) : null}
        {details.state === "ready" && details.data === null ? (
          <p className="text-sm text-muted-foreground">{t("host.missing")}</p>
        ) : null}
        {details.state === "ready" && details.data ? (
          <Body host={details.data} groups={groups} onConnect={onConnect} />
        ) : null}
      </div>

      {details.state === "ready" && details.data ? (
        <div className="flex items-center gap-1 border-t-(length:--scoplen-border-width) border-border px-4 py-3">
          <Button variant="ghost" className="gap-1.5" onClick={() => setEditing(true)}>
            <Pencil aria-hidden="true" className="size-4" />
            {t("host.edit")}
          </Button>
          <Button
            variant="ghost"
            className="ml-auto text-attention hover:bg-[color-mix(in_srgb,var(--attention)_10%,transparent)]"
            onClick={() => onDelete(details.data!)}
          >
            {t("host.delete")}
          </Button>
        </div>
      ) : null}
      {details.state === "ready" && details.data ? (
        <EditHostDialog
          key={`${details.data.id}:${editing ? "open" : "closed"}`}
          open={editing}
          onOpenChange={setEditing}
          host={details.data}
          groups={groups}
        />
      ) : null}
    </aside>
  );
}

function EditHostDialog({
  open,
  onOpenChange,
  host,
  groups,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  host: HostDetails;
  groups: GroupSummary[];
}) {
  const { t } = useI18n();
  const api = useInventory();
  const [name, setName] = useState(host.name);
  const [address, setAddress] = useState(host.address);
  const [port, setPort] = useState(String(host.port));
  const [notes, setNotes] = useState(host.notes ?? "");
  const [tags, setTags] = useState(formatTags(host.tags));
  const [selectedGroups, setSelectedGroups] = useState<string[]>(host.groups);
  const [availableGroups, setAvailableGroups] = useState(groups);
  const [groupDialog, setGroupDialog] = useState<{ id?: string } | null>(null);
  const [problem, setProblem] = useState<EditProblem | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const portNumber = Number(port);
    if (!name.trim()) return setProblem({ field: "name", message: t("host.edit.error.emptyName") });
    if (!address.trim() || /\s/.test(address)) {
      return setProblem({ field: "address", message: t("host.edit.error.invalidAddress") });
    }
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
      return setProblem({ field: "port", message: t("host.edit.error.invalidPort") });
    }
    const parsed = parseTags(tags);
    if (parsed.error) return setProblem({ field: "tags", message: t("host.edit.error.invalidTag") });
    setProblem(null);
    setBusy(true);
    const outcome = await api.updateHost(host.id, {
      name: name.trim(),
      address: address.trim(),
      port: portNumber,
      notes: notes.trim() || null,
      tags: parsed.tags,
      groups: selectedGroups,
    });
    setBusy(false);
    if (outcome.status === "ok") {
      onOpenChange(false);
    } else {
      setProblem(errorForEdit(t, outcome.error));
    }
  };

  const onGroupSaved = (group: GroupSummary, created: boolean) => {
    setAvailableGroups((current) => {
      const without = current.filter((item) => item.id !== group.id);
      return [...without, group];
    });
    if (created) setSelectedGroups((current) => (current.includes(group.id) ? current : [...current, group.id]));
    setGroupDialog(null);
  };

  return (
    <>
      <Dialog
        open={open}
        onOpenChange={onOpenChange}
        title={t("host.edit.title")}
        description={t("host.edit.description")}
        closeLabel={t("host.close")}
        footer={
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
              {t("host.edit.cancel")}
            </Button>
            <Button variant="primary" type="submit" form="edit-host" busy={busy}>
              {t("host.edit.save")}
            </Button>
          </>
        }
      >
        <form id="edit-host" onSubmit={(event) => void submit(event)} noValidate className="flex flex-col gap-4">
          <Field
            label={t("host.edit.name")}
            value={name}
            onChange={(event) => setName(event.target.value)}
            error={problem?.field === "name" ? problem.message : undefined}
            autoFocus
          />
          <Field
            label={t("host.edit.address")}
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            error={problem?.field === "address" ? problem.message : undefined}
            className="[&_input]:font-mono"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <Field
            label={t("host.edit.port")}
            value={port}
            onChange={(event) => setPort(event.target.value)}
            error={problem?.field === "port" ? problem.message : undefined}
            inputMode="numeric"
            className="[&_input]:font-mono"
          />
          <TextAreaField
            label={t("host.edit.notes")}
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            error={problem?.field === "notes" ? problem.message : undefined}
          />
          <TextAreaField
            label={t("host.edit.tags")}
            hint={t("host.edit.tagsHint")}
            value={tags}
            onChange={(event) => setTags(event.target.value)}
            error={problem?.field === "tags" ? problem.message : undefined}
          />
          <fieldset className="m-0 flex flex-col gap-2 border-0 p-0">
            <legend className="text-sm font-medium">{t("host.edit.groups")}</legend>
            {availableGroups.map((group) => (
              <div key={group.id} className="flex items-center gap-2 text-sm">
                <label htmlFor={`host-group-${group.id}`} className="flex min-w-0 flex-1 items-center gap-2">
                  <input
                    id={`host-group-${group.id}`}
                    type="checkbox"
                    checked={selectedGroups.includes(group.id)}
                    onChange={(event) =>
                      setSelectedGroups((current) =>
                        event.target.checked ? [...current, group.id] : current.filter((id) => id !== group.id),
                      )
                    }
                    className="size-4 accent-[var(--primary)]"
                  />
                  <span className="min-w-0 truncate">{group.name}</span>
                </label>
                <button
                  type="button"
                  aria-label={t("host.edit.groupEditButton", { name: group.name })}
                  className="shrink-0 text-xs text-primary hover:underline"
                  onClick={() => setGroupDialog({ id: group.id })}
                >
                  {t("host.edit.groupEdit")}
                </button>
              </div>
            ))}
            <Button type="button" variant="ghost" className="-ml-3 w-fit gap-1.5" onClick={() => setGroupDialog({})}>
              <Plus aria-hidden="true" className="size-4" />
              {t("host.edit.groupCreate")}
            </Button>
          </fieldset>
          {problem?.field === "form" ? (
            <p role="alert" className="m-0 text-sm text-attention">
              {problem.message}
            </p>
          ) : null}
        </form>
      </Dialog>
      {groupDialog ? (
        <GroupDialog
          key={groupDialog.id ?? "new"}
          open
          group={availableGroups.find((group) => group.id === groupDialog.id)}
          groups={availableGroups}
          onOpenChange={(next) => !next && setGroupDialog(null)}
          onSaved={onGroupSaved}
        />
      ) : null}
    </>
  );
}

type EditProblem = { field: "name" | "address" | "port" | "notes" | "tags" | "groups" | "form"; message: string };

function errorForEdit(t: ReturnType<typeof useI18n>["t"], error: EditHostError): EditProblem {
  switch (error.kind) {
    case "emptyName":
      return { field: "name", message: t("host.edit.error.emptyName") };
    case "invalidAddress":
      return { field: "address", message: t("host.edit.error.invalidAddress") };
    case "invalidPort":
      return { field: "port", message: t("host.edit.error.invalidPort") };
    case "notesTooLong":
      return { field: "notes", message: t("host.edit.error.notesTooLong") };
    case "invalidTag":
      return { field: "tags", message: t("host.edit.error.invalidTag") };
    case "groupNotFound":
      return { field: "groups", message: t("host.edit.error.groupNotFound") };
    case "failed":
      return {
        field: "form",
        message: `${t("failed.body")} ${t("startup.error.reference", { reference: error.reference })}`,
      };
  }
}

function formatTags(tags: Record<string, string>): string {
  return Object.entries(tags)
    .map(([key, value]) => (value ? `${key}=${value}` : key))
    .join("\n");
}

function parseTags(value: string): { tags: Record<string, string>; error?: true } {
  const tags: Record<string, string> = {};
  for (const line of value.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    const key = (separator < 0 ? trimmed : trimmed.slice(0, separator)).trim();
    const tagValue = separator < 0 ? "" : trimmed.slice(separator + 1).trim();
    if (!key || key in tags) return { tags, error: true };
    tags[key] = tagValue;
  }
  return { tags };
}

function GroupDialog({
  open,
  group,
  groups,
  onOpenChange,
  onSaved,
}: {
  open: boolean;
  group?: GroupSummary;
  groups: GroupSummary[];
  onOpenChange: (open: boolean) => void;
  onSaved: (group: GroupSummary, created: boolean) => void;
}) {
  const { t } = useI18n();
  const api = useInventory();
  const [name, setName] = useState(group?.name ?? "");
  const [parent, setParent] = useState(group?.parent ?? "");
  const [problem, setProblem] = useState<string>();
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) return setProblem(t("host.edit.groupError.emptyName"));
    setBusy(true);
    const input: GroupInput = { name: name.trim(), parent: parent || null };
    const outcome = group ? await api.updateGroup(group.id, input) : await api.createGroup(input);
    setBusy(false);
    if (outcome.status === "ok") onSaved(outcome.data, !group);
    else setProblem(groupErrorText(t, outcome.error));
  };
  const parentOptions = groups.filter((candidate) => candidate.id !== group?.id);
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={group ? t("host.edit.groupEditTitle") : t("host.edit.groupCreateTitle")}
      closeLabel={t("host.close")}
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            {t("host.edit.cancel")}
          </Button>
          <Button variant="primary" type="submit" form="edit-group" busy={busy}>
            {t("host.edit.save")}
          </Button>
        </>
      }
    >
      <form id="edit-group" onSubmit={(event) => void submit(event)} noValidate className="flex flex-col gap-4">
        <Field
          label={t("host.edit.groupName")}
          value={name}
          onChange={(event) => setName(event.target.value)}
          error={problem}
          autoFocus
        />
        <label className="flex flex-col gap-1.5 text-sm font-medium" htmlFor="group-parent">
          {t("host.edit.groupParent")}
          <select
            id="group-parent"
            value={parent}
            onChange={(event) => setParent(event.target.value)}
            className="ui-input h-10 px-3 text-sm font-normal"
          >
            <option value="">{t("host.edit.groupNoParent")}</option>
            {parentOptions.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.name}
              </option>
            ))}
          </select>
        </label>
      </form>
    </Dialog>
  );
}

function groupErrorText(t: ReturnType<typeof useI18n>["t"], error: GroupError): string {
  switch (error.kind) {
    case "emptyName":
      return t("host.edit.groupError.emptyName");
    case "parentNotFound":
      return t("host.edit.groupError.parentNotFound");
    case "selfParent":
      return t("host.edit.groupError.selfParent");
    case "failed":
      return `${t("failed.body")} ${t("startup.error.reference", { reference: error.reference })}`;
  }
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-6 last:mb-0">
      <h3 className="mt-0 mb-2 text-[0.6875rem] font-semibold tracking-wide text-muted-foreground uppercase">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Body({
  host,
  groups,
  onConnect,
}: {
  host: HostDetails;
  groups: GroupSummary[];
  onConnect?: (profileId: Id, label: string) => void;
}) {
  const { t } = useI18n();
  const tags = Object.entries(host.tags);
  const memberOf = groups.filter((g) => host.groups.includes(g.id));

  return (
    <>
      {host.logins.length === 1 ? (
        <Section title={t("host.login")}>
          <LoginLine login={host.logins[0]!} hostName={host.name} onConnect={onConnect} />
        </Section>
      ) : host.logins.length > 1 ? (
        <Section title={t("host.logins")}>
          <ul className="m-0 flex list-none flex-col gap-2 p-0">
            {host.logins.map((login) => (
              <li key={login.id}>
                <LoginLine login={login} hostName={host.name} onConnect={onConnect} />
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      {tags.length > 0 ? (
        <Section title={t("host.tags")}>
          <div className="flex flex-wrap gap-1.5">
            {tags.map(([key, value]) => (
              <Tag key={key}>{value ? `${key}: ${value}` : key}</Tag>
            ))}
          </div>
        </Section>
      ) : null}

      {memberOf.length > 0 ? (
        <Section title={t("host.groups")}>
          <p className="m-0 text-sm">{memberOf.map((g) => g.name).join(", ")}</p>
        </Section>
      ) : null}

      {host.notes ? (
        <Section title={t("host.notes")}>
          <p className="m-0 text-sm whitespace-pre-wrap">{host.notes}</p>
        </Section>
      ) : null}
    </>
  );
}

function LoginLine({
  login,
  hostName,
  onConnect,
}: {
  login: LoginSummary;
  hostName: string;
  onConnect?: (profileId: Id, label: string) => void;
}) {
  const { t } = useI18n();
  const label = `${hostName} · ${login.name ?? login.username}`;
  return (
    <div className="flex flex-col gap-0.5 rounded-lg border-(length:--scoplen-border-width) border-border bg-background px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-mono text-sm">{login.name ?? login.username}</span>
          {login.isDefault && login.name ? (
            <span className="shrink-0 text-xs text-muted-foreground">{t("host.default")}</span>
          ) : null}
        </span>
        {onConnect ? (
          <Button variant="primary" className="h-8 shrink-0 px-3.5 text-xs" onClick={() => onConnect(login.id, label)}>
            {t("session.connect")}
          </Button>
        ) : null}
      </div>
      <span className="text-xs text-muted-foreground">
        {credentialText(t, login.credential)} · {routeText(t, login.route)}
      </span>
      {login.credential?.publicKey ? <CopyPublicKey credential={login.credential} /> : null}
    </div>
  );
}

/**
 * The public half of a key, for adding to a host's `authorized_keys`.
 * Copying is the whole task, so the key itself is not shown.
 */
function CopyPublicKey({ credential }: { credential: CredentialLabel }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={t("host.publicKey.hint")}
      onClick={() =>
        void navigator.clipboard.writeText(credential.publicKey ?? "").then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        })
      }
      className="mt-1 self-start rounded text-xs text-primary hover:underline"
    >
      <span aria-live="polite">{copied ? t("host.publicKey.copied") : t("host.publicKey.copy")}</span>
    </button>
  );
}
