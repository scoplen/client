// SPDX-License-Identifier: Apache-2.0
import { Button, Field, TextAreaField } from "@scoplen/ui";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type {
  TeamAuthoringCollection,
  TeamAuthoringData,
  TeamMemberView,
  TeamSimpleRulePreview,
  TeamSummary,
} from "./ipc/bindings";
import {
  assetCollections,
  collectionLabel,
  resourceName,
  TeamCheck,
  TeamSelect,
  type TeamReferences,
} from "./team-authoring-fields";

export function TeamRuleForm({
  team,
  references,
  members,
  moreMembers,
  loadMembers,
  loadMore,
  disabled,
  onSave,
}: {
  team: TeamSummary;
  references: TeamReferences;
  members: TeamMemberView[];
  moreMembers: boolean;
  loadMembers: () => void;
  loadMore: (kind: TeamAuthoringCollection) => void;
  disabled: boolean;
  onSave: (data: TeamAuthoringData) => void;
}) {
  const { t } = useI18n();
  const commands = useProfileCommands();
  const [name, setName] = useState("");
  const [subjectKind, setSubjectKind] = useState("member");
  const [subject, setSubject] = useState("");
  const [permission, setPermission] = useState<"view" | "connect">("view");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [remoteUser, setRemoteUser] = useState("");
  const [preview, setPreview] = useState<TeamSimpleRulePreview | null>(null);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const active = useRef(true);
  const revision = useRef(0);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const changed = () => {
    revision.current++;
    setPreview(null);
    setFailed(false);
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (disabled || busy || !subject || !selected.size) return;
    const captured = ++revision.current;
    setBusy(true);
    setFailed(false);
    setPreview(null);
    try {
      const result = await commands.previewTeamSimpleRule(team.id, {
        membershipId: subjectKind === "member" ? subject : null,
        groupId: subjectKind === "group" ? subject : null,
        permission,
        remoteUser: permission === "connect" ? remoteUser : null,
        resources: [...selected].map((value) => {
          const separator = value.indexOf(":");
          return {
            collection: value.slice(0, separator) as TeamAuthoringCollection,
            id: value.slice(separator + 1),
          };
        }),
      });
      if (!active.current || captured !== revision.current) return;
      if (result.status === "ok") setPreview(result.data);
      else setFailed(true);
    } catch {
      if (active.current && captured === revision.current) setFailed(true);
    } finally {
      if (active.current) setBusy(false);
    }
  };
  const subjectOptions =
    subjectKind === "member"
      ? members
          .filter((member) => member.status === "active")
          .map((member) => ({ value: member.id, label: member.username }))
      : (references.group?.items ?? [])
          .filter((group) => !group.readOnly)
          .map((group) => ({ value: group.id, label: resourceName(group) }));
  return (
    <form onSubmit={(event) => void submit(event)} className="space-y-5" aria-busy={busy}>
      <Field
        label={t("teams.authoring.ruleName")}
        value={name}
        required
        maxLength={128}
        onChange={(event) => setName(event.target.value)}
      />
      <TeamSelect
        label={t("teams.authoring.subject")}
        value={subjectKind}
        onChange={(value) => {
          setSubjectKind(value);
          setSubject("");
          changed();
        }}
        options={[
          { value: "member", label: t("teams.authoring.member") },
          { value: "group", label: t("teams.authoring.group") },
        ]}
      />
      <TeamSelect
        label={t(subjectKind === "member" ? "teams.authoring.member" : "teams.authoring.group")}
        value={subject}
        required
        onChange={(value) => {
          setSubject(value);
          changed();
        }}
        options={[{ value: "", label: t("teams.authoring.select") }, ...subjectOptions]}
      />
      {(subjectKind === "member" ? moreMembers : references.group?.more) ? (
        <Button
          type="button"
          variant="ghost"
          onClick={() => (subjectKind === "member" ? loadMembers() : loadMore("group"))}
        >
          {t("teams.authoring.more")}
        </Button>
      ) : null}
      <TeamSelect
        label={t("teams.authoring.permission")}
        value={permission}
        onChange={(value) => {
          setPermission(value as "view" | "connect");
          setSelected(new Set());
          changed();
        }}
        options={[
          { value: "view", label: t("teams.authoring.view") },
          { value: "connect", label: t("teams.authoring.connect") },
        ]}
      />
      {permission === "connect" ? (
        <>
          <Field
            label={t("teams.authoring.username")}
            value={remoteUser}
            required
            onChange={(event) => {
              setRemoteUser(event.target.value);
              changed();
            }}
          />
          <p className="text-sm text-muted-foreground">{t("teams.authoring.connectNotice")}</p>
        </>
      ) : null}
      <fieldset className="min-w-0 space-y-4 border-0 p-0">
        <legend className="mb-2 text-sm font-medium">{t("teams.authoring.ruleAssets")}</legend>
        {(permission === "connect" ? (["host", "hostGroup"] as const) : assetCollections).map((kind) => (
          <section key={kind}>
            <h3 className="text-sm font-medium">{collectionLabel(t, kind)}</h3>
            {!references[kind] ? (
              <p role="status" className="text-sm text-muted-foreground">
                {t("teams.authoring.loading")}
              </p>
            ) : null}
            {references[kind]?.items.map((resource) => (
              <TeamCheck
                key={resource.id}
                label={resourceName(resource)}
                checked={selected.has(`${kind}:${resource.id}`)}
                onChange={(enabled) => {
                  setSelected((old) => {
                    const next = new Set(old);
                    if (enabled) next.add(`${kind}:${resource.id}`);
                    else next.delete(`${kind}:${resource.id}`);
                    return next;
                  });
                  changed();
                }}
              />
            ))}
            {references[kind]?.more ? (
              <Button type="button" variant="ghost" onClick={() => loadMore(kind)}>
                {t("teams.authoring.more")}
              </Button>
            ) : null}
          </section>
        ))}
      </fieldset>
      <Button type="submit" variant="secondary" disabled={disabled || busy || !subject || !selected.size}>
        {t("teams.authoring.preview")}
      </Button>
      {failed ? (
        <p role="alert" className="text-sm text-attention">
          {t("teams.authoring.invalid")}
        </p>
      ) : null}
      {preview ? (
        <section className="space-y-4 border-t border-border pt-4">
          <p className="text-sm text-muted-foreground">{t("teams.authoring.previewNotice")}</p>
          <TextAreaField
            label={t("teams.authoring.source")}
            value={preview.source}
            readOnly
            rows={12}
            className="font-mono"
          />
          {permission === "view" ? (
            <>
              <p className="text-sm text-muted-foreground">{t("teams.authoring.dependencyNotice")}</p>
              {preview.dependencies.length ? (
                <div>
                  <h3 className="text-sm font-medium">{t("teams.authoring.dependencies")}</h3>
                  <ul className="space-y-2 pl-4 text-xs text-muted-foreground">
                    {preview.dependencies.map((dependency) => (
                      <li key={`${dependency.collection}:${dependency.id}`} className="break-all">
                        {collectionLabel(t, dependency.collection)} · {dependency.id}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </>
          ) : null}
          <Button
            type="button"
            variant="primary"
            disabled={disabled || busy || !name}
            onClick={() => onSave({ kind: "policy", fields: { name, source: preview.source, enabled: true } })}
          >
            {t("teams.authoring.create")}
          </Button>
        </section>
      ) : null}
    </form>
  );
}
