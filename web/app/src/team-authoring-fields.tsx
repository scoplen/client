// SPDX-License-Identifier: Apache-2.0
import { Button, Field, TextAreaField } from "@scoplen/ui";
import { useId, useRef, useState } from "react";
import { useI18n } from "./i18n";
import type {
  TeamAuthoringCollection,
  TeamAuthoringData,
  TeamAuthoringResourceView,
  TeamMemberView,
  TeamSnippetVariable,
} from "./ipc/bindings";

type T = ReturnType<typeof useI18n>["t"];
export const assetCollections = [
  "host",
  "login",
  "hostGroup",
  "route",
  "trustRecord",
  "snippet",
  "gatewayNetwork",
] as const;

export function collectionLabel(t: T, kind: TeamAuthoringCollection) {
  const keys = {
    host: "teams.assets.kind.host",
    login: "teams.assets.kind.login",
    hostGroup: "teams.assets.kind.group",
    route: "teams.assets.kind.route",
    trustRecord: "teams.assets.kind.trust",
    snippet: "teams.assets.kind.snippet",
    gatewayNetwork: "teams.assets.kind.gateway",
    group: "teams.authoring.group",
    policy: "teams.authoring.policy",
  } as const;
  return t(keys[kind]);
}

export function resourceName(resource: TeamAuthoringResourceView) {
  const fields = resource.data.fields;
  return (
    ("name" in fields && fields.name) ||
    ("username" in fields && fields.username) ||
    ("fingerprint" in fields && fields.fingerprint) ||
    resource.id
  );
}

export function emptyTeamData(kind: TeamAuthoringCollection): TeamAuthoringData {
  switch (kind) {
    case "host":
      return { kind, fields: { address: "", port: 22 } };
    case "login":
      return { kind, fields: { host: "", username: "", route: 0 } };
    case "hostGroup":
      return { kind, fields: { name: "" } };
    case "route":
      return { kind, fields: { name: "", kind: 1, hops: [] } };
    case "trustRecord":
      return { kind, fields: { key: "", fingerprint: "", provenance: 1 } };
    case "snippet":
      return { kind, fields: { name: "", template: "" } };
    case "gatewayNetwork":
      return { kind, fields: { name: "" } };
    case "group":
      return { kind, fields: { name: "", members: [] } };
    case "policy":
      return { kind, fields: { name: "", source: "", enabled: true } };
  }
}

export function TeamSelect({
  label,
  value,
  onChange,
  options,
  required = false,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  required?: boolean;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <select
        id={id}
        className="ui-input h-10 min-w-0 max-w-full px-3 text-sm"
        value={value}
        required={required}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function TeamCheck({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="flex min-h-10 cursor-pointer items-center gap-2 break-words text-sm [overflow-wrap:anywhere]">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

function MapFields({
  label,
  value,
  onChange,
  onValid,
  set = false,
}: {
  label: string;
  value: Record<string, string | boolean> | null | undefined;
  set?: boolean;
  onChange: (value: Record<string, string | boolean>) => void;
  onValid: (valid: boolean) => void;
}) {
  const { t } = useI18n();
  const nextId = useRef(Object.keys(value ?? {}).length);
  const [rows, setRows] = useState(() =>
    Object.entries(value ?? {}).map(([key, value], id) => ({ id, key, value: String(value) })),
  );
  const valid = rows.every(
    (row, index) => row.key.length > 0 && rows.findIndex((other) => other.key === row.key) === index,
  );
  const change = (next: typeof rows) => {
    setRows(next);
    const valid = next.every(
      (row, index) => row.key.length > 0 && next.findIndex((other) => other.key === row.key) === index,
    );
    onValid(valid);
    onChange(Object.fromEntries(next.map((row) => [row.key, set ? true : row.value])));
  };
  return (
    <fieldset className="min-w-0 space-y-3 border-0 p-0">
      <legend className="mb-2 text-sm font-medium">{label}</legend>
      {rows.map((row, index) => (
        <div key={row.id} className="space-y-2 border-l-2 border-border pl-3">
          <div className={set ? "" : "grid gap-2 sm:grid-cols-2"}>
            <Field
              label={`${t("teams.authoring.mapKey")} ${index + 1}`}
              value={row.key}
              required
              onChange={(event) =>
                change(rows.map((item) => (item.id === row.id ? { ...item, key: event.target.value } : item)))
              }
            />
            {!set ? (
              <Field
                label={`${t("teams.authoring.mapValue")} ${index + 1}`}
                value={row.value}
                onChange={(event) =>
                  change(rows.map((item) => (item.id === row.id ? { ...item, value: event.target.value } : item)))
                }
              />
            ) : null}
          </div>
          <Button type="button" variant="ghost" onClick={() => change(rows.filter((item) => item.id !== row.id))}>
            {t("teams.authoring.removeRow", { number: index + 1 })}
          </Button>
        </div>
      ))}
      {!valid ? (
        <p role="alert" className="text-sm text-attention">
          {t("teams.authoring.duplicate")}
        </p>
      ) : null}
      <Button
        type="button"
        variant="secondary"
        onClick={() => change([...rows, { id: nextId.current++, key: "", value: "" }])}
      >
        {t("teams.authoring.addRow")}
      </Button>
    </fieldset>
  );
}

function Variables({
  value,
  onChange,
  onValid,
}: {
  value: Record<string, TeamSnippetVariable> | null | undefined;
  onChange: (value: Record<string, TeamSnippetVariable>) => void;
  onValid: (valid: boolean) => void;
}) {
  const { t } = useI18n();
  const nextId = useRef(Object.keys(value ?? {}).length);
  const [rows, setRows] = useState(() =>
    Object.entries(value ?? {}).map(([name, variable], id) => ({ id, name, variable })),
  );
  const valid = rows.every(
    (row, index) => row.name.length > 0 && rows.findIndex((other) => other.name === row.name) === index,
  );
  const change = (next: typeof rows) => {
    setRows(next);
    onValid(
      next.every((row, index) => row.name.length > 0 && next.findIndex((other) => other.name === row.name) === index),
    );
    onChange(Object.fromEntries(next.map((row) => [row.name, row.variable])));
  };
  return (
    <fieldset className="min-w-0 space-y-4 border-0 p-0">
      <legend className="mb-2 text-sm font-medium">{t("teams.authoring.variables")}</legend>
      {rows.map((row, index) => {
        const set = (variable: TeamSnippetVariable) =>
          change(rows.map((item) => (item.id === row.id ? { ...item, variable } : item)));
        return (
          <div key={row.id} className="space-y-3 border-l-2 border-border pl-3">
            <Field
              label={`${t("teams.authoring.name")} ${index + 1}`}
              value={row.name}
              required
              onChange={(event) =>
                change(rows.map((item) => (item.id === row.id ? { ...item, name: event.target.value } : item)))
              }
            />
            <TeamSelect
              label={t("teams.authoring.variableKind")}
              value={String(row.variable.kind)}
              onChange={(value) => set({ kind: Number(value), ...(value === "3" ? { choices: [] } : {}) })}
              options={[
                { value: "1", label: t("teams.authoring.text") },
                { value: "2", label: t("teams.authoring.integer") },
                { value: "3", label: t("teams.authoring.choice") },
                { value: "4", label: t("teams.authoring.secret") },
              ]}
            />
            {row.variable.kind === 4 ? (
              <p className="text-sm text-muted-foreground">{t("teams.authoring.secretNotice")}</p>
            ) : (
              <>
                <TeamCheck
                  label={t("teams.authoring.default")}
                  checked={row.variable.default != null}
                  onChange={(enabled) => set({ ...row.variable, default: enabled ? "" : undefined })}
                />
                {row.variable.default != null ? (
                  <Field
                    label={t("teams.authoring.default")}
                    value={row.variable.default}
                    onChange={(event) => set({ ...row.variable, default: event.target.value })}
                  />
                ) : null}
              </>
            )}
            {row.variable.kind === 3 ? (
              <TextAreaField
                label={t("teams.authoring.choices")}
                value={(row.variable.choices ?? []).join("\n")}
                onChange={(event) => set({ ...row.variable, choices: event.target.value.split("\n") })}
              />
            ) : null}
            <Button type="button" variant="ghost" onClick={() => change(rows.filter((item) => item.id !== row.id))}>
              {t("teams.authoring.removeRow", { number: index + 1 })}
            </Button>
          </div>
        );
      })}
      {!valid ? (
        <p role="alert" className="text-sm text-attention">
          {t("teams.authoring.duplicate")}
        </p>
      ) : null}
      <Button
        type="button"
        variant="secondary"
        onClick={() => change([...rows, { id: nextId.current++, name: "", variable: { kind: 1 } }])}
      >
        {t("teams.authoring.addRow")}
      </Button>
    </fieldset>
  );
}

export type TeamReferences = Partial<
  Record<TeamAuthoringCollection, { items: TeamAuthoringResourceView[]; more: boolean }>
>;

function Reference({
  label,
  kind,
  value,
  onChange,
  references,
  loadMore,
  required = false,
  empty,
}: {
  label: string;
  kind: TeamAuthoringCollection;
  value: string | null | undefined;
  onChange: (value: string | undefined) => void;
  references: TeamReferences;
  loadMore: (kind: TeamAuthoringCollection) => void;
  required?: boolean;
  empty?: string;
}) {
  const { t } = useI18n();
  const page = references[kind];
  const options = [
    { value: "", label: empty ?? t(required ? "teams.authoring.select" : "teams.authoring.none") },
    ...(page?.items ?? []).map((item) => ({ value: item.id, label: resourceName(item) })),
  ];
  if (value && !options.some((option) => option.value === value))
    options.push({ value, label: t("teams.authoring.unreadable", { id: value }) });
  return (
    <div className="space-y-2">
      <TeamSelect
        label={label}
        value={value ?? ""}
        onChange={(value) => onChange(value || undefined)}
        options={options}
        required={required}
      />
      {!page ? (
        <p role="status" className="text-xs text-muted-foreground">
          {t("teams.authoring.loading")}
        </p>
      ) : null}
      {page?.more ? (
        <Button variant="ghost" type="button" onClick={() => loadMore(kind)}>
          {t("teams.authoring.more")}
        </Button>
      ) : null}
    </div>
  );
}

function ReferenceSet({
  label,
  value,
  kind,
  references,
  onChange,
  loadMore,
}: {
  label: string;
  value: Record<string, boolean> | null | undefined;
  kind: TeamAuthoringCollection;
  references: TeamReferences;
  onChange: (value: Record<string, boolean>) => void;
  loadMore: (kind: TeamAuthoringCollection) => void;
}) {
  const { t } = useI18n();
  const page = references[kind];
  const items = (page?.items ?? []).map((item) => ({ id: item.id, name: resourceName(item) }));
  for (const id of Object.keys(value ?? {}))
    if (!items.some((item) => item.id === id)) items.push({ id, name: t("teams.authoring.unreadable", { id }) });
  return (
    <fieldset className="min-w-0 border-0 p-0">
      <legend className="mb-2 text-sm font-medium">{label}</legend>
      {!page ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("teams.authoring.loading")}
        </p>
      ) : null}
      {items.map((item) => (
        <TeamCheck
          key={item.id}
          label={item.name}
          checked={value?.[item.id] === true}
          onChange={(enabled) => {
            const next = { ...value };
            if (enabled) next[item.id] = true;
            onChange(enabled ? next : Object.fromEntries(Object.entries(next).filter(([id]) => id !== item.id)));
          }}
        />
      ))}
      {page?.more ? (
        <Button variant="ghost" type="button" onClick={() => loadMore(kind)}>
          {t("teams.authoring.more")}
        </Button>
      ) : null}
    </fieldset>
  );
}

export function TeamAuthoringFields({
  data,
  onChange,
  references,
  loadMore,
  members,
  moreMembers,
  loadMembers,
  onValid,
}: {
  data: TeamAuthoringData;
  onChange: (data: TeamAuthoringData) => void;
  references: TeamReferences;
  loadMore: (kind: TeamAuthoringCollection) => void;
  members: TeamMemberView[];
  moreMembers: boolean;
  loadMembers: () => void;
  onValid: (field: string, valid: boolean) => void;
}) {
  const { t } = useI18n();
  const optional = (value: string) => (value === "" ? undefined : value);
  const refs = { references, loadMore };
  switch (data.kind) {
    case "host": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={fields.name ?? ""}
            onChange={(event) => set({ name: optional(event.target.value) })}
          />
          <Field
            label={t("teams.authoring.address")}
            value={fields.address}
            required
            onChange={(event) => set({ address: event.target.value })}
          />
          <Field
            label={t("teams.authoring.port")}
            type="number"
            min={1}
            max={65535}
            value={fields.port ?? ""}
            onChange={(event) => set({ port: event.target.value ? Number(event.target.value) : undefined })}
          />
          <Reference
            label={t("teams.authoring.defaultLogin")}
            kind="login"
            value={fields.default_profile}
            onChange={(value) => set({ default_profile: value })}
            {...refs}
          />
          <ReferenceSet
            label={t("teams.authoring.hostGroups")}
            kind="hostGroup"
            value={fields.groups}
            onChange={(groups) => set({ groups })}
            {...refs}
          />
          <TextAreaField
            label={t("teams.authoring.notes")}
            value={fields.notes ?? ""}
            onChange={(event) => set({ notes: optional(event.target.value) })}
          />
          <TeamCheck
            label={t("teams.authoring.favorite")}
            checked={fields.favorite ?? false}
            onChange={(favorite) => set({ favorite })}
          />
          <MapFields
            label={t("teams.authoring.tags")}
            value={fields.tags}
            onChange={(tags) => set({ tags: tags as Record<string, string> })}
            onValid={(valid) => onValid("tags", valid)}
          />
          <details className="space-y-4">
            <summary className="cursor-pointer text-sm font-medium">{t("teams.authoring.sshOptions")}</summary>
            <MapFields
              label={t("teams.authoring.sshOptions")}
              value={fields.ssh_options}
              onChange={(value) => set({ ssh_options: value as Record<string, string> })}
              onValid={(valid) => onValid("ssh_options", valid)}
            />
            <MapFields
              label={t("teams.authoring.mosh")}
              value={fields.mosh}
              onChange={(value) => set({ mosh: value as Record<string, string> })}
              onValid={(valid) => onValid("mosh", valid)}
            />
          </details>
        </>
      );
    }
    case "login": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Reference
            label={t("teams.authoring.host")}
            kind="host"
            value={fields.host}
            onChange={(host) => set({ host: host ?? "" })}
            required
            {...refs}
          />
          <Field
            label={t("teams.authoring.name")}
            value={fields.name ?? ""}
            onChange={(event) => set({ name: optional(event.target.value) })}
          />
          <Field
            label={t("teams.authoring.username")}
            value={fields.username}
            required
            onChange={(event) => set({ username: event.target.value })}
          />
          <Reference
            label={t("teams.authoring.route")}
            kind="route"
            value={typeof fields.route === "string" ? fields.route : undefined}
            onChange={(route) => set({ route: route ?? 0 })}
            empty={t("teams.authoring.direct")}
            {...refs}
          />
          <p className="text-sm text-muted-foreground">{t("teams.authoring.teamSigner")}</p>
          <Field
            label={t("teams.authoring.terminalProfile")}
            value={fields.terminal_profile ?? ""}
            onChange={(event) => set({ terminal_profile: optional(event.target.value) })}
          />
          <Field
            label={t("teams.authoring.startup")}
            value={fields.startup_command ?? ""}
            onChange={(event) => set({ startup_command: optional(event.target.value) })}
          />
          <TeamCheck
            label={t("teams.authoring.agentForwarding")}
            checked={fields.agent_forwarding ?? false}
            onChange={(agent_forwarding) => set({ agent_forwarding })}
          />
        </>
      );
    }
    case "route": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={fields.name ?? ""}
            onChange={(event) => set({ name: optional(event.target.value) })}
          />
          <TeamSelect
            label={t("teams.authoring.routeKind")}
            value={String(fields.kind)}
            onChange={(value) =>
              onChange({
                kind: "route",
                fields: { name: fields.name, kind: Number(value), ...(value === "1" ? { hops: [] } : {}) },
              })
            }
            options={[
              { value: "1", label: t("teams.authoring.jump") },
              { value: "2", label: t("teams.authoring.socks") },
              { value: "3", label: t("teams.authoring.http") },
              { value: "4", label: t("teams.authoring.command") },
              { value: "5", label: t("teams.authoring.managed") },
            ]}
          />
          {fields.kind === 1 ? (
            <fieldset className="space-y-3 border-0 p-0">
              <legend className="mb-2 text-sm font-medium">{t("teams.authoring.hops")}</legend>
              {(fields.hops ?? []).map((hop, index) => (
                <div key={index} className="space-y-2">
                  <Reference
                    label={`${t("teams.assets.kind.login")} ${index + 1}`}
                    kind="login"
                    value={hop}
                    required
                    onChange={(value) =>
                      set({ hops: (fields.hops ?? []).map((old, item) => (item === index ? (value ?? "") : old)) })
                    }
                    {...refs}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => set({ hops: (fields.hops ?? []).filter((_, item) => item !== index) })}
                  >
                    {t("teams.authoring.removeRow", { number: index + 1 })}
                  </Button>
                </div>
              ))}
              <Button type="button" variant="secondary" onClick={() => set({ hops: [...(fields.hops ?? []), ""] })}>
                {t("teams.authoring.addHop")}
              </Button>
            </fieldset>
          ) : null}
          {fields.kind === 2 || fields.kind === 3 ? (
            <>
              <Field
                label={t("teams.authoring.proxy")}
                value={fields.proxy ?? ""}
                required
                onChange={(event) => set({ proxy: event.target.value })}
              />
              <Field
                label={t("teams.authoring.proxyUser")}
                value={fields.proxy_username ?? ""}
                onChange={(event) => set({ proxy_username: optional(event.target.value) })}
              />
              <p className="text-sm text-muted-foreground">{t("teams.authoring.proxyNotice")}</p>
            </>
          ) : null}
          {fields.kind === 4 ? (
            <TextAreaField
              label={t("teams.authoring.command")}
              value={fields.command ?? ""}
              required
              onChange={(event) => set({ command: event.target.value })}
            />
          ) : null}
          {fields.kind === 5 ? (
            <Reference
              label={t("teams.authoring.gateway")}
              kind="gatewayNetwork"
              value={fields.gateway_network}
              required
              onChange={(gateway_network) => set({ gateway_network })}
              {...refs}
            />
          ) : null}
        </>
      );
    }
    case "hostGroup": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={fields.name}
            required
            onChange={(event) => set({ name: event.target.value })}
          />
          <Reference
            label={t("teams.authoring.parent")}
            kind="hostGroup"
            value={fields.parent}
            onChange={(parent) => set({ parent })}
            {...refs}
          />
          <Field
            label={t("teams.authoring.color")}
            value={fields.color ?? ""}
            onChange={(event) => set({ color: optional(event.target.value) })}
          />
          <MapFields
            label={t("teams.authoring.defaults")}
            value={fields.defaults}
            onChange={(defaults) => set({ defaults: defaults as Record<string, string> })}
            onValid={(valid) => onValid("defaults", valid)}
          />
        </>
      );
    }
    case "trustRecord": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Reference
            label={t("teams.authoring.host")}
            kind="host"
            value={fields.host}
            onChange={(host) => set({ host })}
            {...refs}
          />
          <Field
            label={t("teams.authoring.pattern")}
            value={fields.pattern ?? ""}
            onChange={(event) => set({ pattern: optional(event.target.value) })}
          />
          <TextAreaField
            label={t("teams.authoring.key")}
            value={fields.key}
            required
            onChange={(event) => set({ key: event.target.value })}
          />
          <Field
            label={t("teams.authoring.fingerprint")}
            value={fields.fingerprint}
            required
            onChange={(event) => set({ fingerprint: event.target.value })}
          />
          <TeamSelect
            label={t("teams.authoring.provenance")}
            value={String(fields.provenance)}
            onChange={(value) => set({ provenance: Number(value) })}
            options={[
              { value: "1", label: t("teams.authoring.manual") },
              { value: "2", label: t("teams.authoring.imported") },
              { value: "3", label: t("teams.authoring.hostCa") },
              { value: "4", label: t("teams.authoring.organizationPolicy") },
            ]}
          />
          <TeamCheck
            label={t("teams.authoring.revoked")}
            checked={fields.revoked ?? false}
            onChange={(revoked) => set({ revoked })}
          />
          <TeamCheck label={t("teams.authoring.ca")} checked={fields.ca ?? false} onChange={(ca) => set({ ca })} />
          <p className="text-sm text-muted-foreground">{t("teams.authoring.trustNotice")}</p>
        </>
      );
    }
    case "snippet": {
      const fields = data.fields;
      const set = (next: Partial<typeof fields>) => onChange({ ...data, fields: { ...fields, ...next } });
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={fields.name}
            required
            onChange={(event) => set({ name: event.target.value })}
          />
          <TextAreaField
            label={t("teams.authoring.template")}
            value={fields.template}
            required
            onChange={(event) => set({ template: event.target.value })}
          />
          <Field
            label={t("teams.authoring.folder")}
            value={fields.folder ?? ""}
            onChange={(event) => set({ folder: optional(event.target.value) })}
          />
          <Variables
            value={fields.variables}
            onChange={(variables) => set({ variables })}
            onValid={(valid) => onValid("variables", valid)}
          />
          <MapFields
            label={t("teams.authoring.tags")}
            value={fields.tags}
            set
            onChange={(tags) => set({ tags: tags as Record<string, boolean> })}
            onValid={(valid) => onValid("tags", valid)}
          />
        </>
      );
    }
    case "gatewayNetwork":
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={data.fields.name}
            required
            onChange={(event) => onChange({ ...data, fields: { ...data.fields, name: event.target.value } })}
          />
          <TextAreaField
            label={t("teams.authoring.description")}
            value={data.fields.description ?? ""}
            onChange={(event) =>
              onChange({ ...data, fields: { ...data.fields, description: optional(event.target.value) } })
            }
          />
        </>
      );
    case "group": {
      const selected = new Set(data.fields.members);
      const available = members
        .filter((member) => member.status === "active")
        .map((member) => ({ id: member.id, name: member.username }));
      for (const id of selected)
        if (!available.some((member) => member.id === id))
          available.push({ id, name: t("teams.authoring.unreadable", { id }) });
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={data.fields.name}
            required
            onChange={(event) => onChange({ ...data, fields: { ...data.fields, name: event.target.value } })}
          />
          <fieldset className="min-w-0 border-0 p-0">
            <legend className="mb-2 text-sm font-medium">{t("teams.authoring.members")}</legend>
            {available.map((member) => (
              <TeamCheck
                key={member.id}
                label={member.name}
                checked={selected.has(member.id)}
                onChange={(enabled) => {
                  const next = new Set(selected);
                  if (enabled) next.add(member.id);
                  else next.delete(member.id);
                  onChange({ ...data, fields: { ...data.fields, members: [...next] } });
                }}
              />
            ))}
            {moreMembers ? (
              <Button type="button" variant="ghost" onClick={loadMembers}>
                {t("teams.authoring.more")}
              </Button>
            ) : null}
          </fieldset>
        </>
      );
    }
    case "policy":
      return (
        <>
          <Field
            label={t("teams.authoring.name")}
            value={data.fields.name}
            required
            onChange={(event) => onChange({ ...data, fields: { ...data.fields, name: event.target.value } })}
          />
          <TextAreaField
            label={t("teams.authoring.source")}
            value={data.fields.source}
            required
            rows={12}
            onChange={(event) => onChange({ ...data, fields: { ...data.fields, source: event.target.value } })}
            className="font-mono"
          />
          <TeamCheck
            label={t("teams.authoring.enabled")}
            checked={data.fields.enabled}
            onChange={(enabled) => onChange({ ...data, fields: { ...data.fields, enabled } })}
          />
          <p className="text-sm text-muted-foreground">{t("teams.authoring.advancedNotice")}</p>
        </>
      );
  }
}
