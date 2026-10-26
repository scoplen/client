// SPDX-License-Identifier: Apache-2.0
import { Button, Dialog, Field, TextAreaField } from "@scoplen/ui";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { PreparedSnippet, SnippetInput, SnippetIssue, SnippetVariableInput, SnippetView } from "./ipc/bindings";
import { useStoreChanges } from "./ipc/store-events";

type Mode = "library" | "edit" | "values" | "preview" | "delete" | "results";
type DraftVariable = SnippetVariableInput & { key: string };

export interface SnippetTarget {
  sessionId: string;
  transportId: string;
  target: string;
  location?: { tab: number; pane: number };
  canSend: () => boolean;
}

type TargetOutcome = "pending" | "sent" | "notSent" | "unknown";
const targetKey = (target: SnippetTarget) => JSON.stringify([target.sessionId, target.transportId]);

export function SessionSnippetsButton(props: Omit<Parameters<typeof SessionSnippets>[0], "onClose" | "finalFocus">) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLButtonElement>(null);
  return (
    <>
      <Button variant="ghost" ref={opener} onClick={() => setOpen(true)}>
        {t("snippets.open")}
      </Button>
      {open ? <SessionSnippets {...props} onClose={() => setOpen(false)} finalFocus={() => opener.current} /> : null}
    </>
  );
}

/** Mounted only for one active, ready session transport; its parent owns that boundary. */
export function SessionSnippets({
  sessionId,
  transportId,
  target,
  onClose,
  canSend,
  finalFocus,
  getTargets,
}: {
  sessionId: string;
  transportId: string;
  target: string;
  onClose: () => void;
  canSend: () => boolean;
  finalFocus?: () => HTMLButtonElement | null;
  getTargets?: () => SnippetTarget[];
}) {
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [items, setItems] = useState<SnippetView[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState<SnippetIssue | null>(null);
  const [mode, setMode] = useState<Mode>("library");
  const [selected, setSelected] = useState<SnippetView | null>(null);
  const [draft, setDraft] = useState<SnippetInput | null>(null);
  const [variables, setVariables] = useState<DraftVariable[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [prepared, setPrepared] = useState<PreparedSnippet | null>(null);
  const [targets, setTargets] = useState<SnippetTarget[]>([]);
  const [chosen, setChosen] = useState<string[]>([]);
  const [reviewed, setReviewed] = useState<SnippetTarget[]>([]);
  const [outcomes, setOutcomes] = useState<TargetOutcome[]>([]);
  const [targetIssue, setTargetIssue] = useState<"empty" | "limit" | "duplicate" | "unavailable" | null>(null);
  const alive = useRef(false);
  const inFlight = useRef(false);
  const listRevision = useRef(0);
  const formId = useId();

  const reload = useCallback(() => {
    const revision = ++listRevision.current;
    return commands
      .snippetsList()
      .then(
        (result) => {
          if (!alive.current || revision !== listRevision.current) return;
          if (result.status === "ok") setItems(result.data);
          else setIssue(result.error);
        },
        () => {
          if (alive.current && revision === listRevision.current) setIssue({ kind: "storage" });
        },
      )
      .finally(() => {
        if (alive.current && revision === listRevision.current) setLoading(false);
      });
  }, [commands]);

  useEffect(() => {
    alive.current = true;
    void reload();
    return () => {
      alive.current = false;
    };
  }, [reload]);
  useStoreChanges(["snippet"], () => void reload());

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
  const library = () => {
    setMode("library");
    setSelected(null);
    setDraft(null);
    setVariables([]);
    setPrepared(null);
    setTargets([]);
    setChosen([]);
    setReviewed([]);
    setOutcomes([]);
    setTargetIssue(null);
    setValues({});
    setIssue(null);
  };
  const edit = (snippet: SnippetView | null) => {
    setSelected(snippet);
    setDraft(
      snippet
        ? { name: snippet.name, template: snippet.template, variables: [], tags: snippet.tags, folder: snippet.folder }
        : { name: "", template: "", variables: [], tags: [], folder: null },
    );
    setVariables((snippet?.variables ?? []).map((variable) => ({ ...variable, key: crypto.randomUUID() })));
    setIssue(null);
    setMode("edit");
  };
  const save = () => {
    if (!draft) return;
    void run(async () => {
      const input = {
        ...draft,
        variables: variables.map(({ name, kind, default: fallback, choices }) => ({
          name,
          kind,
          default: fallback,
          choices,
        })),
      };
      const result = selected
        ? await commands.snippetsUpdate(selected.id, input)
        : await commands.snippetsCreate(input);
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        library();
        await reload();
      }
    });
  };
  const prepare = () => {
    if (!selected || selected.readOnly) return;
    const selectedTargets = targets.filter((candidate) => chosen.includes(targetKey(candidate)));
    const keys = selectedTargets.map(targetKey);
    const problem = !selectedTargets.length
      ? "empty"
      : selectedTargets.length > 64
        ? "limit"
        : new Set(keys).size !== keys.length
          ? "duplicate"
          : selectedTargets.some((candidate) => !candidate.canSend())
            ? "unavailable"
            : null;
    setTargetIssue(problem);
    if (problem) return;
    void run(async () => {
      const result = await commands.snippetsPrepare(selected.id, values);
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        setPrepared(result.data);
        setReviewed(selectedTargets);
        setMode("preview");
      }
    });
  };
  const send = () => {
    if (!prepared || !reviewed.length) return;
    if (!canSend()) return onClose();
    void run(async () => {
      const data = Array.from(new TextEncoder().encode(prepared.command + "\r"));
      setPrepared(null);
      setValues({});
      setMode("results");
      setOutcomes(reviewed.map(() => "pending"));
      for (const [index, candidate] of reviewed.entries()) {
        if (!alive.current) return;
        if (!canSend()) return onClose();
        let outcome: TargetOutcome = "notSent";
        if (candidate.canSend()) {
          // A failure after invocation cannot prove whether input reached the queue.
          const result = await commands
            .sessionInput(candidate.sessionId, candidate.transportId, data)
            .catch(() => ({ status: "error" as const }));
          outcome = result.status === "ok" ? "sent" : "unknown";
        }
        if (!alive.current) return;
        if (!canSend()) return onClose();
        setOutcomes((current) => current.map((value, position) => (position === index ? outcome : value)));
      }
    });
  };
  const remove = () => {
    if (!selected || selected.readOnly) return;
    void run(async () => {
      const result = await commands.snippetsDelete(selected.id);
      if (!alive.current) return;
      if (result.status === "error") setIssue(result.error);
      else {
        library();
        await reload();
      }
    });
  };
  const updateVariable = (key: string, patch: Partial<SnippetVariableInput>) =>
    setVariables((current) => current.map((variable) => (variable.key === key ? { ...variable, ...patch } : variable)));
  const valueOf = (name: string) => (Object.hasOwn(values, name) ? values[name] : undefined);
  const issueText = (value: SnippetIssue) =>
    t(`snippets.issue.${value.kind}`, { name: "name" in value ? value.name : "" });
  const error = issue ? issueText(issue) : null;
  const location = (candidate: SnippetTarget) =>
    candidate.location ? t("snippets.location", candidate.location) : t("snippets.current");

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t(mode === "edit" ? "snippets.editor" : mode === "preview" ? "snippets.preview" : "snippets.title")}
      description={t("snippets.target", { target })}
      closeLabel={t("snippets.close")}
      finalFocus={finalFocus}
      footer={
        <>
          {mode !== "library" ? (
            <Button variant="ghost" disabled={busy} onClick={library}>
              {t("snippets.back")}
            </Button>
          ) : null}
          {mode === "library" ? (
            <Button variant="primary" disabled={busy || loading} onClick={() => edit(null)}>
              {t("snippets.add")}
            </Button>
          ) : null}
          {mode === "edit" ? (
            <Button variant="primary" type="submit" form={formId} busy={busy}>
              {t("snippets.save")}
            </Button>
          ) : null}
          {mode === "values" && !selected?.readOnly && !selected?.issue ? (
            <Button variant="primary" type="submit" form={formId} busy={busy}>
              {t("snippets.review")}
            </Button>
          ) : null}
          {mode === "preview" ? (
            <>
              <Button
                variant="ghost"
                disabled={busy}
                onClick={() => {
                  setPrepared(null);
                  setReviewed([]);
                  setMode("values");
                }}
              >
                {t("snippets.changeReview")}
              </Button>
              <Button variant="primary" busy={busy} onClick={send}>
                {t(reviewed.length === 1 ? "snippets.send" : "snippets.sendSelected")}
              </Button>
            </>
          ) : null}
          {mode === "delete" ? (
            <Button variant="destructive" busy={busy} onClick={remove}>
              {t("snippets.delete")}
            </Button>
          ) : null}
          {mode === "results" ? (
            <Button variant="primary" disabled={busy} onClick={onClose}>
              {t("snippets.return")}
            </Button>
          ) : null}
        </>
      }
    >
      {loading ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("snippets.loading")}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="mb-4 text-sm wrap-anywhere text-attention">
          {error}
        </p>
      ) : null}
      {targetIssue ? (
        <p role="alert" className="mb-4 text-sm text-attention">
          {t(`snippets.targets.${targetIssue}`)}
        </p>
      ) : null}
      {mode === "library" ? (
        <>
          <Button variant="ghost" disabled={busy || loading} onClick={() => void run(reload)}>
            {t("snippets.refresh")}
          </Button>
          {!loading && !items.length ? (
            <p className="mt-3 text-sm text-muted-foreground">{t("snippets.empty")}</p>
          ) : null}
          <ul aria-label={t("snippets.list")} className="m-0 list-none divide-y divide-border p-0">
            {items.map((snippet) => (
              <li key={snippet.id} className="py-4">
                <p className="m-0 text-sm font-medium wrap-anywhere">{snippet.name}</p>
                {snippet.folder ? (
                  <p className="mt-1 text-xs wrap-anywhere text-muted-foreground">
                    {t("snippets.folderValue", { folder: snippet.folder })}
                  </p>
                ) : null}
                {snippet.tags.length ? (
                  <p className="mt-1 text-xs wrap-anywhere text-muted-foreground">
                    {t("snippets.tagsValue", { tags: snippet.tags.join(", ") })}
                  </p>
                ) : null}
                {snippet.readOnly ? (
                  <p className="mt-2 text-sm text-muted-foreground">{t("snippets.readOnly")}</p>
                ) : null}
                {snippet.issue ? (
                  <p className="mt-2 text-sm wrap-anywhere text-attention">{issueText(snippet.issue)}</p>
                ) : null}
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button
                    disabled={busy}
                    onClick={() => {
                      setSelected(snippet);
                      setValues(
                        Object.fromEntries(
                          snippet.variables
                            .filter(
                              (variable) =>
                                variable.kind === "text" || (variable.kind !== "secret" && variable.default !== null),
                            )
                            .map((variable) => [variable.name, variable.default ?? ""]),
                        ),
                      );
                      setPrepared(null);
                      const current = { sessionId, transportId, target, canSend };
                      setTargets((getTargets?.() ?? [current]).filter((candidate) => candidate.canSend()));
                      setChosen([targetKey(current)]);
                      setReviewed([]);
                      setOutcomes([]);
                      setTargetIssue(null);
                      setIssue(null);
                      setMode("values");
                    }}
                  >
                    {t(snippet.readOnly || snippet.issue ? "snippets.inspect" : "snippets.use")}
                  </Button>
                  {!snippet.readOnly ? (
                    <>
                      <Button variant="ghost" disabled={busy} onClick={() => edit(snippet)}>
                        {t("snippets.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        disabled={busy}
                        onClick={() => {
                          setSelected(snippet);
                          setIssue(null);
                          setMode("delete");
                        }}
                      >
                        {t("snippets.delete")}
                      </Button>
                    </>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {mode === "edit" && draft ? (
        <form
          id={formId}
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            save();
          }}
        >
          <Field
            label={t("snippets.name")}
            value={draft.name}
            disabled={busy}
            required
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
          />
          <Field
            label={t("snippets.template")}
            hint={t("snippets.templateHint")}
            className="font-mono"
            value={draft.template}
            disabled={busy}
            required
            onChange={(event) => setDraft({ ...draft, template: event.target.value })}
          />
          <p className="m-0 text-sm text-muted-foreground">{t("snippets.literal")}</p>
          <Field
            label={t("snippets.folder")}
            value={draft.folder ?? ""}
            disabled={busy}
            onChange={(event) => setDraft({ ...draft, folder: event.target.value || null })}
          />
          <TextAreaField
            label={t("snippets.tags")}
            hint={t("snippets.lines")}
            value={draft.tags.join("\n")}
            disabled={busy}
            onChange={(event) => setDraft({ ...draft, tags: event.target.value ? event.target.value.split("\n") : [] })}
          />
          <h2 className="m-0 text-sm font-medium">{t("snippets.variables")}</h2>
          {variables.map((variable, index) => (
            <fieldset
              key={variable.key}
              disabled={busy}
              className="min-w-0 border-0 border-t border-solid border-border p-0 pt-4"
            >
              <legend className="px-1 text-sm">{t("snippets.variableNumber", { number: index + 1 })}</legend>
              <div className="flex flex-col gap-3">
                <Field
                  label={t("snippets.variableName")}
                  value={variable.name}
                  required
                  onChange={(event) => updateVariable(variable.key, { name: event.target.value })}
                />
                <label className="flex flex-col gap-1.5 text-sm font-medium">
                  {t("snippets.variableKind")}
                  <select
                    className="ui-input h-10 px-3 text-sm"
                    value={variable.kind}
                    onChange={(event) =>
                      updateVariable(variable.key, {
                        kind: event.target.value as SnippetVariableInput["kind"],
                        default: null,
                        choices: event.target.value === "choice" ? [""] : [],
                      })
                    }
                  >
                    <option value="text">{t("snippets.kind.text")}</option>
                    <option value="integer">{t("snippets.kind.integer")}</option>
                    <option value="choice">{t("snippets.kind.choice")}</option>
                  </select>
                </label>
                {variable.kind === "choice" ? (
                  <TextAreaField
                    label={t("snippets.choices")}
                    hint={t("snippets.choicesHint")}
                    value={variable.choices.join("\n")}
                    onChange={(event) => updateVariable(variable.key, { choices: event.target.value.split("\n") })}
                  />
                ) : null}
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={variable.default !== null}
                    onChange={(event) => updateVariable(variable.key, { default: event.target.checked ? "" : null })}
                  />
                  {t("snippets.hasDefault")}
                </label>
                {variable.default !== null ? (
                  <Field
                    label={t("snippets.default")}
                    value={variable.default}
                    onChange={(event) => updateVariable(variable.key, { default: event.target.value })}
                  />
                ) : null}
                <Button
                  variant="ghost"
                  className="self-start"
                  onClick={() => setVariables((current) => current.filter((item) => item.key !== variable.key))}
                >
                  {t("snippets.removeVariable")}
                </Button>
              </div>
            </fieldset>
          ))}
          <Button
            className="self-start"
            disabled={busy}
            onClick={() =>
              setVariables((current) => [
                ...current,
                { key: crypto.randomUUID(), name: "", kind: "text", default: null, choices: [] },
              ])
            }
          >
            {t("snippets.addVariable")}
          </Button>
        </form>
      ) : null}
      {mode === "values" && selected ? (
        <form
          id={formId}
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            prepare();
          }}
        >
          <h2 className="m-0 text-sm font-medium wrap-anywhere">{selected.name}</h2>
          <pre className="m-0 max-h-52 overflow-auto rounded-md bg-inset p-3 font-mono text-xs whitespace-pre-wrap wrap-anywhere">
            {selected.template}
          </pre>
          <p className="m-0 text-sm text-muted-foreground">
            {t(selected.readOnly ? "snippets.readOnly" : "snippets.literal")}
          </p>
          {selected.issue ? (
            <p className="m-0 text-sm wrap-anywhere text-attention">{issueText(selected.issue)}</p>
          ) : null}
          {!selected.readOnly && !selected.issue ? (
            <fieldset disabled={busy} className="min-w-0 border-0 border-t border-border p-0 pt-4">
              <legend className="px-1 text-sm font-medium">{t("snippets.targets")}</legend>
              <p className="mt-1 text-sm text-muted-foreground">{t("snippets.targetsHint")}</p>
              <div className="flex max-h-52 flex-col gap-3 overflow-auto">
                {targets.map((candidate, index) => {
                  const key = targetKey(candidate);
                  const checked = chosen.includes(key);
                  return (
                    <label key={`${key}/${index}`} className="flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={!checked && !candidate.canSend()}
                        onChange={(event) => {
                          setTargetIssue(null);
                          if (event.target.checked && chosen.length >= 64) {
                            setTargetIssue("limit");
                            return;
                          }
                          setChosen(event.target.checked ? [...chosen, key] : chosen.filter((value) => value !== key));
                        }}
                      />
                      <span className="min-w-0 wrap-anywhere">
                        {candidate.target}
                        <span className="block text-xs text-muted-foreground">{location(candidate)}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
          ) : null}
          {selected.variables.map((variable, index) =>
            selected.readOnly || selected.issue ? (
              <p key={index} className="m-0 text-sm wrap-anywhere">
                {variable.name} · {t(`snippets.kind.${variable.kind}`)}
                {variable.hasDefault ? ` · ${t("snippets.defaultPresent")}` : ""}
              </p>
            ) : variable.kind === "choice" ? (
              <label key={index} className="flex flex-col gap-1.5 text-sm font-medium">
                {variable.name}
                <select
                  className="ui-input h-10 px-3 text-sm"
                  disabled={busy}
                  required
                  value={
                    valueOf(variable.name) === undefined
                      ? ""
                      : String(variable.choices.indexOf(valueOf(variable.name) ?? ""))
                  }
                  onChange={(event) => {
                    const value = variable.choices[Number(event.target.value)];
                    if (value !== undefined) setValues({ ...values, [variable.name]: value });
                  }}
                >
                  <option value="" disabled>
                    {t("snippets.choose")}
                  </option>
                  {variable.choices.map((choice, choiceIndex) => (
                    <option key={choiceIndex} value={choiceIndex}>
                      {choice || t("snippets.emptyChoice")}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <Field
                key={index}
                label={variable.name}
                hint={variable.kind === "integer" ? t("snippets.integerHint") : undefined}
                value={valueOf(variable.name) ?? ""}
                disabled={busy}
                inputMode={variable.kind === "integer" ? "numeric" : undefined}
                onChange={(event) => setValues({ ...values, [variable.name]: event.target.value })}
              />
            ),
          )}
        </form>
      ) : null}
      {mode === "preview" && prepared ? (
        <div className="flex flex-col gap-4">
          <p className="m-0 text-sm text-muted-foreground">{t("snippets.promptWarning")}</p>
          <pre
            aria-label={t("snippets.command")}
            className="m-0 max-h-64 overflow-auto rounded-md bg-inset p-3 font-mono text-xs whitespace-pre-wrap wrap-anywhere select-text"
          >
            {prepared.command}
          </pre>
          <p className="m-0 text-sm text-muted-foreground">{t("snippets.enterWarning")}</p>
          <ol aria-label={t("snippets.confirmedTargets")} className="m-0 list-decimal space-y-2 pl-5 text-sm">
            {reviewed.map((candidate) => (
              <li key={targetKey(candidate)} className="wrap-anywhere">
                {candidate.target}
                <span className="block text-xs text-muted-foreground">{location(candidate)}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      {mode === "delete" ? (
        <p className="text-sm wrap-anywhere">{t("snippets.deleteBody", { name: selected?.name ?? "" })}</p>
      ) : null}
      {mode === "results" ? (
        <>
          <p className="text-sm text-muted-foreground">{t("snippets.resultsHint")}</p>
          <ol aria-label={t("snippets.results")} className="m-0 list-decimal space-y-4 pl-5 text-sm">
            {reviewed.map((candidate, index) => (
              <li key={targetKey(candidate)} className="wrap-anywhere">
                <span className="font-medium">{candidate.target}</span>
                <span className="block text-xs text-muted-foreground">{location(candidate)}</span>
                <p role={outcomes[index] === "unknown" ? "alert" : "status"} className="my-1">
                  {t(
                    outcomes[index] === "sent"
                      ? "snippets.sent"
                      : outcomes[index] === "notSent"
                        ? "snippets.notSent"
                        : outcomes[index] === "unknown"
                          ? "snippets.sendFailed"
                          : "snippets.sending",
                  )}
                </p>
              </li>
            ))}
          </ol>
        </>
      ) : null}
    </Dialog>
  );
}
