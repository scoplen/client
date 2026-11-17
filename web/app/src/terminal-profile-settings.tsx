// SPDX-License-Identifier: Apache-2.0
import { Button, Confirm, Dialog, Field, Select } from "@scoplen/ui";
import { useId, useState } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import { useTerminalProfiles } from "./terminal-profiles";
import type { TerminalProfileSettings } from "./ipc/bindings";

const defaultFonts = "ui-monospace, SFMono-Regular, Consolas, monospace";

export function TerminalProfileSettingsPanel() {
  const state = useTerminalProfiles();
  const commands = useProfileCommands();
  const { t } = useI18n();
  const [selected, setSelected] = useState("");
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [notice, setNotice] = useState(false);
  const selectorId = useId();
  if (!state) return null;
  const { directory, busy: saving, issue, loading, change } = state;
  const busy = saving || loading;
  const settings = selected
    ? directory?.named.find((entry) => entry.name === selected)?.settings
    : directory?.defaultProfile;
  return (
    <section className="mt-6 border-t border-border pt-6" aria-labelledby="terminal-profiles-title">
      <h3 id="terminal-profiles-title" className="text-base font-medium">
        {t("terminalProfiles.title")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("terminalProfiles.body")}</p>
      {loading ? <p role="status">{t("terminalProfiles.loading")}</p> : null}
      {issue && !creating && !deleting ? (
        <p role="alert" className="text-sm text-attention">
          {t(`terminalProfiles.issue.${issue}`)}
        </p>
      ) : null}
      {!loading && (!directory || (issue && !creating && !deleting)) ? (
        <Button disabled={busy} onClick={state.reload}>
          {t("terminalProfiles.reload")}
        </Button>
      ) : null}
      {directory ? (
        <>
          <div className="mt-4 flex min-w-0 flex-wrap items-end gap-3">
            <div className="flex min-w-0 flex-1 flex-col gap-1.5">
              <label htmlFor={selectorId} className="text-sm font-medium">
                {t("terminalProfiles.select")}
              </label>
              <Select
                id={selectorId}
                label={t("terminalProfiles.select")}
                size="field"
                value={selected}
                disabled={busy}
                options={[
                  { value: "", label: t("terminalProfiles.default") },
                  ...directory.named.map((entry) => ({ value: entry.name, label: entry.name })),
                ]}
                onValueChange={(name) => {
                  setSelected(name);
                  setNotice(false);
                }}
              />
            </div>
            <Button
              disabled={busy || directory.named.length >= 32}
              onClick={() => {
                setNewName("");
                setCreating(true);
                setNotice(false);
              }}
            >
              {t("terminalProfiles.create")}
            </Button>
            {selected ? (
              <Button disabled={busy} onClick={() => setDeleting(true)}>
                {t("terminalProfiles.delete")}
              </Button>
            ) : null}
          </div>
          <p className="text-xs text-muted-foreground">{t("terminalProfiles.names")}</p>
          {directory.named.length >= 32 ? (
            <p className="text-sm text-muted-foreground">{t("terminalProfiles.issue.limit")}</p>
          ) : null}
          {settings ? (
            <ProfileEditor
              key={`${selected}:${JSON.stringify(settings)}`}
              settings={settings}
              busy={busy}
              onSave={async (next) => {
                setNotice(false);
                if (await change(() => commands.terminalProfilesSave(selected || null, next))) setNotice(true);
              }}
            />
          ) : null}
          {!selected ? (
            <Button
              className="mt-3"
              disabled={busy}
              onClick={() => {
                setNotice(false);
                void change(() => commands.terminalProfilesResetDefault()).then((saved) => setNotice(saved));
              }}
            >
              {t("terminalProfiles.reset")}
            </Button>
          ) : null}
          {notice ? (
            <p role="status" className="text-sm">
              {t("terminalProfiles.saved")}
            </p>
          ) : null}
        </>
      ) : null}
      <Dialog
        open={creating}
        onOpenChange={(open) => {
          if (!busy) setCreating(open);
        }}
        title={t("terminalProfiles.create")}
        closeLabel={t("terminalProfiles.cancel")}
        footer={
          <>
            <Button disabled={busy} onClick={() => setCreating(false)}>
              {t("terminalProfiles.cancel")}
            </Button>
            <Button
              variant="primary"
              disabled={busy || !newName}
              onClick={() => {
                void change(() => commands.terminalProfilesCreate(newName)).then((saved) => {
                  if (saved) {
                    setSelected(newName);
                    setCreating(false);
                  }
                });
              }}
            >
              {t("terminalProfiles.create")}
            </Button>
          </>
        }
      >
        <Field
          label={t("terminalProfiles.name")}
          value={newName}
          onChange={(event) => setNewName(event.target.value)}
          required
          hint={t("terminalProfiles.names")}
        />
        {issue ? (
          <p role="alert" className="text-sm text-attention">
            {t(`terminalProfiles.issue.${issue}`)}
          </p>
        ) : null}
      </Dialog>
      <Confirm
        open={deleting}
        onOpenChange={(open) => {
          if (!busy) setDeleting(open);
        }}
        title={t("terminalProfiles.deleteTitle")}
        body={
          <>
            <p>{t("terminalProfiles.deleteBody", { name: selected })}</p>
            {issue ? (
              <p role="alert" className="text-attention">
                {t(`terminalProfiles.issue.${issue}`)}
              </p>
            ) : null}
          </>
        }
        confirmLabel={t("terminalProfiles.delete")}
        cancelLabel={t("terminalProfiles.cancel")}
        busy={busy}
        onConfirm={() => {
          void change(() => commands.terminalProfilesDelete(selected)).then((saved) => {
            if (saved) {
              setSelected("");
              setDeleting(false);
              setNotice(false);
            }
          });
        }}
      />
    </section>
  );
}

function ProfileEditor({
  settings,
  busy,
  onSave,
}: {
  settings: TerminalProfileSettings;
  busy: boolean;
  onSave: (next: TerminalProfileSettings) => Promise<void>;
}) {
  const { t } = useI18n();
  const [draft, setDraft] = useState(settings);
  const [fontSize, setFontSize] = useState(String(settings.fontSize));
  const [scrollback, setScrollback] = useState(String(settings.scrollback));
  const cursorId = useId();
  return (
    <form
      className="mt-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (busy || !event.currentTarget.reportValidity()) return;
        void onSave({ ...draft, fontSize: Number(fontSize), scrollback: Number(scrollback) });
      }}
    >
      <fieldset disabled={busy} className="m-0 grid min-w-0 gap-4 border-0 p-0 sm:grid-cols-2">
        <div className="min-w-0 sm:col-span-2">
          <Field
            label={t("terminalProfiles.fontFamily")}
            value={draft.fontFamily}
            required
            hint={t("terminalProfiles.fontHint")}
            onChange={(event) => setDraft({ ...draft, fontFamily: event.target.value })}
          />
          <Button className="mt-2" variant="ghost" onClick={() => setDraft({ ...draft, fontFamily: defaultFonts })}>
            {t("terminalProfiles.defaultFonts")}
          </Button>
        </div>
        <Field
          label={t("terminalProfiles.fontSize")}
          type="number"
          min={8}
          max={48}
          step={1}
          required
          value={fontSize}
          onChange={(event) => setFontSize(event.target.value)}
        />
        <div className="flex min-w-0 flex-col gap-1.5">
          <label htmlFor={cursorId} className="text-sm font-medium">
            {t("terminalProfiles.cursorStyle")}
          </label>
          <Select
            id={cursorId}
            label={t("terminalProfiles.cursorStyle")}
            size="field"
            value={draft.cursorStyle}
            options={(["block", "underline", "bar"] as const).map((value) => ({
              value,
              label: t(`terminalProfiles.cursor.${value}`),
            }))}
            onValueChange={(value) =>
              setDraft({ ...draft, cursorStyle: value as TerminalProfileSettings["cursorStyle"] })
            }
          />
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.cursorBlink}
            onChange={(event) => setDraft({ ...draft, cursorBlink: event.target.checked })}
          />
          {t("terminalProfiles.blink")}
        </label>
        <Field
          label={t("terminalProfiles.scrollback")}
          type="number"
          min={0}
          max={100000}
          step={1}
          required
          value={scrollback}
          onChange={(event) => setScrollback(event.target.value)}
          hint={t("terminalProfiles.scrollbackHint")}
        />
        <Button className="justify-self-start" type="submit" variant="primary">
          {t(busy ? "terminalProfiles.saving" : "terminalProfiles.save")}
        </Button>
      </fieldset>
    </form>
  );
}
