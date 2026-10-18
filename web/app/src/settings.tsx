// SPDX-License-Identifier: Apache-2.0
import {
  HostEgg,
  Mark,
  Segmented,
  resolveScheme,
  themes,
  useAppearance,
  type SchemeChoice,
  type ThemeId,
} from "@scoplen/ui";
import { useState } from "react";
import { useI18n } from "./i18n";
import { languageChoices, useLanguage, type LanguageChoice } from "./language";
import type { Status } from "./ipc/bindings";
import { PassphraseSettings } from "./local-data";
import { TerminalSettings } from "./terminal-settings";

export type SettingsSection = "appearance" | "terminal" | "data";
const sections: SettingsSection[] = ["appearance", "terminal", "data"];

/**
 * Settings, in three places: how the interface looks, how the terminal
 * looks, and how this device's data is protected.
 */
export function SettingsView({
  status,
  onStatus,
  section: initial = "appearance",
}: {
  status: Status & { state: "open" };
  onStatus: (status: Status) => void;
  section?: SettingsSection;
}) {
  const { t } = useI18n();
  const [section, setSection] = useState<SettingsSection>(initial);
  return (
    <main id="main" tabIndex={-1} className="h-full overflow-y-auto focus:outline-none">
      <div className="mx-auto max-w-3xl px-6 py-10">
        <h1 className="ui-display text-3xl">{t("settings.title")}</h1>
        <div
          role="tablist"
          aria-label={t("settings.title")}
          className="mt-5 inline-flex gap-1 rounded-full bg-inset p-1"
        >
          {sections.map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={section === id}
              onClick={() => setSection(id)}
              className="rounded-full border-(length:--scoplen-border-width) border-transparent px-4 py-1.5 text-sm text-muted-foreground transition-[background-color,color,box-shadow] duration-(--duration-state) hover:text-foreground aria-selected:border-border aria-selected:bg-raised aria-selected:font-medium aria-selected:text-foreground aria-selected:shadow-(--scoplen-shadow-control)"
            >
              {t(`settings.section.${id}`)}
            </button>
          ))}
        </div>
        <div className="scoplen-rise" key={section}>
          {section === "appearance" ? <Appearance /> : null}
          {section === "terminal" ? <TerminalSettings /> : null}
          {section === "data" ? <PassphraseSettings status={status} onStatus={onStatus} /> : null}
        </div>
      </div>
    </main>
  );
}

/**
 * The theme, chosen by looking: each choice is a small live window in that
 * theme. Then light, dark, or the system's, for themes that have both.
 */
function Appearance() {
  const { t } = useI18n();
  const { appearance, scheme, setAppearance } = useAppearance();
  const darkOnly = themes.find((theme) => theme.id === appearance.theme)?.schemes.length === 1;

  return (
    <section aria-labelledby="appearance-title" className="mt-8">
      <h2 id="appearance-title" className="ui-display text-lg">
        {t("settings.appearance.title")}
      </h2>
      <fieldset className="m-0 mt-4 border-0 p-0">
        <legend className="mb-3 p-0 text-sm font-medium">{t("settings.appearance.theme")}</legend>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {themes.map((theme) => (
            <ThemeChoice
              key={theme.id}
              id={theme.id}
              checked={theme.id === appearance.theme}
              scheme={resolveScheme({ theme: theme.id, scheme: appearance.scheme }, scheme)}
              onChoose={() => setAppearance({ ...appearance, theme: theme.id })}
            />
          ))}
        </div>
      </fieldset>
      <div className="mt-6 max-w-lg">
        <Segmented<SchemeChoice>
          legend={t("settings.appearance.scheme")}
          value={appearance.scheme}
          onChange={(next) => setAppearance({ ...appearance, scheme: next })}
          options={[
            { value: "system", label: t("settings.appearance.scheme.system") },
            { value: "light", label: t("settings.appearance.scheme.light") },
            { value: "dark", label: t("settings.appearance.scheme.dark") },
          ]}
        />
        {darkOnly ? <p className="mt-2 text-sm text-muted-foreground">{t("settings.appearance.darkOnly")}</p> : null}
      </div>
      <Language />
    </section>
  );
}

function ThemeChoice({
  id,
  checked,
  scheme,
  onChoose,
}: {
  id: ThemeId;
  checked: boolean;
  scheme: "light" | "dark";
  onChoose: () => void;
}) {
  const { t } = useI18n();
  return (
    <label className="group flex cursor-pointer flex-col gap-2 rounded-lg p-1 has-focus-visible:outline-2 has-focus-visible:outline-ring">
      <input type="radio" name="theme" value={id} checked={checked} onChange={onChoose} className="sr-only" />
      <span
        aria-hidden="true"
        data-theme={id}
        data-scheme={scheme}
        className={[
          "relative flex h-24 flex-col gap-1.5 overflow-hidden rounded-lg border-(length:--scoplen-border-width) border-border p-2.5",
          "transition-transform duration-(--duration-state) ease-(--ease-spring) group-hover:-translate-y-0.5",
          checked ? "outline-2 outline-offset-2 outline-primary" : "",
        ].join(" ")}
      >
        <span className="flex items-center gap-1.5">
          <Mark size="0.875rem" className="text-primary" />
          <span className="h-1.5 w-10 rounded-full bg-inset" />
        </span>
        <span className="flex items-center gap-1.5 rounded-md border-(length:--scoplen-border-width) border-border bg-raised px-1.5 py-1 shadow-(--scoplen-shadow-card)">
          <HostEgg seed={`${id}-a`} size="0.875rem" active />
          <span className="h-1.5 w-12 rounded-full bg-foreground/60" />
        </span>
        <span className="flex items-center gap-1.5 px-1.5">
          <HostEgg seed={`${id}-b`} size="0.875rem" />
          <span className="h-1.5 w-9 rounded-full bg-muted-foreground/40" />
        </span>
        <span className="ui-control absolute right-2.5 bottom-2.5 rounded-sm bg-primary px-2 py-0.5 text-[0.625rem] font-medium text-primary-foreground">
          {t("session.connect")}
        </span>
      </span>
      <span className="px-0.5">
        <span className="flex items-center gap-1.5 text-sm font-medium">
          {t(`settings.theme.${id}`)}
          {checked ? <span className="text-xs text-primary">✓</span> : null}
        </span>
        <span className="block text-xs text-muted-foreground">{t(`settings.theme.${id}.description`)}</span>
      </span>
    </label>
  );
}

/** The interface language; each language is named in itself. */
function Language() {
  const { t } = useI18n();
  const { choice, setChoice } = useLanguage();
  const names: Record<LanguageChoice, string> = {
    system: t("settings.language.system"),
    en: "English",
    "zh-Hans": "简体中文",
  };
  return (
    <div className="mt-6 max-w-lg">
      <Segmented<LanguageChoice>
        legend={t("settings.language")}
        value={choice}
        onChange={setChoice}
        options={languageChoices.map((value) => ({ value, label: names[value] }))}
      />
    </div>
  );
}
