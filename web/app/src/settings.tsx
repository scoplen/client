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
import { useI18n } from "./i18n";
import type { Status } from "./ipc/bindings";
import { PassphraseSettings } from "./local-data";

/** Settings: how Scoplen looks, then how this device's data is protected. */
export function SettingsView({
  status,
  onStatus,
}: {
  status: Status & { state: "open" };
  onStatus: (status: Status) => void;
}) {
  const { t } = useI18n();
  return (
    <main id="main" tabIndex={-1} className="h-full overflow-y-auto focus:outline-none">
      <div className="mx-auto max-w-2xl px-6 py-10">
        <h1 className="ui-display text-3xl">{t("settings.title")}</h1>
        <Appearance />
        <PassphraseSettings status={status} onStatus={onStatus} />
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
      <div className="mt-6 max-w-sm">
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
