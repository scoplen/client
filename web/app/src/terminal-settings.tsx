// SPDX-License-Identifier: Apache-2.0
import { useI18n } from "./i18n";
import {
  ansiNames,
  surfaceColors,
  terminalSchemes,
  useTerminalColors,
  type SurfaceColor,
  type TerminalColors,
  type TerminalSchemeId,
} from "./terminal-colors";

/**
 * How the terminal looks: a scheme chosen by looking at a small terminal in
 * it, a larger sample of the current colors, and every color editable. An
 * edit turns the colors into the person's own scheme.
 */
export function TerminalSettings() {
  const { t } = useI18n();
  const { scheme, colors, colorsOf, setScheme, setColor } = useTerminalColors();
  const schemes: TerminalSchemeId[] = [...terminalSchemes, ...(scheme === "custom" ? (["custom"] as const) : [])];

  return (
    <section aria-labelledby="terminal-title" className="mt-8">
      <h2 id="terminal-title" className="ui-display text-lg">
        {t("settings.terminal.title")}
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">{t("settings.terminal.body")}</p>

      <fieldset className="m-0 mt-4 border-0 p-0">
        <legend className="mb-3 p-0 text-sm font-medium">{t("settings.terminal.scheme")}</legend>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {schemes.map((id) => (
            <label
              key={id}
              className="group flex cursor-pointer flex-col gap-1.5 rounded-lg p-1 has-focus-visible:outline-2 has-focus-visible:outline-ring"
            >
              <input
                type="radio"
                name="terminal-scheme"
                value={id}
                checked={scheme === id}
                onChange={() => setScheme(id)}
                className="sr-only"
              />
              <MiniTerminal
                colors={colorsOf(id)}
                className={[
                  "transition-transform duration-(--duration-state) ease-(--ease-spring) group-hover:-translate-y-0.5",
                  scheme === id ? "outline-2 outline-offset-2 outline-primary" : "",
                ].join(" ")}
              />
              <span className="px-0.5 text-sm font-medium">
                {t(`settings.terminal.scheme.${id}`)}
                {scheme === id ? <span className="ml-1.5 text-xs text-primary">✓</span> : null}
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <Sample colors={colors} />

      <div className="mt-6 grid gap-6 sm:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <fieldset className="m-0 border-0 p-0">
          <legend className="mb-2 p-0 text-sm font-medium">{t("settings.terminal.surface")}</legend>
          <div className="flex flex-col gap-1">
            {surfaceColors.map((name) => (
              <ColorField
                key={name}
                label={t(`settings.terminal.color.${name}`)}
                value={colors[name]}
                onChange={(value) => setColor(name as SurfaceColor, value)}
              />
            ))}
          </div>
        </fieldset>
        <fieldset className="m-0 border-0 p-0">
          <legend className="mb-2 p-0 text-sm font-medium">{t("settings.terminal.ansi")}</legend>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1">
            {ansiNames.map((name, index) => (
              <ColorField
                key={name}
                label={t(`settings.terminal.color.${name}`)}
                value={colors.ansi[index]!}
                onChange={(value) => setColor(index, value)}
              />
            ))}
            {ansiNames.map((name, index) => (
              <ColorField
                key={`bright-${name}`}
                label={t("settings.terminal.color.bright", { color: t(`settings.terminal.color.${name}`) })}
                value={colors.ansi[index + 8]!}
                onChange={(value) => setColor(index + 8, value)}
              />
            ))}
          </div>
        </fieldset>
      </div>
    </section>
  );
}

/** One color: a swatch that opens the system color picker, and its hex value. */
function ColorField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="flex items-center gap-2.5 rounded-md px-1.5 py-1 text-sm hover:bg-inset">
      <span className="relative size-6 shrink-0 overflow-hidden rounded-full border-(length:--scoplen-border-width) border-border-strong shadow-(--scoplen-shadow-card)">
        <span aria-hidden="true" className="absolute inset-0" style={{ background: value }} />
        <input
          type="color"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="absolute inset-0 size-full cursor-pointer opacity-0"
        />
      </span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      <span className="font-mono text-xs text-muted-foreground uppercase">{value}</span>
    </label>
  );
}

/** A tiny terminal for a scheme card: a prompt, a command, and its colors as a strip. */
function MiniTerminal({ colors, className }: { colors: TerminalColors; className?: string }) {
  const c = colors.ansi;
  return (
    <span
      aria-hidden="true"
      className={`flex h-20 flex-col justify-between rounded-lg border-(length:--scoplen-border-width) border-border p-2.5 font-mono text-[0.625rem] leading-4 ${className ?? ""}`}
      style={{ background: colors.background, color: colors.foreground }}
    >
      <span className="block truncate">
        <span style={{ color: c[2] }}>~</span>
        <span style={{ color: c[4] }}>$</span> ls{" "}
        <span className="inline-block h-3 w-1.5 translate-y-0.5" style={{ background: colors.cursor }} />
      </span>
      <span className="block truncate">
        <span style={{ color: c[4] }}>logs/</span> <span style={{ color: c[2] }}>run.sh</span>{" "}
        <span style={{ color: c[3] }}>app.yml</span>
      </span>
      <span className="flex gap-0.5">
        {c.slice(1, 7).map((color, i) => (
          <span key={i} className="h-1.5 flex-1 rounded-full" style={{ background: color }} />
        ))}
      </span>
    </span>
  );
}

/** A larger sample of the current colors, as a short session would show them. */
function Sample({ colors }: { colors: TerminalColors }) {
  const { t } = useI18n();
  const c = colors.ansi;
  const prompt = (
    <>
      <span style={{ color: c[2] }}>deploy@prod-api-01</span>
      <span style={{ color: colors.foreground }}>:</span>
      <span style={{ color: c[4] }}>~</span>
      <span style={{ color: colors.foreground }}>$ </span>
    </>
  );
  return (
    <figure className="m-0 mt-6">
      <figcaption className="mb-2 text-sm font-medium">{t("settings.terminal.preview")}</figcaption>
      <pre
        aria-hidden="true"
        className="m-0 overflow-x-auto rounded-xl border-(length:--scoplen-border-width) border-border p-4 font-mono text-[0.8125rem] leading-6 shadow-(--scoplen-shadow-card)"
        style={{ background: colors.background, color: colors.foreground }}
      >
        <span className="block">{prompt}ls -la</span>
        <span className="block">
          <span style={{ color: c[4] }}>logs/</span> <span style={{ color: c[2] }}>run.sh</span>{" "}
          <span style={{ color: c[3] }}>app.yml</span> <span style={{ color: c[8] }}>.env.example</span>
        </span>
        <span className="block">{prompt}git status</span>
        <span className="block">
          <span style={{ color: c[1] }}>modified:</span> src/app.ts{"  "}
          <span style={{ color: c[10] }}>new file:</span> notes.md
        </span>
        <span className="block">
          <span style={{ color: c[5] }}>warning</span> <span style={{ color: c[6] }}>cache warm</span>{" "}
          <span style={{ color: c[11] }}>3 skipped</span> <span style={{ color: c[12] }}>v2.4.1</span>{" "}
          <span style={{ background: colors.selection }}>selected text</span>
        </span>
        <span className="block">
          {prompt}
          <span className="inline-block h-4 w-2 translate-y-0.5" style={{ background: colors.cursor }} />
        </span>
      </pre>
    </figure>
  );
}
