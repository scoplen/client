// SPDX-License-Identifier: Apache-2.0
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/** The themes in `themes.css`, in the order the settings show them. */
export const themes = [
  { id: "paper", schemes: ["light", "dark"] },
  { id: "brutal", schemes: ["light", "dark"] },
  { id: "sakura", schemes: ["light", "dark"] },
  { id: "midnight", schemes: ["dark"] },
  { id: "phosphor", schemes: ["dark"] },
] as const;

export type ThemeId = (typeof themes)[number]["id"];
export type Scheme = "light" | "dark";
/** What the person chose: a scheme, or whatever the system uses. */
export type SchemeChoice = Scheme | "system";

export interface Appearance {
  theme: ThemeId;
  scheme: SchemeChoice;
}

export const defaultAppearance: Appearance = { theme: "paper", scheme: "system" };

const storageKey = "scoplen.appearance";

function systemScheme(): Scheme {
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

/** The scheme a theme is actually shown in: a dark-only theme is always dark. */
export function resolveScheme(appearance: Appearance, system: Scheme = systemScheme()): Scheme {
  const supported = themes.find((t) => t.id === appearance.theme)?.schemes ?? ["light", "dark"];
  const wanted = appearance.scheme === "system" ? system : appearance.scheme;
  return (supported as readonly Scheme[]).includes(wanted) ? wanted : supported[0]!;
}

/** Sets the theme attributes on an element (the document, or a preview). */
export function applyAppearance(element: HTMLElement, appearance: Appearance, system?: Scheme) {
  element.dataset.theme = appearance.theme;
  element.dataset.scheme = resolveScheme(appearance, system);
}

/**
 * The person's appearance choice. It is an interface preference of this
 * device, kept in the webview's local storage; it holds nothing secret.
 */
export function readAppearance(): Appearance {
  try {
    const stored = JSON.parse(localStorage.getItem(storageKey) ?? "null") as Partial<Appearance> | null;
    const theme = themes.some((t) => t.id === stored?.theme) ? (stored!.theme as ThemeId) : defaultAppearance.theme;
    const scheme = ["light", "dark", "system"].includes(stored?.scheme ?? "")
      ? (stored!.scheme as SchemeChoice)
      : defaultAppearance.scheme;
    return { theme, scheme };
  } catch {
    return defaultAppearance;
  }
}

function writeAppearance(appearance: Appearance) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(appearance));
  } catch {
    // Storage can be unavailable; the choice then lasts until the window closes.
  }
}

/** Applies the stored choice to the document before the first render, so nothing flashes. */
export function applyStoredAppearance() {
  applyAppearance(document.documentElement, readAppearance());
}

interface AppearanceContextValue {
  appearance: Appearance;
  scheme: Scheme;
  setAppearance: (next: Appearance) => void;
}

const AppearanceContext = createContext<AppearanceContextValue | null>(null);

/** Keeps the document's theme in step with the choice and with the system scheme. */
export function AppearanceProvider({ children, initial }: { children: ReactNode; initial?: Appearance }) {
  const [appearance, setState] = useState<Appearance>(() => initial ?? readAppearance());
  const [system, setSystem] = useState<Scheme>(systemScheme);

  useEffect(() => {
    const query = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!query) return;
    const update = () => setSystem(query.matches ? "dark" : "light");
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    applyAppearance(document.documentElement, appearance, system);
  }, [appearance, system]);

  const setAppearance = useCallback((next: Appearance) => {
    setState(next);
    writeAppearance(next);
  }, []);

  const value = useMemo(
    () => ({ appearance, scheme: resolveScheme(appearance, system), setAppearance }),
    [appearance, system, setAppearance],
  );
  return <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>;
}

export function useAppearance(): AppearanceContextValue {
  const value = useContext(AppearanceContext);
  if (!value) throw new Error("useAppearance needs an AppearanceProvider");
  return value;
}
