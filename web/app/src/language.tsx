// SPDX-License-Identifier: Apache-2.0
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";
import type { Locale } from "./ipc/bindings";

/** The interface language a person chose, or the one the system implies. */
export type LanguageChoice = Locale | "system";

export const languageChoices: LanguageChoice[] = ["system", "en", "zh-Hans"];

const storageKey = "scoplen.language";

function readChoice(): LanguageChoice {
  try {
    const stored = localStorage.getItem(storageKey);
    return languageChoices.includes(stored as LanguageChoice) ? (stored as LanguageChoice) : "system";
  } catch {
    return "system";
  }
}

const LanguageContext = createContext<{ choice: LanguageChoice; setChoice: (choice: LanguageChoice) => void }>({
  choice: "system",
  setChoice: () => undefined,
});

/**
 * The person's language choice. "system" uses the language the core
 * negotiated from the system; a chosen language overrides it in the
 * interface. Kept in the webview's local storage as an interface
 * preference of this device, like the theme.
 */
export function useLanguageState(): [LanguageChoice, (choice: LanguageChoice) => void] {
  const [choice, setState] = useState<LanguageChoice>(readChoice);
  const setChoice = useCallback((next: LanguageChoice) => {
    setState(next);
    try {
      localStorage.setItem(storageKey, next);
    } catch {
      // Without storage the choice lasts until the window closes.
    }
  }, []);
  return [choice, setChoice];
}

export function LanguageProvider({
  choice,
  setChoice,
  children,
}: {
  choice: LanguageChoice;
  setChoice: (choice: LanguageChoice) => void;
  children: ReactNode;
}) {
  return <LanguageContext.Provider value={{ choice, setChoice }}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  return useContext(LanguageContext);
}
