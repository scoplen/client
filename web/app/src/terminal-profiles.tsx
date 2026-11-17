// SPDX-License-Identifier: Apache-2.0
import { Button, Select } from "@scoplen/ui";
import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useProfileCommands } from "./account-profiles";
import { useI18n } from "./i18n";
import type { TerminalProfileDirectory, TerminalProfileIssue } from "./ipc/bindings";

type DirectoryResult =
  { status: "ok"; data: TerminalProfileDirectory } | { status: "error"; error: TerminalProfileIssue };
type DirectoryContext = {
  directory: TerminalProfileDirectory | null;
  issue: TerminalProfileIssue | null;
  loading: boolean;
  busy: boolean;
  reload: () => void;
  change: (operation: () => Promise<DirectoryResult>) => Promise<boolean>;
};
const Context = createContext<DirectoryContext | null>(null);

/** Mounted within the immutable Account generation; it never retains another Store's directory. */
export function TerminalProfilesProvider({ children }: { children: ReactNode }) {
  const commands = useProfileCommands();
  const [directory, setDirectory] = useState<TerminalProfileDirectory | null>(null);
  const [issue, setIssue] = useState<TerminalProfileIssue | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const alive = useRef(false);
  const pending = useRef(false);
  useEffect(() => {
    alive.current = true;
    let current = true;
    void commands
      .terminalProfilesList()
      .then((result) => {
        if (!current) return;
        if (result.status === "ok") {
          setDirectory(result.data);
          setIssue(null);
        } else setIssue(result.error);
      })
      .catch(() => {
        if (current) setIssue("unavailable");
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
      alive.current = false;
    };
  }, [commands, revision]);
  const change = useCallback(async (operation: () => Promise<DirectoryResult>) => {
    if (!alive.current || pending.current) return false;
    pending.current = true;
    setBusy(true);
    setIssue(null);
    try {
      const result = await operation();
      if (!alive.current) return false;
      if (result.status === "error") {
        setIssue(result.error);
        return false;
      }
      setDirectory(result.data);
      return true;
    } catch {
      if (alive.current) setIssue("unavailable");
      return false;
    } finally {
      pending.current = false;
      if (alive.current) setBusy(false);
    }
  }, []);
  return (
    <Context.Provider
      value={{
        directory,
        issue,
        loading,
        busy,
        reload: () => {
          setLoading(true);
          setRevision((value) => value + 1);
        },
        change,
      }}
    >
      {children}
    </Context.Provider>
  );
}

export function useTerminalProfiles() {
  return useContext(Context);
}

/** Login references remain exact, including unavailable names, until explicitly changed. */
export function TerminalProfileSelect({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string | null;
  onChange: (name: string | null) => void;
}) {
  const state = useTerminalProfiles();
  const id = useId();
  const { t } = useI18n();
  const named = state?.directory?.named ?? [];
  const missing = value !== null && !named.some((entry) => entry.name === value);
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      <Select
        id={id}
        label={label}
        size="field"
        value={value === null ? "default" : `name:${value}`}
        disabled={!!state && !state.directory}
        options={[
          { value: "default", label: t("terminalProfiles.default") },
          ...named.map((entry) => ({ value: `name:${entry.name}`, label: entry.name })),
          ...(missing
            ? [{ value: `name:${value!}`, label: t("terminalProfiles.unavailableName", { name: value! }) }]
            : []),
        ]}
        onValueChange={(name) => onChange(name === "default" ? null : name.slice(5))}
      />
      {state?.loading ? <p className="m-0 text-xs text-muted-foreground">{t("terminalProfiles.loading")}</p> : null}
      {state && !state.directory && state.issue ? (
        <div role="alert" className="text-sm text-attention">
          {t(`terminalProfiles.issue.${state.issue}`)}{" "}
          <Button variant="ghost" onClick={state.reload}>
            {t("terminalProfiles.reload")}
          </Button>
        </div>
      ) : null}
      {state?.directory && missing ? (
        <p className="m-0 text-xs text-muted-foreground">{t("terminalProfiles.missing", { name: value! })}</p>
      ) : null}
    </div>
  );
}
