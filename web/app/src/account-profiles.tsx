// SPDX-License-Identifier: Apache-2.0
import { invoke } from "@tauri-apps/api/core";
import { Button, Dialog, Field } from "@scoplen/ui";
import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { commands, events, makeCommands, type ProfileSnapshot } from "./ipc/bindings";
import { useI18n } from "./i18n";

type ProfileContext = {
  snapshot: ProfileSnapshot;
  commands: typeof commands;
  accept: (snapshot: ProfileSnapshot) => void;
};
const Context = createContext<ProfileContext | null>(null);

export function useProfile() {
  return useContext(Context);
}
export function useProfileCommands() {
  return useContext(Context)?.commands ?? commands;
}

/** Every view captures one immutable invoker; obsolete callbacks never borrow a newer profile. */
export function AccountProfilesBoundary({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<ProfileSnapshot | null>(null);
  const [failed, setFailed] = useState(false);
  const [reload, setReload] = useState(0);
  const { t } = useI18n();
  useEffect(() => {
    let active = true;
    let stop: (() => void) | undefined;
    void events.profileChanged
      .listen((event) => {
        if (active) setSnapshot(event.payload.snapshot);
      })
      .then((unlisten) => {
        if (active) stop = unlisten;
        else unlisten();
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    void commands
      .accountProfilesSnapshot()
      .then((result) => {
        if (!active) return;
        if (result.status === "ok") {
          setSnapshot(result.data);
          setFailed(false);
        } else setFailed(true);
      })
      .catch(() => {
        if (active) setFailed(true);
      });
    return () => {
      active = false;
      stop?.();
    };
  }, [reload]);
  if (!snapshot)
    return (
      <main id="main" className="mx-auto max-w-xl px-6 py-16" aria-busy={!failed}>
        <h1 className="ui-display text-xl">{t(failed ? "accounts.unavailable" : "accounts.loading")}</h1>
        {failed ? (
          <Button className="mt-4" onClick={() => setReload((value) => value + 1)}>
            {t("accounts.reload")}
          </Button>
        ) : null}
      </main>
    );
  return (
    <BoundProfile key={snapshot.generation} snapshot={snapshot} accept={setSnapshot}>
      {children}
    </BoundProfile>
  );
}

function BoundProfile({
  snapshot,
  accept,
  children,
}: {
  snapshot: ProfileSnapshot;
  accept: (snapshot: ProfileSnapshot) => void;
  children: ReactNode;
}) {
  const [binding] = useState(() => bindProfileCommands(snapshot.generation));
  useLayoutEffect(() => {
    binding.activate();
    return binding.deactivate;
  }, [binding]);
  return <Context.Provider value={{ snapshot, commands: binding.commands, accept }}>{children}</Context.Provider>;
}

function bindProfileCommands(generation: string) {
  let active = true;
  const bound = makeCommands(
    async <T,>(command: string, args?: Parameters<typeof invoke>[1], options?: Parameters<typeof invoke>[2]) => {
      if (!active) throw new Error("profileChanged");
      const headers = new Headers(options?.headers);
      headers.set("x-scoplen-profile-generation", generation);
      try {
        const result = await invoke<T>(command, args, { ...options, headers });
        if (!active) throw new Error("profileChanged");
        return result;
      } catch (error) {
        if (!active) throw new Error("profileChanged", { cause: error });
        throw error;
      }
    },
  );
  return {
    commands: bound,
    activate: () => {
      active = true;
    },
    deactivate: () => {
      active = false;
    },
  };
}

export function ProfileSwitcher() {
  const profile = useProfile();
  const { t } = useI18n();
  const [target, setTarget] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const form = useRef<HTMLFormElement>(null);
  if (!profile) return null;
  const snapshot = profile.snapshot;
  if (snapshot.retainedProfile)
    return <span className="max-w-40 truncate text-xs text-muted-foreground">{t("accounts.retained")}</span>;
  const select = async () => {
    if (busy || target === undefined) return;
    setBusy(true);
    setFailed(null);
    const input = form.current?.elements.namedItem("passphrase") as HTMLInputElement | null;
    const request = commands.selectAccountProfile(snapshot.generation, target || null, input?.value || null);
    if (input) input.value = "";
    try {
      const result = await request;
      if (result.status === "ok") profile.accept(result.data);
      else setFailed(result.error);
    } catch {
      setFailed("profileUnavailable");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <label className="sr-only" htmlFor="account-profile">
        {t("accounts.selector")}
      </label>
      <select
        id="account-profile"
        aria-label={t("accounts.selector")}
        value={snapshot.selected ?? ""}
        className="ui-control h-8 max-w-40 min-w-0 rounded-md border border-border bg-background px-2 text-xs sm:max-w-56"
        onChange={(event) => {
          setTarget(event.target.value);
          setFailed(null);
        }}
      >
        <option value="">{t("accounts.local")}</option>
        {snapshot.accounts
          .filter((account) => account.ready)
          .map((account) => (
            <option key={account.id} value={account.id}>
              {account.origin} · {account.accountId}
            </option>
          ))}
      </select>
      <Dialog
        open={target !== undefined}
        onOpenChange={(open) => {
          if (!open && !busy) setTarget(undefined);
        }}
        title={t("accounts.switchTitle")}
        description={t("accounts.switchBody")}
        closeLabel={t("accounts.keep")}
        footer={
          <>
            <Button disabled={busy} onClick={() => setTarget(undefined)}>
              {t("accounts.keep")}
            </Button>
            <Button variant="primary" disabled={busy} onClick={() => void select()}>
              {t(busy ? "accounts.switching" : "accounts.switch")}
            </Button>
          </>
        }
      >
        <form
          ref={form}
          onSubmit={(event) => {
            event.preventDefault();
            void select();
          }}
          aria-busy={busy}
        >
          {target ? (
            <Field
              name="passphrase"
              type="password"
              autoComplete="off"
              label={t("accounts.passphrase")}
              hint={t("accounts.passphraseHint")}
              disabled={busy}
            />
          ) : null}
          {failed ? <AccountError code={failed} /> : null}
        </form>
      </Dialog>
    </>
  );
}

export function AccountError({ code }: { code: string }) {
  const { t } = useI18n();
  const known = [
    "invalidInput",
    "busy",
    "profileChanged",
    "profileChanging",
    "finishNativeDialog",
    "retainedProfile",
    "existingProfile",
    "notPrepared",
    "recoveryRequired",
    "recoverySave",
    "outcomeUnknown",
    "cancelled",
    "network",
    "unsupportedService",
    "policyDenied",
    "registrationDenied",
    "quotaExceeded",
    "retryDeferred",
    "explicitRetryRequired",
    "verification",
    "serviceUnavailable",
    "storage",
    "profileUnavailable",
    "tunnelShutdown",
    "profileUnlock",
    "installation",
    "passphraseRequired",
    "signInExisting",
    "signInAgain",
    "signInDenied",
    "signInPolicy",
    "deviceQuota",
  ] as const;
  const key = known.find((value) => value === code) ?? "storage";
  return (
    <p role="alert" className="mt-4 text-sm text-attention">
      {t(`accounts.error.${key}`)}
    </p>
  );
}
