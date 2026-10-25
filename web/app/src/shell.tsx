// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useI18n } from "./i18n";
import type { AppInfo, Status, SavedTerminalOutput, TerminalSnapshot } from "./ipc/bindings";
import { Frame } from "./frame";
import { HostsHome } from "./inventory/home";
import { InventoryContext } from "./inventory/api";
import { createInventoryApi } from "./inventory/core-api";
import { SessionTerminal, type SessionState } from "./session";
import { SettingsView, type SettingsSection } from "./settings";
import { ForwardsContext, useForwards } from "./use-forwards";
import { useProfile, useProfileCommands } from "./account-profiles";

type View = "hosts" | "settings";

type OpenSession = { id: string; profileId: string; label: string; snapshot?: TerminalSnapshot };

/** The application once its local data is open. */
export function Shell({
  info,
  status,
  onStatus,
}: {
  info: AppInfo;
  status: Status & { state: "open" };
  onStatus: (status: Status) => void;
}) {
  const { t } = useI18n();
  const commands = useProfileCommands();
  const profileGeneration = useProfile()?.snapshot.generation;
  const [view, setView] = useState<View>("hosts");
  const [sessions, setSessions] = useState<OpenSession[]>([]);
  const [activeTab, setActiveTab] = useState("hosts");
  const [states, setStates] = useState<Record<string, SessionState>>({});
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("appearance");
  const inventory = useMemo(() => createInventoryApi(commands, profileGeneration), [commands, profileGeneration]);
  const forwards = useForwards();
  const closeControllers = useRef(new Map<string, (discard?: boolean) => Promise<boolean>>());
  const closingTabs = useRef(false);
  const allowWindowClose = useRef(false);
  const [windowError, setWindowError] = useState(false);

  const openSession = (profileId: string, label: string) => {
    const id = `session-${Date.now()}-${sessions.length}`;
    setSessions((current) => [...current, { id, profileId, label }]);
    setActiveTab(id);
    setView("hosts");
  };

  const viewOutput = (output: SavedTerminalOutput) => {
    const id = `output-${crypto.randomUUID()}`;
    const { target, snapshot } = output;
    setSessions((current) => [
      ...current,
      { id, profileId: target.profileId, label: `${target.hostName} · ${target.loginName}`, snapshot },
    ]);
    setActiveTab(id);
    setView("hosts");
  };

  const closeSession = (id: string, discard = false) => {
    void closeSessions([id], discard);
  };

  // Closing tabs ends their sessions; if the open tab goes, its left neighbor opens.
  const closeSessions = async (ids: string[], discard = false) => {
    if (closingTabs.current) return;
    closingTabs.current = true;
    const closed: string[] = [];
    let failed: string | undefined;
    try {
      for (const id of ids) {
        const controller = closeControllers.current.get(id);
        if (controller && !(await controller(discard))) {
          failed ??= id;
          continue;
        }
        closed.push(id);
      }
    } finally {
      closingTabs.current = false;
    }
    const order = ["hosts", ...sessions.map((session) => session.id)];
    if (closed.includes(activeTab)) {
      const index = order.indexOf(activeTab);
      const next =
        order
          .slice(0, index)
          .reverse()
          .find((id) => !closed.includes(id)) ?? "hosts";
      setActiveTab(next);
    }
    setSessions((current) => current.filter((session) => !closed.includes(session.id)));
    if (failed) {
      setActiveTab(failed);
      setView("hosts");
    }
  };

  useEffect(() => {
    if (!isTauri()) return;
    const window = getCurrentWindow();
    let active = true;
    const subscription = window.onCloseRequested((event) => {
      if (allowWindowClose.current) return;
      event.preventDefault();
      if (closingTabs.current) return;
      closingTabs.current = true;
      void (async () => {
        for (const [id, close] of closeControllers.current) {
          if (!(await close())) {
            if (active) {
              setActiveTab(id);
              setView("hosts");
            }
            return;
          }
        }
        allowWindowClose.current = true;
        // Request normal native close again, preserving geometry and shutdown hooks.
        await window.close();
      })()
        .catch(() => {
          allowWindowClose.current = false;
          if (active) setWindowError(true);
        })
        .finally(() => {
          closingTabs.current = false;
        });
    });
    void subscription.catch(() => {
      if (active) setWindowError(true);
    });
    return () => {
      active = false;
      void subscription.then((unlisten) => unlisten()).catch(() => undefined);
    };
  }, []);

  const tabs = [
    { id: "hosts", label: t("frame.hosts") },
    ...sessions.map((session) => ({
      id: session.id,
      label: session.label,
      seed: session.profileId,
      state: states[session.id],
    })),
  ];

  return (
    <Frame
      platform={info.platform}
      tabs={tabs}
      active={activeTab}
      onTab={(id) => {
        setActiveTab(id);
        setView("hosts");
      }}
      onSettings={() => {
        setSettingsSection("appearance");
        setView(view === "settings" ? "hosts" : "settings");
      }}
      settingsActive={view === "settings"}
      onCloseTabs={(ids) => {
        void closeSessions(ids);
      }}
      onDuplicate={(id) => {
        const session = sessions.find((candidate) => candidate.id === id);
        if (session) openSession(session.profileId, session.label);
      }}
    >
      {windowError ? (
        <p role="alert" className="m-0 px-4 py-2 text-sm text-attention">
          {t("session.output.windowCloseFailed")}
        </p>
      ) : null}
      {view === "settings" ? (
        <SettingsView key={settingsSection} status={status} onStatus={onStatus} section={settingsSection} />
      ) : activeTab !== "hosts" ? null : (
        <InventoryContext.Provider value={inventory}>
          <ForwardsContext.Provider value={forwards}>
            <main id="main" tabIndex={-1} className="h-full min-h-0 focus:outline-none">
              <HostsHome manage onConnect={openSession} onViewOutput={viewOutput} />
            </main>
          </ForwardsContext.Provider>
        </InventoryContext.Provider>
      )}
      {/* Sessions stay mounted, and connected, while another tab or Settings is shown. */}
      {sessions.map((session) => (
        <div key={session.id} className="h-full min-h-0" hidden={view === "settings" || session.id !== activeTab}>
          <SessionTerminal
            profileId={session.profileId}
            label={session.label}
            active={view !== "settings" && session.id === activeTab}
            savedOutput={session.snapshot}
            onClose={(discard) => closeSession(session.id, discard)}
            registerClose={(close) => {
              closeControllers.current.set(session.id, close);
              return () => {
                if (closeControllers.current.get(session.id) === close) closeControllers.current.delete(session.id);
              };
            }}
            onStateChange={(state) => setStates((current) => ({ ...current, [session.id]: state }))}
            onOpenColors={() => {
              setSettingsSection("terminal");
              setView("settings");
            }}
          />
        </div>
      ))}
    </Frame>
  );
}
