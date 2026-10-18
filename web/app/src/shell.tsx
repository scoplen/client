// SPDX-License-Identifier: Apache-2.0
import { useMemo, useState } from "react";
import { useI18n } from "./i18n";
import type { AppInfo, Status } from "./ipc/bindings";
import { Frame } from "./frame";
import { HostsHome } from "./inventory/home";
import { InventoryContext } from "./inventory/api";
import { createInventoryApi } from "./inventory/core-api";
import { SessionTerminal, type SessionState } from "./session";
import { SettingsView, type SettingsSection } from "./settings";

type View = "hosts" | "settings";

type OpenSession = { id: string; profileId: string; label: string };

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
  const [view, setView] = useState<View>("hosts");
  const [sessions, setSessions] = useState<OpenSession[]>([]);
  const [activeTab, setActiveTab] = useState("hosts");
  const [states, setStates] = useState<Record<string, SessionState>>({});
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("appearance");
  const inventory = useMemo(() => createInventoryApi(), []);

  const openSession = (profileId: string, label: string) => {
    const id = `session-${Date.now()}-${sessions.length}`;
    setSessions((current) => [...current, { id, profileId, label }]);
    setActiveTab(id);
    setView("hosts");
  };

  const closeSession = (id: string) => closeSessions([id]);

  // Closing tabs ends their sessions; if the open tab goes, its left neighbor opens.
  const closeSessions = (ids: string[]) => {
    const order = ["hosts", ...sessions.map((session) => session.id)];
    if (ids.includes(activeTab)) {
      const index = order.indexOf(activeTab);
      const next =
        order
          .slice(0, index)
          .reverse()
          .find((id) => !ids.includes(id)) ?? "hosts";
      setActiveTab(next);
    }
    setSessions((current) => current.filter((session) => !ids.includes(session.id)));
  };

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
      onCloseTabs={closeSessions}
      onDuplicate={(id) => {
        const session = sessions.find((candidate) => candidate.id === id);
        if (session) openSession(session.profileId, session.label);
      }}
    >
      {view === "settings" ? (
        <SettingsView key={settingsSection} status={status} onStatus={onStatus} section={settingsSection} />
      ) : activeTab !== "hosts" ? null : (
        <InventoryContext.Provider value={inventory}>
          <main id="main" tabIndex={-1} className="h-full min-h-0 focus:outline-none">
            <HostsHome manage onConnect={openSession} />
          </main>
        </InventoryContext.Provider>
      )}
      {/* Sessions stay mounted, and connected, while another tab or Settings is shown. */}
      {sessions.map((session) => (
        <div key={session.id} className="h-full min-h-0" hidden={view === "settings" || session.id !== activeTab}>
          <SessionTerminal
            profileId={session.profileId}
            label={session.label}
            onClose={() => closeSession(session.id)}
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
