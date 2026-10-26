// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useRef, useState } from "react";
import { TerminalWorkspace, type TerminalLayoutNode, type TerminalSplitDirection } from "@scoplen/terminal";
import { Button } from "@scoplen/ui";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { useI18n } from "./i18n";
import type {
  AppInfo,
  Status,
  SavedTerminalOutput,
  TerminalSnapshot,
  WorkspaceTree,
  WorkspaceTreeInput,
} from "./ipc/bindings";
import { Frame } from "./frame";
import { HostsHome } from "./inventory/home";
import { InventoryContext } from "./inventory/api";
import { createInventoryApi } from "./inventory/core-api";
import { SessionTerminal, type SessionState } from "./session";
import { SettingsView, type SettingsSection } from "./settings";
import { ForwardsContext, useForwards } from "./use-forwards";
import { useProfile, useProfileCommands } from "./account-profiles";
import { WorkspacesDialog } from "./workspaces";
import { canvasMinimum, paneDepth, paneOrder, paneRectangles } from "./terminal-layout";
import type { SnippetTarget } from "./session-snippets";

type View = "hosts" | "settings";

type OpenSession = { id: string; profileId: string; label: string; snapshot?: TerminalSnapshot; sessionId?: string };

function savedTree(node: TerminalLayoutNode, sessions: OpenSession[]): WorkspaceTreeInput {
  if (node.type === "pane") {
    const session = sessions.find((entry) => entry.id === node.paneId)!;
    return session.snapshot ? { kind: "savedOutput" } : { kind: "terminal", profileId: session.profileId };
  }
  return {
    kind: "split",
    direction: node.direction,
    first: savedTree(node.children[0]!, sessions),
    second: savedTree(node.children[1]!, sessions),
  };
}

function restoredTree(tree: WorkspaceTree, sessions: OpenSession[]): TerminalLayoutNode {
  if (tree.kind === "terminal") {
    const terminal = tree.terminal;
    sessions.push({
      id: terminal.sessionId,
      sessionId: terminal.sessionId,
      profileId: terminal.profileId,
      label: terminal.label,
    });
    return { type: "pane", paneId: terminal.sessionId };
  }
  return {
    type: "split",
    direction: tree.direction,
    children: [restoredTree(tree.first, sessions), restoredTree(tree.second, sessions)],
  };
}

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
  const [workspace] = useState(() => new TerminalWorkspace());
  const [layout, setLayout] = useState(() => workspace.snapshot());
  useEffect(() => workspace.subscribe(setLayout), [workspace]);
  const activeTab = layout.activeTabId ?? "hosts";
  const setActiveTab = (id: string) => workspace.setActiveTab(id === "hosts" ? null : id);
  const [states, setStates] = useState<Record<string, SessionState>>({});
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("appearance");
  const inventory = useMemo(() => createInventoryApi(commands, profileGeneration), [commands, profileGeneration]);
  const forwards = useForwards();
  const closeControllers = useRef(new Map<string, (discard?: boolean) => Promise<boolean>>());
  const focusControllers = useRef(new Map<string, () => void>());
  const snippetTargets = useRef(new Map<string, () => SnippetTarget | null>());
  const paneElements = useRef(new Map<string, HTMLDivElement>());
  const [focusRequest, setFocusRequest] = useState<{ id: string } | null>(null);
  const [closingPanes, setClosingPanes] = useState<string[]>([]);
  useEffect(() => {
    if (!focusRequest) return;
    paneElements.current.get(focusRequest.id)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
    focusControllers.current.get(focusRequest.id)?.();
  }, [focusRequest]);
  const closingTabs = useRef(false);
  const allowWindowClose = useRef(false);
  const [windowError, setWindowError] = useState(false);
  const [workspacesOpen, setWorkspacesOpen] = useState(false);

  const openSession = (profileId: string, label: string) => {
    const id = `session-${crypto.randomUUID()}`;
    workspace.restoreTab({ id, title: label }, { type: "pane", paneId: id }, id);
    setSessions((current) => [...current, { id, profileId, label }]);
    setActiveTab(id);
    setView("hosts");
  };

  const viewOutput = (output: SavedTerminalOutput) => {
    const id = `output-${crypto.randomUUID()}`;
    const { target, snapshot } = output;
    workspace.restoreTab({ id, title: target.hostName }, { type: "pane", paneId: id }, id);
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

  const selectPane = (id: string, input = false) => {
    workspace.focusPane(id);
    paneElements.current.get(id)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
    if (input) setFocusRequest({ id });
  };
  const split = (id: string, direction: TerminalSplitDirection) => {
    const session = sessions.find((entry) => entry.id === id);
    const snapshot = workspace.snapshot();
    const tabId = snapshot.panes.find((pane) => pane.id === id)?.tabId;
    const tree = tabId ? snapshot.layouts[tabId] : null;
    if (
      !session ||
      session.snapshot ||
      closingTabs.current ||
      !tree ||
      paneOrder(tree).length >= 8 ||
      paneDepth(tree, id) >= 3
    )
      return;
    const paneId = `pane-${crypto.randomUUID()}`;
    workspace.splitPane(id, direction, paneId);
    setSessions((current) => [...current, { id: paneId, profileId: session.profileId, label: session.label }]);
    setFocusRequest({ id: paneId });
  };

  // Closing tabs ends their sessions; if the open tab goes, its left neighbor opens.
  const closeSessions = async (ids: string[], discard = false) => {
    if (closingTabs.current) return;
    closingTabs.current = true;
    setClosingPanes(ids);
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
        const focused = workspace.snapshot().activePaneId === id;
        workspace.closePane(id);
        const next = workspace.snapshot().activePaneId;
        if (focused && next) setFocusRequest({ id: next });
        setSessions((current) => current.filter((session) => session.id !== id));
      }
    } finally {
      closingTabs.current = false;
      setClosingPanes([]);
    }
    setStates((current) => Object.fromEntries(Object.entries(current).filter(([id]) => !closed.includes(id))));
    if (failed) {
      selectPane(failed, true);
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
              workspace.focusPane(id);
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
  }, [workspace]);

  const tabs = [
    { id: "hosts", label: t("frame.hosts") },
    ...layout.tabs.map((tab) => {
      const ids = paneOrder(layout.layouts[tab.id]!);
      const first = sessions.find((session) => session.id === ids[0]);
      const attention = ids
        .map((id) => states[id])
        .find((state) => state && ["trusting", "passphrase", "keyboardInteractive", "failed"].includes(state));
      return {
        id: tab.id,
        label: first?.label ?? tab.title,
        seed: first?.profileId,
        state: attention ?? states[ids[0]!],
      };
    }),
  ];
  const minimum = layout.layout ? canvasMinimum(layout.layout) : { width: 320, height: 240 };
  const rectangles = layout.layout ? paneRectangles(layout.layout) : {};
  const currentIds = layout.layout ? paneOrder(layout.layout) : [];

  return (
    <Frame
      platform={info.platform}
      tabs={tabs}
      active={activeTab}
      onTab={(id) => {
        setActiveTab(id);
        setView("hosts");
        const focused = workspace.snapshot().activePaneId;
        if (focused) setFocusRequest({ id: focused });
      }}
      onSettings={() => {
        setSettingsSection("appearance");
        setView(view === "settings" ? "hosts" : "settings");
      }}
      settingsActive={view === "settings"}
      onWorkspaces={() => setWorkspacesOpen(true)}
      onCloseTabs={(ids) => {
        void closeSessions(ids.flatMap((id) => (layout.layouts[id] ? paneOrder(layout.layouts[id]) : [])));
      }}
      onDuplicate={(id) => {
        const session = sessions.find((candidate) => candidate.id === paneOrder(layout.layouts[id]!)[0]);
        if (session) openSession(session.profileId, session.label);
      }}
    >
      {workspacesOpen ? (
        <WorkspacesDialog
          tabs={layout.tabs.map((tab) => ({
            tree: savedTree(layout.layouts[tab.id]!, sessions),
            focused: paneOrder(layout.layouts[tab.id]!).indexOf(layout.focusedPaneIds[tab.id]!),
          }))}
          active={activeTab === "hosts" ? null : layout.tabs.findIndex((tab) => tab.id === activeTab)}
          onClose={() => setWorkspacesOpen(false)}
          onOpen={(opened) => {
            const added: OpenSession[] = [];
            const ids = opened.tabs.map((tab) => {
              const tree = restoredTree(tab.tree, added);
              const id = `tab-${crypto.randomUUID()}`;
              const first = added.find((session) => session.id === paneOrder(tree)[0])!;
              return { id, title: first.label, tree, focused: tab.focusedSessionId };
            });
            for (const tab of ids) {
              // The local model accepts only complete safe projections returned by Rust.
              workspace.restoreTab({ id: tab.id, title: tab.title }, tab.tree, tab.focused);
            }
            setSessions((current) => [...current, ...added]);
            setActiveTab(opened.active === null ? "hosts" : ids[opened.active]!.id);
            setView("hosts");
          }}
        />
      ) : null}
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
      <main
        hidden={view === "settings" || activeTab === "hosts"}
        aria-label={t("panes.workspace")}
        className="h-full min-h-0"
      >
        <div className="flex h-10 shrink-0 items-center justify-end gap-1 border-b border-border px-3">
          <Button
            variant="ghost"
            disabled={currentIds.length < 2}
            onClick={() => {
              const id = workspace.moveFocus(-1);
              if (id) selectPane(id, true);
            }}
          >
            {t("panes.previous")}
          </Button>
          <Button
            variant="ghost"
            disabled={currentIds.length < 2}
            onClick={() => {
              const id = workspace.moveFocus(1);
              if (id) selectPane(id, true);
            }}
          >
            {t("panes.next")}
          </Button>
        </div>
        <div className="min-h-0 overflow-auto overscroll-contain" style={{ height: "calc(100% - 2.5rem)" }}>
          <div className="relative h-full w-full" style={{ minWidth: minimum.width, minHeight: minimum.height }}>
            {/* Stable siblings preserve terminal DOM and transport across layout changes. */}
            {sessions.map((session) => {
              const rectangle = rectangles[session.id];
              const owner = layout.panes.find((pane) => pane.id === session.id)?.tabId;
              const tree = owner ? layout.layouts[owner] : null;
              const splitIssue = session.snapshot
                ? t("panes.offline")
                : closingPanes.includes(session.id)
                  ? t("panes.closing")
                  : tree && (paneOrder(tree).length >= 8 || paneDepth(tree, session.id) >= 3)
                    ? t("panes.limit")
                    : undefined;
              return (
                <div
                  key={session.id}
                  hidden={view === "settings" || !rectangle}
                  data-pane-id={session.id}
                  ref={(element) => {
                    if (element) paneElements.current.set(session.id, element);
                    else paneElements.current.delete(session.id);
                  }}
                  onPointerDownCapture={() => selectPane(session.id)}
                  onFocusCapture={() => {
                    if (rectangle && view !== "settings") selectPane(session.id);
                  }}
                  className={`absolute min-h-0 min-w-0 border border-border ${layout.activePaneId === session.id ? "ring-1 ring-primary ring-inset" : ""}`}
                  style={
                    rectangle
                      ? {
                          left: `${rectangle.left}%`,
                          top: `${rectangle.top}%`,
                          width: `${rectangle.width}%`,
                          height: `${rectangle.height}%`,
                        }
                      : undefined
                  }
                >
                  <SessionTerminal
                    profileId={session.profileId}
                    label={session.label}
                    active={view !== "settings" && session.id === layout.activePaneId}
                    savedOutput={session.snapshot}
                    sessionId={session.sessionId}
                    splitIssue={splitIssue}
                    onSplit={(direction) => split(session.id, direction)}
                    registerFocus={(focus) => {
                      focusControllers.current.set(session.id, focus);
                      return () => {
                        if (focusControllers.current.get(session.id) === focus)
                          focusControllers.current.delete(session.id);
                      };
                    }}
                    registerSnippetTarget={(target) => {
                      snippetTargets.current.set(session.id, target);
                      return () => {
                        if (snippetTargets.current.get(session.id) === target)
                          snippetTargets.current.delete(session.id);
                      };
                    }}
                    getSnippetTargets={() =>
                      layout.tabs.flatMap((tab, tabIndex) =>
                        paneOrder(layout.layouts[tab.id]!).flatMap((id, paneIndex) => {
                          const target = snippetTargets.current.get(id)?.();
                          return target ? [{ ...target, location: { tab: tabIndex + 1, pane: paneIndex + 1 } }] : [];
                        }),
                      )
                    }
                    onClose={(discard) => closeSession(session.id, discard)}
                    registerClose={(close) => {
                      closeControllers.current.set(session.id, close);
                      return () => {
                        if (closeControllers.current.get(session.id) === close)
                          closeControllers.current.delete(session.id);
                      };
                    }}
                    onStateChange={(state) => setStates((current) => ({ ...current, [session.id]: state }))}
                    onLabelChange={(label) =>
                      setSessions((current) =>
                        current.map((pane) =>
                          pane.id === session.id && pane.label !== label ? { ...pane, label } : pane,
                        ),
                      )
                    }
                    onOpenColors={() => {
                      setSettingsSection("terminal");
                      setView("settings");
                    }}
                  />
                </div>
              );
            })}
          </div>
        </div>
      </main>
    </Frame>
  );
}
