// SPDX-License-Identifier: Apache-2.0
import { HostEgg, IconButton, Mark, useContextMenu, type MarkMood } from "@scoplen/ui";
import { Settings, X } from "lucide-react";
import type { ReactNode } from "react";
import { useI18n } from "./i18n";
import type { Platform } from "./ipc/bindings";
import type { SessionState } from "./session";

export interface FrameTab {
  id: string;
  label: string;
  /** For a session tab: what the connection is doing, shown on the host's egg. */
  state?: SessionState;
  /** For a session tab: the login, so the tab's egg matches the host's. */
  seed?: string;
}

/** The face a session tab's egg makes for each connection state. */
const faces: Record<SessionState, { mood: MarkMood; active: boolean; attention: boolean }> = {
  verifying: { mood: "awake", active: true, attention: false },
  trusting: { mood: "awake", active: true, attention: true },
  passphrase: { mood: "awake", active: true, attention: true },
  keyboardInteractive: { mood: "awake", active: true, attention: true },
  connecting: { mood: "awake", active: true, attention: false },
  reconnecting: { mood: "awake", active: true, attention: false },
  connected: { mood: "rest", active: true, attention: false },
  closed: { mood: "closed", active: false, attention: false },
  failed: { mood: "low", active: false, attention: true },
};

/**
 * The window: a strip of tabs above the content. The first tab is always
 * Hosts, led by the mark; each session adds a tab led by its host's egg,
 * whose face shows the connection (eyes wide while connecting, asleep when
 * closed). On macOS the strip is the title bar, with room left for the
 * window controls, and dragging its empty space moves the window.
 */
export function Frame({
  platform,
  tabs,
  active,
  onTab,
  onSettings,
  settingsActive,
  onCloseTabs,
  onDuplicate,
  children,
}: {
  platform: Platform;
  tabs: FrameTab[];
  active: string;
  onTab: (id: string) => void;
  onSettings: () => void;
  settingsActive: boolean;
  /** Closes these session tabs (the Hosts tab cannot be closed). */
  onCloseTabs?: (ids: string[]) => void;
  /** Opens another session to the same login as this tab. */
  onDuplicate?: (id: string) => void;
  children: ReactNode;
}) {
  const { t } = useI18n();
  const menu = useContextMenu();
  const sessionIds = tabs.slice(1).map((tab) => tab.id);
  return (
    <div className="isolate flex h-screen flex-col bg-background">
      <header
        data-tauri-drag-region
        className={`flex h-12 shrink-0 items-center gap-1.5 border-b-(length:--scoplen-border-width) border-border pr-2 ${platform === "macos" ? "pl-[5.75rem]" : "pl-2"}`}
      >
        <div
          role="tablist"
          aria-label={t("frame.tabs")}
          className="-my-1.5 flex min-w-0 items-center gap-1 overflow-x-auto py-1.5 pr-1.5 pl-0.5"
        >
          {tabs.map((tab, index) => {
            const selected = tab.id === active && !settingsActive;
            const face = tab.state ? faces[tab.state] : null;
            const closable = index > 0 && onCloseTabs;
            return (
              <div
                key={tab.id}
                className={[
                  "group/tab relative flex h-8 max-w-56 shrink-0 items-center rounded-md border-(length:--scoplen-border-width) border-transparent text-sm text-muted-foreground",
                  "transition-[background-color,color,box-shadow] duration-(--duration-state) hover:bg-inset hover:text-foreground",
                  "has-[[aria-selected=true]]:border-border has-[[aria-selected=true]]:bg-raised has-[[aria-selected=true]]:text-foreground has-[[aria-selected=true]]:shadow-(--scoplen-shadow-control)",
                  index > 0 ? "scoplen-tab-in" : "",
                ].join(" ")}
                onAuxClick={(event) => {
                  if (closable && event.button === 1) onCloseTabs([tab.id]);
                }}
                onContextMenu={(event) => {
                  if (!closable) return menu(event, []);
                  const right = sessionIds.slice(sessionIds.indexOf(tab.id) + 1);
                  menu(event, [
                    ...(onDuplicate
                      ? [{ label: t("menu.duplicate"), onSelect: () => onDuplicate(tab.id) }, "separator" as const]
                      : []),
                    { label: t("menu.closeTab"), onSelect: () => onCloseTabs([tab.id]) },
                    {
                      label: t("menu.closeOthers"),
                      disabled: sessionIds.length < 2,
                      onSelect: () => onCloseTabs(sessionIds.filter((id) => id !== tab.id)),
                    },
                    { label: t("menu.closeRight"), disabled: right.length === 0, onSelect: () => onCloseTabs(right) },
                  ]);
                }}
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  onClick={() => onTab(tab.id)}
                  className={`flex h-full min-w-0 items-center gap-2 rounded-md pl-3 ${closable ? "pr-1.5" : "pr-3"}`}
                >
                  {index === 0 ? (
                    <Mark size="1.125rem" className={selected ? "text-primary" : ""} />
                  ) : (
                    <HostEgg
                      seed={tab.seed ?? tab.id}
                      size="1.125rem"
                      mood={face?.mood}
                      active={face?.active ?? selected}
                      attention={face?.attention}
                    />
                  )}
                  <span className="truncate">{tab.label}</span>
                  {tab.state ? <span className="sr-only">{t(`frame.state.${tab.state}`)}</span> : null}
                </button>
                {closable ? (
                  <IconButton
                    label={t("frame.close", { name: tab.label })}
                    onClick={() => onCloseTabs([tab.id])}
                    className={`mr-1 size-5! rounded-sm! ${selected ? "" : "opacity-0 group-hover/tab:opacity-100 focus-visible:opacity-100"}`}
                  >
                    <X aria-hidden="true" className="size-3.5" />
                  </IconButton>
                ) : null}
              </div>
            );
          })}
        </div>
        <div data-tauri-drag-region className="h-full min-w-6 flex-1" />
        <IconButton label={t("frame.settings")} pressed={settingsActive} onClick={onSettings}>
          <Settings aria-hidden="true" className="size-4" />
        </IconButton>
      </header>
      <div className="relative min-h-0 flex-1">{children}</div>
    </div>
  );
}
