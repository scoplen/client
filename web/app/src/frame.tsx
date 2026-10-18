// SPDX-License-Identifier: Apache-2.0
import { HostEgg, IconButton, Mark, type MarkMood } from "@scoplen/ui";
import { Settings } from "lucide-react";
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
  trusting: { mood: "awake", active: true, attention: false },
  connecting: { mood: "awake", active: true, attention: false },
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
  children,
}: {
  platform: Platform;
  tabs: FrameTab[];
  active: string;
  onTab: (id: string) => void;
  onSettings: () => void;
  settingsActive: boolean;
  children: ReactNode;
}) {
  const { t } = useI18n();
  return (
    <div className="flex h-screen flex-col bg-background">
      <header
        data-tauri-drag-region
        className={`flex h-12 shrink-0 items-center gap-1.5 border-b-(length:--scoplen-border-width) border-border pr-2 ${platform === "macos" ? "pl-[5.25rem]" : "pl-2"}`}
      >
        <div role="tablist" aria-label={t("frame.tabs")} className="flex min-w-0 items-center gap-1 overflow-x-auto">
          {tabs.map((tab, index) => {
            const selected = tab.id === active && !settingsActive;
            const face = tab.state ? faces[tab.state] : null;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={selected}
                onClick={() => onTab(tab.id)}
                className={[
                  "flex h-8 max-w-56 shrink-0 items-center gap-2 rounded-md border-(length:--scoplen-border-width) border-transparent px-3 text-sm text-muted-foreground",
                  "transition-[background-color,color,box-shadow] duration-(--duration-state) hover:bg-inset hover:text-foreground",
                  "aria-selected:border-border aria-selected:bg-raised aria-selected:text-foreground aria-selected:shadow-(--scoplen-shadow-control)",
                  index > 0 ? "scoplen-tab-in" : "",
                ].join(" ")}
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
