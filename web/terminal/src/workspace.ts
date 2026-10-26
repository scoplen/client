// SPDX-License-Identifier: Apache-2.0

export type TerminalSplitDirection = "horizontal" | "vertical";

export interface TerminalTab {
  id: string;
  title: string;
}

export interface TerminalPane {
  id: string;
  tabId: string;
}

export type TerminalLayoutNode =
  | { type: "pane"; paneId: string }
  | { type: "split"; direction: TerminalSplitDirection; children: TerminalLayoutNode[] };

export interface TerminalWorkspaceSnapshot {
  tabs: TerminalTab[];
  /** All panes, including panes belonging to inactive tabs. */
  panes: TerminalPane[];
  /** The active tab's layout, or null when no tab is open. */
  layout: TerminalLayoutNode | null;
  /** Complete layouts and remembered focus, including inactive tabs. */
  layouts: Record<string, TerminalLayoutNode>;
  focusedPaneIds: Record<string, string>;
  activePaneId: string | null;
  activeTabId: string | null;
}

export type TerminalWorkspaceListener = (snapshot: TerminalWorkspaceSnapshot) => void;

interface WorkspaceTab {
  tab: TerminalTab;
  layout: TerminalLayoutNode;
  focusedPaneId: string;
}

function leaves(node: TerminalLayoutNode): string[] {
  return node.type === "pane" ? [node.paneId] : node.children.flatMap(leaves);
}

function cloneNode(node: TerminalLayoutNode): TerminalLayoutNode {
  return node.type === "pane"
    ? { type: "pane", paneId: node.paneId }
    : { type: "split", direction: node.direction, children: node.children.map(cloneNode) };
}

function requireId(id: string, name: string): string {
  if (!id.trim()) {
    throw new TypeError(`${name} must not be empty`);
  }
  return id;
}

/**
 * Session-agnostic tabs and split layout state. It deliberately stores no
 * connection, transport, or credential; callers attach a terminal element to
 * each pane when a session exists.
 */
export class TerminalWorkspace {
  private tabs: WorkspaceTab[] = [];
  private panes: TerminalPane[] = [];
  private activeTabId: string | null = null;
  private listeners = new Set<TerminalWorkspaceListener>();

  snapshot(): TerminalWorkspaceSnapshot {
    const active = this.activeTabId ? this.tabs.find((entry) => entry.tab.id === this.activeTabId) : undefined;
    return {
      tabs: this.tabs.map(({ tab }) => ({ ...tab })),
      panes: this.panes.map((pane) => ({ ...pane })),
      layout: active ? cloneNode(active.layout) : null,
      layouts: Object.fromEntries(this.tabs.map(({ tab, layout }) => [tab.id, cloneNode(layout)])),
      focusedPaneIds: Object.fromEntries(this.tabs.map(({ tab, focusedPaneId }) => [tab.id, focusedPaneId])),
      activePaneId: active?.focusedPaneId ?? null,
      activeTabId: this.activeTabId,
    };
  }

  subscribe(listener: TerminalWorkspaceListener): () => void {
    this.listeners.add(listener);
    listener(this.snapshot());
    return () => this.listeners.delete(listener);
  }

  openTab(tab: TerminalTab): string {
    const paneId = this.paneId(tab.id);
    this.restoreTab(tab, { type: "pane", paneId }, paneId);
    return paneId;
  }

  /** Append a complete layout; identities and connection creation belong to the caller. */
  restoreTab(tab: TerminalTab, layout: TerminalLayoutNode, focusedPaneId: string): void {
    const id = requireId(tab.id, "tab.id");
    const title = requireId(tab.title, "tab.title");
    if (this.tabs.some((entry) => entry.tab.id === id)) {
      throw new Error(`terminal tab already exists: ${id}`);
    }
    const paneIds: string[] = [];
    const validate = (node: TerminalLayoutNode) => {
      if (node.type === "pane") {
        const paneId = requireId(node.paneId, "paneId");
        if (paneIds.includes(paneId) || this.panes.some((pane) => pane.id === paneId)) {
          throw new Error(`terminal pane already exists: ${paneId}`);
        }
        paneIds.push(paneId);
      } else {
        if ((node.direction !== "horizontal" && node.direction !== "vertical") || node.children.length !== 2) {
          throw new TypeError("terminal splits require a direction and exactly two children");
        }
        node.children.forEach(validate);
      }
    };
    validate(layout);
    if (!paneIds.includes(focusedPaneId)) throw new Error("focused pane must belong to its tab");
    this.tabs.push({ tab: { id, title }, layout: cloneNode(layout), focusedPaneId });
    this.panes.push(...paneIds.map((paneId) => ({ id: paneId, tabId: id })));
    this.activeTabId = id;
    this.notify();
  }

  splitPane(paneId: string, direction: TerminalSplitDirection, newPaneId: string): string {
    requireId(paneId, "paneId");
    const owner = this.tabs.find((entry) => this.containsPane(entry.layout, paneId));
    if (!owner) {
      throw new Error(`terminal pane does not exist: ${paneId}`);
    }
    if (direction !== "horizontal" && direction !== "vertical") {
      throw new TypeError("terminal split direction must be horizontal or vertical");
    }
    const id = requireId(newPaneId, "newPaneId");
    if (this.panes.some((entry) => entry.id === id)) {
      throw new Error(`terminal pane already exists: ${id}`);
    }
    const nextPaneId = id;
    owner.layout = this.replacePane(owner.layout, paneId, {
      type: "split",
      direction,
      children: [
        { type: "pane", paneId },
        { type: "pane", paneId: nextPaneId },
      ],
    });
    this.panes.push({ id: nextPaneId, tabId: owner.tab.id });
    owner.focusedPaneId = nextPaneId;
    this.notify();
    return nextPaneId;
  }

  setActiveTab(tabId: string | null): void {
    if (tabId !== null) requireId(tabId, "tabId");
    if (tabId !== null && !this.tabs.some((entry) => entry.tab.id === tabId)) {
      throw new Error(`terminal tab does not exist: ${tabId}`);
    }
    if (this.activeTabId === tabId) {
      return;
    }
    this.activeTabId = tabId;
    this.notify();
  }

  focusPane(paneId: string): void {
    const owner = this.tabs.find((entry) => this.containsPane(entry.layout, paneId));
    if (!owner) throw new Error(`terminal pane does not exist: ${paneId}`);
    if (owner.focusedPaneId === paneId && this.activeTabId === owner.tab.id) return;
    owner.focusedPaneId = paneId;
    this.activeTabId = owner.tab.id;
    this.notify();
  }

  /** Select metadata only; callers move the actual terminal input focus. */
  moveFocus(offset: -1 | 1): string | null {
    const owner = this.tabs.find((entry) => entry.tab.id === this.activeTabId);
    if (!owner) return null;
    const order = leaves(owner.layout);
    const id = order[(order.indexOf(owner.focusedPaneId) + offset + order.length) % order.length];
    this.focusPane(id);
    return id;
  }

  /** Remove a successfully closed pane and collapse its parent to its sibling. */
  closePane(paneId: string): boolean {
    const owner = this.tabs.find((entry) => this.containsPane(entry.layout, paneId));
    if (!owner) return false;
    const order = leaves(owner.layout);
    if (order.length === 1) return this.closeTab(owner.tab.id);
    const remove = (node: TerminalLayoutNode): TerminalLayoutNode | null => {
      if (node.type === "pane") return node.paneId === paneId ? null : node;
      const remaining = node.children.map(remove).filter((child) => child !== null);
      return remaining.length === 1 ? remaining[0] : { ...node, children: remaining };
    };
    owner.layout = remove(owner.layout)!;
    this.panes = this.panes.filter((pane) => pane.id !== paneId);
    if (owner.focusedPaneId === paneId) {
      const index = order.indexOf(paneId);
      owner.focusedPaneId = order[index - 1] ?? order[1];
    }
    this.notify();
    return true;
  }

  closeTab(tabId: string): boolean {
    requireId(tabId, "tabId");
    const tabIndex = this.tabs.findIndex((entry) => entry.tab.id === tabId);
    if (tabIndex < 0) {
      return false;
    }
    const paneIds = this.panes.filter((pane) => pane.tabId === tabId).map((pane) => pane.id);
    this.tabs.splice(tabIndex, 1);
    this.panes = this.panes.filter((pane) => !paneIds.includes(pane.id));
    if (this.activeTabId === tabId) {
      this.activeTabId = this.tabs[tabIndex - 1]?.tab.id ?? null;
    }
    this.notify();
    return true;
  }

  paneForTab(tabId: string): TerminalPane | undefined {
    const owner = this.tabs.find((entry) => entry.tab.id === tabId);
    const first = owner ? leaves(owner.layout)[0] : undefined;
    return this.panes.find((pane) => pane.id === first);
  }

  private paneId(tabId: string): string {
    return `pane:${tabId}`;
  }

  private replacePane(node: TerminalLayoutNode, paneId: string, replacement: TerminalLayoutNode): TerminalLayoutNode {
    if (node.type === "pane") {
      if (node.paneId !== paneId) {
        throw new Error(`terminal pane does not exist: ${paneId}`);
      }
      return replacement;
    }
    if (!node.children.some((child) => this.containsPane(child, paneId))) {
      throw new Error(`terminal pane does not exist: ${paneId}`);
    }
    return {
      ...node,
      children: node.children.map((child) =>
        this.containsPane(child, paneId) ? this.replacePane(child, paneId, replacement) : child,
      ),
    };
  }

  private containsPane(node: TerminalLayoutNode, paneId: string): boolean {
    return node.type === "pane"
      ? node.paneId === paneId
      : node.children.some((child) => this.containsPane(child, paneId));
  }

  private notify(): void {
    const snapshot = this.snapshot();
    for (const listener of this.listeners) {
      listener(snapshot);
    }
  }
}
