// SPDX-License-Identifier: Apache-2.0
import { TerminalWorkspace } from "../src";

describe("TerminalWorkspace", () => {
  it("keeps tabs independent and splits panes inside the active tab", () => {
    const workspace = new TerminalWorkspace();
    const firstPane = workspace.openTab({ id: "one", title: "One" });
    const secondPane = workspace.splitPane(firstPane, "vertical", "pane:logs");
    const secondTabPane = workspace.openTab({ id: "two", title: "Two" });

    expect(workspace.snapshot()).toMatchObject({
      activeTabId: "two",
      tabs: [
        { id: "one", title: "One" },
        { id: "two", title: "Two" },
      ],
      panes: [
        { id: firstPane, tabId: "one" },
        { id: secondPane, tabId: "one" },
        { id: secondTabPane, tabId: "two" },
      ],
      layout: { type: "pane", paneId: secondTabPane },
    });

    workspace.setActiveTab("one");
    expect(workspace.snapshot().layout).toEqual({
      type: "split",
      direction: "vertical",
      children: [
        { type: "pane", paneId: firstPane },
        { type: "pane", paneId: secondPane },
      ],
    });
    expect(workspace.closeTab("one")).toBe(true);
    expect(workspace.snapshot().activeTabId).toBeNull();
    expect(workspace.snapshot().layout).toBeNull();
  });

  it("notifies subscribers with isolated snapshots and rejects duplicate tabs", () => {
    const workspace = new TerminalWorkspace();
    const snapshots: string[] = [];
    const unsubscribe = workspace.subscribe((snapshot) => snapshots.push(snapshot.activeTabId ?? "empty"));
    workspace.openTab({ id: "one", title: "One" });
    expect(snapshots).toEqual(["empty", "one"]);

    expect(() => workspace.openTab({ id: "one", title: "Duplicate" })).toThrow(/already exists/);
    unsubscribe();
    workspace.closeTab("one");
    expect(snapshots).toEqual(["empty", "one"]);
  });

  it("can split a nested pane without rewriting its sibling", () => {
    const workspace = new TerminalWorkspace();
    const firstPane = workspace.openTab({ id: "one", title: "One" });
    const secondPane = workspace.splitPane(firstPane, "horizontal", "pane:two");
    const thirdPane = workspace.splitPane(secondPane, "vertical", "pane:three");

    expect(workspace.snapshot().layout).toEqual({
      type: "split",
      direction: "horizontal",
      children: [
        { type: "pane", paneId: firstPane },
        {
          type: "split",
          direction: "vertical",
          children: [
            { type: "pane", paneId: secondPane },
            { type: "pane", paneId: thirdPane },
          ],
        },
      ],
    });
  });

  it("keeps connection state outside the layout model", () => {
    const workspace = new TerminalWorkspace();
    expect(workspace.snapshot()).toEqual({
      tabs: [],
      panes: [],
      layout: null,
      layouts: {},
      focusedPaneIds: {},
      activePaneId: null,
      activeTabId: null,
    });
    expect(workspace.paneForTab("missing")).toBeUndefined();
  });

  it("projects the first surviving pane in tree order after closing the original", () => {
    const workspace = new TerminalWorkspace();
    const first = workspace.openTab({ id: "one", title: "One" });
    workspace.splitPane(first, "horizontal", "second");
    workspace.splitPane(first, "vertical", "third");
    workspace.closePane(first);
    expect(workspace.paneForTab("one")?.id).toBe("third");
  });

  it("projects inactive trees and remembered focus, with isolated snapshots", () => {
    const workspace = new TerminalWorkspace();
    const one = workspace.openTab({ id: "one", title: "One" });
    const two = workspace.splitPane(one, "horizontal", "two");
    const three = workspace.splitPane(two, "vertical", "three");
    workspace.focusPane(two);
    workspace.openTab({ id: "other", title: "Other" });
    const snapshot = workspace.snapshot();
    expect(snapshot.focusedPaneIds.one).toBe(two);
    expect(snapshot.layouts.one).toEqual({
      type: "split",
      direction: "horizontal",
      children: [
        { type: "pane", paneId: one },
        {
          type: "split",
          direction: "vertical",
          children: [
            { type: "pane", paneId: two },
            { type: "pane", paneId: three },
          ],
        },
      ],
    });
    snapshot.focusedPaneIds.one = "broken";
    snapshot.layouts.one = { type: "pane", paneId: "broken" };
    workspace.setActiveTab("one");
    expect(workspace.snapshot().activePaneId).toBe(two);
    expect(workspace.moveFocus(1)).toBe(three);
    expect(workspace.moveFocus(1)).toBe(one);
    expect(workspace.moveFocus(-1)).toBe(three);
  });

  it("collapses the closed leaf and selects its preceding surviving neighbor", () => {
    const workspace = new TerminalWorkspace();
    const first = workspace.openTab({ id: "one", title: "One" });
    const second = workspace.splitPane(first, "horizontal", "second");
    const third = workspace.splitPane(second, "vertical", "third");
    expect(workspace.closePane(second)).toBe(true);
    expect(workspace.snapshot().activePaneId).toBe(third);
    expect(workspace.snapshot().layout).toEqual({
      type: "split",
      direction: "horizontal",
      children: [
        { type: "pane", paneId: first },
        { type: "pane", paneId: third },
      ],
    });
    workspace.closePane(third);
    expect(workspace.snapshot().activePaneId).toBe(first);
    expect(workspace.snapshot().layout).toEqual({ type: "pane", paneId: first });
    workspace.splitPane(first, "vertical", "fourth");
    workspace.focusPane(first);
    workspace.closePane(first);
    expect(workspace.snapshot().activePaneId).toBe("fourth");
    workspace.closePane("fourth");
    expect(workspace.snapshot().tabs).toEqual([]);
    expect(workspace.closePane("missing")).toBe(false);
  });

  it("restores complete trees atomically and never retains caller-owned objects", () => {
    const workspace = new TerminalWorkspace();
    const tree = {
      type: "split" as const,
      direction: "vertical" as const,
      children: [
        { type: "pane" as const, paneId: "one" },
        { type: "pane" as const, paneId: "two" },
      ],
    };
    workspace.restoreTab({ id: "restored", title: "Restored" }, tree, "two");
    tree.children[0].paneId = "changed";
    expect(workspace.snapshot().activePaneId).toBe("two");
    expect(workspace.paneForTab("restored")?.id).toBe("one");
    const before = workspace.snapshot();
    expect(() => workspace.restoreTab({ id: "bad", title: "Bad" }, { type: "pane", paneId: "one" }, "one")).toThrow(
      /already exists/,
    );
    expect(() => workspace.restoreTab({ id: "bad", title: "Bad" }, { type: "pane", paneId: "new" }, "absent")).toThrow(
      /focused pane/,
    );
    expect(workspace.snapshot()).toEqual(before);
    workspace.setActiveTab(null);
    expect(workspace.snapshot().layout).toBeNull();
    expect(workspace.snapshot().layouts.restored).toBeDefined();
  });
});
