// SPDX-License-Identifier: Apache-2.0
import type { TerminalLayoutNode } from "@scoplen/terminal";
import { canvasMinimum, paneDepth, paneOrder, paneRectangles } from "../src/terminal-layout";

it("preserves depth-first ordering and equal halves at the minimum inner canvas size", () => {
  const tree: TerminalLayoutNode = {
    type: "split",
    direction: "horizontal",
    children: [
      { type: "pane", paneId: "one" },
      {
        type: "split",
        direction: "vertical",
        children: [
          { type: "pane", paneId: "two" },
          { type: "pane", paneId: "three" },
        ],
      },
    ],
  };
  expect(paneOrder(tree)).toEqual(["one", "two", "three"]);
  expect(paneDepth(tree, "one")).toBe(1);
  expect(paneDepth(tree, "two")).toBe(2);
  expect(paneDepth(tree, "absent")).toBe(-1);
  expect(canvasMinimum(tree)).toEqual({ width: 640, height: 480 });
  expect(paneRectangles(tree)).toEqual({
    one: { left: 0, top: 0, width: 50, height: 100 },
    two: { left: 50, top: 0, width: 50, height: 50 },
    three: { left: 50, top: 50, width: 50, height: 50 },
  });
  expect(
    canvasMinimum({ type: "split", direction: "horizontal", children: [tree, { type: "pane", paneId: "four" }] }),
  ).toEqual({ width: 1280, height: 480 });
});
