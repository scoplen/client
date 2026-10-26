// SPDX-License-Identifier: Apache-2.0
import type { TerminalLayoutNode } from "@scoplen/terminal";

export function paneOrder(node: TerminalLayoutNode): string[] {
  return node.type === "pane" ? [node.paneId] : node.children.flatMap(paneOrder);
}

export function paneDepth(node: TerminalLayoutNode, id: string, depth = 0): number {
  if (node.type === "pane") return node.paneId === id ? depth : -1;
  return Math.max(...node.children.map((child) => paneDepth(child, id, depth + 1)));
}

/** Equal halves must accommodate the larger child at every branch. */
export function canvasMinimum(node: TerminalLayoutNode): { width: number; height: number } {
  if (node.type === "pane") return { width: 320, height: 240 };
  const children = node.children.map(canvasMinimum);
  return {
    width: Math.max(...children.map((child) => child.width)) * (node.direction === "horizontal" ? 2 : 1),
    height: Math.max(...children.map((child) => child.height)) * (node.direction === "vertical" ? 2 : 1),
  };
}

export interface PaneRectangle {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** Flat geometry keeps each React child and custom element under one stable parent. */
export function paneRectangles(
  node: TerminalLayoutNode,
  rectangle: PaneRectangle = { left: 0, top: 0, width: 100, height: 100 },
): Record<string, PaneRectangle> {
  if (node.type === "pane") return { [node.paneId]: rectangle };
  const horizontal = node.direction === "horizontal";
  return Object.assign(
    {},
    ...node.children.map((child, index) =>
      paneRectangles(child, {
        left: rectangle.left + (horizontal ? (index * rectangle.width) / 2 : 0),
        top: rectangle.top + (horizontal ? 0 : (index * rectangle.height) / 2),
        width: rectangle.width / (horizontal ? 2 : 1),
        height: rectangle.height / (horizontal ? 1 : 2),
      }),
    ),
  );
}
