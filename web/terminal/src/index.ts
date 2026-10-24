// SPDX-License-Identifier: Apache-2.0
export {
  DEFAULT_MAX_INPUT_BYTES,
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_MAX_PENDING_WRITES,
  TERMINAL_TAG_NAME,
  ScoplenTerminalElement,
  defineTerminalElement,
} from "./terminal-element";
export { TerminalBackpressureError, TerminalBoundsError, TerminalDisconnectedError, TerminalError } from "./types";
export { TerminalWorkspace } from "./workspace";
export { TerminalImeCompositionBridge } from "./ime";
export type { TerminalImeCommit } from "./ime";
export type {
  TerminalBytes,
  TerminalBroadcastConfirmation,
  TerminalClipboard,
  TerminalElementEventMap,
  TerminalObjectSink,
  TerminalProfile,
  TerminalSize,
  TerminalSnapshot,
  TerminalSink,
  TerminalSource,
  TerminalSubscription,
  TerminalSubscriptionSource,
  TerminalEventName,
} from "./types";
export type {
  TerminalLayoutNode,
  TerminalPane,
  TerminalSplitDirection,
  TerminalTab,
  TerminalWorkspaceListener,
  TerminalWorkspaceSnapshot,
} from "./workspace";
