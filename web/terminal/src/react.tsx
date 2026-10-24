// SPDX-License-Identifier: Apache-2.0
import { forwardRef, useImperativeHandle, useLayoutEffect, useRef, type HTMLAttributes, type Ref } from "react";
import {
  DEFAULT_MAX_INPUT_BYTES,
  DEFAULT_MAX_OUTPUT_BYTES,
  DEFAULT_MAX_PENDING_WRITES,
  ScoplenTerminalElement,
  defineTerminalElement,
} from "./terminal-element";
import type {
  TerminalBytes,
  TerminalClipboard,
  TerminalError,
  TerminalProfile,
  TerminalSink,
  TerminalSize,
  TerminalSource,
} from "./types";

export interface TerminalProps extends Omit<HTMLAttributes<ScoplenTerminalElement>, "onError" | "onInput"> {
  source?: TerminalSource | null;
  sink?: TerminalSink | null;
  broadcastSink?: TerminalSink | null;
  clipboard?: TerminalClipboard | null;
  profile?: TerminalProfile;
  maxOutputBytes?: number;
  maxInputBytes?: number;
  maxPendingWrites?: number;
  readOnly?: boolean;
  onTerminalInput?: (bytes: TerminalBytes) => void;
  onTerminalBroadcastInput?: (bytes: TerminalBytes) => void;
  onTerminalBroadcastState?: (enabled: boolean) => void;
  onTerminalOutput?: (bytes: TerminalBytes) => void;
  onTerminalError?: (error: TerminalError) => void;
  onTerminalComplete?: () => void;
  /** The grid changed size; a session passes it on to the remote terminal. */
  onTerminalResize?: (size: TerminalSize) => void;
}

function assignRef<T>(ref: Ref<T> | undefined, value: T | null): void {
  if (typeof ref === "function") {
    ref(value);
  } else if (ref) {
    ref.current = value;
  }
}

/** React binding for the binary custom element; it contains no IPC or client state. */
export const Terminal = forwardRef<ScoplenTerminalElement, TerminalProps>(function Terminal(
  {
    source = null,
    sink = null,
    broadcastSink = null,
    clipboard = null,
    profile,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    maxInputBytes = DEFAULT_MAX_INPUT_BYTES,
    maxPendingWrites = DEFAULT_MAX_PENDING_WRITES,
    readOnly = false,
    onTerminalInput,
    onTerminalBroadcastInput,
    onTerminalBroadcastState,
    onTerminalOutput,
    onTerminalError,
    onTerminalComplete,
    onTerminalResize,
    children,
    ...attributes
  },
  forwardedRef,
) {
  const elementRef = useRef<ScoplenTerminalElement | null>(null);
  useImperativeHandle(forwardedRef, () => elementRef.current as ScoplenTerminalElement, []);

  useLayoutEffect(() => {
    const element = elementRef.current;
    if (!element) {
      return;
    }
    const input = (event: Event) => onTerminalInput?.((event as CustomEvent<TerminalBytes>).detail.slice());
    const broadcastInput = (event: Event) =>
      onTerminalBroadcastInput?.((event as CustomEvent<TerminalBytes>).detail.slice());
    const broadcastState = (event: Event) => onTerminalBroadcastState?.((event as CustomEvent<boolean>).detail);
    const output = (event: Event) => onTerminalOutput?.((event as CustomEvent<TerminalBytes>).detail.slice());
    const error = (event: Event) => onTerminalError?.((event as CustomEvent<TerminalError>).detail);
    const complete = () => onTerminalComplete?.();
    const resize = (event: Event) => onTerminalResize?.({ ...(event as CustomEvent<TerminalSize>).detail });
    element.addEventListener("terminal-input", input);
    element.addEventListener("terminal-broadcast-input", broadcastInput);
    element.addEventListener("terminal-broadcast-state", broadcastState);
    element.addEventListener("terminal-output", output);
    element.addEventListener("terminal-error", error);
    element.addEventListener("terminal-complete", complete);
    element.addEventListener("terminal-resize", resize);
    return () => {
      element.removeEventListener("terminal-input", input);
      element.removeEventListener("terminal-broadcast-input", broadcastInput);
      element.removeEventListener("terminal-broadcast-state", broadcastState);
      element.removeEventListener("terminal-output", output);
      element.removeEventListener("terminal-error", error);
      element.removeEventListener("terminal-complete", complete);
      element.removeEventListener("terminal-resize", resize);
    };
  }, [
    onTerminalInput,
    onTerminalBroadcastInput,
    onTerminalBroadcastState,
    onTerminalOutput,
    onTerminalError,
    onTerminalComplete,
    onTerminalResize,
  ]);

  useLayoutEffect(() => {
    defineTerminalElement();
    const element = elementRef.current;
    if (!element) {
      return;
    }
    element.source = source;
  }, [source]);

  useLayoutEffect(() => {
    const element = elementRef.current;
    if (!element) {
      return;
    }
    element.sink = sink;
    element.readOnly = readOnly;
    element.broadcastSink = broadcastSink;
    element.clipboard = clipboard;
    if (profile) {
      element.profile = profile;
    }
    element.maxOutputBytes = maxOutputBytes;
    element.maxInputBytes = maxInputBytes;
    element.maxPendingWrites = maxPendingWrites;
  }, [sink, broadcastSink, clipboard, profile, maxOutputBytes, maxInputBytes, maxPendingWrites, readOnly]);

  return (
    <scoplen-terminal
      {...attributes}
      ref={(element: ScoplenTerminalElement | null) => {
        elementRef.current = element;
        assignRef(forwardedRef, element);
      }}
    >
      {children}
    </scoplen-terminal>
  );
});

declare module "react" {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace JSX {
    interface IntrinsicElements {
      "scoplen-terminal": import("react").HTMLAttributes<ScoplenTerminalElement> &
        import("react").RefAttributes<ScoplenTerminalElement>;
    }
  }
}

export type {
  TerminalBytes,
  TerminalClipboard,
  TerminalError,
  TerminalProfile,
  TerminalSink,
  TerminalSize,
  TerminalSource,
};
