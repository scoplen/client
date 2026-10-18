// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { Mark } from "./mark";

export interface NoticeProps {
  /** What just happened. */
  message: string;
  /** An action such as Undo, if there is one. */
  action?: { label: string; onAction: () => void };
  /** Called when the notice goes away. */
  onDismiss: () => void;
  /** Milliseconds before it goes away; paused while pointed at or focused. */
  duration?: number;
}

/**
 * A brief notice at the bottom of the window, announced politely. It stays
 * while the pointer or keyboard focus is on it, so its action stays reachable.
 */
export function Notice({ message, action, onDismiss, duration = 8000 }: NoticeProps) {
  const [held, setHeld] = useState(false);
  const dismiss = useRef(onDismiss);
  useEffect(() => {
    dismiss.current = onDismiss;
  });
  useEffect(() => {
    if (held) return;
    const timer = setTimeout(() => dismiss.current(), duration);
    return () => clearTimeout(timer);
  }, [held, duration, message]);

  return (
    <div
      role="status"
      onPointerEnter={() => setHeld(true)}
      onPointerLeave={() => setHeld(false)}
      onFocus={() => setHeld(true)}
      onBlur={() => setHeld(false)}
      className="scoplen-notice fixed bottom-5 left-1/2 z-40 flex max-w-[calc(100vw-2rem)] -translate-x-1/2 items-center gap-3 rounded-full border-(length:--scoplen-border-width) border-border bg-foreground py-1.5 pr-1.5 pl-3 text-sm text-background shadow-(--scoplen-shadow-popover)"
    >
      <Mark size="1.375rem" className="shrink-0 text-background" />
      <span className="py-1 pr-2">{message}</span>
      {action ? (
        <button
          type="button"
          onClick={action.onAction}
          className="rounded-full px-3.5 py-1.5 font-medium text-[color-mix(in_srgb,var(--primary)_55%,var(--background))] transition-colors duration-(--duration-micro) hover:bg-[color-mix(in_srgb,var(--background)_14%,transparent)]"
        >
          {action.label}
        </button>
      ) : null}
    </div>
  );
}
