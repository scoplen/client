// SPDX-License-Identifier: Apache-2.0
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow, type Window } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useI18n } from "./i18n";

/** Stays available during startup and unlocking as well as inside the main shell. */
export function WindowControls({ standalone }: { standalone: boolean }) {
  const { t } = useI18n();
  const [window, setWindow] = useState<Window | null>(null);
  const [maximized, setMaximized] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!isTauri()) return;
    const current = getCurrentWindow();
    let active = true;
    const update = async () => {
      try {
        const value = await current.isMaximized();
        if (active) setMaximized(value);
      } catch {
        if (active) setFailed(true);
      }
    };
    const subscription = (async () => {
      if (await current.isDecorated()) return;
      if (!active) return;
      setWindow(current);
      await update();
      return current.onResized(() => void update());
    })();
    void subscription.catch(() => {
      if (active) setFailed(true);
    });
    return () => {
      active = false;
      void subscription.then((stop) => stop?.()).catch(() => undefined);
    };
  }, []);

  const perform = async (action: "minimize" | "toggleMaximize" | "close") => {
    if (!window) return;
    setFailed(false);
    try {
      // Normal close preserves the shell's terminal-save and shutdown checks.
      await window[action]();
      if (action === "toggleMaximize") setMaximized(await window.isMaximized());
    } catch {
      setFailed(true);
    }
  };

  if (!window && !failed) return null;
  return (
    <div
      data-tauri-drag-region
      className={`fixed top-0 right-0 z-40 flex h-12 justify-end ${standalone ? "left-0 bg-background" : ""}`}
    >
      {window ? (
        <div role="group" aria-label={t("window.controls")} className="flex h-full shrink-0">
          {(
            [
              ["minimize", "window.minimize", Minus],
              ["toggleMaximize", maximized ? "window.restore" : "window.maximize", maximized ? Copy : Square],
              ["close", "window.close", X],
            ] as const
          ).map(([action, label, Icon]) => (
            <button
              key={action}
              type="button"
              aria-label={t(label)}
              title={t(label)}
              className={`grid h-full w-[2.875rem] place-items-center text-muted-foreground transition-colors duration-(--duration-micro) focus-visible:-outline-offset-4 ${action === "close" ? "hover:bg-attention hover:text-attention-foreground" : "hover:bg-inset hover:text-foreground"}`}
              onClick={() => void perform(action)}
            >
              <Icon aria-hidden="true" className="size-3.5" strokeWidth={1.5} />
            </button>
          ))}
        </div>
      ) : null}
      {failed ? (
        <p
          role="alert"
          className="absolute top-full right-2 max-w-64 rounded-md border border-border bg-raised p-3 text-xs text-attention shadow-md"
        >
          {t("window.failed")}
        </p>
      ) : null}
    </div>
  );
}
