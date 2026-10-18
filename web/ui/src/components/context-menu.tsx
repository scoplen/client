// SPDX-License-Identifier: Apache-2.0
import { Menu } from "@base-ui/react/menu";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";

/** One entry of a context menu, or a line between groups. */
export type ContextMenuEntry =
  | {
      label: string;
      onSelect: () => void;
      /** A key equivalent shown at the right, such as "⌘C". Informational. */
      shortcut?: string;
      icon?: ReactNode;
      disabled?: boolean;
      /** Deletes, closes, or otherwise removes something. */
      destructive?: boolean;
    }
  | "separator";

/** The words the built-in menu for text fields uses. */
export interface EditMenuLabels {
  cut: string;
  copy: string;
  paste: string;
  selectAll: string;
}

type Open = { x: number; y: number; entries: ContextMenuEntry[] };

const ContextMenuContext = createContext<
  ((event: ReactMouseEvent | MouseEvent, entries: ContextMenuEntry[]) => void) | null
>(null);

const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform);
const mod = isMac ? "⌘" : "Ctrl+";

/**
 * The application's context menus, instead of the web view's. Anything can
 * offer a menu with `useContextMenu()`; text fields get Cut, Copy, Paste, and
 * Select all; everywhere else a right click does nothing, so the web view's
 * Reload and Inspect never appear. One menu is open at a time, at the
 * pointer (or at the focused element, from the keyboard), and it is a real
 * menu: arrow keys, typeahead, Escape, and focus return all work.
 */
export function ContextMenuProvider({ children, editLabels }: { children: ReactNode; editLabels: EditMenuLabels }) {
  const [open, setOpen] = useState<Open | null>(null);
  const labels = useRef(editLabels);
  useEffect(() => {
    labels.current = editLabels;
  });

  const show = useCallback((event: ReactMouseEvent | MouseEvent, entries: ContextMenuEntry[]) => {
    event.preventDefault();
    event.stopPropagation();
    // Nothing to offer here: no menu at all, rather than an empty one.
    if (entries.length === 0) return;
    let { clientX: x, clientY: y } = event;
    // From the keyboard there is no pointer: open at the element.
    if (x === 0 && y === 0 && event.target instanceof Element) {
      const rect = event.target.getBoundingClientRect();
      x = rect.left + 8;
      y = rect.top + rect.height / 2;
    }
    setOpen({ x, y, entries });
  }, []);

  // Whatever no component claimed: text fields get the edit menu, the rest nothing.
  useEffect(() => {
    const onContextMenu = (event: MouseEvent) => {
      if (event.defaultPrevented) return;
      const field = editableField(event.target);
      if (field) show(event, editEntries(field, labels.current));
      else event.preventDefault();
    };
    document.addEventListener("contextmenu", onContextMenu);
    return () => document.removeEventListener("contextmenu", onContextMenu);
  }, [show]);

  const anchor = useMemo(
    () =>
      open
        ? { getBoundingClientRect: () => DOMRect.fromRect({ x: open.x, y: open.y, width: 0, height: 0 }) }
        : undefined,
    [open],
  );

  return (
    <ContextMenuContext.Provider value={show}>
      {children}
      <Menu.Root open={open !== null} onOpenChange={(next) => !next && setOpen(null)} modal={false}>
        <Menu.Portal>
          <Menu.Positioner
            anchor={anchor}
            side="bottom"
            align="start"
            sideOffset={2}
            collisionPadding={8}
            className="z-50 outline-none"
          >
            <Menu.Popup className="scoplen-menu min-w-52 rounded-lg border-(length:--scoplen-border-width) border-border bg-raised p-1 text-sm text-foreground shadow-(--scoplen-shadow-popover) outline-none">
              {open?.entries.map((entry, index) =>
                entry === "separator" ? (
                  <Menu.Separator key={`separator-${index}`} className="mx-2 my-1 h-px bg-border" />
                ) : (
                  <Menu.Item
                    key={`${entry.label}-${index}`}
                    disabled={entry.disabled}
                    onClick={entry.onSelect}
                    className={[
                      "flex h-8 cursor-default items-center gap-2.5 rounded-md px-2.5 outline-none select-none",
                      "data-highlighted:bg-primary data-highlighted:text-primary-foreground data-disabled:opacity-45",
                      entry.destructive
                        ? "text-attention data-highlighted:bg-attention data-highlighted:text-attention-foreground"
                        : "",
                    ].join(" ")}
                  >
                    {entry.icon ? (
                      <span aria-hidden="true" className="grid size-4 shrink-0 place-items-center opacity-80">
                        {entry.icon}
                      </span>
                    ) : null}
                    <span className="min-w-0 flex-1 truncate">{entry.label}</span>
                    {entry.shortcut ? (
                      <span aria-hidden="true" className="shrink-0 pl-6 text-xs opacity-60">
                        {entry.shortcut}
                      </span>
                    ) : null}
                  </Menu.Item>
                ),
              )}
            </Menu.Popup>
          </Menu.Positioner>
        </Menu.Portal>
      </Menu.Root>
    </ContextMenuContext.Provider>
  );
}

/** Returns a function that opens a menu for a context-menu event. */
export function useContextMenu(): (event: ReactMouseEvent | MouseEvent, entries: ContextMenuEntry[]) => void {
  const show = useContext(ContextMenuContext);
  // Without a provider (in tests of a single component) the web view's menu is left alone.
  return show ?? (() => undefined);
}

/** The modifier shown before a shortcut letter on this platform: "⌘" or "Ctrl+". */
export const shortcutModifier = mod;

type Editable = HTMLInputElement | HTMLTextAreaElement;

function editableField(target: EventTarget | null): Editable | null {
  if (target instanceof HTMLTextAreaElement) return target;
  if (
    target instanceof HTMLInputElement &&
    ["text", "search", "url", "email", "password", "number", "tel", ""].includes(target.type)
  )
    return target;
  return null;
}

function editEntries(field: Editable, labels: EditMenuLabels): ContextMenuEntry[] {
  const selected = (field.selectionEnd ?? 0) > (field.selectionStart ?? 0);
  const writable = !field.readOnly && !field.disabled;
  // A password's characters are never copied out of the field.
  const secret = field instanceof HTMLInputElement && field.type === "password";
  const run = (command: string) => {
    field.focus();
    document.execCommand(command);
  };
  return [
    { label: labels.cut, shortcut: `${mod}X`, disabled: !selected || !writable || secret, onSelect: () => run("cut") },
    { label: labels.copy, shortcut: `${mod}C`, disabled: !selected || secret, onSelect: () => run("copy") },
    {
      label: labels.paste,
      shortcut: `${mod}V`,
      disabled: !writable,
      onSelect: () => {
        void navigator.clipboard
          ?.readText()
          .then((text) => {
            field.focus();
            document.execCommand("insertText", false, text);
          })
          .catch(() => undefined);
      },
    },
    "separator",
    {
      label: labels.selectAll,
      shortcut: `${mod}A`,
      onSelect: () => {
        field.focus();
        field.select();
      },
    },
  ];
}
