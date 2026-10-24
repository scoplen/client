// SPDX-License-Identifier: Apache-2.0
import { AlertDialog } from "@base-ui/react/alert-dialog";
import { Dialog as BaseDialog } from "@base-ui/react/dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "./button";

const backdrop =
  "fixed inset-0 bg-[color-mix(in_srgb,var(--foreground)_28%,transparent)] transition-opacity duration-(--duration-overlay) data-[ending-style]:opacity-0 data-[starting-style]:opacity-0";
const popup =
  "fixed top-[12vh] left-1/2 flex max-h-[76vh] w-[min(30rem,calc(100vw-2rem))] -translate-x-1/2 flex-col rounded-xl border-(length:--scoplen-border-width) border-border bg-raised text-foreground shadow-(--scoplen-shadow-overlay) outline-none transition-[opacity,scale,translate] duration-(--duration-overlay) ease-(--ease-spring) data-[ending-style]:scale-[0.97] data-[ending-style]:opacity-0 data-[starting-style]:translate-y-2 data-[starting-style]:scale-[0.96] data-[starting-style]:opacity-0";

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** One line under the title saying what the dialog is for. */
  description?: string;
  /** Label of the close button. */
  closeLabel: string;
  children: ReactNode;
  /** The dialog's buttons, primary last. */
  footer: ReactNode;
  /** A character beside the title, such as the mark reacting to the form. Decorative. */
  mark?: ReactNode;
}

/** A modal dialog: focus stays inside, Escape closes, focus returns on close. */
export function Dialog({ open, onOpenChange, title, description, closeLabel, children, footer, mark }: DialogProps) {
  return (
    <BaseDialog.Root open={open} onOpenChange={onOpenChange}>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop className={backdrop} />
        <BaseDialog.Popup className={`${popup} overflow-hidden`}>
          <div className="min-h-0 flex-1 overflow-y-auto">
            <div className="flex items-start gap-3.5 px-6 pt-5">
              {mark ? (
                <span aria-hidden="true" className="-mt-0.5 shrink-0 text-primary">
                  {mark}
                </span>
              ) : null}
              <div className="min-w-0 flex-1">
                <BaseDialog.Title className="ui-display m-0 text-lg wrap-anywhere">{title}</BaseDialog.Title>
                {description ? (
                  <BaseDialog.Description className="mt-1 text-sm wrap-anywhere text-muted-foreground">
                    {description}
                  </BaseDialog.Description>
                ) : null}
              </div>
              <BaseDialog.Close
                aria-label={closeLabel}
                title={closeLabel}
                className="-mr-2 grid size-8 place-items-center rounded-full text-muted-foreground transition-colors duration-(--duration-micro) hover:bg-inset hover:text-foreground"
              >
                <X aria-hidden="true" className="size-4" />
              </BaseDialog.Close>
            </div>
            <div className="px-6 py-5">{children}</div>
          </div>
          <div className="flex shrink-0 flex-wrap justify-end gap-3 px-6 pt-2 pb-5">{footer}</div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  );
}

export interface ConfirmProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** What will happen, and whether it can be undone. */
  body: ReactNode;
  confirmLabel: string;
  cancelLabel: string;
  onConfirm: () => void;
  busy?: boolean;
  /** Destructive confirmations get the attention color. */
  destructive?: boolean;
}

/**
 * A confirmation, used only where `11-client-architecture.md` §4.2 requires
 * one. Focus starts on Cancel, so pressing Enter by habit changes nothing.
 */
export function Confirm({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  cancelLabel,
  onConfirm,
  busy,
  destructive,
}: ConfirmProps) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className={backdrop} />
        <AlertDialog.Popup className={popup}>
          <div className="px-6 pt-5 pb-5">
            <AlertDialog.Title className="ui-display m-0 text-lg">{title}</AlertDialog.Title>
            <AlertDialog.Description render={<div />} className="mt-2 text-sm">
              {body}
            </AlertDialog.Description>
          </div>
          <div className="flex justify-end gap-3 px-6 pt-1 pb-5">
            <AlertDialog.Close render={<Button variant="ghost" autoFocus />}>{cancelLabel}</AlertDialog.Close>
            <Button variant={destructive ? "destructive" : "primary"} busy={busy} onClick={onConfirm}>
              {confirmLabel}
            </Button>
          </div>
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
