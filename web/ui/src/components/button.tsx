// SPDX-License-Identifier: Apache-2.0
import type { ButtonHTMLAttributes, Ref } from "react";

type Role = "primary" | "secondary" | "ghost" | "destructive";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Primary is the one forward action of a screen; destructive deletes, revokes, or resets. */
  variant?: Role;
  /** Shows that the action is running while keeping the button's size. */
  busy?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

const roles: Record<Role, string> = {
  primary: "ui-control bg-primary text-primary-foreground hover:bg-primary-hover",
  secondary: "ui-control border-border-strong! bg-raised text-foreground hover:bg-inset",
  ghost: "border-(length:--scoplen-border-width) border-transparent text-foreground hover:bg-inset",
  destructive: "ui-control bg-attention text-attention-foreground hover:opacity-90",
};

/**
 * A button. Its label names the result of the action ("Add host"). While
 * `busy`, the label stays in place, invisible, so the button does not change
 * size, and assistive technology is told the action is running.
 */
export function Button({
  variant = "secondary",
  busy = false,
  className,
  children,
  disabled,
  type = "button",
  ref,
  ...rest
}: ButtonProps) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={[
        "relative inline-flex h-9 items-center justify-center rounded-md px-4 text-sm font-medium select-none",
        "transition-[background-color,color,transform,box-shadow] duration-(--duration-micro) ease-(--ease-out)",
        "disabled:cursor-not-allowed disabled:opacity-55",
        roles[variant],
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      {...rest}
    >
      <span className={["inline-flex items-center gap-[inherit]", busy ? "invisible" : ""].join(" ")}>{children}</span>
      {busy ? (
        <span aria-hidden="true" className="absolute inset-0 grid place-items-center">
          <span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
        </span>
      ) : null}
    </button>
  );
}
