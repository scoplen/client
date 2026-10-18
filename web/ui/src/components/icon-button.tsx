// SPDX-License-Identifier: Apache-2.0
import type { ButtonHTMLAttributes, ReactNode, Ref } from "react";

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> {
  /** What the button does; read by assistive technology and shown as a tooltip. */
  label: string;
  children: ReactNode;
  /** For toggles: whether it is on. */
  pressed?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

/** A small button showing only an icon, always with an accessible label. */
export function IconButton({ label, children, pressed, className, type = "button", ref, ...rest }: IconButtonProps) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      className={[
        "inline-grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground",
        "transition-[background-color,color,transform] duration-(--duration-micro) hover:bg-inset hover:text-foreground enabled:active:scale-90",
        "disabled:cursor-not-allowed disabled:opacity-50 aria-pressed:text-primary",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      {...rest}
    >
      {children}
    </button>
  );
}
