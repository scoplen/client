// SPDX-License-Identifier: Apache-2.0
import { Select as BaseSelect } from "@base-ui/react/select";
import { Check, ChevronDown } from "lucide-react";
import type { Ref } from "react";

export interface SelectOption<T extends string> {
  value: T;
  label: string;
  disabled?: boolean;
}

export interface SelectProps<T extends string> {
  label: string;
  options: SelectOption<T>[];
  value: T;
  onValueChange: (value: T) => void;
  disabled?: boolean;
  className?: string;
  ref?: Ref<HTMLButtonElement>;
}

/** A compact themed choice with keyboard navigation, typeahead and focus return. */
export function Select<T extends string>({
  label,
  options,
  value,
  onValueChange,
  disabled,
  className,
  ref,
}: SelectProps<T>) {
  return (
    <BaseSelect.Root
      items={options}
      value={value}
      disabled={disabled}
      onValueChange={(next) => {
        if (next !== null && next !== value) onValueChange(next);
      }}
    >
      <BaseSelect.Trigger
        ref={ref}
        aria-label={label}
        className={[
          "ui-control inline-flex h-8 min-w-0 items-center justify-between gap-2 rounded-md bg-raised px-2.5 text-xs text-foreground",
          "transition-[background-color,box-shadow] duration-(--duration-micro) hover:bg-inset data-popup-open:bg-inset",
          "disabled:cursor-not-allowed disabled:opacity-55",
          className,
        ]
          .filter(Boolean)
          .join(" ")}
      >
        <BaseSelect.Value className="min-w-0 flex-1 truncate text-left" />
        <BaseSelect.Icon>
          <ChevronDown aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
        </BaseSelect.Icon>
      </BaseSelect.Trigger>
      <BaseSelect.Portal>
        <BaseSelect.Positioner
          align="end"
          sideOffset={4}
          collisionPadding={8}
          alignItemWithTrigger={false}
          className="z-50 outline-none"
        >
          <BaseSelect.Popup className="min-w-(--anchor-width) max-w-[min(30rem,calc(100vw-1rem))] overflow-hidden rounded-lg border-(length:--scoplen-border-width) border-border bg-raised p-1 text-xs text-foreground shadow-(--scoplen-shadow-popover) outline-none">
            <BaseSelect.List aria-label={label} className="max-h-[min(20rem,var(--available-height))] overflow-y-auto">
              {options.map((option) => (
                <BaseSelect.Item
                  key={option.value}
                  value={option.value}
                  label={option.label}
                  disabled={option.disabled}
                  className="grid min-h-8 cursor-default grid-cols-[1rem_minmax(0,1fr)] items-start gap-2 rounded-md px-2.5 py-2 outline-none select-none data-disabled:opacity-45 data-highlighted:bg-primary data-highlighted:text-primary-foreground"
                >
                  <span aria-hidden="true" className="grid size-4 place-items-center">
                    <BaseSelect.ItemIndicator>
                      <Check className="size-3.5" />
                    </BaseSelect.ItemIndicator>
                  </span>
                  <BaseSelect.ItemText className="min-w-0 wrap-anywhere">{option.label}</BaseSelect.ItemText>
                </BaseSelect.Item>
              ))}
            </BaseSelect.List>
          </BaseSelect.Popup>
        </BaseSelect.Positioner>
      </BaseSelect.Portal>
    </BaseSelect.Root>
  );
}
