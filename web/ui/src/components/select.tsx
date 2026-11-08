// SPDX-License-Identifier: Apache-2.0
import { Select as BaseSelect } from "@base-ui/react/select";
import { Check, ChevronDown } from "lucide-react";
import type { Ref } from "react";

export interface SelectOption<T extends string> {
  value: T;
  label: string;
  disabled?: boolean;
  group?: string;
}

export interface SelectProps<T extends string> {
  label: string;
  options: SelectOption<T>[];
  value: T;
  onValueChange: (value: T) => void;
  disabled?: boolean;
  id?: string;
  required?: boolean;
  size?: "compact" | "field";
  "aria-describedby"?: string;
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
  id,
  required,
  size = "compact",
  "aria-describedby": describedBy,
  className,
  ref,
}: SelectProps<T>) {
  const groups = new Map<string | undefined, SelectOption<T>[]>();
  for (const option of options) {
    const items = groups.get(option.group) ?? [];
    items.push(option);
    groups.set(option.group, items);
  }
  const item = (option: SelectOption<T>) => (
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
  );
  return (
    <BaseSelect.Root
      items={options}
      value={value}
      disabled={disabled}
      required={required}
      onValueChange={(next) => {
        if (next !== null && next !== value) onValueChange(next);
      }}
    >
      <BaseSelect.Trigger
        ref={ref}
        id={id}
        aria-label={label}
        aria-describedby={describedBy}
        className={[
          "inline-flex min-w-0 items-center justify-between gap-2 rounded-md text-foreground",
          size === "field" ? "ui-input h-10 px-3 text-sm" : "ui-control h-8 bg-raised px-2.5 text-xs",
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
              {Array.from(groups, ([group, items]) =>
                group ? (
                  <BaseSelect.Group key={group}>
                    <BaseSelect.GroupLabel className="px-2.5 pt-2 pb-1 text-xs font-medium text-muted-foreground">
                      {group}
                    </BaseSelect.GroupLabel>
                    {items.map(item)}
                  </BaseSelect.Group>
                ) : (
                  items.map(item)
                ),
              )}
            </BaseSelect.List>
          </BaseSelect.Popup>
        </BaseSelect.Positioner>
      </BaseSelect.Portal>
    </BaseSelect.Root>
  );
}
