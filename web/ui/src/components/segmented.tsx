// SPDX-License-Identifier: Apache-2.0
import { useId } from "react";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

export interface SegmentedProps<T extends string> {
  /** The question the choice answers, shown as its legend. */
  legend: string;
  options: SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
}

/**
 * One choice among a few, shown side by side. It is a group of native radio
 * buttons, so arrow keys move the choice and assistive technology reads it as
 * a radio group.
 */
export function Segmented<T extends string>({ legend, options, value, onChange }: SegmentedProps<T>) {
  const name = useId();
  return (
    <fieldset className="m-0 flex flex-col gap-1.5 border-0 p-0">
      <legend className="mb-1.5 p-0 text-sm font-medium text-foreground">{legend}</legend>
      <div
        className={`${options.length > 3 ? "grid grid-cols-2 sm:flex" : "inline-flex"} w-full rounded-md border-(length:--scoplen-border-width) border-border-strong bg-inset p-0.5`}
      >
        {options.map((option) => (
          <label
            key={option.value}
            className="relative flex-1 cursor-pointer rounded-sm px-3 py-1.5 text-center text-sm whitespace-nowrap text-muted-foreground transition-[background-color,color,box-shadow] duration-(--duration-state) ease-(--ease-out) hover:text-foreground has-checked:bg-raised has-checked:font-medium has-checked:text-foreground has-checked:shadow-(--scoplen-shadow-control) has-focus-visible:outline-2 has-focus-visible:outline-ring"
          >
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={option.value === value}
              onChange={() => onChange(option.value)}
              className="sr-only"
            />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
