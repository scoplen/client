// SPDX-License-Identifier: Apache-2.0
import { Search, X } from "lucide-react";
import type { Ref } from "react";

export interface SearchFieldProps {
  /** Accessible name, such as "Search hosts". */
  label: string;
  /** Shown while empty; never the only label. */
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  /** Label of the clear button. */
  clearLabel: string;
  className?: string;
  ref?: Ref<HTMLInputElement>;
}

/** A search box. Escape clears it; a clear button appears while it has text. */
export function SearchField({ label, placeholder, value, onChange, clearLabel, className, ref }: SearchFieldProps) {
  return (
    <div className={["relative flex items-center", className].filter(Boolean).join(" ")}>
      <Search aria-hidden="true" className="pointer-events-none absolute left-3 size-4 text-muted-foreground" />
      <input
        ref={ref}
        type="search"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && value !== "") {
            event.preventDefault();
            onChange("");
          }
        }}
        className="ui-input h-9 w-full rounded-full! pr-8 pl-9 text-sm [&::-webkit-search-cancel-button]:hidden"
      />
      {value !== "" ? (
        <button
          type="button"
          aria-label={clearLabel}
          title={clearLabel}
          onClick={() => onChange("")}
          className="absolute right-1.5 grid size-6 place-items-center rounded-full text-muted-foreground hover:bg-inset hover:text-foreground"
        >
          <X aria-hidden="true" className="size-3.5" />
        </button>
      ) : null}
    </div>
  );
}
