// SPDX-License-Identifier: Apache-2.0
import { useId, type TextareaHTMLAttributes } from "react";

export interface TextAreaFieldProps extends Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, "id"> {
  label: string;
  hint?: string;
  error?: string;
}

/** A labelled multi-line input, with the same hint and error behavior as `Field`. */
export function TextAreaField({ label, hint, error, className, ...input }: TextAreaFieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <div className={["flex flex-col gap-1.5", className].filter(Boolean).join(" ")}>
      <label htmlFor={id} className="text-sm font-medium text-foreground">
        {label}
      </label>
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        aria-describedby={[errorId, hintId].filter(Boolean).join(" ") || undefined}
        className="ui-input min-h-28 resize-y px-3 py-2 font-mono text-xs"
        {...input}
      />
      {error ? (
        <p id={errorId} className="m-0 text-sm text-attention">
          {error}
        </p>
      ) : null}
      {hint ? (
        <p id={hintId} className="m-0 text-sm text-muted-foreground">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
