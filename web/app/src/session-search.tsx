// SPDX-License-Identifier: Apache-2.0
import { Button, Field, IconButton } from "@scoplen/ui";
import type { ScoplenTerminalElement } from "@scoplen/terminal";
import { X } from "lucide-react";
import { useEffect, useId, useState, type RefObject } from "react";
import { useI18n } from "./i18n";

export function SessionSearch({
  open,
  active,
  terminal,
  input,
  onClose,
}: {
  open: boolean;
  active: boolean;
  terminal: RefObject<ScoplenTerminalElement | null>;
  input: RefObject<HTMLInputElement | null>;
  onClose: () => void;
}) {
  const { t } = useI18n();
  const hintId = useId();
  const resultId = useId();
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<"idle" | "match" | "none" | "error">("idle");

  useEffect(() => {
    if (open && active) input.current?.focus();
  }, [open, active, input]);

  const clear = () => {
    try {
      terminal.current?.clearSearch();
      setResult("idle");
    } catch {
      setResult("error");
    }
  };
  const close = () => {
    clear();
    onClose();
  };
  const find = (previous = false) => {
    if (!query) return clear();
    try {
      const element = terminal.current;
      if (!element) return setResult("error");
      const options = { caseSensitive: true, regex: false, wholeWord: false };
      const found = previous ? element.findPrevious(query, options) : element.findNext(query, options);
      setResult(found ? "match" : "none");
    } catch {
      setResult("error");
    }
  };

  if (!open) return null;
  return (
    <form
      role="search"
      aria-label={t("session.find.open")}
      className="absolute inset-x-3 top-3 z-10 max-h-[calc(100%_-_1.5rem)] overflow-y-auto rounded-lg border border-border bg-raised p-3 shadow-(--scoplen-shadow-card)"
      onSubmit={(event) => {
        event.preventDefault();
        find();
      }}
      onKeyDown={(event) => {
        if (event.nativeEvent.isComposing) return;
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          close();
        } else if (event.key === "Enter" && event.target === input.current) {
          event.preventDefault();
          event.stopPropagation();
          find(event.shiftKey);
        }
      }}
    >
      <div className="flex flex-wrap items-end gap-2">
        <Field
          ref={input}
          label={t("session.find.query")}
          className="min-w-0 flex-[1_1_14rem]"
          value={query}
          aria-describedby={result === "idle" ? hintId : `${hintId} ${resultId}`}
          aria-invalid={result === "error" || undefined}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setQuery(event.currentTarget.value);
            clear();
          }}
        />
        <div className="flex items-center gap-1">
          <Button variant="ghost" disabled={!query} onClick={() => find(true)}>
            {t("session.find.previous")}
          </Button>
          <Button variant="ghost" disabled={!query} type="submit">
            {t("session.find.next")}
          </Button>
          <IconButton label={t("session.find.close")} onClick={close}>
            <X aria-hidden="true" className="size-4" />
          </IconButton>
        </div>
      </div>
      <p id={hintId} className="mt-2 mb-0 text-xs text-muted-foreground">
        {t("session.find.hint")}
      </p>
      {result !== "idle" ? (
        <p
          id={resultId}
          role={result === "error" ? "alert" : "status"}
          className={`mt-2 mb-0 text-xs ${result === "error" ? "text-attention" : "text-muted-foreground"}`}
        >
          {t(`session.find.${result}`)}
        </p>
      ) : null}
    </form>
  );
}
