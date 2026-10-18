// SPDX-License-Identifier: Apache-2.0
import { Mark, type MarkProps } from "./mark";

export interface LockupProps {
  /** Font size of the wordmark; the mark is sized from it. */
  size?: string;
  className?: string;
  /** Passed to the mark, so the lockup can blink or look when something happens. */
  mark?: Omit<MarkProps, "size" | "title">;
}

/**
 * The mark beside the wordmark "Scoplen" in Lora 500. The mark's height is
 * the wordmark's cap height plus one third, and the gap is about a fifth of
 * the mark, since the egg is narrower than its square
 * (`scoplen-docs/18-visual-identity.md`). Lora's cap height is 0.7 em.
 */
export function Lockup({ size = "1.5rem", className, mark }: LockupProps) {
  return (
    <span
      className={["inline-flex items-center font-serif font-medium text-foreground", className]
        .filter(Boolean)
        .join(" ")}
      style={{ fontSize: size, gap: "0.2em", lineHeight: 1 }}
    >
      <Mark size="0.933em" {...mark} />
      <span lang="en">Scoplen</span>
    </span>
  );
}
