// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

/** A short label such as a host tag (`env: prod`). */
export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex h-5 items-center rounded-full bg-inset px-2 font-mono text-[0.6875rem] whitespace-nowrap text-muted-foreground">
      {children}
    </span>
  );
}
