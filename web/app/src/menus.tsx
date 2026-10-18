// SPDX-License-Identifier: Apache-2.0
import { ContextMenuProvider } from "@scoplen/ui";
import type { ReactNode } from "react";
import { useI18n } from "./i18n";

/** The application's own context menus, in the interface language. */
export function Menus({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  return (
    <ContextMenuProvider
      editLabels={{ cut: t("menu.cut"), copy: t("menu.copy"), paste: t("menu.paste"), selectAll: t("menu.selectAll") }}
    >
      {children}
    </ContextMenuProvider>
  );
}
