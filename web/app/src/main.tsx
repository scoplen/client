// SPDX-License-Identifier: Apache-2.0
import "@scoplen/ui/styles.css";
import { applyStoredAppearance } from "@scoplen/ui";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";

// The chosen theme is on the document before the first paint.
applyStoredAppearance();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
