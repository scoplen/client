// SPDX-License-Identifier: Apache-2.0
import { applyAppearance, readAppearance, resolveScheme, themes } from "../src";

describe("themes", () => {
  it("show a dark-only theme in dark even when light is chosen", () => {
    expect(resolveScheme({ theme: "phosphor", scheme: "light" }, "light")).toBe("dark");
    expect(resolveScheme({ theme: "paper", scheme: "system" }, "dark")).toBe("dark");
    expect(resolveScheme({ theme: "brutal", scheme: "light" }, "dark")).toBe("light");
  });

  it("set the attributes the stylesheet reads", () => {
    const element = document.createElement("div");
    applyAppearance(element, { theme: "sakura", scheme: "dark" });
    expect(element.dataset.theme).toBe("sakura");
    expect(element.dataset.scheme).toBe("dark");
  });

  it("fall back to the default for an unknown stored choice", () => {
    localStorage.setItem("scoplen.appearance", JSON.stringify({ theme: "nope", scheme: "sideways" }));
    expect(readAppearance()).toEqual({ theme: "paper", scheme: "system" });
    localStorage.removeItem("scoplen.appearance");
  });

  it("list every theme once", () => {
    expect(new Set(themes.map((t) => t.id)).size).toBe(themes.length);
  });
});
