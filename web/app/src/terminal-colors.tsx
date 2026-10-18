// SPDX-License-Identifier: Apache-2.0
import { useAppearance } from "@scoplen/ui";
import type { TerminalProfile } from "@scoplen/terminal";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/** The colors of a terminal: four for the surface and sixteen ANSI colors. */
export interface TerminalColors {
  background: string;
  foreground: string;
  cursor: string;
  selection: string;
  /** Black, red, green, yellow, blue, magenta, cyan, white; then the bright eight. */
  ansi: string[];
}

export const surfaceColors = ["background", "foreground", "cursor", "selection"] as const;
export type SurfaceColor = (typeof surfaceColors)[number];
export const ansiNames = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"] as const;

/**
 * The schemes offered in Settings. `app` follows the interface theme; the
 * rest are fixed palettes. A person's own edits are kept as `custom`.
 */
export const terminalSchemes = [
  "app",
  "paperLight",
  "scoplenNight",
  "solarizedLight",
  "solarizedDark",
  "oneLight",
  "oneDark",
  "githubLight",
  "githubDark",
  "catppuccinLatte",
  "catppuccinMocha",
  "gruvboxLight",
  "gruvboxDark",
  "rosePineDawn",
  "rosePine",
  "ayuLight",
  "tokyoNight",
  "dracula",
  "nord",
  "monokai",
  "everforest",
] as const;
export type TerminalSchemeId = (typeof terminalSchemes)[number] | "custom";

const lightAnsi = [
  "#3b3631",
  "#c0392b",
  "#2e7d4f",
  "#a86b00",
  "#2f5fb3",
  "#9b3d8f",
  "#1f7f7b",
  "#d9d3c7",
  "#6b645b",
  "#e0533f",
  "#3f9d65",
  "#c98a12",
  "#4a7bd1",
  "#b85aab",
  "#2b9c97",
  "#f5f1ea",
];
const darkAnsi = [
  "#2a2622",
  "#ef7a6a",
  "#7fcf98",
  "#e8c06a",
  "#7aa7f0",
  "#d28fd0",
  "#7cc4bd",
  "#e7e1d7",
  "#5c564f",
  "#ff9a8b",
  "#9fe3b4",
  "#f5d58e",
  "#9cc0ff",
  "#e6aee4",
  "#9adad3",
  "#fbf8f2",
];

/** Fixed palettes. The named schemes use their projects' published colors. */
const fixed: Record<Exclude<TerminalSchemeId, "app" | "custom">, TerminalColors> = {
  paperLight: {
    background: "#fbfaf8",
    foreground: "#2a2622",
    cursor: "#1f6f6b",
    selection: "#cfe5e2",
    ansi: lightAnsi,
  },
  scoplenNight: {
    background: "#24201d",
    foreground: "#ece6dc",
    cursor: "#7cc4bd",
    selection: "#3d4a47",
    ansi: darkAnsi,
  },
  solarizedLight: {
    background: "#fdf6e3",
    foreground: "#657b83",
    cursor: "#586e75",
    selection: "#eee8d5",
    ansi: [
      "#073642",
      "#dc322f",
      "#859900",
      "#b58900",
      "#268bd2",
      "#d33682",
      "#2aa198",
      "#eee8d5",
      "#002b36",
      "#cb4b16",
      "#586e75",
      "#657b83",
      "#839496",
      "#6c71c4",
      "#93a1a1",
      "#fdf6e3",
    ],
  },
  solarizedDark: {
    background: "#002b36",
    foreground: "#839496",
    cursor: "#93a1a1",
    selection: "#073642",
    ansi: [
      "#073642",
      "#dc322f",
      "#859900",
      "#b58900",
      "#268bd2",
      "#d33682",
      "#2aa198",
      "#eee8d5",
      "#002b36",
      "#cb4b16",
      "#586e75",
      "#657b83",
      "#839496",
      "#6c71c4",
      "#93a1a1",
      "#fdf6e3",
    ],
  },
  dracula: {
    background: "#282a36",
    foreground: "#f8f8f2",
    cursor: "#f8f8f2",
    selection: "#44475a",
    ansi: [
      "#21222c",
      "#ff5555",
      "#50fa7b",
      "#f1fa8c",
      "#bd93f9",
      "#ff79c6",
      "#8be9fd",
      "#f8f8f2",
      "#6272a4",
      "#ff6e6e",
      "#69ff94",
      "#ffffa5",
      "#d6acff",
      "#ff92df",
      "#a4ffff",
      "#ffffff",
    ],
  },
  nord: {
    background: "#2e3440",
    foreground: "#d8dee9",
    cursor: "#d8dee9",
    selection: "#434c5e",
    ansi: [
      "#3b4252",
      "#bf616a",
      "#a3be8c",
      "#ebcb8b",
      "#81a1c1",
      "#b48ead",
      "#88c0d0",
      "#e5e9f0",
      "#4c566a",
      "#bf616a",
      "#a3be8c",
      "#ebcb8b",
      "#81a1c1",
      "#b48ead",
      "#8fbcbb",
      "#eceff4",
    ],
  },
  oneLight: {
    background: "#fafafa",
    foreground: "#383a42",
    cursor: "#526fff",
    selection: "#e5e5e6",
    ansi: [
      "#383a42",
      "#e45649",
      "#50a14f",
      "#c18401",
      "#4078f2",
      "#a626a4",
      "#0184bc",
      "#a0a1a7",
      "#4f525e",
      "#e45649",
      "#50a14f",
      "#c18401",
      "#4078f2",
      "#a626a4",
      "#0184bc",
      "#ffffff",
    ],
  },
  oneDark: {
    background: "#282c34",
    foreground: "#abb2bf",
    cursor: "#528bff",
    selection: "#3e4451",
    ansi: [
      "#282c34",
      "#e06c75",
      "#98c379",
      "#e5c07b",
      "#61afef",
      "#c678dd",
      "#56b6c2",
      "#abb2bf",
      "#5c6370",
      "#e06c75",
      "#98c379",
      "#e5c07b",
      "#61afef",
      "#c678dd",
      "#56b6c2",
      "#ffffff",
    ],
  },
  githubLight: {
    background: "#ffffff",
    foreground: "#1f2328",
    cursor: "#0969da",
    selection: "#b6e3ff",
    ansi: [
      "#24292f",
      "#cf222e",
      "#116329",
      "#4d2d00",
      "#0969da",
      "#8250df",
      "#1b7c83",
      "#6e7781",
      "#57606a",
      "#a40e26",
      "#1a7f37",
      "#633c01",
      "#218bff",
      "#a475f9",
      "#3192aa",
      "#8c959f",
    ],
  },
  githubDark: {
    background: "#0d1117",
    foreground: "#e6edf3",
    cursor: "#2f81f7",
    selection: "#264f78",
    ansi: [
      "#484f58",
      "#ff7b72",
      "#3fb950",
      "#d29922",
      "#58a6ff",
      "#bc8cff",
      "#39c5cf",
      "#b1bac4",
      "#6e7681",
      "#ffa198",
      "#56d364",
      "#e3b341",
      "#79c0ff",
      "#d2a8ff",
      "#56d4dd",
      "#ffffff",
    ],
  },
  catppuccinLatte: {
    background: "#eff1f5",
    foreground: "#4c4f69",
    cursor: "#dc8a78",
    selection: "#ccd0da",
    ansi: [
      "#5c5f77",
      "#d20f39",
      "#40a02b",
      "#df8e1d",
      "#1e66f5",
      "#ea76cb",
      "#179299",
      "#acb0be",
      "#6c6f85",
      "#d20f39",
      "#40a02b",
      "#df8e1d",
      "#1e66f5",
      "#ea76cb",
      "#179299",
      "#bcc0cc",
    ],
  },
  catppuccinMocha: {
    background: "#1e1e2e",
    foreground: "#cdd6f4",
    cursor: "#f5e0dc",
    selection: "#45475a",
    ansi: [
      "#45475a",
      "#f38ba8",
      "#a6e3a1",
      "#f9e2af",
      "#89b4fa",
      "#f5c2e7",
      "#94e2d5",
      "#bac2de",
      "#585b70",
      "#f38ba8",
      "#a6e3a1",
      "#f9e2af",
      "#89b4fa",
      "#f5c2e7",
      "#94e2d5",
      "#a6adc8",
    ],
  },
  gruvboxDark: {
    background: "#282828",
    foreground: "#ebdbb2",
    cursor: "#ebdbb2",
    selection: "#504945",
    ansi: [
      "#282828",
      "#cc241d",
      "#98971a",
      "#d79921",
      "#458588",
      "#b16286",
      "#689d6a",
      "#a89984",
      "#928374",
      "#fb4934",
      "#b8bb26",
      "#fabd2f",
      "#83a598",
      "#d3869b",
      "#8ec07c",
      "#ebdbb2",
    ],
  },
  rosePineDawn: {
    background: "#faf4ed",
    foreground: "#575279",
    cursor: "#9893a5",
    selection: "#dfdad9",
    ansi: [
      "#f2e9e1",
      "#b4637a",
      "#286983",
      "#ea9d34",
      "#56949f",
      "#907aa9",
      "#d7827e",
      "#575279",
      "#9893a5",
      "#b4637a",
      "#286983",
      "#ea9d34",
      "#56949f",
      "#907aa9",
      "#d7827e",
      "#575279",
    ],
  },
  rosePine: {
    background: "#191724",
    foreground: "#e0def4",
    cursor: "#524f67",
    selection: "#403d52",
    ansi: [
      "#26233a",
      "#eb6f92",
      "#31748f",
      "#f6c177",
      "#9ccfd8",
      "#c4a7e7",
      "#ebbcba",
      "#e0def4",
      "#6e6a86",
      "#eb6f92",
      "#31748f",
      "#f6c177",
      "#9ccfd8",
      "#c4a7e7",
      "#ebbcba",
      "#e0def4",
    ],
  },
  ayuLight: {
    background: "#fafafa",
    foreground: "#5c6166",
    cursor: "#ffaa33",
    selection: "#d1e4f4",
    ansi: [
      "#000000",
      "#ea6c6d",
      "#6cbf43",
      "#eca944",
      "#3199e1",
      "#9e75c7",
      "#46ba94",
      "#bababa",
      "#686868",
      "#f07171",
      "#86b300",
      "#f2ae49",
      "#399ee6",
      "#a37acc",
      "#4cbf99",
      "#d1d1d1",
    ],
  },
  tokyoNight: {
    background: "#1a1b26",
    foreground: "#c0caf5",
    cursor: "#c0caf5",
    selection: "#33467c",
    ansi: [
      "#15161e",
      "#f7768e",
      "#9ece6a",
      "#e0af68",
      "#7aa2f7",
      "#bb9af7",
      "#7dcfff",
      "#a9b1d6",
      "#414868",
      "#f7768e",
      "#9ece6a",
      "#e0af68",
      "#7aa2f7",
      "#bb9af7",
      "#7dcfff",
      "#c0caf5",
    ],
  },
  monokai: {
    background: "#272822",
    foreground: "#f8f8f2",
    cursor: "#f8f8f0",
    selection: "#49483e",
    ansi: [
      "#272822",
      "#f92672",
      "#a6e22e",
      "#f4bf75",
      "#66d9ef",
      "#ae81ff",
      "#a1efe4",
      "#f8f8f2",
      "#75715e",
      "#f92672",
      "#a6e22e",
      "#f4bf75",
      "#66d9ef",
      "#ae81ff",
      "#a1efe4",
      "#f9f8f5",
    ],
  },
  everforest: {
    background: "#2d353b",
    foreground: "#d3c6aa",
    cursor: "#d3c6aa",
    selection: "#475258",
    ansi: [
      "#475258",
      "#e67e80",
      "#a7c080",
      "#dbbc7f",
      "#7fbbb3",
      "#d699b6",
      "#83c092",
      "#d3c6aa",
      "#5c6a72",
      "#e67e80",
      "#a7c080",
      "#dbbc7f",
      "#7fbbb3",
      "#d699b6",
      "#83c092",
      "#d3c6aa",
    ],
  },
  gruvboxLight: {
    background: "#fbf1c7",
    foreground: "#3c3836",
    cursor: "#3c3836",
    selection: "#ebdbb2",
    ansi: [
      "#fbf1c7",
      "#cc241d",
      "#98971a",
      "#d79921",
      "#458588",
      "#b16286",
      "#689d6a",
      "#7c6f64",
      "#928374",
      "#9d0006",
      "#79740e",
      "#b57614",
      "#076678",
      "#8f3f71",
      "#427b58",
      "#3c3836",
    ],
  },
};

/** A color token of the interface theme, as a hex color. */
function token(name: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
  return /^#[0-9a-f]{6}$/i.test(value) ? value : "";
}

/** Mixes two hex colors; `amount` of `b`. */
function mix(a: string, b: string, amount: number): string {
  const parse = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
  const [x, y] = [parse(a), parse(b)];
  return `#${x
    .map((v, i) => Math.round(v + (y[i]! - v) * amount))
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("")}`;
}

/** The terminal in the interface's own colors: its raised surface, text, and accent. */
function appColors(scheme: "light" | "dark"): TerminalColors {
  const background = token("raised") || (scheme === "dark" ? "#24201d" : "#fbfaf8");
  const foreground = token("foreground") || (scheme === "dark" ? "#f5f3ef" : "#1c1917");
  const primary = token("primary") || (scheme === "dark" ? "#7cc4bd" : "#1f6f6b");
  return {
    background,
    foreground,
    cursor: primary,
    selection: mix(background, primary, 0.25),
    ansi: scheme === "dark" ? darkAnsi : lightAnsi,
  };
}

/** The xterm.js theme for a set of colors. */
export function xtermTheme(colors: TerminalColors): NonNullable<TerminalProfile["theme"]> {
  const [black, red, green, yellow, blue, magenta, cyan, white, ...bright] = colors.ansi;
  return {
    background: colors.background,
    foreground: colors.foreground,
    cursor: colors.cursor,
    cursorAccent: colors.background,
    selectionBackground: colors.selection,
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    brightBlack: bright[0],
    brightRed: bright[1],
    brightGreen: bright[2],
    brightYellow: bright[3],
    brightBlue: bright[4],
    brightMagenta: bright[5],
    brightCyan: bright[6],
    brightWhite: bright[7],
  };
}

interface Stored {
  scheme: TerminalSchemeId;
  custom: TerminalColors | null;
}

const storageKey = "scoplen.terminal-colors";

function readStored(): Stored {
  try {
    const stored = JSON.parse(localStorage.getItem(storageKey) ?? "null") as Partial<Stored> | null;
    const custom = isColors(stored?.custom) ? stored.custom : null;
    const scheme =
      stored?.scheme === "custom" && custom
        ? "custom"
        : (terminalSchemes as readonly string[]).includes(stored?.scheme ?? "")
          ? (stored!.scheme as TerminalSchemeId)
          : "app";
    return { scheme, custom };
  } catch {
    return { scheme: "app", custom: null };
  }
}

function isColors(value: unknown): value is TerminalColors {
  const hex = (v: unknown) => typeof v === "string" && /^#[0-9a-f]{6}$/i.test(v);
  const c = value as TerminalColors | null | undefined;
  return (
    !!c && surfaceColors.every((k) => hex(c[k])) && Array.isArray(c.ansi) && c.ansi.length === 16 && c.ansi.every(hex)
  );
}

interface TerminalColorsValue {
  scheme: TerminalSchemeId;
  /** The colors in use now. */
  colors: TerminalColors;
  /** The colors a scheme stands for, for previews. */
  colorsOf: (scheme: TerminalSchemeId) => TerminalColors;
  setScheme: (scheme: TerminalSchemeId) => void;
  /** Changes one color; the result becomes the person's own scheme. */
  setColor: (which: SurfaceColor | number, value: string) => void;
}

const TerminalColorsContext = createContext<TerminalColorsValue | null>(null);

/**
 * The terminal's colors: a scheme, or the person's own edits of one. Kept in
 * the webview's local storage as an interface preference of this device,
 * like the theme; it holds nothing secret.
 */
export function TerminalColorsProvider({ children }: { children: ReactNode }) {
  const { appearance, scheme: interfaceScheme } = useAppearance();
  const [stored, setStored] = useState<Stored>(readStored);
  // The interface theme's colors are read once its attributes are on the document.
  const [app, setApp] = useState<TerminalColors>(() => appColors(interfaceScheme));
  useEffect(() => {
    const frame = requestAnimationFrame(() => setApp(appColors(interfaceScheme)));
    return () => cancelAnimationFrame(frame);
  }, [appearance.theme, interfaceScheme]);

  const save = useCallback((next: Stored) => {
    setStored(next);
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
    } catch {
      // Without storage the choice lasts until the window closes.
    }
  }, []);

  const colorsOf = useCallback(
    (scheme: TerminalSchemeId): TerminalColors =>
      scheme === "app" ? app : scheme === "custom" ? (stored.custom ?? app) : fixed[scheme],
    [app, stored.custom],
  );

  const value = useMemo<TerminalColorsValue>(() => {
    const colors = colorsOf(stored.scheme);
    return {
      scheme: stored.scheme,
      colors,
      colorsOf,
      setScheme: (scheme) => save({ ...stored, scheme }),
      setColor: (which, color) => {
        const next: TerminalColors = { ...colors, ansi: colors.ansi.slice() };
        if (typeof which === "number") next.ansi[which] = color;
        else next[which] = color;
        save({ scheme: "custom", custom: next });
      },
    };
  }, [colorsOf, save, stored]);

  return <TerminalColorsContext.Provider value={value}>{children}</TerminalColorsContext.Provider>;
}

export function useTerminalColors(): TerminalColorsValue {
  const value = useContext(TerminalColorsContext);
  if (!value) throw new Error("useTerminalColors needs a TerminalColorsProvider");
  return value;
}
