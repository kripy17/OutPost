// Theme registry — one source of truth for the console's visual identities.
//
// A "theme" is a full token set (index.css `[data-theme="…"]` blocks): field
// colors, accent/signal, risk scale, borders, shadows and glows. The id is
// stored under the same localStorage key the pre-paint script in index.html
// reads, so the first paint already carries the right identity.

export interface ThemeDef {
  id: string;
  name: string;
  note: string;
  /** Three swatch dots — base / accent / signal preview. */
  swatch: [string, string, string];
}

export const THEMES: ThemeDef[] = [
  {
    id: "midnight",
    name: "Midnight Ops",
    note: "blue-black field · electric cyan · lime telemetry",
    swatch: ["#0a0f1a", "#22d3ee", "#a3e635"],
  },
  {
    id: "glass",
    name: "Glass Cockpit",
    note: "violet night · frosted neon panels",
    swatch: ["#150f2b", "#b18bff", "#22d3ee"],
  },
  {
    id: "paper",
    name: "Paper Analyst",
    note: "warm light · ink-blue accent · hairline clarity",
    swatch: ["#f6f6f4", "#2456e6", "#0e7490"],
  },
  {
    id: "terminal",
    name: "Terminal Heritage",
    note: "phosphor green on black · scanlines · all-mono",
    swatch: ["#050807", "#4ade80", "#fbbf24"],
  },
  {
    id: "ember",
    name: "Ember Lab",
    note: "charcoal classic · amber signature",
    swatch: ["#14171c", "#d9a441", "#4fd1c5"],
  },
];

export const DEFAULT_THEME = "midnight";
const STORAGE_KEY = "outpost-theme-v2"; // same key the pre-paint script reads

/** Normalize legacy ids ("dark"/"light") written by older builds. */
export function normalizeThemeId(saved: string | null | undefined): string {
  if (saved === "dark") return "ember"; // the old default look lives on as Ember Lab
  if (saved === "light") return "paper";
  if (saved && THEMES.some((t) => t.id === saved)) return saved;
  return DEFAULT_THEME;
}

export function readTheme(): string {
  const attr = document.documentElement.dataset.theme;
  if (attr && THEMES.some((t) => t.id === attr)) return attr;
  try {
    return normalizeThemeId(localStorage.getItem(STORAGE_KEY));
  } catch {
    return DEFAULT_THEME;
  }
}

export function applyTheme(id: string): void {
  const theme = THEMES.some((t) => t.id === id) ? id : DEFAULT_THEME;
  document.documentElement.dataset.theme = theme;
  // The palette sub-system was folded into themes — never resurrect it.
  delete document.documentElement.dataset.palette;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
    localStorage.removeItem("outpost-palette");
  } catch {
    /* storage unavailable — attribute still applied for this session */
  }
}
