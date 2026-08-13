// browserSupport — the deck's browser floor, checked up front.
//
// The UI depends on features that predate "default dark" browsers: Tailwind
// v4 (cascade layers, @property) plus color-mix() and :has() used throughout
// index.css. On an older browser the page still loads but the design quietly
// degrades — color-mix() falls back to a hard-coded color, layers collapse to
// source order, the rail tooltip's :has() selectors stop matching. Rather than
// discover that mid-investigation, warn once on first paint.
//
// The check is intentionally two-layered:
//   1. a UA-version baseline (the documented Tailwind v4 floor), and
//   2. live CSS.supports() probes for the two features that matter most.
// Probe results are injected as data so the pure logic is unit-testable;
// detectFeatures() is the only place that touches the real CSSOM.

export type BrowserName = "chrome" | "edge" | "firefox" | "safari" | "unknown";

export interface BrowserInfo {
  name: BrowserName;
  /** parseFloat of the UA version — major.minor ("16.4", "123") */
  version: number;
}

export interface FeatureProbes {
  "color-mix": boolean;
  ":has()": boolean;
}

/** The deck's CSS floor — Tailwind v4's documented minimum plus the browsers
 *  that ship color-mix() and :has() (Chrome 111 / Edge 111 / Firefox 113+,
 *  Safari 16.2+). Firefox 128 is Tailwind v4's stated floor; color-mix lands
 *  at 113, so 128 is the union. */
export const DECK_BASELINE: Record<Exclude<BrowserName, "unknown">, number> = {
  chrome: 111,
  edge: 111,
  firefox: 128,
  safari: 16.4,
};

/** Parse a User-Agent string into { name, version }. Pure and order-safe:
 *  Edge before Chrome (Edg/), Chrome before Safari (a Chromium UA contains
 *  "Safari"), Safari via its Version/ token rather than the WebKit build. */
export function parseBrowser(ua: string): BrowserInfo {
  const u = ua || "";
  const edge = /Edg\/(\d+(?:\.\d+)?)/.exec(u);
  if (edge) return { name: "edge", version: parseFloat(edge[1]) };

  const chrome = /Chrome\/(\d+(?:\.\d+)?)/.exec(u);
  if (chrome) return { name: "chrome", version: parseFloat(chrome[1]) };

  const firefox = /Firefox\/(\d+(?:\.\d+)?)/.exec(u);
  if (firefox) return { name: "firefox", version: parseFloat(firefox[1]) };

  // Real Safari: Version/ token + no Chrome marker (already excluded above).
  const safari = /Version\/(\d+(?:\.\d+)?)/.exec(u);
  if (safari) return { name: "safari", version: parseFloat(safari[1]) };

  return { name: "unknown", version: 0 };
}

/** The full support verdict. Unknown browsers are judged purely on feature
 *  probes — an embedded engine that passes every probe runs the deck fine. */
export interface SupportVerdict {
  ok: boolean;
  browser: BrowserInfo;
  missing: string[];
}

export function checkBrowserSupport(ua: string, features: FeatureProbes): SupportVerdict {
  const browser = parseBrowser(ua);
  const missing: string[] = [];

  if (browser.name !== "unknown" && browser.version < DECK_BASELINE[browser.name]) {
    missing.push(`${browser.name} ${browser.version}`);
  }
  if (!features["color-mix"]) missing.push("color-mix()");
  if (!features[":has()"]) missing.push(":has()");

  return { ok: missing.length === 0, browser, missing };
}

/** Live CSSOM probes. Each returns whether the browser understands the
 *  feature; browsers that cannot tell us anything (no CSS.supports) report
 *  false so the warning fires rather than silently degrading. */
export function detectFeatures(): FeatureProbes {
  const supports =
    typeof CSS !== "undefined" && typeof CSS.supports === "function" ? CSS.supports.bind(CSS) : null;
  return {
    "color-mix": supports ? supports("color", "color-mix(in srgb, red 50%, blue)") : false,
    ":has()": supports ? supports("selector(:has(*))") : false,
  };
}
