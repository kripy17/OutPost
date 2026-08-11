#!/usr/bin/env node
/**
 * OutPost — layout regression sweep (Playwright overflow gate).
 *
 * Catches the "min-width bug class" before it ships: a grid/flex item that
 * refuses to shrink (min-width: auto) pushes the page wider than the
 * viewport (document.scrollWidth > clientWidth) — e.g. the kill-chain
 * stepper or a nowrap recon-actor chip blowing out the run-detail page.
 *
 * Visits every webapp route (static + seeded dynamic IDs) at a few desktop
 * widths and fails on any horizontal overflow. Also asserts each route
 * actually rendered a PageHeader (a crashed route is a layout failure too —
 * blank pages can't overflow, so absence of content fails the gate).
 *
 * Usage:
 *   node demo/layout-sweep.mjs \
 *     --web http://localhost:5175 --api http://127.0.0.1:8013
 *
 * Exit 0 = all routes clean; exit 1 = overflow or missing content on any
 * route at any width. Prints a per-route PASS/FAIL table.
 */

import { chromium } from "playwright";

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};

const WEB = (getArg("--web", process.env.WEBAPP_URL ?? "http://localhost:5174")).replace(/\/$/, "");
const API = (getArg("--api", process.env.API_URL ?? "http://localhost:8001")).replace(/\/$/, "");
const WIDTHS = (getArg("--widths", "1440,1280,1024"))
  .split(",")
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => Number.isFinite(n) && n >= 800);
const HEIGHT = parseInt(getArg("--height", "900"), 10);
const HEADLESS = process.env.HEADLESS !== "0";

const TOLERANCE = 2; // px — subpixel rounding, not real overflow

async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

/** The full static route set (mirrors frontend/src/main.tsx). */
const STATIC_ROUTES = [
  "/",
  "/welcome",
  "/history",
  "/monitor",
  "/search",
  "/watchlist",
  "/agents",
  "/audit",
  "/findings",
  "/campaigns",
  "/coverage",
  "/rules",
  "/settings",
  "/events",
  "/footprint",
  "/samples",
];

/** Build the dynamic routes (run detail + sample detail) from seeded data.
 *  include_synthetic=true: the isolated sweep DB is seeded with source="seed"
 *  runs, and the archive hides synthetic provenance by default — without the
 *  flag the seeded runs (the data-heavy pages the gate exists for) would be
 *  invisible and run detail would never be swept. */
async function dynamicRoutes() {
  const routes = [];
  try {
    const runs = await apiGet("/runs?limit=3&include_synthetic=true");
    const runList = Array.isArray(runs) ? runs : runs.runs ?? [];
    for (const r of runList.slice(0, 2)) routes.push(`/runs/${r.run_id}`);
  } catch {
    /* no runs — skip run detail */
  }
  try {
    const samples = await apiGet("/samples?limit=3&include_synthetic=true");
    const sampleList = Array.isArray(samples) ? samples : samples.samples ?? [];
    for (const s of sampleList.slice(0, 2)) routes.push(`/samples/${s.sample_id}`);
  } catch {
    /* no samples — skip sample detail */
  }
  return routes;
}

/** Wait until the page has real content (a PageHeader + main body) or fail. */
async function waitForContent(page, label) {
  try {
    await page.waitForFunction(
      () => {
        const main = document.querySelector("main");
        if (!main) return false;
        const text = main.innerText ?? "";
        // A PageHeader renders a kicker + h1; the Loading fallback doesn't.
        return main.querySelector("h1") !== null && text.length > 40;
      },
      { timeout: 15_000 },
    );
  } catch {
    return false;
  }
  // Give late async renders (charts, tables, toasts) a beat to settle.
  await page.waitForTimeout(600);
  return true;
}

/** Measure overflow — document scrollWidth vs clientWidth + worst offender. */
async function measureOverflow(page) {
  return page.evaluate((tol) => {
    const doc = document.documentElement;
    const overflow = doc.scrollWidth > doc.clientWidth + tol;
    // Find the rightmost visible element past the viewport edge (diagnostic).
    let offender = null;
    if (overflow) {
      let maxRight = doc.clientWidth;
      for (const el of document.querySelectorAll("body *")) {
        const r = el.getBoundingClientRect();
        if (r.right > maxRight + tol && r.width > 0) {
          maxRight = r.right;
          offender = {
            tag: el.tagName,
            cls: (typeof el.className === "string" ? el.className : "").split(" ").slice(0, 3).join("."),
            right: Math.round(r.right),
            text: (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 60),
          };
        }
      }
    }
    return { scrollW: doc.scrollWidth, clientW: doc.clientWidth, overflow, offender };
  }, TOLERANCE);
}

let failed = 0;
const results = [];

async function sweepRoute(browser, route, width) {
  const context = await browser.newContext({
    viewport: { width, height: HEIGHT },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();
  let label = `${route} @${width}px`;

  // Crash the route if it throws — a white page is a failed gate.
  let pageError = null;
  page.on("pageerror", (err) => {
    pageError = err.message;
  });

  const rendered = await (async () => {
    try {
      await page.goto(`${WEB}${route}`, { waitUntil: "domcontentloaded", timeout: 20_000 });
      // History's charts default to a 24h window — the isolated sweep DB is
      // seeded with backdated campaign runs, so switch to "All" to make the
      // chart SVGs actually render (empty charts can't overflow).
      if (route === "/history") {
        const allBtn = page.getByRole("button", { name: "All", exact: true });
        try {
          await allBtn.click({ timeout: 5_000 });
        } catch {
          /* already on All or button absent — measure what's there */
        }
      }
      return await waitForContent(page, label);
    } catch {
      return false;
    }
  })();

  let ok = rendered;
  let detail = "";
  if (!rendered) {
    detail = pageError ? `route error: ${pageError.slice(0, 120)}` : "no PageHeader content rendered";
  } else {
    const m = await measureOverflow(page);
    if (m.overflow) {
      ok = false;
      detail = `scrollW ${m.scrollW} > clientW ${m.clientW}`;
      if (m.offender) {
        detail += ` — worst: <${m.offender.tag}${m.offender.cls ? "." + m.offender.cls : ""}> at x=${m.offender.right} "${m.offender.text}"`;
      }
    }
  }

  results.push({ label, ok, detail });
  if (!ok) failed += 1;
  await context.close();
}

const routes = [...STATIC_ROUTES, ...(await dynamicRoutes())];

const browser = await chromium.launch({ headless: HEADLESS, args: ["--no-sandbox"] });
for (const route of routes) {
  for (const width of WIDTHS) {
    await sweepRoute(browser, route, width);
  }
}
await browser.close();

// ── report ────────────────────────────────────────────────────────────────
console.log(`\nLayout sweep — ${routes.length} routes × ${WIDTHS.length} widths (${WEB})`);
console.log("─".repeat(72));
for (const r of results) {
  console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.label.padEnd(34)} ${r.detail}`);
}
console.log("─".repeat(72));
console.log(`${results.length - failed}/${results.length} checks passed`);

if (failed > 0) {
  console.error("\nFAILED: horizontal overflow or missing content on the routes above (min-width bug class).");
  process.exit(1);
}
process.exit(0);
