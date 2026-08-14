#!/usr/bin/env node
/**
 * OutPost — air-gapped cold-start latency measurement.
 *
 * Measures production-build page load under three network modes:
 *   baseline   — network fully available (control).
 *   airgap     — `--host-resolver-rules` maps every external hostname to
 *                0.0.0.0: the browser's resolver simply has no external
 *                records, so any stray external request fails fast, exactly
 *                like a machine with no external DNS / routing.
 *   worstcase  — same resolver rules PLUS a 25s black-hole on any external
 *                request (Playwright route delay + abort). If the app had
 *                any residual external dependency, this mode would hang the
 *                load for ~25s and the number would tell the truth.
 *
 * Every iteration is a cold load: fresh browser context, CDP cache disabled,
 * production assets served from the local preview server, local backend.
 *
 * Metrics (ms): TTFB, DOMContentLoaded, full Load, first-contentful-paint,
 * and "interactive" — wall time until the Overview renders its session count
 * (data arrived + React committed). Also reports browser-process boot time
 * (the true cold-start ceiling) and any external request attempts.
 *
 * Usage:
 *   node demo/measure-airgap-load.mjs [--web http://localhost:5174] [--iters 5]
 *
 * Exit 0 always (it is a measurement, not a gate).
 */

import { chromium } from "playwright";

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};

const WEB = getArg("--web", process.env.WEBAPP_URL ?? "http://localhost:5174").replace(/\/$/, "");
const ITER = Number(getArg("--iters", process.env.ITERS ?? "5"));
const HANG_MS = 25_000;
// Optional budget: when set, the harness exits 1 if the airgap mode's worst
// interactive render exceeds it (the measured value is ~300ms; 1000ms is a
// comfortable regression ceiling for a local, air-gapped deployment).
const MAX_INTERACTIVE = Number(getArg("--max-interactive", process.env.MAX_INTERACTIVE ?? "0"));

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);

const isExternal = (url) => {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    return !LOOPBACK.has(u.hostname);
  } catch {
    return true;
  }
};

const med = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
};

const fmt = (n) => (Number.isFinite(n) ? `${Math.round(n)}ms` : "—");

async function runMode(mode) {
  const launchArgs = [];
  if (mode !== "baseline") {
    launchArgs.push(
      "--host-resolver-rules=MAP * 0.0.0.0 , EXCLUDE localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1"
    );
  }

  const tBoot0 = Date.now();
  const browser = await chromium.launch({ args: launchArgs });
  const bootMs = Date.now() - tBoot0;

  const rows = [];
  let externalAttempts = 0;
  let hungRequests = 0;

  for (let i = 0; i < ITER; i++) {
    const context = await browser.newContext({ serviceWorkers: "block" });
    const page = await context.newPage();
    const client = await context.newCDPSession(page);
    await client.send("Network.enable");
    await client.send("Network.setCacheDisabled", { cacheDisabled: true });

    page.on("request", (r) => {
      if (isExternal(r.url())) externalAttempts++;
    });

    if (mode === "worstcase") {
      await page.route("**/*", (route) => {
        if (isExternal(route.request().url())) {
          hungRequests++;
          setTimeout(() => route.abort("blockedbyclient"), HANG_MS);
        } else {
          route.continue().catch(() => {});
        }
      });
    }

    const t0 = Date.now();
    let timedOut = false;
    try {
      await page.goto(WEB, { waitUntil: "load", timeout: Math.max(120_000, HANG_MS * 3) });
    } catch {
      timedOut = true;
    }

    let interactiveMs = Date.now() - t0;
    if (!timedOut) {
      try {
        await page.waitForSelector("text=/sessions/i", { timeout: 60_000 });
        interactiveMs = Date.now() - t0;
      } catch {
        interactiveMs = -1; // rendered without the sessions anchor
      }
    }

    const nav = await page
      .evaluate(() => {
        const n = performance.getEntriesByType("navigation")[0];
        const paints = Object.fromEntries(
          performance.getEntriesByType("paint").map((e) => [e.name, e.startTime])
        );
        return {
          ttfb: n ? n.responseStart : -1,
          dcl: n ? n.domContentLoadedEventEnd : -1,
          load: n ? n.loadEventEnd : -1,
          fcp: paints["first-contentful-paint"] ?? -1,
        };
      })
      .catch(() => ({ ttfb: -1, dcl: -1, load: -1, fcp: -1 }));

    rows.push({ iter: i + 1, ...nav, interactive: interactiveMs, timedOut });
    await context.close();
  }

  await browser.close();

  const pick = (k) => rows.map((r) => r[k]).filter((v) => v >= 0);
  return {
    mode,
    bootMs,
    externalAttempts,
    hungRequests,
    rows,
    summary: {
      ttfb: [med(pick("ttfb")), Math.max(...pick("ttfb"))],
      dcl: [med(pick("dcl")), Math.max(...pick("dcl"))],
      load: [med(pick("load")), Math.max(...pick("load"))],
      fcp: [med(pick("fcp")), Math.max(...pick("fcp"))],
      interactive: [med(pick("interactive")), Math.max(...pick("interactive"))],
    },
  };
}

const pad = (s, n) => String(s).padEnd(n);

console.log(`OutPost air-gapped cold-start measurement`);
console.log(`web=${WEB}  iterations=${ITER}/mode  hang=${HANG_MS}ms  cache=disabled  build=production\n`);

const results = [];
for (const mode of ["baseline", "airgap", "worstcase"]) {
  results.push(await runMode(mode));
}

for (const r of results) {
  console.log(`\n=== ${r.mode.toUpperCase()} (browser boot ${fmt(r.bootMs)}, external attempts: ${r.externalAttempts}, hung: ${r.hungRequests}) ===`);
  console.log(pad("iter", 6) + pad("TTFB", 10) + pad("DOMContentLoaded", 20) + pad("Load", 10) + pad("FCP", 10) + pad("interactive", 14));
  for (const row of r.rows) {
    console.log(
      pad(row.iter, 6) +
        pad(fmt(row.ttfb), 10) +
        pad(fmt(row.dcl), 20) +
        pad(fmt(row.load), 10) +
        pad(fmt(row.fcp), 10) +
        pad(row.interactive >= 0 ? fmt(row.interactive) : "no-anchor", 14) +
        (row.timedOut ? " TIMEOUT" : "")
    );
  }
  const s = r.summary;
  console.log(
    `median   ${fmt(s.ttfb[0])}  ${pad(fmt(s.dcl[0]), 17)} ${fmt(s.load[0])}  ${fmt(s.fcp[0])}  ${fmt(s.interactive[0])}`
  );
  console.log(
    `max      ${fmt(s.ttfb[1])}  ${pad(fmt(s.dcl[1]), 17)} ${fmt(s.load[1])}  ${fmt(s.fcp[1])}  ${fmt(s.interactive[1])}   <- worst case`
  );
}

const a = results.find((r) => r.mode === "airgap");
const w = results.find((r) => r.mode === "worstcase");
console.log(`\n=== verdict ===`);
console.log(`worst-case air-gapped cold start (browser boot + max interactive): ${fmt(a.bootMs + a.summary.interactive[1])}`);
console.log(`worst-case interactive (max): ${fmt(a.summary.interactive[1])}  |  black-hole variant: ${fmt(w.summary.interactive[1])}`);
console.log(`external request attempts across all modes: ${results.reduce((n, r) => n + r.externalAttempts, 0)}`);
console.log(`external requests that would hang a black-holed network: ${w.hungRequests}`);

if (MAX_INTERACTIVE > 0) {
  const worst = a.summary.interactive[1];
  const ok = worst <= MAX_INTERACTIVE;
  console.log(`budget: airgap worst interactive ${fmt(worst)} vs limit ${MAX_INTERACTIVE}ms → ${ok ? "PASS" : "FAIL"}`);
  if (!ok) {
    console.error(`air-gap latency budget exceeded: ${fmt(worst)} > ${MAX_INTERACTIVE}ms`);
    process.exit(1);
  }
}
