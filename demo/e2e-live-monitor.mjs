#!/usr/bin/env node
/**
 * OutPost — live-monitor e2e (Playwright behavioral gate).
 *
 * The other half of the browser-coverage gap: the triage lifecycle is
 * proven by e2e-alert-lifecycle.mjs; this one proves LIVE monitoring. It
 * drives the Monitor page exactly like a real user — the host OS is
 * auto-detected, a synthetic dropper is detonated, alerts arrive as live
 * toasts while the session streams, and the analysis completes — all
 * through the real UI + real backend, with zero console errors allowed.
 *
 * Usage:
 *   node demo/e2e-live-monitor.mjs \
 *     --web http://localhost:5176 --api http://127.0.0.1:8013
 *
 * Exit 0 = auto-detect + live toast stream + detonation completion all
 * pass cleanly; exit 1 = any step failed.
 */

import { chromium } from "playwright";

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};

const WEB = (getArg("--web", process.env.WEBAPP_URL ?? "http://localhost:5174")).replace(/\/$/, "");
const API = (getArg("--api", process.env.API_URL ?? "http://localhost:8001")).replace(/\/$/, "");
const HEADLESS = process.env.HEADLESS !== "0";

async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function waitFor(fn, { label, timeoutMs = 30000, intervalMs = 1000 }) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`timed out waiting for ${label}${last ? ` (${last.message})` : ""}`);
}

let failures = 0;
const fail = (msg) => {
  console.error(`  ✗ ${msg}`);
  failures += 1;
};
const ok = (msg) => console.log(`  ✓ ${msg}`);

const browser = await chromium.launch({ headless: HEADLESS });
const page = await browser.newPage();
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error") pageErrors.push(m.text());
});
// Failed resource loads log an EMPTY-URL "Failed to load resource: 404"
// console message — attach the actual URL so a CI failure is actionable.
// Air-gap gate: any request to an EXTERNAL origin (not localhost / the API)
// fails the run — the console must render self-contained (fonts, assets,
// no CDNs), so a dependency sneaking back in fails here, not in the field.
page.on("response", (r) => {
  if (r.status() >= 400) pageErrors.push(`HTTP ${r.status()} ${r.url()}`);
  try {
    const host = new URL(r.url()).hostname;
    if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") {
      pageErrors.push(`external request ${r.url()}`);
    }
  } catch {
    /* non-URL responses are not resource loads */
  }
});

try {
  await page.goto(`${WEB}/monitor`, { waitUntil: "domcontentloaded" });

  // 1. The vision: the host OS is auto-detected, no OS picker.
  await page.getByText(/auto-detected/i).first().waitFor({ timeout: 30000 });
  ok("host OS auto-detected (no OS picker)");

  // 2. Detonate a synthetic dropper and watch alerts land live as toasts.
  const before = await apiGet("/runs?include_synthetic=true");
  const beforeIds = new Set(before.map((r) => r.run_id));

  await page.getByRole("button", { name: /detonate synthetic sample/i }).click();

  // First live alert toast — the SSE-driven event trickle surfacing in UI.
  await page.getByRole("button", { name: "Dismiss alert" }).first().waitFor({ timeout: 45000 });
  ok("live alert toast appeared during the stream");

  // The trickle keeps coming: more alerts land while the session streams.
  await page.waitForTimeout(4000);
  const toastCount = await page.getByRole("button", { name: "Dismiss alert" }).count();
  if (toastCount === 0) fail("toast stream emptied unexpectedly mid-detonation");
  else ok(`${toastCount} live toast(s) on screen — stream alive`);

  // 3. The analysis completes — a brand-new run with completed_at.
  const rid = await waitFor(
    async () => {
      const runs = await apiGet("/runs?include_synthetic=true");
      const fresh = runs.find((r) => !beforeIds.has(r.run_id) && r.completed_at);
      return fresh ? fresh.run_id : null;
    },
    { label: "detonation run to complete", timeoutMs: 90000 }
  );
  ok(`detonation completed — run ${rid}`);
} catch (err) {
  fail(`unexpected error: ${err.message}`);
  await browser.close();
  process.exit(1);
}

await browser.close();

if (pageErrors.length) {
  fail(`${pageErrors.length} console/page error(s): ${pageErrors.slice(0, 3).join(" | ")}`);
} else {
  ok("zero console/page errors");
}

if (failures) {
  console.error(`\n✗ live-monitor e2e FAILED (${failures} check(s))`);
  process.exit(1);
}
console.log("\n✓ live-monitor e2e passed — auto-detect → live toasts → completed detonation");
