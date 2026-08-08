#!/usr/bin/env node
/**
 * "Operation Shelf-Stack" — automated Playwright walkthrough of the OutPost
 * webapp demo (campaign arc: detonate → search → compare → watchlist → rules).
 *
 * Drives the five-step campaign arc — detonate → search → compare → watchlist
 * → rules — against the live webapp + API, capturing a screenshot per step
 * into ./screenshots. Re-runnable anytime; works headless for CI.
 *
 * Prereqs (once):
 *   cd demo && npm i
 *   Backend (port 8001) + frontend (port 5174) running, and the campaign pair
 *   seeded:  cd backend && python -m app.seed_campaign
 *
 * Run:
 *   node shelf-stack-demo.mjs                     # visible browser (default)
 *   HEADLESS=1 node shelf-stack-demo.mjs          # no visible browser
 *   WEBAPP_URL=... API_URL=... node shelf-stack-demo.mjs
 */

import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const WEBAPP_URL = (process.env.WEBAPP_URL ?? "http://localhost:5174").replace(/\/$/, "");
const API_URL = (process.env.API_URL ?? "http://localhost:8001").replace(/\/$/, "");
const C2_IP = process.env.C2_IP ?? "203.0.113.88";
const C2_LABEL = process.env.C2_LABEL ?? "Shelf-Stack C2";
const SHOTS = join(__dirname, "screenshots");
const HEADLESS = process.env.HEADLESS === "1";

const VARIANT_A = "ACME_invoice.docm";
const VARIANT_B = "invoice_lure.lnk";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function log(...args) {
  console.log(...args);
}

async function apiGet(path) {
  const res = await fetch(`${API_URL}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function waitFor(predicate, { timeoutMs = 60000, intervalMs = 2000, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(intervalMs);
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

async function shot(page, name) {
  const path = join(SHOTS, `${name}.png`);
  await page.screenshot({ path, fullPage: true });
  log(`  📸 ${path}`);
}

// -- steps -------------------------------------------------------------------

async function stepDetonate(page) {
  log("Step 1/5 — Detonate synthetic sample (Monitor page)");
  await page.goto(`${WEBAPP_URL}/monitor`, { waitUntil: "domcontentloaded" });

  const before = await apiGet("/runs");
  const beforeNewest = before[0]?.run_id ?? null;

  await page.getByRole("button", { name: /detonate synthetic sample/i }).click();
  log("  detonation started — capturing mid-stream state (toast stream, live tree)");
  await sleep(6000);
  await shot(page, "01-detonate-live");

  let rid = null;
  await waitFor(async () => {
    const runs = await apiGet("/runs");
    const newest = runs[0];
    if (!newest || newest.run_id === beforeNewest) return false;
    if (newest.sample_name !== "detonate-demo.exe") return false;
    if (!newest.completed_at) return false;
    rid = newest.run_id;
    return true;
  }, { label: "detonation run to complete", timeoutMs: 90000 });

  log(`  ✅ detonation complete — run ${rid}`);
  await shot(page, "01-detonate-complete");
  return rid;
}

async function stepSearch(page) {
  log("Step 2/5 — IOC search: the shared C2");
  await page.goto(`${WEBAPP_URL}/search`, { waitUntil: "domcontentloaded" });

  await page.getByPlaceholder("e.g. 185.220.101.34").fill(C2_IP);
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await page.getByText(/match\(es\) for/i).waitFor({ timeout: 15000 });
  await shot(page, "02-search");

  const body = await page.locator("body").innerText();
  for (const sample of [VARIANT_A, VARIANT_B, "detonate-demo.exe"]) {
    if (!body.includes(sample)) log(`  ⚠ expected "${sample}" in the results — not found`);
  }
  log("  ✅ shared-C2 search returned results");
}

async function stepCompare(page, variantA, variantB) {
  log("Step 3/5 — Compare the two campaign variants");
  await page.goto(`${WEBAPP_URL}/compare`, { waitUntil: "domcontentloaded" });

  // Both selects populate from the same run list (react-query).
  await page
    .locator("select")
    .nth(0)
    .locator(`option:has-text("${VARIANT_A}")`)
    .waitFor({ timeout: 15000 });
  await page.locator("select").nth(0).selectOption(variantA.run_id);
  await page.locator("select").nth(1).selectOption(variantB.run_id);

  await page.getByText("Only in A", { exact: true }).waitFor({ timeout: 15000 });
  await sleep(600); // let both diff tables settle
  await shot(page, "03-compare");
  log("  ✅ compare diff rendered (only-A / shared / only-B)");
}

async function stepWatchlist(page) {
  log("Step 4/5 — Personal watchlist: flag the C2");
  await page.goto(`${WEBAPP_URL}/watchlist`, { waitUntil: "domcontentloaded" });

  await page.getByPlaceholder("value (IP / domain / hash)").fill(C2_IP);
  await page.getByPlaceholder(/label/).fill(C2_LABEL);
  await page.getByRole("button", { name: "Add", exact: true }).click();

  await page.getByText(C2_IP, { exact: true }).first().waitFor({ timeout: 15000 });
  await sleep(400);
  await shot(page, "04-watchlist");
  log(`  ✅ ${C2_IP} added to the watchlist`);
}

async function stepRules(page, detonationRid) {
  log("Step 5/5 — Detection rules from the fresh detonation");
  await page.goto(`${WEBAPP_URL}/runs/${detonationRid}`, { waitUntil: "domcontentloaded" });

  // Step 4 pays off: the watchlisted C2 now carries the ★ badge.
  await page.getByText(C2_IP).first().waitFor({ timeout: 15000 });
  await shot(page, "05-c2-star");

  await page.getByRole("button", { name: /generate rules from this run/i }).click();
  await page.locator("pre").waitFor({ timeout: 15000 });
  await shot(page, "05-rules-suricata");

  await page.getByRole("button", { name: "sigma", exact: true }).click();
  await waitFor(async () => (await page.locator("pre").innerText()).includes("title:"), {
    label: "Sigma rules to render",
    intervalMs: 500,
    timeoutMs: 20000,
  });
  await shot(page, "05-rules-sigma");
  log("  ✅ Suricata + Sigma rules generated");
}

// -- main --------------------------------------------------------------------

async function main() {
  log(`OutPost — "Operation Shelf-Stack" automated demo`);
  log(`  webapp: ${WEBAPP_URL}   api: ${API_URL}   c2: ${C2_IP}   headless: ${HEADLESS}`);
  log("");

  mkdirSync(SHOTS, { recursive: true });

  // 0. Backend reachable + campaign pair seeded.
  const runs = await apiGet("/runs");
  const variantA = runs.find((r) => r.sample_name === VARIANT_A);
  const variantB = runs.find((r) => r.sample_name === VARIANT_B);
  if (!variantA || !variantB) {
    throw new Error(
      `Campaign pair not found in the backend — seed it first:\n` +
        `    cd backend && python -m app.seed_campaign\n` +
        `(seed the campaign pair first — see the header comment)`,
    );
  }
  log(`Campaign pair present: ${VARIANT_A} (${variantA.run_id}), ${VARIANT_B} (${variantB.run_id})`);

  // Clear any stale watchlist entry so step 4 starts clean.
  await fetch(`${API_URL}/watchlist/${encodeURIComponent(C2_IP)}`, { method: "DELETE" });
  log(`Cleared any stale watchlist entry for ${C2_IP}`);

  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    throw new Error("playwright is not installed — run:  cd demo && npm i");
  }

  const browser = await (async () => {
    try {
      return await chromium.launch({ headless: HEADLESS, channel: "chrome" }); // system Chrome
    } catch {
      log("  (system Chrome not found — using bundled Chromium)");
      return await chromium.launch({ headless: HEADLESS });
    }
  })();

  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("console", (msg) => {
    if (msg.type() === "error") console.error("  [page console.error]", msg.text());
  });
  page.on("pageerror", (err) => console.error("  [page error]", err.message));

  try {
    const detonationRid = await stepDetonate(page);
    await stepSearch(page);
    await stepCompare(page, variantA, variantB);
    await stepWatchlist(page);
    await stepRules(page, detonationRid);

    log("");
    log("✅ Walkthrough complete — screenshots in ./screenshots/");
    log("  (1) detonate → (2) search → (3) compare → (4) watchlist → (5) rules");
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error(`❌ Demo failed: ${err.message}`);
  process.exit(1);
});
