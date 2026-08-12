#!/usr/bin/env node
/**
 * OutPost — alert-lifecycle e2e (Playwright behavioral gate).
 *
 * Closes the "no real browser test for the alert-lifecycle round-trip"
 * gap: drives the run-detail triage UI against a LIVE seeded backend —
 * Ack with a comment (pill Open→Acked, comment renders), Resolve
 * (Acked→Resolved), Reopen (back to Open), then the bulk bar (select two
 * open alerts → Ack all). Every transition goes through the real API, so
 * this is the alert-status state machine proven in a browser, not just in
 * unit tests.
 *
 * Usage:
 *   node demo/e2e-alert-lifecycle.mjs \
 *     --web http://localhost:5176 --api http://127.0.0.1:8013
 *
 * Exit 0 = lifecycle round-trips cleanly (and no console/page errors);
 * exit 1 = any step failed. Requires a backend seeded with a run that has
 * at least two open alerts (verify.sh's layout step seeds that state).
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

let failures = 0;
const fail = (msg) => {
  console.error(`  ✗ ${msg}`);
  failures += 1;
};
const ok = (msg) => console.log(`  ✓ ${msg}`);

// 1. Find a run with >= 2 open alerts (id-bearing, so triage buttons exist).
let target = null;
for (const run of (await apiGet("/runs")).slice(0, 12)) {
  const detail = await apiGet(`/runs/${run.run_id}`);
  const open = (detail.alerts ?? []).filter(
    (a) => a.status === "open" && a.id !== null && a.id !== undefined
  );
  if (open.length >= 2) {
    target = { runId: run.run_id, open };
    break;
  }
}
if (!target) {
  console.error("no run with >= 2 open alerts — seed the campaign pair first (verify.sh does)");
  process.exit(1);
}
console.log(`run ${target.runId} — ${target.open.length} open alerts`);
ok("found a run with >= 2 open, id-bearing alerts");

// 2. Drive the triage UI.
const browser = await chromium.launch({ headless: HEADLESS });
const page = await browser.newPage();
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error") pageErrors.push(m.text());
});

try {
  await page.goto(`${WEB}/runs/${target.runId}`, { waitUntil: "domcontentloaded" });

  const ackBtn = page.getByRole("button", { name: "Ack", exact: true });
  await ackBtn.first().waitFor({ timeout: 30000 });
  ok("run detail rendered the triage controls");

  // Leg 1 — Ack with a comment: pill Open -> Acked, comment persists.
  const comment = `e2e-ack-${Date.now()}`;
  await page.getByPlaceholder("Optional comment…").first().fill(comment);
  await ackBtn.first().click();
  await page
    .getByRole("button", { name: "Reopen", exact: true })
    .first()
    .waitFor({ timeout: 15000 });
  await page.getByText("Acked", { exact: true }).first().waitFor({ timeout: 15000 });
  await page.getByText(comment).waitFor({ timeout: 15000 });
  ok("Ack with comment: pill -> Acked, comment rendered");

  // Leg 2 — Resolve: Acked -> Resolved (Reopen-only state).
  await page.getByRole("button", { name: "Resolve", exact: true }).first().click();
  await page.getByText("Resolved", { exact: true }).first().waitFor({ timeout: 15000 });
  ok("Resolve: pill -> Resolved");

  // Leg 3 — Reopen: back to Open (Ack button returns).
  await page.getByRole("button", { name: "Reopen", exact: true }).first().click();
  await page
    .getByRole("button", { name: "Ack", exact: true })
    .first()
    .waitFor({ timeout: 15000 });
  ok("Reopen: pill -> Open, Ack button returns");

  // Leg 4 — Bulk triage: select two open alerts -> Ack all.
  await page.getByRole("button", { name: "Bulk", exact: true }).click();
  const selectors = page.getByRole("button", { name: /for bulk triage/ });
  await selectors.nth(0).click();
  await selectors.nth(1).click();
  await page.getByRole("button", { name: "Ack all", exact: true }).click();
  await page.getByText("Acked", { exact: true }).first().waitFor({ timeout: 15000 });
  const ackedPills = await page.getByText("Acked", { exact: true }).count();
  if (ackedPills < 2) fail(`bulk ack flipped only ${ackedPills} alert(s) to Acked (want >= 2)`);
  else ok(`bulk Ack all: ${ackedPills} alerts now Acked`);
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
  console.error(`\n✗ alert-lifecycle e2e FAILED (${failures} check(s))`);
  process.exit(1);
}
console.log("\n✓ alert-lifecycle e2e passed — open→acked→resolved→open + bulk round-trip");
