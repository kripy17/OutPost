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

async function waitFor(fn, { label, timeoutMs = 5000, intervalMs = 200 }) {
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
  await page.goto(`${WEB}/runs/${target.runId}`, { waitUntil: "domcontentloaded" });

  const ackBtn = page.getByRole("button", { name: "Ack", exact: true });
  await ackBtn.first().waitFor({ timeout: 30000 });
  ok("run detail rendered the triage controls");

  // Leg 1 — Ack with a comment: pill Open -> Acked, comment persists.
  // Scope BOTH controls to the Ack button's own card: the comment input
  // renders on every alert card (acked ones included), while the Ack button
  // only renders on open ones — so "first input" and "first Ack" can land
  // in different cards (the sort is not guaranteed to lead with an open
  // alert). The ancestor XPath pins the nearest rounded-lg card.
  const comment = `e2e-ack-${Date.now()}`;
  const ackCard = ackBtn
    .first()
    .locator("xpath=(ancestor::div[contains(@class, 'rounded-lg')])[1]");
  const commentInput = ackCard.getByPlaceholder("Optional comment…");
  await commentInput.fill(comment);
  // Playwright's fill is instant, but React commits the controlled-input
  // draft asynchronously — a real user can't click before their typing
  // renders. Wait for the draft to land before clicking, or the submit
  // reads a stale closure and the comment never reaches the request.
  await waitFor(
    async () => (await commentInput.inputValue()) === comment,
    { label: "comment draft to commit (React state flush)", timeoutMs: 5000 }
  );
  await ackCard.getByRole("button", { name: "Ack", exact: true }).click();
  await page
    .getByRole("button", { name: "Reopen", exact: true })
    .first()
    .waitFor({ timeout: 15000 });
  await page.getByText("Acked", { exact: true }).first().waitFor({ timeout: 15000 });
  await page.getByText(comment).waitFor({ timeout: 15000 });
  ok("Ack with comment: pill -> Acked, comment rendered");

  // Persistence proof via the API — immune to banner ordering/rendering.
  const after = await apiGet(`/runs/${target.runId}`);
  const persisted = (after.alerts ?? []).find(
    (a) => a.status === "acknowledged" && a.status_comment === comment
  );
  if (!persisted) fail(`comment not persisted server-side (run ${target.runId})`);
  else ok("comment persisted server-side (API round-trip)");

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
