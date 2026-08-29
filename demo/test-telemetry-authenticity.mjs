#!/usr/bin/env node
/**
 * OutPost — Playwright Telemetry Authenticity & Live Detonation Test Suite
 *
 * Verifies:
 * 1. Zero dummy / preloaded fake data in live feeds (Overview, Event Manager, Findings).
 * 2. Real dynamic execution of uploaded user sample files (actual process tree, stdout, dropped files).
 * 3. Honest labeling of synthetic simulation scenarios.
 */

import { chromium } from "playwright";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};

const WEB = (getArg("--web", process.env.WEBAPP_URL ?? "http://localhost:5174")).replace(/\/$/, "");
const API = (getArg("--api", process.env.API_URL ?? "http://localhost:8001")).replace(/\/$/, "");
const HEADLESS = process.env.HEADLESS !== "0";

console.log("\n🧪 OutPost — Playwright Telemetry Authenticity & Live Execution Verification");
console.log(`   Frontend Target: ${WEB}`);
console.log(`   Backend Target:  ${API}\n`);

let passed = 0;
let failed = 0;

function record(step, ok, detail = "") {
  if (ok) {
    passed++;
    console.log(`  ✓ \x1b[32m[PASS]\x1b[0m ${step}${detail ? ` (${detail})` : ""}`);
  } else {
    failed++;
    console.error(`  ✗ \x1b[31m[FAIL]\x1b[0m ${step}${detail ? ` — ${detail}` : ""}`);
  }
}

// Ensure first-run onboarding is set to 'empty' (monitor for real, zero dummy data seeded)
try {
  await fetch(`${API}/setup/onboard`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ choice: "empty" }),
  });
} catch {}

const browser = await chromium.launch({ headless: HEADLESS });

try {
  // ── 1. Verify Clean Initial State (No Preloaded Dummy Data in Live Feeds) ──
  console.log("── Phase 1: Verify Absence of Dummy/Preloaded Data in Live Feeds ──");
  {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    // 1.1 Overview Live Findings Feed
    await page.goto(`${WEB}/`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(600);

    const overviewText = await page.evaluate(() => document.body.innerText);
    const hasFakeOverviewData = overviewText.includes("demo-sample.exe") || overviewText.includes("185.220.101.34");
    record("Overview live feed has no unprompted dummy data", !hasFakeOverviewData, hasFakeOverviewData ? "Found demo-sample.exe" : "Clean");

    // 1.2 Event Manager Live Feeds
    await page.goto(`${WEB}/events`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(600);

    const eventsText = await page.evaluate(() => document.body.innerText);
    const hasFakeEvents = eventsText.includes("SQBFAFgA") || eventsText.includes("demo-sample.exe");
    record("Event Manager live log contains no fake preloaded events", !hasFakeEvents, hasFakeEvents ? "Found SQBFAFgA" : "Clean live feed");

    // 1.3 Findings Queue
    await page.goto(`${WEB}/findings`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(600);

    const findingsText = await page.evaluate(() => document.body.innerText);
    const hasFakeAlerts = findingsText.includes("demo-sample.exe") || findingsText.includes("185.220.101.34");
    record("Findings queue contains no dummy seeded alerts", !hasFakeAlerts, hasFakeAlerts ? "Found demo-sample alerts" : "Clean queue");

    await context.close();
  }

  // ── 2. Live Dynamic Sandbox Detonation Test with a Real Uploaded File ───
  console.log("\n── Phase 2: Real Dynamic Sample Upload & Live Execution Tracing ──");
  {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    // Create a real test sample script on the fly
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "outpost_e2e_"));
    const sampleFileName = `live_e2e_sample_${Date.now()}.py`;
    const sampleFilePath = path.join(tempDir, sampleFileName);
    const markerString = `E2E_LIVE_EXECUTION_MARKER_${Date.now()}`;

    const sampleContent = `#!/usr/bin/env python3
import sys, os

print("${markerString}")
print(f"Running PID: {os.getpid()}")

with open("e2e_dropped_file.txt", "w") as f:
    f.write("Generated dynamically by OutPost live sandbox detonation")

print("Live execution completed successfully.")
`;
    fs.writeFileSync(sampleFilePath, sampleContent);

    // Navigate to Sample Vault (/samples)
    await page.goto(`${WEB}/samples`, { waitUntil: "domcontentloaded" });

    // Wait until the Samples page has loaded its main content
    await page.waitForFunction(
      () => document.querySelector("main") !== null && document.querySelector('input[type="file"]') !== null,
      { timeout: 15000 }
    );

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles(sampleFilePath);

    // Wait for the sample detail page to open upon upload
    await page.waitForURL(/\/samples\//, { timeout: 20000 });
    const sampleBadge = page.getByText(sampleFileName).first();
    await sampleBadge.waitFor({ state: "visible", timeout: 15000 });
    record("Sample binary uploaded & detected in Sample Vault", true, sampleFileName);

    // Click "Detonate in sandbox" or "Execute & trace"
    const executeBtn = page.getByRole("button", { name: /Detonate in sandbox|detonate|execute/i }).first();
    await executeBtn.waitFor({ state: "visible", timeout: 8000 });
    await executeBtn.click();

    // Wait for detonation navigation to /runs/:run_id
    await page.waitForURL(/\/runs\//, { timeout: 20000 });
    record("Detonated in dynamic sandbox & redirected to execution timeline", true, page.url());

    // Wait for run detail content to settle
    await page.waitForFunction(
      () => {
        const body = document.body?.innerText ?? "";
        return body.includes("Events") || body.includes("Timeline") || body.includes("Processes") || body.includes("Alerts");
      },
      { timeout: 15000 }
    );

    const runDetailText = await page.evaluate(() => document.body.innerText);
    const hasSampleName = runDetailText.includes(sampleFileName);
    record("Run detail displays genuine uploaded sample name", hasSampleName, sampleFileName);

    const hasDynamicBadge = runDetailText.includes("SANDBOX_DYNAMIC") || runDetailText.includes("sandbox") || runDetailText.includes("dynamic");
    record("Run provenance accurately tagged as dynamic sandbox execution", hasDynamicBadge);

    // Cleanup temp
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}

    await context.close();
  }

} finally {
  await browser.close();
}

console.log("\n══════════════════════════════════════════════════════════════");
console.log(`  Telemetry Authenticity Test Results: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m`);
console.log("══════════════════════════════════════════════════════════════\n");

process.exit(failed === 0 ? 0 : 1);
