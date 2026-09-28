import { chromium } from "playwright";
import fs from "fs";
import path from "path";

const ROOT = path.resolve(process.cwd());
const SCREENSHOT_DIR = path.join(ROOT, "demo", "screenshots", "fresh");
const FRONTEND_URL = "http://localhost:5174";

fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

console.log("[*] Launching Chromium with Playwright for fresh visual capture...");
const browser = await chromium.launch({
  executablePath: "/usr/bin/chromium",
  headless: true,
  args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
});

const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2 // High-DPI retina rendering
});

const page = await context.newPage();

const pagesToCapture = [
  { name: "01_overview", path: "/" },
  { name: "02_events", path: "/events" },
  { name: "03_findings", path: "/findings" },
  { name: "04_agents", path: "/agents" },
  { name: "05_investigations", path: "/investigations" },
  { name: "06_samples", path: "/samples" },
  { name: "07_simulation_lab", path: "/monitor" },
  { name: "08_search", path: "/search" },
  { name: "09_rules", path: "/rules" },
  { name: "10_coverage", path: "/coverage" },
  { name: "11_settings", path: "/settings" },
  { name: "12_audit", path: "/audit" },
  { name: "13_host_detail", path: "/hosts/local" },
];

for (const p of pagesToCapture) {
  try {
    console.log(`[*] Capturing ${p.path} -> ${p.name}.png`);
    await page.goto(`${FRONTEND_URL}${p.path}`, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(1500); // Allow charts, graphs, and badges to stabilize
    const outPath = path.join(SCREENSHOT_DIR, `${p.name}.png`);
    await page.screenshot({ path: outPath });
    console.log(`[✓] Captured: ${p.name}.png`);
  } catch (err) {
    console.warn(`[!] Warning on ${p.name}: ${err.message}`);
  }
}

// Capture Live Simulation Cockpit (detonate a scenario in /monitor)
try {
  console.log("[*] Capturing 14_live_simulation_cockpit.png...");
  await page.goto(`${FRONTEND_URL}/monitor`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);
  const runBtn = page.locator("button", { hasText: /Detonate Sample/i }).first();
  if (await runBtn.isVisible()) {
    await runBtn.click();
    await page.waitForTimeout(4000); // Wait for simulation execution and terminal streaming
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "14_live_simulation_cockpit.png") });
    console.log("[✓] Captured: 14_live_simulation_cockpit.png");
  }
} catch (e) {
  console.warn("[!] Simulation cockpit capture warning:", e.message);
}

// Capture ATT&CK Matrix Navigator Modal
try {
  console.log("[*] Capturing 17_mitre_navigator_matrix.png...");
  await page.goto(`${FRONTEND_URL}/coverage`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);
  const matrixBtn = page.locator("button", { hasText: /ATT&CK Technique Matrix|Technique Matrix|Navigator/i }).first();
  if (await matrixBtn.isVisible()) {
    await matrixBtn.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "17_mitre_navigator_matrix.png") });
    console.log("[✓] Captured: 17_mitre_navigator_matrix.png");
  }
} catch (e) {
  console.warn("[!] MITRE modal capture warning:", e.message);
}

// Capture Host Forensics sub-views on /events
try {
  console.log("[*] Navigating to /events for host sub-views...");
  await page.goto(`${FRONTEND_URL}/events`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);

  // 19_process_causality_tree.png
  const treeTab = page.locator("button", { hasText: "Causality Tree" }).first();
  if (await treeTab.isVisible()) {
    console.log("[*] Capturing 19_process_causality_tree.png...");
    await treeTab.click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "19_process_causality_tree.png") });
    console.log("[✓] Captured: 19_process_causality_tree.png");
  }

  // 20_network_threat_matrix.png
  const netTab = page.locator("button", { hasText: "Network Matrix" }).first();
  if (await netTab.isVisible()) {
    console.log("[*] Capturing 20_network_threat_matrix.png...");
    await netTab.click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "20_network_threat_matrix.png") });
    console.log("[✓] Captured: 20_network_threat_matrix.png");
  }

  // 21_behavioral_insights.png
  const insightsTab = page.locator("button", { hasText: "Behavioral Insights" }).first();
  if (await insightsTab.isVisible()) {
    console.log("[*] Capturing 21_behavioral_insights.png...");
    await insightsTab.click();
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "21_behavioral_insights.png") });
    console.log("[✓] Captured: 21_behavioral_insights.png");
  }

  // 22_process_context_dossier.png
  const procTab = page.locator("button", { hasText: "Live Processes" }).first();
  if (await procTab.isVisible()) {
    await procTab.click();
    await page.waitForTimeout(1000);
    const inspectBtn = page.locator("button", { hasText: "Inspect" }).first();
    if (await inspectBtn.isVisible()) {
      console.log("[*] Capturing 22_process_context_dossier.png...");
      await inspectBtn.click();
      await page.waitForTimeout(1500);
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "22_process_context_dossier.png") });
      console.log("[✓] Captured: 22_process_context_dossier.png");
    }
  }
} catch (e) {
  console.warn("[!] Events sub-views capture warning:", e.message);
}

await browser.close();
console.log(`[✓] Visual capture complete! All fresh screenshots saved to ${SCREENSHOT_DIR}`);
process.exit(0);
