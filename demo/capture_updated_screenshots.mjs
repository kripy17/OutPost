import { chromium } from "playwright";
import fs from "fs";
import path from "path";

const ROOT = path.resolve(process.cwd());
const SCREENSHOT_DIR = path.join(ROOT, "demo", "screenshots", "fresh");
const FRONTEND_URL = "http://localhost:5174";

// Clean and recreate screenshot directory
if (fs.existsSync(SCREENSHOT_DIR)) {
  fs.rmSync(SCREENSHOT_DIR, { recursive: true, force: true });
}
fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

console.log("[*] Launching Chromium with Playwright for complete updated visual capture...");
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
  { name: "06_investigation_detail", path: "/investigations/INC-2026-0819" },
  { name: "07_samples", path: "/samples" },
  { name: "08_sample_detail", path: "/samples/samp_001_lockbit" },
  { name: "09_simulation_lab", path: "/monitor" },
  { name: "10_search", path: "/search" },
  { name: "11_rules", path: "/rules" },
  { name: "12_coverage", path: "/coverage" },
  { name: "13_campaigns", path: "/campaigns" },
  { name: "14_footprint", path: "/footprint" },
  { name: "15_audit", path: "/audit" },
  { name: "16_settings", path: "/settings" },
  { name: "17_history", path: "/history" },
  { name: "18_welcome", path: "/welcome" },
  { name: "19_host_detail", path: "/hosts/local" },
  { name: "20_tasks", path: "/tasks" },
  { name: "21_run_detail", path: "/runs/de2e122a58f4" },
  { name: "22_analysis", path: "/analysis" },
];

for (const p of pagesToCapture) {
  try {
    console.log(`[*] Capturing ${p.path} -> ${p.name}.png`);
    await page.goto(`${FRONTEND_URL}${p.path}`, { waitUntil: "domcontentloaded", timeout: 20000 });
    await page.waitForTimeout(1800); // Allow charts, graphs, data tables, and badges to stabilize
    const outPath = path.join(SCREENSHOT_DIR, `${p.name}.png`);
    await page.screenshot({ path: outPath });
    console.log(`[✓] Captured: ${p.name}.png`);
  } catch (err) {
    console.warn(`[!] Warning on ${p.name}: ${err.message}`);
  }
}

// 23: Capture ATT&CK Matrix Navigator Modal
try {
  console.log("[*] Capturing 23_mitre_navigator_matrix.png...");
  await page.goto(`${FRONTEND_URL}/coverage`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  const matrixBtn = page.locator("button", { hasText: /ATT&CK Technique Matrix|Technique Matrix|Navigator/i }).first();
  if (await matrixBtn.isVisible()) {
    await matrixBtn.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "23_mitre_navigator_matrix.png") });
    console.log("[✓] Captured: 23_mitre_navigator_matrix.png");
  }
} catch (e) {
  console.warn("[!] MITRE modal capture warning:", e.message);
}

// 24: Capture Process Causality Tree on /tasks
try {
  console.log("[*] Capturing 24_process_causality_tree.png on /tasks...");
  await page.goto(`${FRONTEND_URL}/tasks`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  const treeTab = page.locator("button", { hasText: /Causality Tree/i }).first();
  if (await treeTab.isVisible()) {
    await treeTab.click();
    await page.waitForTimeout(2000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "24_process_causality_tree.png") });
    console.log("[✓] Captured: 24_process_causality_tree.png");
  }
} catch (e) {
  console.warn("[!] Causality tree capture warning:", e.message);
}

// 25: Capture Network Threat Matrix on /tasks
try {
  console.log("[*] Capturing 25_network_threat_matrix.png on /tasks...");
  await page.goto(`${FRONTEND_URL}/tasks`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  const netTab = page.locator("button", { hasText: /Network Matrix/i }).first();
  if (await netTab.isVisible()) {
    await netTab.click();
    await page.waitForTimeout(2000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "25_network_threat_matrix.png") });
    console.log("[✓] Captured: 25_network_threat_matrix.png");
  }
} catch (e) {
  console.warn("[!] Network matrix capture warning:", e.message);
}

// 26: Capture Behavioral Insights on /tasks
try {
  console.log("[*] Capturing 26_behavioral_insights.png on /tasks...");
  await page.goto(`${FRONTEND_URL}/tasks`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  const insightsTab = page.locator("button", { hasText: /Behavioral Insights/i }).first();
  if (await insightsTab.isVisible()) {
    await insightsTab.click();
    await page.waitForTimeout(2000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "26_behavioral_insights.png") });
    console.log("[✓] Captured: 26_behavioral_insights.png");
  }
} catch (e) {
  console.warn("[!] Behavioral insights capture warning:", e.message);
}

// 27: Capture Live Simulation Cockpit (detonate a scenario in /monitor)
try {
  console.log("[*] Capturing 27_live_simulation_cockpit.png...");
  await page.goto(`${FRONTEND_URL}/monitor`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  const runBtn = page.locator("button", { hasText: /Detonate Sample|Execute Scenario|Simulate/i }).first();
  if (await runBtn.isVisible()) {
    await runBtn.click();
    await page.waitForTimeout(4500); // Wait for simulation execution and terminal streaming
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "27_live_simulation_cockpit.png") });
    console.log("[✓] Captured: 27_live_simulation_cockpit.png");
  }
} catch (e) {
  console.warn("[!] Simulation cockpit capture warning:", e.message);
}

await browser.close();
console.log(`[✓] Visual capture complete! All fresh screenshots saved to ${SCREENSHOT_DIR}`);
process.exit(0);
