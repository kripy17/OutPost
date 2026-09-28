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
  deviceScaleFactor: 2 // Crisp high-DPI retina rendering
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
  { name: "15_sample_detail_benign", path: "/samples/4e54acaf9e3a" },
  { name: "16_sample_detail_adversary", path: "/samples/8438618d439e" },
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

// Capture Live Simulation Cockpit (detonate a Canary in /monitor)
try {
  console.log("[*] Capturing 14_live_simulation_cockpit.png...");
  await page.goto(`${FRONTEND_URL}/monitor`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);
  const runBtn = page.getByRole("button", { name: /Detonate Sample/i }).first();
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
  const matrixBtn = page.getByRole("button", { name: /ATT&CK Technique Matrix|Technique Matrix|Navigator/i }).first();
  if (await matrixBtn.isVisible()) {
    await matrixBtn.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "17_mitre_navigator_matrix.png") });
    console.log("[✓] Captured: 17_mitre_navigator_matrix.png");
  }
} catch (e) {
  console.warn("[!] MITRE modal capture warning:", e.message);
}

// Capture Host Forensics & Pulse Explorer view
try {
  console.log("[*] Capturing 18_host_forensics_pulse.png...");
  await page.goto(`${FRONTEND_URL}/events`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);
  const forensicsBtn = page.getByRole("button", { name: /Host Forensics & Pulse/i }).first();
  if (await forensicsBtn.isVisible()) {
    await forensicsBtn.click();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "18_host_forensics_pulse.png") });
    console.log("[✓] Captured: 18_host_forensics_pulse.png");
  }
} catch (e) {
  console.warn("[!] Forensics pulse capture warning:", e.message);
}

await browser.close();
console.log(`[✓] Visual capture complete! All fresh screenshots saved to ${SCREENSHOT_DIR}`);
process.exit(0);
