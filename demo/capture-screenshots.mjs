import { chromium } from "playwright";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";

const ROOT = path.resolve(process.cwd());
const SCREENSHOT_DIR = "/home/kripy/.gemini/antigravity/brain/e36d59a0-8b3c-428a-bc79-acbabd56891b/screenshots";
const BACKEND_PORT = 8092;
const FRONTEND_PORT = 5195;
const DB_PATH = `/tmp/visual_test_${Date.now()}.db`;
const SAMPLES_DIR = `/tmp/visual_samples_${Date.now()}`;

fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
fs.mkdirSync(SAMPLES_DIR, { recursive: true });

console.log("[*] Initializing backend database with sample telemetry for visual review...");
const pythonBin = path.join(ROOT, ".venv/bin/python");

// Run seed_demo into the temp DB so we have realistic data to visually review
const seedProc = spawn(pythonBin, ["-m", "app.seed_demo"], {
  cwd: path.join(ROOT, "backend"),
  env: { ...process.env, DATABASE_PATH: DB_PATH, SAMPLES_DIR }
});

await new Promise((resolve) => seedProc.on("close", resolve));

console.log("[*] Starting test backend server on port " + BACKEND_PORT);
const backendProc = spawn(pythonBin, [
  "-m", "uvicorn", "app.main:app",
  "--host", "127.0.0.1",
  "--port", String(BACKEND_PORT),
  "--app-dir", path.join(ROOT, "backend")
], {
  env: {
    ...process.env,
    DATABASE_PATH: DB_PATH,
    SAMPLES_DIR,
    CORS_ORIGINS: `http://localhost:${FRONTEND_PORT}`
  }
});

console.log("[*] Starting test frontend on port " + FRONTEND_PORT);
const frontendProc = spawn("npm", ["run", "dev", "--", "--port", String(FRONTEND_PORT), "--strictPort"], {
  cwd: path.join(ROOT, "frontend"),
  env: {
    ...process.env,
    VITE_API_URL: `http://127.0.0.1:${BACKEND_PORT}`
  }
});

// Wait for servers to be ready
async function waitForUrl(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

await waitForUrl(`http://127.0.0.1:${BACKEND_PORT}/health`);
await waitForUrl(`http://localhost:${FRONTEND_PORT}`);
console.log("[✓] Test servers online. Launching Chromium...");

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2 // Crisp retina screenshots
});

const page = await context.newPage();

const routes = [
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
];

for (const r of routes) {
  console.log(`[*] Navigating to ${r.path} -> ${r.name}.png`);
  await page.goto(`http://localhost:${FRONTEND_PORT}${r.path}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(600); // Allow any smooth transitions to settle
  const outPath = path.join(SCREENSHOT_DIR, `${r.name}.png`);
  await page.screenshot({ path: outPath, fullPage: false });
  console.log(`[✓] Saved: ${outPath}`);
}

// Also test detail view and interactive X-Ray / Simulation states
try {
  console.log("[*] Navigating to /hosts/workstation-01");
  await page.goto(`http://localhost:${FRONTEND_PORT}/hosts/workstation-01`, { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(SCREENSHOT_DIR, "13_host_detail.png") });

  console.log("[*] Navigating to /monitor and executing live simulation...");
  await page.goto(`http://localhost:${FRONTEND_PORT}/monitor`, { waitUntil: "networkidle" });
  const runBtn = page.getByRole("button", { name: "Run Live Simulation" }).first();
  if (await runBtn.isVisible()) {
    await runBtn.click();
    await page.waitForTimeout(3500); // Wait for live stages to execute and terminal to populate
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "14_live_simulation_cockpit.png") });
    console.log("[✓] Saved: 14_live_simulation_cockpit.png");
  }

  console.log("[*] Navigating to /events and switching to Host X-Ray Explorer...");
  await page.goto(`http://localhost:${FRONTEND_PORT}/events`, { waitUntil: "networkidle" });
  const xrayTabBtn = page.getByRole("button", { name: "Host X-Ray Explorer" });
  if (await xrayTabBtn.isVisible()) {
    await xrayTabBtn.click();
    await page.waitForTimeout(1000);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, "15_host_xray_explorer.png") });
    console.log("[✓] Saved: 15_host_xray_explorer.png");

    const inspectBtn = page.getByRole("button", { name: "Inspect X-Ray" }).first();
    if (await inspectBtn.isVisible()) {
      await inspectBtn.click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "16_process_xray_drawer.png") });
      console.log("[✓] Saved: 16_process_xray_drawer.png");

      const secTab = page.getByRole("button", { name: /Security Posture/i });
      if (await secTab.isVisible()) {
        await secTab.click();
        await page.waitForTimeout(600);
        await page.screenshot({ path: path.join(SCREENSHOT_DIR, "17_process_xray_security_posture.png") });
        console.log("[✓] Saved: 17_process_xray_security_posture.png");
      }

      const libTab = page.getByRole("button", { name: /Libraries/i });
      if (await libTab.isVisible()) {
        await libTab.click();
        await page.waitForTimeout(600);
        await page.screenshot({ path: path.join(SCREENSHOT_DIR, "18_process_xray_libraries.png") });
        console.log("[✓] Saved: 18_process_xray_libraries.png");
      }

      // Close modal
      const closeBtn = page.getByRole("button", { name: "Close Process X-Ray inspector" });
      if (await closeBtn.isVisible()) {
        await closeBtn.click();
        await page.waitForTimeout(400);
      }
    }

    // Capture SubView: Causality Tree
    const treeTabBtn = page.getByRole("button", { name: /Causality Tree/i });
    if (await treeTabBtn.isVisible()) {
      await treeTabBtn.click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "19_process_causality_tree.png") });
      console.log("[✓] Saved: 19_process_causality_tree.png");
    }

    // Capture SubView: Network Threat Matrix
    const netTabBtn = page.getByRole("button", { name: /Network Threat Matrix/i });
    if (await netTabBtn.isVisible()) {
      await netTabBtn.click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "20_network_threat_matrix.png") });
      console.log("[✓] Saved: 20_network_threat_matrix.png");
    }

    // Capture SubView: Behavioral Insights
    const expTabBtn = page.getByRole("button", { name: /Behavioral Insights/i });
    if (await expTabBtn.isVisible()) {
      await expTabBtn.click();
      await page.waitForTimeout(800);
      await page.screenshot({ path: path.join(SCREENSHOT_DIR, "21_behavioral_insights.png") });
      console.log("[✓] Saved: 21_behavioral_insights.png");
    }
  }
} catch (e) {
  console.error("Interactive captures failed:", e);
}

await browser.close();

backendProc.kill();
frontendProc.kill();
console.log("[✓] All screenshots captured successfully in " + SCREENSHOT_DIR);
process.exit(0);
