import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "../frontend/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = resolve(__dirname, "..");
const outDir = resolve(root, "docs/screenshots");
mkdirSync(outDir, { recursive: true });

const BACKEND_PORT = 8001;
const FRONTEND_PORT = 5173;

console.log("[*] Seeding demo threat samples & telemetry...");
const seedProc = spawn(resolve(root, ".venv/bin/python"), ["-m", "app.seed_demo"], {
  cwd: resolve(root, "backend"),
  stdio: "inherit",
});

await new Promise((res, rej) => {
  seedProc.on("exit", (code) => (code === 0 ? res() : rej(new Error(`Seed failed with ${code}`))));
});

console.log(`[*] Launching backend on port ${BACKEND_PORT}...`);
const backendProc = spawn(
  resolve(root, ".venv/bin/python"),
  ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(BACKEND_PORT), "--log-level", "error"],
  { cwd: resolve(root, "backend"), stdio: "inherit" }
);

console.log(`[*] Launching frontend preview on port ${FRONTEND_PORT}...`);
const frontendProc = spawn(
  "npm",
  ["run", "preview", "--", "--host", "127.0.0.1", "--port", String(FRONTEND_PORT), "--strictPort"],
  { cwd: resolve(root, "frontend"), stdio: "ignore" }
);

const cleanup = () => {
  try { backendProc.kill(); } catch {}
  try { frontendProc.kill(); } catch {}
};
process.on("exit", cleanup);
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

async function waitFor(url, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

try {
  console.log("[*] Waiting for servers to be healthy...");
  await waitFor(`http://127.0.0.1:${BACKEND_PORT}/health`);
  await waitFor(`http://127.0.0.1:${FRONTEND_PORT}/`);
  console.log("[✓] Both servers running!");

  const browser = await puppeteer.launch({
    executablePath: "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox", "--disable-gpu", "--ozone-platform=headless", "--window-size=1440,900"],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });

  const targets = [
    { name: "01_malware_vault.png", url: `http://127.0.0.1:${FRONTEND_PORT}/samples`, waitSelector: "table, [data-testid]" },
    { name: "02_sample_detail.png", url: `http://127.0.0.1:${FRONTEND_PORT}/samples/sample_remcos_01`, waitSelector: "h1, h2, table, .font-mono" },
    { name: "03_simulation_lab.png", url: `http://127.0.0.1:${FRONTEND_PORT}/monitor`, waitSelector: "button, .grid" },
    { name: "04_detonation_runs.png", url: `http://127.0.0.1:${FRONTEND_PORT}/analysis`, waitSelector: "table, [data-testid]" },
    { name: "05_run_detail.png", url: `http://127.0.0.1:${FRONTEND_PORT}/runs/dyn_db3a8da614ef`, waitSelector: "svg, canvas, table, .font-mono" },
    { name: "06_telemetry_stream.png", url: `http://127.0.0.1:${FRONTEND_PORT}/events`, waitSelector: "table, .font-mono, [role='table']" },
    { name: "07_rules_studio.png", url: `http://127.0.0.1:${FRONTEND_PORT}/rules`, waitSelector: "table, pre, code, .font-mono" },
    { name: "08_mitre_coverage.png", url: `http://127.0.0.1:${FRONTEND_PORT}/coverage`, waitSelector: ".grid, table" },
    { name: "09_threat_watchlist.png", url: `http://127.0.0.1:${FRONTEND_PORT}/watchlist`, waitSelector: "table, [data-testid]" },
    { name: "10_ioc_search.png", url: `http://127.0.0.1:${FRONTEND_PORT}/search?q=remcos`, waitSelector: "input, table, [data-testid]" },
    { name: "11_settings_airgap.png", url: `http://127.0.0.1:${FRONTEND_PORT}/settings`, waitSelector: "form, input, button" },
  ];

  for (const t of targets) {
    process.stdout.write(`[*] Capturing ${t.name} from ${t.url}... `);
    await page.goto(t.url, { waitUntil: "domcontentloaded", timeout: 15000 });
    // Allow React queries and rendering animations to settle
    await new Promise((r) => setTimeout(r, 2200));

    // Wait for content selector if possible
    if (t.waitSelector) {
      await page.waitForSelector(t.waitSelector, { timeout: 3000 }).catch(() => {});
    }

    const dest = resolve(outDir, t.name);
    await page.screenshot({ path: dest, fullPage: false });
    console.log(`[✓] Done (${dest})`);
  }

  await browser.close();
  console.log("\n[✓] All 11 populated screenshots captured successfully!");
} finally {
  cleanup();
}
