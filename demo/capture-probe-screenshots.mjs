import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { chromium } from "playwright";

const sysChrome = process.env.CHROMIUM_PATH || [
  "/usr/bin/chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
].find(existsSync);

const root = resolve(import.meta.dirname, "..");
const outDir = resolve(root, "docs/screenshots");
mkdirSync(outDir, { recursive: true });
const backendPort = 8013;
const webPort = 5176;

console.log("Starting backend on port " + backendPort + "...");
const be = spawn(
  resolve(root, ".venv/bin/python"),
  ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(backendPort)],
  {
    cwd: resolve(root, "backend"),
    env: {
      ...process.env,
      DATABASE_PATH: resolve(root, "backend/data/outpost.db"),
      CORS_ORIGINS: `http://localhost:${webPort}`,
    },
    stdio: "inherit",
  }
);

console.log("Starting frontend on port " + webPort + "...");
const fe = spawn(
  "npm",
  ["run", "dev", "--", "--port", String(webPort), "--strictPort"],
  {
    cwd: resolve(root, "frontend"),
    env: {
      ...process.env,
      VITE_API_URL: `http://127.0.0.1:${backendPort}`,
    },
    stdio: "inherit",
  }
);

const cleanup = () => {
  try { be.kill(); } catch {}
  try { fe.kill(); } catch {}
};
process.on("exit", cleanup);
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

// Poll for readiness
async function waitFor(url, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 600));
  }
  throw new Error(`Timeout waiting for ${url}`);
}

try {
  await waitFor(`http://127.0.0.1:${backendPort}/meta`);
  await waitFor(`http://localhost:${webPort}/`);
  console.log("Services ready! Launching Chromium...");

  const browser = await chromium.launch({
    executablePath: sysChrome,
    headless: true,
  });

  const context = await browser.newContext({
    viewport: { width: 1440, height: 1100 },
  });
  const page = await context.newPage();

  const targets = [
    { url: `http://localhost:${webPort}/runs/541f07d3290c`, name: "step2e_c_probe_run_detail.png" },
    { url: `http://localhost:${webPort}/runs/run_probe_shell`, name: "step2e_shell_probe_run_detail.png" },
    { url: `http://localhost:${webPort}/runs/run_probe_python`, name: "step2e_python_probe_run_detail.png" },
    { url: `http://localhost:${webPort}/samples`, name: "step2e_samples_dashboard.png" },
  ];

  for (const t of targets) {
    console.log(`Capturing ${t.url} -> ${t.name}...`);
    await page.goto(t.url, { waitUntil: "networkidle" });
    await page.waitForTimeout(1200);
    const dest = resolve(outDir, t.name);
    await page.screenshot({ path: dest, fullPage: true });
    console.log(`✓ Saved ${dest}`);
  }

  await browser.close();
  console.log("All screenshots captured successfully!");
} finally {
  cleanup();
}
