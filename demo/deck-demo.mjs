#!/usr/bin/env node
/**
 * OutPost — "Command deck" demo footage (ui-demo skill).
 *
 * Records the redesigned SOC deck end-to-end: Overview pan → Sample vault
 * (library + detail) → Monitor detonation (live toast stream) → Run detail
 * (risk gauge, kill chain, process-tree halos, timeline, analyst notes).
 *
 * Output:
 *   demo/deck-demo.webm            — the full recording (cursor + subtitles)
 *   demo/screenshots/deck/0X-*.png — per-step stills
 *
 * Prereqs (once):
 *   cd demo && npm i
 *   Backend (8001) + frontend (5174) running.
 *
 * Run:
 *   node deck-demo.mjs            # record
 *   node deck-demo.mjs --rehearse # verify selectors, no recording
 */

import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEBAPP = (process.env.WEBAPP_URL ?? "http://localhost:5174").replace(/\/$/, "");
const API = (process.env.API_URL ?? "http://localhost:8001").replace(/\/$/, "");
const SHOTS = join(__dirname, "screenshots", "deck");
const VIDEO_OUT = join(__dirname, "deck-demo.webm");
const REHEARSE = process.argv.includes("--rehearse");
const HEADLESS = process.env.HEADLESS !== "0"; // headless by default for recording
const VIEW = { width: 1440, height: 900 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function log(...args) {
  console.log(...args);
}

async function apiGet(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function waitFor(predicate, { timeoutMs = 90000, intervalMs = 2000, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await sleep(intervalMs);
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

// -- overlay helpers (ui-demo) -------------------------------------------------

async function injectCursor(page) {
  await page.evaluate(() => {
    if (document.getElementById("demo-cursor")) return;
    const cursor = document.createElement("div");
    cursor.id = "demo-cursor";
    cursor.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M5 3L19 12L12 13L9 20L5 3Z" fill="white" stroke="black" stroke-width="1.5" stroke-linejoin="round"/>
    </svg>`;
    cursor.style.cssText = `
      position: fixed; z-index: 999999; pointer-events: none;
      width: 24px; height: 24px;
      transition: left 0.1s, top 0.1s;
      filter: drop-shadow(1px 1px 2px rgba(0,0,0,0.3));
    `;
    cursor.style.left = "0px";
    cursor.style.top = "0px";
    document.body.appendChild(cursor);
    document.addEventListener("mousemove", (e) => {
      cursor.style.left = `${e.clientX}px`;
      cursor.style.top = `${e.clientY}px`;
    });
  });
}

async function injectSubtitleBar(page) {
  await page.evaluate(() => {
    if (document.getElementById("demo-subtitle")) return;
    const bar = document.createElement("div");
    bar.id = "demo-subtitle";
    bar.style.cssText = `
      position: fixed; bottom: 0; left: 0; right: 0; z-index: 999998;
      text-align: center; padding: 12px 24px;
      background: rgba(0, 0, 0, 0.75);
      color: white; font-family: -apple-system, "Segoe UI", sans-serif;
      font-size: 16px; font-weight: 500; letter-spacing: 0.3px;
      transition: opacity 0.3s;
      pointer-events: none;
    `;
    bar.textContent = "";
    bar.style.opacity = "0";
    document.body.appendChild(bar);
  });
}

async function showSubtitle(page, text) {
  await page.evaluate((t) => {
    const bar = document.getElementById("demo-subtitle");
    if (!bar) return;
    if (t) {
      bar.textContent = t;
      bar.style.opacity = "1";
    } else {
      bar.style.opacity = "0";
    }
  }, text);
  if (text) await page.waitForTimeout(800);
}

async function ensureVisible(page, locator, label) {
  const el = typeof locator === "string" ? page.locator(locator).first() : locator;
  const visible = await el.isVisible().catch(() => false);
  if (!visible) {
    console.error(`REHEARSAL FAIL: "${label}" not found - selector: ${typeof locator === "string" ? locator : "(locator object)"}`);
    const found = await page.evaluate(() =>
      Array.from(document.querySelectorAll("button, input, select, textarea, a"))
        .filter((el) => el.offsetParent !== null)
        .map((el) => `${el.tagName}[${el.type || ""}] "${(el.textContent || "").trim().substring(0, 30)}"`)
        .join("\n  "),
    );
    console.error("  Visible elements:\n  " + found);
    return false;
  }
  console.log(`REHEARSAL OK: "${label}"`);
  return true;
}

async function moveAndClick(page, locator, label, opts = {}) {
  const { postClickDelay = 800, ...clickOpts } = opts;
  const el = typeof locator === "string" ? page.locator(locator).first() : locator;
  const visible = await el.isVisible().catch(() => false);
  if (!visible) {
    console.error(`WARNING: moveAndClick skipped - "${label}" not visible`);
    return false;
  }
  try {
    await el.scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);
    const box = await el.boundingBox();
    if (box) {
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 10 });
      await page.waitForTimeout(400);
    }
    await el.click(clickOpts);
  } catch (e) {
    console.error(`WARNING: moveAndClick failed on "${label}": ${e.message}`);
    return false;
  }
  await page.waitForTimeout(postClickDelay);
  return true;
}

async function panElements(page, selector, maxCount = 6, { sweepMs = 500 } = {}) {
  const elements = await page.locator(selector).all();
  for (let i = 0; i < Math.min(elements.length, maxCount); i++) {
    try {
      const box = await elements[i].boundingBox();
      if (box && box.y < 760) {
        await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 8 });
        await page.waitForTimeout(sweepMs);
      }
    } catch (e) {
      console.warn(`WARNING: panElements skipped element ${i}: ${e.message}`);
    }
  }
}

async function smoothScroll(page, top, holdMs = 1500) {
  await page.evaluate((y) => window.scrollTo({ top: y, behavior: "smooth" }), top);
  await page.waitForTimeout(holdMs);
}

async function shot(page, name) {
  if (REHEARSE) return;
  const path = join(SHOTS, `${name}.png`);
  await page.screenshot({ path, fullPage: true });
  log(`  📸 ${path}`);
}

// -- acts ----------------------------------------------------------------------

async function actOverview(page) {
  log("Act 1/4 — Overview: the command deck");
  await page.goto(`${WEBAPP}/`, { waitUntil: "domcontentloaded" });
  await injectCursor(page);
  await injectSubtitleBar(page);
  await showSubtitle(page, "Step 1 - The command deck");
  await page.waitForTimeout(1800);

  // Stat strip — ticker tape across the deck.
  await showSubtitle(page, "Live posture at a glance");
  await panElements(page, ".statstrip .flex, main dl div, .panel dl > div", 5, { sweepMs: 650 });
  await shot(page, "01-overview-stats");

  // Risk timeline — hover the bars.
  await smoothScroll(page, 260, 800);
  await showSubtitle(page, "Risk over the last 24h");
  await panElements(page, "a[href*='/runs/']", 5, { sweepMs: 650 });
  await panElements(page, "svg [style*='height'], [role='img'] *", 3, { sweepMs: 550 });
  await shot(page, "02-overview-risk-timeline");

  // Detection volume.
  await showSubtitle(page, "Detection density by kill-chain family");
  await panElements(page, "svg g a, svg [fill]", 3, { sweepMs: 600 });
  await shot(page, "03-overview-detection-volume");

  // Findings feed + campaign spotlight.
  await smoothScroll(page, 900, 900);
  await showSubtitle(page, "Live findings, auto-refresh");
  await panElements(page, "ol a, .panel a", 4, { sweepMs: 550 });
  await shot(page, "04-overview-findings");
  await smoothScroll(page, 1300, 1000);
  await shot(page, "05-overview-bottom");

  // Quick actions — hover each command.
  await showSubtitle(page, "");
  await panElements(page, ".panel a[href='/monitor'], .panel a[href='/search'], .panel a[href='/compare'], .panel a[href='/watchlist']", 4, { sweepMs: 600 });
  await showSubtitle(page, "Quick actions ready");
  await shot(page, "06-overview-quick-actions");
  await showSubtitle(page, "");
}

async function actVault(page) {
  log("Act 2/4 — Sample vault: the binary library");
  await page.goto(`${WEBAPP}/samples`, { waitUntil: "domcontentloaded" });
  await injectCursor(page);
  await injectSubtitleBar(page);
  await showSubtitle(page, "Step 2 - The sample vault");
  await page.waitForTimeout(1600);

  // Stat strip — library posture.
  await showSubtitle(page, "Every uploaded binary, scanned");
  await panElements(page, "main dl > div", 4, { sweepMs: 600 });
  await shot(page, "07-vault-stats");

  // Table — pan rows, hover YARA chips + detonation links.
  await showSubtitle(page, "OS sniff, signatures, detonations");
  await panElements(page, "tbody tr", 5, { sweepMs: 550 });
  await shot(page, "08-vault-table");

  // Filter — type into the search box (debounced server-side filter).
  await showSubtitle(page, "Filter the vault");
  await moveAndClick(page, page.getByLabel("Filter samples"), "Vault filter", { postClickDelay: 400 });
  await page.keyboard.type("rep", { delay: 120 });
  await page.waitForTimeout(1100); // debounce + fetch
  await shot(page, "09-vault-filter");

  // Open a sample detail — full hash, YARA evidence, detonations.
  await showSubtitle(page, "Sample detail - full evidence");
  await moveAndClick(page, page.locator("tbody tr a").first(), "Sample row", { postClickDelay: 1400 });
  await panElements(page, ".panel", 2, { sweepMs: 600 });
  await shot(page, "10-vault-detail");
  await showSubtitle(page, "");
}

async function actMonitor(page) {
  log("Act 3/4 — Monitor: detonate a sample");
  await page.goto(`${WEBAPP}/monitor`, { waitUntil: "domcontentloaded" });
  await injectCursor(page);
  await injectSubtitleBar(page);
  await showSubtitle(page, "Step 2 - Detonate a sample");
  await page.waitForTimeout(1500);

  await showSubtitle(page, "Choose a platform");
  await moveAndClick(page, page.getByRole("radio", { name: /Windows/i }), "Windows chip", { postClickDelay: 600 });
  await moveAndClick(page, page.getByRole("radio", { name: /Linux/i }), "Linux chip", { postClickDelay: 600 });

  const before = await apiGet("/runs");
  const beforeIds = new Set(before.map((r) => r.run_id)); // any run created by the detonation counts

  await showSubtitle(page, "Detonate a synthetic dropper");
  await moveAndClick(page, page.getByRole("button", { name: /detonate synthetic sample/i }), "Detonate synthetic sample", { postClickDelay: 1200 });
  await showSubtitle(page, "Live analysis - events streaming");
  await sleep(6000);
  await shot(page, "11-detonate-live");

  let rid = null;
  await waitFor(async () => {
    const runs = await apiGet("/runs");
    const fresh = runs.find((r) => !beforeIds.has(r.run_id) && r.completed_at);
    if (!fresh) return false;
    rid = fresh.run_id;
    return true;
  }, { label: "detonation run to complete", timeoutMs: 90000 });

  log(`  ✅ detonation complete — run ${rid}`);
  await showSubtitle(page, "Analysis complete");
  await sleep(1200);
  await shot(page, "12-detonate-complete");
  await showSubtitle(page, "");
  return rid;
}

async function actRunDetail(page, rid) {
  log(`Act 4/4 — Run detail: ${rid}`);
  await page.goto(`${WEBAPP}/runs/${rid}`, { waitUntil: "domcontentloaded" });
  await injectCursor(page);
  await injectSubtitleBar(page);
  await showSubtitle(page, "Step 3 - The analysis report");
  await page.waitForTimeout(1800);
  await shot(page, "13-detail-top");

  // Risk gauge / header stats.
  await showSubtitle(page, "Risk score and verdict");
  await panElements(page, ".panel dl > div, .panel .grid > div", 4, { sweepMs: 600 });

  // Kill chain.
  await showSubtitle(page, "Kill chain across the session");
  await panElements(page, "a[href*='/runs/'], .panel a, [role='link']", 4, { sweepMs: 550 });
  await shot(page, "14-detail-killchain");

  // Process tree — hover the flagged node for the halo.
  await smoothScroll(page, 500, 800);
  await showSubtitle(page, "Process tree with risk halos");
  await page.locator(".process-tree [data-rep], .process-node, [class*='process'] [title*='net']").first().hover({ trial: true }).catch(() => {});
  await panElements(page, ".process-node, [class*='process'] li, [class*='ProcessTree'] *[role='treeitem']", 5, { sweepMs: 600 });
  await shot(page, "15-detail-process-tree");

  // Network connections.
  await smoothScroll(page, 1100, 800);
  await showSubtitle(page, "Network connections - C2");
  await panElements(page, "table tbody tr", 4, { sweepMs: 550 });
  await shot(page, "16-detail-network");

  // Timeline.
  await smoothScroll(page, 1700, 800);
  await showSubtitle(page, "Event timeline");
  await shot(page, "17-detail-timeline");

  // Analyst note — capture the notes box in action.
  await smoothScroll(page, 2300, 800);
  await showSubtitle(page, "Add an analyst note");
  await moveAndClick(page, page.getByPlaceholder("Add an observation…"), "Notes box", { postClickDelay: 400 });
  await page.keyboard.type("Campaign-adjacent — C2 beaconing to 203.0.113.88.", { delay: 28 });
  await moveAndClick(page, page.getByRole("button", { name: "Add note" }), "Add note", { postClickDelay: 900 });
  await shot(page, "18-detail-notes");
  await showSubtitle(page, "");

  await showSubtitle(page, "Detection rules - Suricata");
  await smoothScroll(page, 2600, 600);
  await moveAndClick(page, page.getByRole("button", { name: /generate rules from this run/i }), "Generate rules", { postClickDelay: 1000 });
  await page.locator("pre").first().waitFor({ timeout: 15000 });
  await shot(page, "19-detail-rules");
  await showSubtitle(page, "");
}

// -- main ----------------------------------------------------------------------

async function main() {
  log(`OutPost — "Command deck" demo`);
  log(`  webapp: ${WEBAPP}   api: ${API}   headless: ${HEADLESS}   mode: ${REHEARSE ? "rehearse" : "record"}`);
  log("");

  mkdirSync(SHOTS, { recursive: true });

  const browser = await (async () => {
    try {
      return await chromium.launch({ headless: HEADLESS, channel: "chrome" });
    } catch {
      log("  (system Chrome not found — using bundled Chromium)");
      return await chromium.launch({ headless: HEADLESS });
    }
  })();

  const context = await browser.newContext({
    viewport: VIEW,
    colorScheme: "dark", // the deck's signature look — force it before first paint
    ...(REHEARSE ? {} : { recordVideo: { dir: join(__dirname, ".deck-video"), size: VIEW } }),
  });
  // The theme init in index.html reads localStorage before first paint; seed it
  // so footage shows the dark command deck regardless of OS preference.
  await context.addInitScript(() => {
    localStorage.setItem("outpost-theme", "dark");
  });
  const page = await context.newPage();
  page.on("console", (msg) => {
    if (msg.type() === "error") console.error("  [page console.error]", msg.text());
  });
  page.on("pageerror", (err) => console.error("  [page error]", err.message));

  try {
    await actOverview(page);
    await actVault(page);
    const rid = await actMonitor(page); // detonation feeds the run-detail act
    await actRunDetail(page, rid);
    log("");
    log("✅ Walkthrough complete");
  } finally {
    await context.close();
    await browser.close();
    if (!REHEARSE) {
      const video = page.video();
      if (video) {
        const src = await video.path().catch(() => null);
        if (src) {
          const { copyFileSync } = await import("node:fs");
          copyFileSync(src, VIDEO_OUT);
          log(`🎬 Video saved: ${VIDEO_OUT}`);
        }
      } else {
        log("⚠ No video recorded (rehearsal mode or recording unavailable)");
      }
    }
  }
}

main().catch((err) => {
  console.error(`❌ Demo failed: ${err.message}`);
  process.exit(1);
});
