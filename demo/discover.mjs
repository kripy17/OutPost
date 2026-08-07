// Phase 1 discovery — dump interactive elements per page so the demo script
// uses real selectors (ui-demo skill). Run: node discover.mjs
import { chromium } from "playwright";

const WEBAPP = "http://localhost:5174";
const API = "http://localhost:8001";

async function dump(page, url, label) {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2500);
  const fields = await page.evaluate(() => {
    const els = [];
    document.querySelectorAll("input, select, textarea, button, [contenteditable]").forEach((el) => {
      if (el.offsetParent !== null) {
        els.push({
          tag: el.tagName,
          type: el.type || "",
          name: el.name || "",
          placeholder: el.placeholder || "",
          text: (el.textContent || "").trim().replace(/\s+/g, " ").substring(0, 60),
          role: el.getAttribute("role") || "",
          aria: el.getAttribute("aria-label") || "",
        });
      }
    });
    return els;
  });
  console.log(`\n=== ${label} (${url}) ===`);
  fields.forEach((f) => console.log(`  ${f.tag}[${f.type}] ph="${f.placeholder}" aria="${f.aria}" txt="${f.text}"`));
  return fields;
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

await dump(page, `${WEBAPP}/`, "Overview");
await dump(page, `${WEBAPP}/monitor`, "Monitor");

// Get a recent run id for the detail page
const runs = await (await fetch(`${API}/runs`)).json();
const rid = runs[0]?.run_id;
console.log(`\nUsing run ${rid} for detail page`);
if (rid) await dump(page, `${WEBAPP}/runs/${rid}`, "Run detail");

await browser.close();
