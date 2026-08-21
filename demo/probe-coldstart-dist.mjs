// Sample the cold-start anchor distribution: 12 fresh loads, cache off,
// report sorted times + median + p80, plus which fetch resolved last.
import { chromium } from "playwright";

const WEB = "http://localhost:5188";
const browser = await chromium.launch();

const anchors = [];
for (let iter = 1; iter <= 12; iter++) {
  const ctx = await browser.newContext({ serviceWorkers: "block" });
  const page = await ctx.newPage();
  const client = await ctx.newCDPSession(page);
  await client.send("Network.enable");
  await client.send("Network.setCacheDisabled", { cacheDisabled: true });

  const t0 = Date.now();
  await page.goto(WEB, { waitUntil: "load" });
  const a = await page
    .waitForSelector("text=/[0-9]+\\s+sessions/i", { timeout: 8000 })
    .then(() => Date.now() - t0)
    .catch(() => -1);
  anchors.push(a);
  await ctx.close();
}

const sorted = [...anchors].sort((x, y) => x - y);
const med = sorted[Math.floor(sorted.length / 2)];
const p80 = sorted[Math.floor(sorted.length * 0.8)];
console.log(`samples: ${sorted.join(", ")}`);
console.log(`median: ${med}ms   p80: ${p80}ms   best: ${sorted[0]}ms   worst: ${sorted[sorted.length - 1]}ms`);
await browser.close();
