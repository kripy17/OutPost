// Profile repeated Overview loads against the real-soak store to find the
// intermittent ~1.5s iteration: fresh context per load, cache disabled (the
// harness's conditions), logging which fetch arrives last each time.
import { chromium } from "playwright";

const WEB = "http://localhost:5188";

const browser = await chromium.launch();
for (let iter = 1; iter <= 5; iter++) {
  const ctx = await browser.newContext({ serviceWorkers: "block" });
  const page = await ctx.newPage();
  const client = await ctx.newCDPSession(page);
  await client.send("Network.enable");
  await client.send("Network.setCacheDisabled", { cacheDisabled: true });

  const arrivals = [];
  page.on("response", (r) => {
    const u = r.url();
    if (u.includes("/api") || u.includes(":8001") || u.includes(":8001/")) {
      arrivals.push({ url: u.slice(0, 70), at: Date.now() });
    }
  });

  const t0 = Date.now();
  await page.goto(WEB, { waitUntil: "load" });
  const anchorAt = await page
    .waitForSelector("text=/[0-9]+\\s+sessions/i", { timeout: 30000 })
    .then(() => Date.now() - t0)
    .catch(() => -1);

  arrivals.sort((a, b) => a.at - b.at);
  const last = arrivals[arrivals.length - 1];
  console.log(
    `iter${iter}: anchor=${anchorAt}ms  apiFetches=${arrivals.length}  lastApi=${last ? `${(last.at - t0)}ms ${last.url}` : "none"}`
  );
  await ctx.close();
}
await browser.close();
