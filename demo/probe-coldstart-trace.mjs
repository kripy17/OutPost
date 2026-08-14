// Break down the cold-start budget on the real soak store: how much is JS
// download+parse+execute, how much is fonts, how much is the data fetch.
// Uses a CDP devtools.timeline trace so V8 compile/evaluate are measured
// precisely, plus resource timing for bytes.
import { chromium } from "playwright";
import fs from "node:fs";

const WEB = "http://localhost:5188";

const browser = await chromium.launch();
const ctx = await browser.newContext({ serviceWorkers: "block" });
const page = await ctx.newPage();

const TRACE = "/tmp/coldstart-trace.json";
const cdp = await ctx.newCDPSession(page);
const traceChunks = [];
cdp.on("Tracing.dataCollected", (p) => traceChunks.push(...(p.value ?? [])));
await cdp.send("Tracing.start", {
  traceConfig: { includedCategories: ["devtools.timeline", "v8.execute"], recordConsoleMessages: false },
});

const apiTimes = {};
page.on("response", (r) => {
  const u = r.url();
  if (u.includes(":8001/")) apiTimes[u.slice(u.indexOf(":8001/") + 6).split("?")[0]] = Date.now();
});

const t0 = Date.now();
await page.goto(WEB, { waitUntil: "load" });
const loadAt = Date.now() - t0;
const anchorAt = await page
  .waitForSelector("text=/[0-9]+\\s+sessions/i", { timeout: 30000 })
  .then(() => Date.now() - t0)
  .catch(() => -1);
await cdp.send("Tracing.end");
await new Promise((r) => setTimeout(r, 300));
fs.writeFileSync(TRACE, JSON.stringify({ traceEvents: traceChunks }));
const trace = JSON.parse(fs.readFileSync(TRACE, "utf8"));
const evs = trace.traceEvents ?? [];

const sum = (name) => {
  let total = 0, max = 0, count = 0;
  for (const e of evs) {
    if (e.name === name && typeof e.dur === "number") {
      total += e.dur;
      if (e.dur > max) max = e.dur;
      count++;
    }
  }
  return { totalUs: total, maxUs: max, count };
};

const parse = sum("ParseHTML");
const compile = sum("v8.compile");
const evaluate = sum("EvaluateScript");
const parseCSS = sum("ParseAuthorStyleSheet");

const paints = await page.evaluate(() => {
  const paintList = performance.getEntriesByType("paint").map((e) => [e.name, Math.round(e.startTime)]);
  const res = performance
    .getEntriesByType("resource")
    .map((r) => ({ n: r.name.slice(r.name.lastIndexOf("/") + 1), ms: Math.round(r.duration), kb: Math.round(r.transferSize / 1024) }));
  const js = res.filter((r) => r.n.endsWith(".js"));
  const woff = res.filter((r) => r.n.endsWith(".woff2"));
  const css = res.filter((r) => r.n.endsWith(".css"));
  return {
    paintList,
    jsBytes: js.reduce((s, r) => s + r.kb, 0),
    jsMaxMs: Math.max(0, ...js.map((r) => r.ms)),
    woffCount: woff.length,
    woffMaxMs: Math.max(0, ...woff.map((r) => r.ms)),
    cssMs: css.reduce((s, r) => s + r.ms, 0),
  };
});

const lastApi = Object.values(apiTimes).length ? Math.max(...Object.values(apiTimes)) - t0 : -1;

console.log(`anchor: ${anchorAt}ms  (load event at ${loadAt}ms)`);
console.log(`paints: ${JSON.stringify(paints.paintList)}`);
console.log(`--- trace (V8/main-thread) ---`);
console.log(`  ParseHTML:   ${(parse.totalUs / 1000).toFixed(1)}ms total, max ${(parse.maxUs / 1000).toFixed(1)}ms`);
console.log(`  v8.compile:  ${(compile.totalUs / 1000).toFixed(1)}ms total, max ${(compile.maxUs / 1000).toFixed(1)}ms`);
console.log(`  EvaluateScript: ${(evaluate.totalUs / 1000).toFixed(1)}ms total over ${evaluate.count} scripts, max ${(evaluate.maxUs / 1000).toFixed(1)}ms`);
console.log(`  ParseAuthorStyleSheet: ${(parseCSS.totalUs / 1000).toFixed(1)}ms`);
console.log(`--- resources ---`);
console.log(`  JS: ${paints.jsBytes}KB total, slowest ${paints.jsMaxMs}ms`);
console.log(`  woff2: ${paints.woffCount} fonts, slowest ${paints.woffMaxMs}ms`);
console.log(`  CSS total: ${paints.cssMs}ms`);
console.log(`  last API response at ${lastApi}ms`);
console.log(`--- anchor - load gap: ${anchorAt - loadAt}ms (hydration + query + render) ---`);
await browser.close();
