// Browser-baseline contracts — UA parsing, version floor, and the
// unknown-engine feature-probe fallback.

import { describe, expect, it } from "vitest";
import {
  DECK_BASELINE,
  checkBrowserSupport,
  parseBrowser,
  type FeatureProbes,
} from "../lib/browserSupport";

const ALL_OK: FeatureProbes = { "color-mix": true, ":has()": true };

describe("parseBrowser", () => {
  it("parses a modern Chrome UA", () => {
    expect(parseBrowser("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")).toEqual({ name: "chrome", version: 123 });
  });

  it("parses Edge via its Edg/ token (not Chrome/)", () => {
    expect(parseBrowser("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/122.0.2365.92")).toEqual({ name: "edge", version: 122 });
  });

  it("parses Firefox", () => {
    expect(parseBrowser("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0")).toEqual({ name: "firefox", version: 115 });
  });

  it("parses real Safari via Version/ (its WebKit build is not the version)", () => {
    expect(parseBrowser("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15")).toEqual({ name: "safari", version: 16.6 });
  });

  it("keeps Safari minor precision (16.2 vs 16.4 floor)", () => {
    expect(parseBrowser("Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1")).toEqual({ name: "safari", version: 16.2 });
  });

  it("falls back to unknown for an empty or unrecognized UA", () => {
    expect(parseBrowser("")).toEqual({ name: "unknown", version: 0 });
    expect(parseBrowser("some-embedded-engine/1.0")).toEqual({ name: "unknown", version: 0 });
  });
});

describe("checkBrowserSupport", () => {
  it("passes a browser at the floor", () => {
    const v = checkBrowserSupport("Mozilla/5.0 (X11; Linux) Chrome/111.0.0.0 Safari/537.36", ALL_OK);
    expect(v.ok).toBe(true);
    expect(v.missing).toEqual([]);
  });

  it("flags an old browser with its version", () => {
    const v = checkBrowserSupport("Mozilla/5.0 (X11; Linux) Chrome/109.0.0.0 Safari/537.36", ALL_OK);
    expect(v.ok).toBe(false);
    expect(v.missing).toContain("chrome 109");
  });

  it("flags Safari under its minor floor", () => {
    const v = checkBrowserSupport("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15", ALL_OK);
    expect(v.ok).toBe(false);
    expect(v.missing).toContain("safari 16.2");
  });

  it("flags missing CSS features even on a current browser", () => {
    const v = checkBrowserSupport("Mozilla/5.0 (X11; Linux) Chrome/123.0.0.0 Safari/537.36", { "color-mix": false, ":has()": true });
    expect(v.ok).toBe(false);
    expect(v.missing).toEqual(["color-mix()"]);
  });

  it("judges an unknown engine purely on probes — passing probes mean ok", () => {
    const v = checkBrowserSupport("some-embedded-engine/1.0", ALL_OK);
    expect(v.ok).toBe(true);
    expect(v.missing).toEqual([]);
  });

  it("warns on an unknown engine that fails a probe", () => {
    const v = checkBrowserSupport("some-embedded-engine/1.0", { "color-mix": false, ":has()": false });
    expect(v.ok).toBe(false);
    expect(v.missing).toEqual(["color-mix()", ":has()"]);
  });

  it("the baseline table covers all four named engines", () => {
    expect(DECK_BASELINE).toEqual({ chrome: 111, edge: 111, firefox: 128, safari: 16.4 });
  });
});
