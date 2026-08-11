// Settings page pure helpers — the login brute-force guard's status text.

import { describe, expect, it } from "vitest";
import { lockedIpsText, rateLimitBadge } from "../routes/settingsHelpers";

describe("rateLimitBadge", () => {
  it("labels an active guard", () => {
    expect(rateLimitBadge(true)).toBe("active");
  });

  it("labels the zero-config default (auth off)", () => {
    expect(rateLimitBadge(false)).toBe("auth off · inactive");
  });
});

describe("lockedIpsText", () => {
  it("reads calm when nothing is locked", () => {
    expect(lockedIpsText(0)).toBe("No IPs currently locked out.");
  });

  it("singularizes one locked IP", () => {
    expect(lockedIpsText(1)).toContain("1 IP is locked out");
  });

  it("pluralizes several locked IPs", () => {
    expect(lockedIpsText(3)).toContain("3 IPs are locked out");
  });

  it("mentions the cooldown refusal for locked states", () => {
    expect(lockedIpsText(2)).toContain("cooldown expires");
    expect(lockedIpsText(0)).not.toContain("cooldown");
  });
});
