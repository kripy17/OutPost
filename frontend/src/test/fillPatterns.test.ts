// The deck-wide fill language (lib/fillPatterns.ts) — the pattern-not-just-
// color encoding shared by the Campaigns cluster bars, the History risk
// timeline, and the kill-chain stepper. Locks the vocabulary: SOLID =
// critical/malicious, DIAGONAL = elevated/suspicious, VERTICAL = low/clean,
// CROSSHATCH = unknown.

import { describe, expect, it } from "vitest";
import { toneFill, toneForReputation, toneForRiskBand, toneForSeverity, type FillTone } from "../lib/fillPatterns";

const TONES: FillTone[] = ["critical", "elevated", "low", "unknown"];

describe("toneFill", () => {
  it("gives every tone a distinct fill so pattern carries meaning", () => {
    const fills = TONES.map((t) => toneFill(t).background);
    expect(new Set(fills).size).toBe(4);
  });

  it("critical is solid with the malicious token", () => {
    const f = toneFill("critical");
    expect(f.background).toBe("var(--risk-malicious)");
    expect(f.background).not.toContain("repeating-linear-gradient");
  });

  it("elevated is diagonal-hatched with the suspicious token", () => {
    const f = toneFill("elevated");
    expect(f.background).toContain("repeating-linear-gradient(45deg");
    expect(f.background).toContain("var(--risk-suspicious)");
  });

  it("low is vertically-hatched with the clean token", () => {
    const f = toneFill("low");
    expect(f.background).toContain("repeating-linear-gradient(90deg");
    expect(f.background).toContain("var(--risk-clean)");
  });

  it("unknown is crosshatched (two directions) with the muted token", () => {
    const f = toneFill("unknown");
    const matches = f.background.match(/repeating-linear-gradient/g) ?? [];
    expect(matches.length).toBe(2);
    expect(f.background).toContain("var(--text-muted)");
  });

  it("keeps opacity in (0, 1] for legibility over the fill", () => {
    for (const t of TONES) {
      const { opacity } = toneFill(t);
      expect(opacity).toBeGreaterThan(0);
      expect(opacity).toBeLessThanOrEqual(1);
    }
  });
});

describe("toneForReputation", () => {
  it("maps the four reputations onto the four tones", () => {
    expect(toneForReputation("malicious")).toBe("critical");
    expect(toneForReputation("suspicious")).toBe("elevated");
    expect(toneForReputation("clean")).toBe("low");
    expect(toneForReputation("unknown")).toBe("unknown");
  });
});

describe("toneForRiskBand", () => {
  it("maps risk-band labels onto the tone vocabulary", () => {
    expect(toneForRiskBand("critical")).toBe("critical");
    expect(toneForRiskBand("elevated")).toBe("elevated");
    expect(toneForRiskBand("low")).toBe("low");
    expect(toneForRiskBand("none")).toBe("low");
  });
});

describe("toneForSeverity", () => {
  it("maps severity onto the tone vocabulary", () => {
    expect(toneForSeverity("malicious")).toBe("critical");
    expect(toneForSeverity("suspicious")).toBe("elevated");
  });
});
