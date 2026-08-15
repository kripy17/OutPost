// The deck's fill language — pattern-encoded, not just color, so risk levels
// and stage states stay readable for color-blind viewers. Shared by the
// Campaigns cluster bars, the History risk timeline, and the kill-chain
// stepper so the whole deck speaks one vocabulary:
//
//   SOLID      = critical / malicious / full chain
//   DIAGONAL   = elevated / suspicious / reached
//   VERTICAL   = low / none / clean
//   CROSSHATCH = unknown
//
// Opacity keeps text legible over the fill; tokens come from the CSS design
// variables so the patterns re-theme with the app.

import type { Reputation, Severity } from "../types";

export type FillTone = "critical" | "elevated" | "low" | "unknown";

export interface FillStyle {
  background: string;
  opacity: number;
}

/** The CSS fill for a tone — used directly on HTML elements (bar rows,
 *  legend swatches, tooltip dots). Pure — no fetch, no component. */
export function toneFill(tone: FillTone): FillStyle {
  switch (tone) {
    case "critical":
      return { background: "var(--risk-malicious)", opacity: 0.45 };
    case "elevated":
      return {
        background: "repeating-linear-gradient(45deg, var(--risk-suspicious) 0 4px, transparent 4px 8px)",
        opacity: 0.6,
      };
    case "low":
      return {
        background: "repeating-linear-gradient(90deg, var(--risk-clean) 0 2px, transparent 2px 7px)",
        opacity: 0.6,
      };
    default: // unknown
      return {
        background:
          "repeating-linear-gradient(45deg, var(--text-muted) 0 2px, transparent 2px 6px), repeating-linear-gradient(-45deg, var(--text-muted) 0 2px, transparent 2px 6px)",
        opacity: 0.6,
      };
  }
}

/** Reputation → tone: malicious = critical, suspicious = elevated, clean =
 *  low, anything else (unknown) = crosshatch. Pure. */
export function toneForReputation(reputation: Reputation): FillTone {
  switch (reputation) {
    case "malicious":
      return "critical";
    case "suspicious":
      return "elevated";
    case "clean":
      return "low";
    default:
      return "unknown";
  }
}

/** Risk-band label (from riskBand()) → tone: critical / elevated stay as-is,
 *  none and low map to the low (vertical) hatch. Pure. */
export function toneForRiskBand(label: string): FillTone {
  if (label === "critical") return "critical";
  if (label === "elevated") return "elevated";
  return "low";
}

/** Severity → tone: malicious = critical (solid), suspicious = elevated
 *  (diagonal hatch) — the severity dots and donut segments speak the same
 *  vocabulary as the risk bands. Pure. */
export function toneForSeverity(severity: Severity): FillTone {
  return severity === "malicious" ? "critical" : "elevated";
}
