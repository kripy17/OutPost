// Theme-reactive design tokens for SVG work.
//
// The app's colors live as CSS custom properties (index.css) and re-theme via
// the data-theme attribute. Reading them with getComputedStyle and re-reading
// on data-theme changes lets charts (RiskTimeline, DetectionVolume) recolor
// instantly when the toggle flips — no duplicated palette in TS.

import { useEffect, useState } from "react";

export interface ThemeColors {
  clean: string;
  suspicious: string;
  malicious: string;
  accent: string;
  grid: string;
  faint: string;
  muted: string;
}

export function readColors(): ThemeColors {
  const css = getComputedStyle(document.documentElement);
  const get = (name: string) => css.getPropertyValue(name).trim();
  return {
    clean: get("--risk-clean") || "#3fa796",
    suspicious: get("--risk-suspicious") || "#d9a441",
    malicious: get("--risk-malicious") || "#c4453b",
    accent: get("--accent-amber") || "#d9a441",
    grid: get("--border-subtle") || "#2a2f3a",
    faint: get("--text-faint") || "#4b5261",
    muted: get("--text-muted") || "#7a8290",
  };
}

export function useThemeColors(): ThemeColors {
  const [colors, setColors] = useState(() => readColors());

  useEffect(() => {
    // Re-read whenever the theme flips (Nav's toggle only sets data-theme).
    const observer = new MutationObserver(() => setColors(readColors()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);

  return colors;
}
