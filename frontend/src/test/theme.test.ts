// Theme token reader (lib/theme.ts) — the SVG-facing palette. Tests lock the
// dark-first fallbacks when CSS custom properties are absent, the override
// path when they are defined, and the MutationObserver re-read when the
// data-theme attribute flips.

import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { readColors, useThemeColors } from "../lib/theme";

const VARS = ["--risk-clean", "--risk-suspicious", "--risk-malicious", "--accent", "--border-subtle", "--text-faint", "--text-muted"];

afterEach(() => {
  document.documentElement.removeAttribute("data-theme");
  for (const k of VARS) document.documentElement.style.removeProperty(k);
});

describe("readColors", () => {
  it("falls back to the dark palette when no CSS vars are defined", () => {
    expect(readColors()).toEqual({
      clean: "#3fa796",
      suspicious: "#d9a441",
      malicious: "#c4453b",
      accent: "#d9a441",
      grid: "#262c38",
      faint: "#6a7480",
      muted: "#7a8290",
    });
  });

  it("reads the CSS custom properties when defined and falls back per-var", () => {
    const root = document.documentElement;
    root.style.setProperty("--risk-malicious", "#123456");
    root.style.setProperty("--accent", "#abcdef");
    const c = readColors();
    expect(c.malicious).toBe("#123456");
    expect(c.accent).toBe("#abcdef");
    expect(c.clean).toBe("#3fa796"); // untouched var keeps its fallback
  });
});

describe("useThemeColors", () => {
  it("re-reads colors when the data-theme attribute flips", async () => {
    document.documentElement.style.setProperty("--risk-malicious", "#111111");
    const { result } = renderHook(() => useThemeColors());
    expect(result.current.malicious).toBe("#111111");
    document.documentElement.style.setProperty("--risk-malicious", "#222222");
    document.documentElement.setAttribute("data-theme", "light");
    await waitFor(() => expect(result.current.malicious).toBe("#222222"));
  });
});
