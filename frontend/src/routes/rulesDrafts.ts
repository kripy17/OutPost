// Rules-page draft persistence — the YARA authoring and enum-pattern tables
// save in-progress state to localStorage so unsaved work survives a reload.
// Both drafts are cleared on successful save — a returning analyst sees
// server state, never a stale draft. Restore happens in useState initializers
// (NOT a mount effect): a mirror effect would clobber the stored draft with
// the empty default before the restore could read it back.

import type { EnumPatternRow } from "../types";

export type YaraDraft = {
  ruleText: string;
  family: string;
  description: string;
  scope: "all" | "picked";
  picked: string[];
};

export function readYaraDraft(): YaraDraft | null {
  try {
    const raw = localStorage.getItem("outpost-yara-draft");
    if (!raw) return null;
    const d: unknown = JSON.parse(raw);
    if (!d || typeof d !== "object") return null;
    const o = d as Record<string, unknown>;
    if (typeof o.ruleText !== "string" || typeof o.family !== "string" || typeof o.description !== "string") return null;
    if (o.scope !== "all" && o.scope !== "picked") return null;
    const picked = Array.isArray(o.picked) ? o.picked.filter((p): p is string => typeof p === "string") : [];
    return { ruleText: o.ruleText, family: o.family, description: o.description, scope: o.scope, picked };
  } catch {
    return null;
  }
}

export function writeYaraDraft(d: YaraDraft) {
  try {
    localStorage.setItem("outpost-yara-draft", JSON.stringify(d));
  } catch {
    /* storage unavailable — drafting still works for this visit */
  }
}

export function clearYaraDraft() {
  try {
    localStorage.removeItem("outpost-yara-draft");
  } catch {
    /* ignore */
  }
}

export function readEnumDrafts(): Record<string, EnumPatternRow[]> | null {
  try {
    const raw = localStorage.getItem("outpost-enum-drafts");
    if (!raw) return null;
    const d: unknown = JSON.parse(raw);
    if (!d || typeof d !== "object" || Array.isArray(d)) return null;
    const out: Record<string, EnumPatternRow[]> = {};
    for (const [platform, rows] of Object.entries(d as Record<string, unknown>)) {
      if (!Array.isArray(rows)) continue;
      const clean = rows.filter(
        (r): r is EnumPatternRow =>
          !!r && typeof r === "object" && typeof (r as EnumPatternRow).pattern === "string" && typeof (r as EnumPatternRow).label === "string",
      );
      if (clean.length) out[platform] = clean;
    }
    return Object.keys(out).length ? out : null;
  } catch {
    return null;
  }
}

export function writeEnumDrafts(drafts: Record<string, EnumPatternRow[]>) {
  try {
    if (Object.keys(drafts).length) localStorage.setItem("outpost-enum-drafts", JSON.stringify(drafts));
    else localStorage.removeItem("outpost-enum-drafts");
  } catch {
    /* storage unavailable */
  }
}

export function clearEnumDrafts() {
  try {
    localStorage.removeItem("outpost-enum-drafts");
  } catch {
    /* ignore */
  }
}
