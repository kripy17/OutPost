export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export interface SeverityStyle {
  border: string;
  text: string;
  bg: string;
  label: string;
}

export const SEVERITY: Record<SeverityLevel, SeverityStyle> = {
  critical: {
    border: "border-l-[#f85149]",
    text: "text-[#ff7b72]",
    bg: "bg-[rgba(248,81,73,0.12)]",
    label: "Critical",
  },
  high: {
    border: "border-l-[#db6d28]",
    text: "text-[#ffa657]",
    bg: "bg-[rgba(219,109,40,0.12)]",
    label: "High",
  },
  medium: {
    border: "border-l-[#d29922]",
    text: "text-[#e3b341]",
    bg: "bg-[rgba(210,153,34,0.12)]",
    label: "Medium",
  },
  low: {
    border: "border-l-[#3fb950]",
    text: "text-[#56d364]",
    bg: "bg-[rgba(63,185,80,0.12)]",
    label: "Low",
  },
  info: {
    border: "border-l-[#8b949e]",
    text: "text-[#8b949e]",
    bg: "bg-[rgba(139,148,158,0.12)]",
    label: "Info",
  },
};

export const normalizeSeverity = (raw?: string | null): SeverityLevel => {
  const s = (raw ?? "").toLowerCase();
  if (s.includes("crit") || s === "p1") return "critical";
  if (s.includes("high") || s.includes("malicious") || s === "p2") return "high";
  if (s.includes("med") || s.includes("suspicious") || s === "p3") return "medium";
  if (s.includes("low") || s === "p4") return "low";
  return "info";
};

export const TOKENS = {
  bgBase: "bg-[#0c0d0e]",
  bgSurface: "bg-[#141618]",
  bgRaised: "bg-[#1a1d20]",
  border: "border-[#26292e]",
  borderHairline: "border-[0.5px] border-[#26292e]",
  textPrimary: "text-[#e6edf3]",
  textMuted: "text-[#8b949e]",
  textMetadata: "text-[#7d8590]",
  textDisabled: "text-[#5a626c]",
  accent: "#2f81f7",
  accentBg: "bg-[#2f81f7]",
  accentText: "text-[#58a6ff]",
  accentBorder: "border-[#2f81f7]",
  radius: "rounded-[4px]",
  radiusSm: "rounded-[2px]",
  fontBody: "text-[13px] leading-normal font-sans",
  fontTable: "text-[12px] leading-tight font-sans",
  fontMeta: "text-[11px] leading-tight font-sans text-[#7d8590]",
  fontMono: "font-mono text-[12px]",
  fontMonoSm: "font-mono text-[11px]",
  tabularNums: "tabular-nums text-right",
} as const;

export const RAW_COLORS = {
  bgBase: "#0c0d0e",
  bgSurface: "#141618",
  bgRaised: "#1a1d20",
  border: "#26292e",
  textPrimary: "#e6edf3",
  textMuted: "#8b949e",
  textMetadata: "#7d8590",
  textDisabled: "#5a626c",
  accent: "#2f81f7",
} as const;
