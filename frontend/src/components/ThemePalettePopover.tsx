import { useEffect, useRef, useState } from "react";
import { IconMoon, IconSun } from "./Icon";

export interface ThemePreset {
  id: string;
  name: string;
  badge: string;
  icon: string;
  desc: string;
  bgDot: string;
  accentDot: string;
}

export const THEME_PRESETS: ThemePreset[] = [
  { id: "dark", name: "Midnight Obsidian", badge: "Default", icon: "🌌", desc: "Cyber obsidian base & electric indigo accent", bgDot: "bg-[#090a0f]", accentDot: "bg-[#6366f1]" },
  { id: "matrix", name: "Phosphor Matrix", badge: "Hacker", icon: "⚡", desc: "CRT terminal obsidian & phosphor emerald", bgDot: "bg-[#050805]", accentDot: "bg-[#10b981]" },
  { id: "cyberpunk", name: "Cyberpunk Neon", badge: "Synthwave", icon: "🌆", desc: "Night City abyss & neon rose lasers", bgDot: "bg-[#0b0817]", accentDot: "bg-[#f43f5e]" },
  { id: "mission", name: "Mission Control", badge: "Aerospace", icon: "🛰️", desc: "Deep space navy & telemetry gold", bgDot: "bg-[#080e1a]", accentDot: "bg-[#f59e0b]" },
  { id: "amethyst", name: "Amethyst Void", badge: "Cyber", icon: "🟣", desc: "Royal violet obsidian & radiant magenta", bgDot: "bg-[#0a0714]", accentDot: "bg-[#a855f7]" },
  { id: "nordic", name: "Nordic Glacier", badge: "Nord", icon: "❄️", desc: "Polar night & aurora cyan frost", bgDot: "bg-[#242933]", accentDot: "bg-[#88c0d0]" },
  { id: "monokai", name: "Monokai Carbon", badge: "Pro", icon: "🪵", desc: "Warm carbon & studio amber gold", bgDot: "bg-[#18181b]", accentDot: "bg-[#eab308]" },
  { id: "light", name: "Arctic Frost", badge: "Light", icon: "🧊", desc: "Clean modern high-contrast daylight", bgDot: "bg-[#f8fafc]", accentDot: "bg-[#2563eb]" },
];

export interface PaletteOption {
  id: string;
  name: string;
  dot: string;
  accent: string;
}

export const THEME_PALETTES: PaletteOption[] = [
  { id: "", name: "Graphite", dot: "bg-[#8b7cf6]", accent: "#8b7cf6" },
  { id: "emerald", name: "Emerald", dot: "bg-[#10b981]", accent: "#10b981" },
  { id: "amber", name: "Amber", dot: "bg-[#f59e0b]", accent: "#f59e0b" },
  { id: "ocean", name: "Ocean", dot: "bg-[#5aa2ff]", accent: "#5aa2ff" },
  { id: "amethyst", name: "Amethyst", dot: "bg-[#a855f7]", accent: "#a855f7" },
  { id: "rose", name: "Rose", dot: "bg-[#f43f5e]", accent: "#f43f5e" },
  { id: "teal", name: "Teal", dot: "bg-[#2dd4bf]", accent: "#2dd4bf" },
  { id: "slate", name: "Slate", dot: "bg-[#8b7cf6]", accent: "#8b7cf6" },
];

export function ThemePalettePopover({
  theme: _theme,
  toggleTheme,
  onClose,
}: {
  theme?: "dark" | "light";
  toggleTheme?: () => void;
  onClose?: () => void;
}) {
  const [activeTheme, setActiveTheme] = useState(() => document.documentElement.dataset.theme ?? "dark");
  const [palette, setPalette] = useState(() => document.documentElement.dataset.palette ?? "");
  const [tab, setTab] = useState<"THEMES" | "ACCENTS">("THEMES");
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const applyThemePreset = (themeId: string) => {
    document.documentElement.dataset.theme = themeId;
    localStorage.setItem("outpost-theme-v2", themeId);
    if (themeId === "light") {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
      setPalette("");
    }
    setActiveTheme(themeId);
    if (toggleTheme) {
      // sync outer component state if any
    }
  };

  const setPaletteMode = (id: string) => {
    if (activeTheme === "light") {
      applyThemePreset("dark");
    }
    if (id) {
      document.documentElement.dataset.palette = id;
      localStorage.setItem("outpost-palette", id);
    } else {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
    }
    setPalette(id);
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
        if (onClose) onClose();
      }
    };
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open, onClose]);

  return (
    <div className="relative inline-block" ref={containerRef}>
      <button
        onClick={() => setOpen((prev) => !prev)}
        aria-label="Theme and visual customization studio"
        title="Custom Themes & Accent Palettes (Click to open studio)"
        className="press flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-border-subtle bg-bg-surface text-text-muted transition-colors duration-150 hover:border-accent/50 hover:text-accent shadow-[var(--shadow-panel)]"
      >
        <span className="relative flex items-center justify-center text-sm">
          {activeTheme === "light" ? <IconSun /> : <IconMoon />}
          <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-accent animate-pulse shadow-[var(--glow-accent)]" />
        </span>
      </button>

      {open && (
        <div
          className="absolute bottom-full left-0 z-50 mb-2 w-80 rounded-2xl border border-border-subtle bg-bg-overlay/95 p-3.5 shadow-2xl backdrop-blur-2xl animate-scale-in"
          role="dialog"
          aria-label="Theme & Customization Studio"
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
            <div className="flex items-center gap-1.5">
              <span className="text-sm">🎨</span>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
                Theme Studio
              </span>
            </div>
            <span className="font-mono text-[10px] font-semibold text-accent uppercase">
              {THEME_PRESETS.find((t) => t.id === activeTheme)?.name ?? activeTheme}
            </span>
          </div>

          {/* Tab Selector */}
          <div className="mt-2.5 flex rounded-lg border border-border-subtle bg-bg-surface p-0.5 font-mono text-[11px]">
            <button
              onClick={() => setTab("THEMES")}
              className={`flex-1 rounded-md py-1 text-center font-medium transition ${
                tab === "THEMES" ? "bg-accent/15 font-bold text-accent shadow-sm" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Theme Presets ({THEME_PRESETS.length})
            </button>
            <button
              onClick={() => setTab("ACCENTS")}
              className={`flex-1 rounded-md py-1 text-center font-medium transition ${
                tab === "ACCENTS" ? "bg-accent/15 font-bold text-accent shadow-sm" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Accent Palettes ({THEME_PALETTES.length})
            </button>
          </div>

          {/* Tab Content: Themes */}
          {tab === "THEMES" && (
            <div className="mt-3 max-h-72 space-y-1.5 overflow-y-auto pr-0.5">
              {THEME_PRESETS.map((t) => {
                const isCurrent = activeTheme === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => applyThemePreset(t.id)}
                    className={`flex w-full items-center justify-between rounded-xl border p-2 text-left transition ${
                      isCurrent
                        ? "border-accent/60 bg-accent/15 shadow-[var(--glow-accent)]"
                        : "border-border-subtle bg-bg-surface/70 hover:border-border-strong hover:bg-bg-surface"
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <span className="text-base">{t.icon}</span>
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-xs font-semibold ${isCurrent ? "text-accent font-bold" : "text-text-primary"}`}>
                            {t.name}
                          </span>
                          <span className="rounded bg-bg-elevated px-1 py-0.2 font-mono text-[9px] text-text-faint uppercase">
                            {t.badge}
                          </span>
                        </div>
                        <p className="text-[10px] text-text-muted">{t.desc}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className={`h-3 w-3 rounded-full border border-border-strong ${t.bgDot}`} />
                      <span className={`h-3 w-3 rounded-full ${t.accentDot}`} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}

          {/* Tab Content: Accents */}
          {tab === "ACCENTS" && (
            <div className="mt-3">
              <p className="mb-2 text-[10px] text-text-muted">
                Override the active accent color across buttons, graphs, and indicators:
              </p>
              <div className="grid grid-cols-4 gap-1.5">
                {THEME_PALETTES.map((p) => {
                  const active = palette === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => setPaletteMode(p.id)}
                      title={p.name}
                      className={`flex flex-col items-center gap-1.5 rounded-xl border p-2 text-[10px] transition ${
                        active
                          ? "border-accent/70 bg-accent/20 font-bold text-accent shadow-[var(--glow-accent)]"
                          : "border-border-subtle bg-bg-surface text-text-muted hover:border-border-strong"
                      }`}
                    >
                      <span className={`h-4 w-4 rounded-full shadow-sm ${p.dot}`} />
                      <span className="truncate font-medium">{p.name}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Footer Live Status */}
          <div className="mt-3 flex items-center justify-between border-t border-border-subtle pt-2 text-[10px] text-text-faint">
            <span>✨ Saved in local browser session</span>
            <button
              onClick={() => {
                applyThemePreset("dark");
                setPaletteMode("");
              }}
              className="text-text-muted hover:text-accent transition underline"
            >
              Reset Default
            </button>
          </div>
        </div>
      )}
    </div>
  );
}