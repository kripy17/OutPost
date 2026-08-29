// Icon — the single icon vocabulary for the app. Every glyph that used to be
// a text character (▶ ⬡ ⚠ ✕ ⛨ ▤ ⇄ ★ ⎈ ⊞ ☀ ☾ ●) is now a real inline SVG.
// Stroke-based, 24×24, currentColor, round caps — inherits tone from its
// container. Icons are plain React nodes so they compose with <Chip>, links,
// and buttons without extra components.

import type { ReactNode } from "react";

function S({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="1em"
      height="1em"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable="false"
    >
      {children}
    </svg>
  );
}

/* ── Navigation ─────────────────────────────────────────────────────────── */

export function IconGrid() {
  return (
    <S>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" />
    </S>
  );
}

export function IconActivity() {
  return (
    <S>
      <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />
    </S>
  );
}

export function IconList() {
  return (
    <S>
      <path d="M8 6h13M8 12h13M8 18h13" />
      <circle cx="4" cy="6" r="0.9" fill="currentColor" />
      <circle cx="4" cy="12" r="0.9" fill="currentColor" />
      <circle cx="4" cy="18" r="0.9" fill="currentColor" />
    </S>
  );
}

export function IconBox() {
  return (
    <S>
      <path d="M21 8.2 12 3 3 8.2v7.6L12 21l9-5.2V8.2Z" />
      <path d="M3 8.2 12 13.4l9-5.2M12 13.4V21" />
    </S>
  );
}

export function IconClock() {
  return (
    <S>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </S>
  );
}

export function IconCompare() {
  return (
    <S>
      <circle cx="5" cy="7" r="2.6" />
      <circle cx="19" cy="17" r="2.6" />
      <path d="M7.6 7H16a2.5 2.5 0 0 1 2.5 2.5V14.4M16.4 17H8a2.5 2.5 0 0 1-2.5-2.5V9.6" />
    </S>
  );
}

export function IconSearch() {
  return (
    <S>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m21 21-4.8-4.8" />
    </S>
  );
}

export function IconFlag() {
  return (
    <S>
      <path d="M5 21V4" />
      <path d="M5 5h13l-3 4 3 4H5" />
    </S>
  );
}

export function IconGlobe() {
  return (
    <S>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17M12 3.5c2.7 2.3 4 5 4 8.5s-1.3 6.2-4 8.5c-2.7-2.3-4-5-4-8.5s1.3-6.2 4-8.5Z" />
    </S>
  );
}

export function IconStar() {
  return (
    <S>
      <path d="m12 3.5 2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 17.1l-5.2 2.5 1-5.8L3.5 9.7l5.9-.8L12 3.5Z" />
    </S>
  );
}

export function IconShield() {
  return (
    <S>
      <path d="M12 3 5 5.8v5.4c0 4.3 3 8 7 9.8 4-1.8 7-5.5 7-9.8V5.8L12 3Z" />
      <path d="m9 12 2 2 4-4.5" />
    </S>
  );
}

export function IconSliders() {
  return (
    <S>
      <path d="M4 7h10M18 7h2M4 17h4M12 17h8" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="8" cy="17" r="2" />
    </S>
  );
}

/* ── Actions / states ───────────────────────────────────────────────────── */

export function IconPlay({ filled = false }: { filled?: boolean }) {
  return (
    <S>
      <path d="M8 5.5v13l10-6.5L8 5.5Z" fill={filled ? "currentColor" : "none"} />
    </S>
  );
}

export function IconAlert() {
  return (
    <S>
      <path d="M12 4 2.8 19.5h18.4L12 4Z" />
      <path d="M12 10v4.2M12 17.4v.1" />
    </S>
  );
}

export function IconZap() {
  return (
    <S>
      <path d="M13 3 4.5 13.5H11L9.5 21 19 10.5h-6.5L13 3Z" />
    </S>
  );
}

export function IconCheck() {
  return (
    <S>
      <path d="m4.5 12.5 5 5 10-11" />
    </S>
  );
}

export function IconX() {
  return (
    <S>
      <path d="m6 6 12 12M18 6 6 18" />
    </S>
  );
}

export function IconChevronRight() {
  return (
    <S>
      <path d="m9 5.5 6.5 6.5L9 18.5" />
    </S>
  );
}

export function IconChevronDown() {
  return (
    <S>
      <path d="m5.5 9 6.5 6.5L18.5 9" />
    </S>
  );
}

export function IconChevronLeft() {
  return (
    <S>
      <path d="m15 5.5-6.5 6.5L15 18.5" />
    </S>
  );
}

export function IconArrowRight() {
  return (
    <S>
      <path d="M4 12h15M13.5 6 20 12l-6.5 6" />
    </S>
  );
}

export function IconDownload() {
  return (
    <S>
      <path d="M12 4v10m0 0 4-4m-4 4-4-4" />
      <path d="M4.5 18.5h15" />
    </S>
  );
}

export function IconExternal() {
  return (
    <S>
      <path d="M14 4.5h5.5V10M19.5 4.5 10.5 13.5" />
      <path d="M19.5 14v4a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V6A1.5 1.5 0 0 1 6 4.5h4" />
    </S>
  );
}

export function IconPlus() {
  return (
    <S>
      <path d="M12 5v14M5 12h14" />
    </S>
  );
}

export function IconCopy() {
  return (
    <S>
      <rect x="8.5" y="8.5" width="12" height="12" rx="2" />
      <path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5" />
    </S>
  );
}

export function IconNotes() {
  return (
    <S>
      <path d="M5 4.5h14v15H5z" />
      <path d="M8.5 9h7M8.5 12.5h7M8.5 16h4" />
    </S>
  );
}

export function IconBell() {
  return (
    <S>
      <path d="M6 9.5a6 6 0 0 1 12 0c0 4.5 2 5.5 2 5.5H4s2-1 2-5.5Z" />
      <path d="M10 19a2.2 2.2 0 0 0 4 0" />
    </S>
  );
}

export function IconEye() {
  return (
    <S>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="2.8" />
    </S>
  );
}

export function IconRefresh() {
  return (
    <S>
      <path d="M20 12a8 8 0 1 1-2.3-5.6" />
      <path d="M20 3.5V8h-4.5" />
    </S>
  );
}

export function IconFilter() {
  return (
    <S>
      <path d="M4 5.5h16l-6.5 7v5l-3 2v-7L4 5.5Z" />
    </S>
  );
}

/* ── Event types ────────────────────────────────────────────────────────── */

export function IconProcess() {
  return (
    <S>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M9 8.5v7M15 8.5v7" />
    </S>
  );
}

export function IconNetwork() {
  return (
    <S>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="3.5" />
      <path d="M12 3.5v5M12 15.5v5M3.5 12h5M15.5 12h5" />
    </S>
  );
}

export function IconFile() {
  return (
    <S>
      <path d="M6 3.5h8l4 4V20.5H6z" />
      <path d="M14 3.5v4h4M9.5 12h5M9.5 15.5h5" />
    </S>
  );
}

export function IconRegistry() {
  return (
    <S>
      <rect x="3.5" y="4.5" width="17" height="15" rx="2" />
      <path d="M7 9h3M7 13h3M7 17h3" />
      <circle cx="14.5" cy="9" r="0.8" fill="currentColor" />
      <circle cx="17" cy="13" r="0.8" fill="currentColor" />
      <circle cx="14.5" cy="17" r="0.8" fill="currentColor" />
    </S>
  );
}

/* ── OS / platform ──────────────────────────────────────────────────────── */

export function IconWindows() {
  return (
    <S>
      <path d="M3.5 6.5 10 5.7v6H3.5v-5.2ZM10 18.3l-6.5-.8v-5h6.5v5.8ZM11 5.5 20.5 4v7.7H11V5.5ZM11 18.5l9.5-1.3V12.3H11v6.2Z" />
    </S>
  );
}

export function IconLinux() {
  return (
    <S>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 4.5c2 1.5 2.5 4 2.5 6.5 0 2.5-.5 4.5-2.5 6-2-1.5-2.5-3.5-2.5-6 0-2.5.5-5 2.5-6.5Z" />
      <path d="M12 3v3M12 18v3" />
    </S>
  );
}

export function IconMac() {
  return (
    <S>
      <rect x="3" y="5" width="18" height="12.5" rx="2.5" />
      <path d="M9.5 20.5h5" />
    </S>
  );
}

/* ── Theme / chrome ─────────────────────────────────────────────────────── */

export function IconSun() {
  return (
    <S>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8" />
    </S>
  );
}

export function IconMoon() {
  return (
    <S>
      <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z" />
    </S>
  );
}

export function IconMenu() {
  return (
    <S>
      <path d="M4 6.5h16M4 12h16M4 17.5h16" />
    </S>
  );
}

export function IconCommand() {
  return (
    <S>
      <path d="M9 6a3 3 0 1 1 3 3H6a3 3 0 1 1 3-3Z" />
      <path d="M15 18a3 3 0 1 1-3-3h6a3 3 0 1 1-3 3Z" />
      <path d="M9 9v6M15 9v6" />
    </S>
  );
}

export function IconTerminal() {
  return (
    <S>
      <rect x="3" y="4.5" width="18" height="15" rx="2" />
      <path d="m7 9 3 3-3 3M13 15h4" />
    </S>
  );
}

export function IconTarget() {
  return (
    <S>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4.5" />
      <circle cx="12" cy="12" r="0.9" fill="currentColor" />
    </S>
  );
}

const ICONS = {
  grid: IconGrid,
  activity: IconActivity,
  list: IconList,
  box: IconBox,
  clock: IconClock,
  compare: IconCompare,
  search: IconSearch,
  flag: IconFlag,
  globe: IconGlobe,
  star: IconStar,
  shield: IconShield,
  sliders: IconSliders,
  play: IconPlay,
  alert: IconAlert,
  zap: IconZap,
  check: IconCheck,
  x: IconX,
  chevronRight: IconChevronRight,
  chevronDown: IconChevronDown,
  chevronLeft: IconChevronLeft,
  arrowRight: IconArrowRight,
  download: IconDownload,
  external: IconExternal,
  plus: IconPlus,
  copy: IconCopy,
  notes: IconNotes,
  bell: IconBell,
  eye: IconEye,
  refresh: IconRefresh,
  filter: IconFilter,
  process: IconProcess,
  network: IconNetwork,
  file: IconFile,
  registry: IconRegistry,
  windows: IconWindows,
  linux: IconLinux,
  mac: IconMac,
  sun: IconSun,
  moon: IconMoon,
  menu: IconMenu,
  command: IconCommand,
  terminal: IconTerminal,
  target: IconTarget,
  camera: IconCamera,
} as const;

/** Camera — detonation screenshot artifacts. */
export function IconCamera() {
  return (
    <S>
      <path d="M3 8a2 2 0 0 1 2-2h2l1.5-2h7L17 6h2a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8Z" />
      <circle cx="12" cy="13" r="3.5" />
    </S>
  );
}

export type IconName = keyof typeof ICONS;

/** Render an icon by name with an explicit size (em by default). */
export function Icon({ name, size = 16, className = "" }: { name: IconName; size?: number; className?: string }) {
  const Cmp = ICONS[name];
  return (
    <span className={`inline-flex shrink-0 ${className}`} style={{ fontSize: size }} aria-hidden>
      <Cmp />
    </span>
  );
}


