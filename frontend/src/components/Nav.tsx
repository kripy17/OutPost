// Nav — the left-rail workspace (the shell). A compact, modern desktop-app
// rail: grouped icon-tile navigation, with the live status cluster (backend
// pulse, session count, last finding), host OS, ⌘K, and theme toggle docked
// in the footer. No top bar — the rail carries all chrome.
//
// The rail can collapse to an icon-only activity bar (⌘B / the chevron at the
// top): width is driven by var(--rail-w) (64px collapsed), which main.tsx
// mirrors for the content offset, so the two never drift. Collapsed state
// persists (outpost-rail) and restores pre-paint via index.html.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  useEffect,
  useState,
  type FocusEvent,
  type MouseEvent,
} from "react";
import { NavLink } from "react-router-dom";
import CommandPalette from "./CommandPalette";
import { ThemePalettePopover } from "./ThemePalettePopover";
import { getHealth, getMeta, getPlatform, getRecentAlerts, getRuns } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { Icon, IconMenu, type IconName } from "./Icon";
import { platformIconName } from "./iconMeta";

const STORAGE_KEY = "outpost-theme-v2"; // v2 key: dark-first default (index.html pre-paint)
const RAIL_KEY = "outpost-rail"; // "collapsed" | "expanded" (pre-paint restored)

/** Rail tooltip wiring — hover/focus handlers attached to a rail element so
 *  the tooltip can be positioned from the element's own rect. */
type TipHandlers = (label: string) => {
  onMouseEnter: (e: MouseEvent<HTMLElement>) => void;
  onMouseLeave: () => void;
  onFocus: (e: FocusEvent<HTMLElement>) => void;
  onBlur: () => void;
};

/* ── Theme ─────────────────────────────────────────────────────────────── */

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    document.documentElement.dataset.theme === "dark" ? "dark" : "light",
  );

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem(STORAGE_KEY, next);
    if (next === "light") {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
    }
    setTheme(next);
  };

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY && (e.newValue === "light" || e.newValue === "dark")) setTheme(e.newValue);
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  return { theme, toggle };
}

/* ── Mark ──────────────────────────────────────────────────────────────── */

function Mark() {
  return (
    <svg viewBox="0 0 24 24" className="h-6 w-6" aria-hidden>
      <rect x="1.5" y="1.5" width="21" height="21" rx="6" fill="none" stroke="var(--border-strong)" strokeWidth="1.2" />
      <path d="M4 13h4l2-5 3 9 2-4h5" fill="none" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="20.5" cy="4.5" r="2.2" fill="var(--accent)" />
    </svg>
  );
}

/* ── Nav model ─────────────────────────────────────────────────────────── */

interface NavItem {
  to: string;
  label: string;
  iconName: IconName;
  end?: boolean;
}

const GROUPS: { label: string; links: NavItem[] }[] = [
  {
    label: "Live Operations",
    links: [
      { to: "/", label: "Overview", iconName: "grid", end: true },
      { to: "/events", label: "Host Forensics", iconName: "box" },
      { to: "/findings", label: "Findings Queue", iconName: "alert" },
      { to: "/investigations", label: "Case Files", iconName: "notes" },
      { to: "/agents", label: "Sensor Fleet", iconName: "terminal" },
    ],
  },
  {
    label: "Sandbox & Lab",
    links: [
      { to: "/samples", label: "Sample Vault", iconName: "box" },
      { to: "/monitor", label: "Simulation Lab", iconName: "activity" },
      { to: "/analysis", label: "Analysis Tasks", iconName: "process" },
    ],
  },
  {
    label: "Detection & Intel",
    links: [
      { to: "/rules", label: "Detection Rules", iconName: "shield" },
      { to: "/coverage", label: "ATT&CK Matrix", iconName: "target" },
      { to: "/campaigns", label: "Threat Campaigns", iconName: "flag" },
      { to: "/search", label: "Forensic Search", iconName: "search" },
      { to: "/watchlist", label: "IOC Watchlist", iconName: "star" },
      { to: "/footprint", label: "Digital Footprint", iconName: "globe" },
    ],
  },
  {
    label: "Administration",
    links: [
      { to: "/settings", label: "Settings", iconName: "sliders" },
      { to: "/audit", label: "Audit Log", iconName: "file" },
    ],
  },
];

/* ── Status cluster — docked in the rail footer ────────────────────────── */

function StatusCluster({
  compact = false,
  collapsed = false,
  makeTip,
}: {
  compact?: boolean;
  collapsed?: boolean;
  makeTip?: TipHandlers;
}) {
  const queryClient = useQueryClient();
  useEventStream(() => {
    void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["runs"] });
  });

  const health = useQuery({ queryKey: ["health"], queryFn: getHealth, refetchInterval: 5_000 });
  const latest = useQuery({ queryKey: ["statusbar", "latest-finding"], queryFn: () => getRecentAlerts(1, "real"), refetchInterval: 10_000 });
  // The session count mirrors the History page's toggles (synthetic + soak):
  // the status bar reads as real telemetry first, matching the archive
  // default. The 10 s poll picks up toggle changes within a few seconds.
  const runs = useQuery({
    queryKey: ["statusbar", "runs", "soak", localStorage.getItem("outpost-history-soak") === "1"],
    queryFn: () => getRuns({
      include_synthetic: localStorage.getItem("outpost-history-synthetic") === "1" ? undefined : false,
      include_soak: localStorage.getItem("outpost-history-soak") === "1" ? undefined : false,
    }),
    refetchInterval: 10_000,
  });
  const meta = useQuery({ queryKey: ["meta"], queryFn: getMeta, staleTime: 60_000 });

  const online = health.data === true;
  const offline = health.data === false || health.isError;
  const latestTime = latest.data?.[0] ? `${latest.data[0].triggered_at.slice(11, 19)} UTC` : null;
  const count = runs.isLoading ? "…" : runs.data?.length ?? "—";
  const demo = meta.data?.demo_mode === true;

  // Icon-only rail: a single live pulse dot, summary in the tooltip.
  if (collapsed) {
    const summary = `${online ? "Online" : offline ? "Offline" : "Connecting"} · ${count} sessions${
      demo ? " · demo data" : ""
    }${latestTime ? ` · latest finding ${latestTime}` : ""}`;
    return (
      <span
        {...(makeTip ? makeTip(summary) : {})}
        className="flex h-8 w-8 items-center justify-center rounded-lg border border-border-subtle bg-bg-elevated/30"
        role="status"
        aria-label={summary}
      >
        <span className="relative flex h-2 w-2">
          {online && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/50" />}
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${online ? "bg-risk-clean" : offline ? "bg-risk-malicious" : "bg-text-faint"}`}
          />
        </span>
      </span>
    );
  }

  return (
    <div className={`text-[11px] ${compact ? "flex items-center gap-1.5" : "space-y-1.5"}`}>
      <span className="flex items-center gap-1.5 font-medium">
        <span className="relative flex h-2 w-2">
          {online && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/50" />}
          <span
            className={`relative inline-flex h-2 w-2 rounded-full ${online ? "bg-risk-clean" : offline ? "bg-risk-malicious" : "bg-text-faint"}`}
          />
        </span>
        <span className={online ? "text-risk-clean" : offline ? "text-risk-malicious" : "text-text-muted"}>
          {online ? "Online" : offline ? "Offline" : "Connecting"}
        </span>
        <span className="ml-auto flex items-baseline gap-1 text-text-faint">
          <span className="font-semibold tabular-nums text-text-primary">{count}</span> sessions
        </span>
      </span>
      {demo && (
        <span
          className="inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-1.5 py-px font-mono text-[9px] uppercase tracking-wide text-accent"
          title="The store contains seeded demo data — see Settings → Start fresh to clear it"
        >
          demo data
        </span>
      )}
      {latestTime && (
        <span className="flex items-center gap-1.5 text-text-faint">
          <Icon name="zap" size={11} className="text-risk-suspicious" />
          {latestTime}
        </span>
      )}
    </div>
  );
}

function HostOsChip({
  collapsed = false,
  makeTip,
}: {
  collapsed?: boolean;
  makeTip?: TipHandlers;
}) {
  const { data } = useQuery({ queryKey: ["platform"], queryFn: getPlatform, staleTime: Infinity });
  if (!data) return null;
  const label = `Host OS auto-detected: ${data.name} ${data.release} (${data.machine}) · ${data.collector}`;

  if (collapsed) {
    return (
      <span
        {...(makeTip ? makeTip(label) : {})}
        role="img"
        className="flex h-8 w-8 items-center justify-center rounded-lg border border-border-subtle bg-bg-surface"
        aria-label={label}
      >
        <Icon name={platformIconName(data.os)} size={15} className={data.os === "windows" ? "text-accent" : "text-risk-clean"} />
      </span>
    );
  }

  return (
    <span
      className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-2 py-1.5 text-[11px] font-medium text-text-muted"
      title={label}
    >
      <Icon name={platformIconName(data.os)} size={13} className={data.os === "windows" ? "text-accent" : "text-risk-clean"} />
      <span className="capitalize">{data.os}</span>
      <span className="ml-auto font-mono text-[10px] text-text-faint">{data.collector}</span>
    </span>
  );
}


function CommandButton({
  onClick,
  collapsed = false,
  makeTip,
}: {
  onClick: () => void;
  collapsed?: boolean;
  makeTip?: TipHandlers;
}) {
  if (collapsed) {
    return (
      <button
        onClick={onClick}
        {...(makeTip ? makeTip("Jump to… (⌘K)") : {})}
        className="press flex h-9 w-full items-center justify-center rounded-lg border border-border-subtle bg-bg-surface text-text-muted transition-colors duration-150 hover:border-accent/50 hover:text-text-primary"
        aria-label="Open command palette"
      >
        <Icon name="search" size={14} />
      </button>
    );
  }
  return (
    <button
      onClick={onClick}
      className="press flex h-9 w-full items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-2.5 text-[12px] text-text-faint transition-colors duration-150 hover:border-accent/50 hover:text-text-primary"
      aria-label="Open command palette"
    >
      <Icon name="search" size={13} />
      <span className="flex-1 text-left">Jump to…</span>
      <kbd className="rounded border border-border-subtle bg-bg-elevated px-1 font-mono text-[10px] text-text-muted">⌘K</kbd>
    </button>
  );
}

/* ── Mobile header ─────────────────────────────────────────────────────── */

function MobileMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 lg:hidden">
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} aria-hidden />
      <div className="animate-slide-in absolute inset-y-0 left-0 w-72 max-w-[85vw] overflow-y-auto border-r border-border-subtle bg-bg-surface p-4">
        <div className="mb-4 flex items-center justify-between">
          <span className="flex items-center gap-2 font-bold text-text-primary">
            <Mark /> OutPost
          </span>
          <button onClick={onClose} aria-label="Close menu" className="flex h-8 w-8 items-center justify-center rounded-lg text-text-muted hover:bg-bg-elevated">
            <Icon name="x" size={16} />
          </button>
        </div>
        <nav className="space-y-5" aria-label="Mobile">
          {GROUPS.map((g) => (
            <div key={g.label}>
              <p className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-text-faint">{g.label}</p>
              <div className="space-y-0.5">
                {g.links.map((l) => (
                  <NavLink
                    key={l.to}
                    to={l.to}
                    end={l.end}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm ${
                        isActive ? "bg-accent/10 font-semibold text-accent" : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                      }`
                    }
                  >
                    <Icon name={l.iconName} size={16} />
                    {l.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
      </div>
    </div>
  );
}

/* ── App ───────────────────────────────────────────────────────────────── */

interface RailTip {
  label: string;
  left: number;
  top: number;
}

export default function Nav() {
  const { theme, toggle } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Opening a modal (⌘K palette / mobile menu) must dismiss the rail tooltip,
  // or it would keep floating above the overlay (z-70 > z-50).
  const openPalette = () => {
    setTip(null);
    setPaletteOpen(true);
  };
  const openMobileMenu = () => {
    setTip(null);
    setMobileOpen(true);
  };
  const [railCollapsed, setRailCollapsed] = useState(
    () => document.documentElement.dataset.rail === "collapsed",
  );
  const [tip, setTip] = useState<RailTip | null>(null);

  const toggleRail = () => {
    const next = document.documentElement.dataset.rail !== "collapsed";
    document.documentElement.dataset.rail = next ? "collapsed" : "expanded";
    try {
      localStorage.setItem(RAIL_KEY, next ? "collapsed" : "expanded");
    } catch {
      /* storage unavailable — the attribute still applies for this session */
    }
    setRailCollapsed(next);
  };

  // Tooltip follow: elements inside the rail report their own rects (the rail
  // is fixed at left:0, so viewport coords line up). Rendered at the Nav root
  // so the fixed tooltip is never clipped by the nav's overflow.
  const makeTip = (label: string) => ({
    onMouseEnter: (e: MouseEvent<HTMLElement>) => {
      const r = e.currentTarget.getBoundingClientRect();
      setTip({ label, left: r.right + 10, top: r.top + r.height / 2 });
    },
    onMouseLeave: () => setTip(null),
    onFocus: (e: FocusEvent<HTMLElement>) => {
      const r = e.currentTarget.getBoundingClientRect();
      setTip({ label, left: r.right + 10, top: r.top + r.height / 2 });
    },
    onBlur: () => setTip(null),
  });

  // ⌘K / Ctrl+K opens the palette; ⌘B / Ctrl+B collapses the rail (skipped
  // while typing so it never fights the browser or form fields).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey)) return;
      const k = e.key.toLowerCase();
      if (k === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (k === "b") {
        const t = e.target as HTMLElement | null;
        if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
        e.preventDefault();
        toggleRail();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      {/* Desktop — left rail (collapsible to an icon-only activity bar) */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 hidden w-[var(--rail-w)] flex-col border-r border-border-subtle bg-bg-surface/70 backdrop-blur-md transition-[width] duration-200 ease-out lg:flex ${
          railCollapsed ? "items-center" : ""
        }`}
      >
        <div className={`flex w-full items-center gap-2.5 pb-2 ${railCollapsed ? "flex-col gap-1.5 px-0 pb-0 pt-4" : "px-4 pt-5"}`}>
          <Mark />
          {!railCollapsed && <span className="text-[15px] font-bold tracking-tight text-text-primary">OutPost</span>}
          <button
            onClick={toggleRail}
            aria-label={railCollapsed ? "Expand rail" : "Collapse rail"}
            aria-pressed={railCollapsed}
            title={`${railCollapsed ? "Expand" : "Collapse"} rail (⌘B)`}
            className={`press flex h-7 w-7 items-center justify-center rounded-lg text-text-faint transition-colors duration-150 hover:bg-bg-elevated hover:text-text-primary ${
              railCollapsed ? "" : "ml-auto"
            }`}
          >
            <Icon name={railCollapsed ? "chevronRight" : "chevronLeft"} size={14} />
          </button>
        </div>

        <nav
          className={`mt-2 flex-1 overflow-y-auto pb-4 ${
            railCollapsed ? "w-full space-y-1 px-2" : "space-y-5 px-3"
          }`}
          aria-label="Primary"
        >
          {GROUPS.map((group, i) => (
            <div key={group.label} className={railCollapsed && i > 0 ? "border-t border-border-subtle/70 pt-1.5" : ""}>
              {!railCollapsed && (
                <p className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-text-faint">{group.label}</p>
              )}
              <div className="space-y-0.5">
                {group.links.map((link) => (
                  <NavLink
                    key={link.to}
                    to={link.to}
                    end={link.end}
                    aria-label={railCollapsed ? link.label : undefined}
                    {...(railCollapsed ? makeTip(link.label) : {})}
                    className={({ isActive }) =>
                      `relative flex items-center gap-2.5 rounded-lg transition-colors duration-150 ${railCollapsed ? "justify-center px-0 py-2" : "px-2 py-1.5 text-[13px]"} ${
                        isActive
                          ? "bg-accent/15 font-semibold text-accent"
                          : "font-medium text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {/* Collapsed: a violet indicator bar marks the active page. */}
                        {railCollapsed && isActive && (
                          <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full bg-accent" aria-hidden />
                        )}
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center">
                          <Icon name={link.iconName} size={railCollapsed ? 18 : 16} />
                        </span>
                        {!railCollapsed && link.label}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <footer className={`w-full border-t border-border-subtle py-3 ${railCollapsed ? "flex flex-col items-center gap-2 px-2" : "space-y-2 px-3"}`}>
          <CommandButton onClick={openPalette} collapsed={railCollapsed} makeTip={railCollapsed ? makeTip : undefined} />
          <HostOsChip collapsed={railCollapsed} makeTip={railCollapsed ? makeTip : undefined} />
          <div className={`flex items-center gap-2 rounded-lg border border-border-subtle ${railCollapsed ? "flex-col bg-bg-elevated/30 p-1.5" : "bg-bg-elevated/30 px-2.5 py-2"}`}>
            <StatusCluster collapsed={railCollapsed} makeTip={railCollapsed ? makeTip : undefined} />
            <ThemePalettePopover theme={theme} toggleTheme={toggle} />
          </div>
        </footer>
      </aside>

      {/* Mobile — slim header */}
      <header className="topbar lg:hidden">
        <div className="flex items-center gap-3 px-4 py-2.5">
          <button
            className="press -ml-1 flex h-9 w-9 items-center justify-center rounded-lg text-text-muted hover:bg-bg-elevated"
            onClick={openMobileMenu}
            aria-label="Open navigation menu"
          >
            <IconMenu />
          </button>
          <span className="flex items-center gap-2 font-bold text-text-primary">
            <Mark /> OutPost
          </span>
          <div className="ml-auto flex items-center gap-2">
            <span className="flex items-center gap-1 text-[11px] text-text-faint">
              <StatusCluster compact />
            </span>
            <ThemePalettePopover theme={theme} toggleTheme={toggle} />
          </div>
        </div>
      </header>

      <MobileMenu open={mobileOpen} onClose={() => setMobileOpen(false)} />
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}

      {/* Positioned rail tooltip — lives at the root so nothing clips it. */}
      {tip && (
        <div className="rail-tip" style={{ left: tip.left, top: tip.top }} role="tooltip">
          {tip.label}
        </div>
      )}
    </>
  );
}
