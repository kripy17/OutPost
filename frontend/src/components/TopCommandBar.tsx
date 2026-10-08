import { useState, useRef, useEffect } from "react";
import { useLocation, Link, useNavigate } from "react-router-dom";
import { Icon } from "./Icon";
import { useSocTimeRange, SOC_TIME_PRESETS } from "../lib/useSocTimeRange";
import { useQuery } from "@tanstack/react-query";
import { getAlertQueue, getAgents } from "../lib/api";

interface RouteMeta {
  pillar: string;
  pillarHref?: string;
  name: string;
}

function resolveRouteMeta(pathname: string): RouteMeta {
  if (pathname === "/") return { pillar: "Live Operations", name: "Overview" };
  if (pathname === "/events") return { pillar: "Live Operations", name: "Host Forensics & Pulse" };
  if (pathname === "/findings") return { pillar: "Live Operations", name: "Incident Findings" };
  if (pathname === "/investigations") return { pillar: "Live Operations", name: "Incident Cases" };
  if (pathname.startsWith("/investigations/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Incident Cases",
      pillarHref: "/investigations",
      name: `Case Dossier (${id.slice(0, 8)})`,
    };
  }
  if (pathname === "/agents") return { pillar: "Endpoint Fleet", name: "Sensor Agents" };
  if (pathname.startsWith("/hosts/")) {
    const host = decodeURIComponent(pathname.split("/")[2] || "");
    return {
      pillar: "Endpoint Fleet",
      pillarHref: "/agents",
      name: `Host (${host.slice(0, 16)})`,
    };
  }
  if (pathname === "/footprint") return { pillar: "Threat Intelligence", name: "Digital Footprint" };
  if (pathname === "/watchlist") return { pillar: "Threat Intelligence", name: "Threat Watchlist" };

  if (pathname === "/samples") return { pillar: "Malware Analysis", name: "Malware Vault & Triage" };
  if (pathname.startsWith("/samples/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Malware Analysis",
      pillarHref: "/samples",
      name: `Binary Triage (${id.slice(0, 8)})`,
    };
  }
  if (pathname === "/monitor") return { pillar: "Malware Analysis", name: "Simulation Lab" };
  if (pathname === "/history") return { pillar: "Malware Analysis", name: "Detonation Runs" };
  if (pathname.startsWith("/runs/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Malware Analysis",
      pillarHref: "/history",
      name: `Telemetry Run (${id.slice(0, 8)})`,
    };
  }
  if (pathname === "/analysis") return { pillar: "Malware Analysis", name: "Static Analysis" };
  if (pathname.startsWith("/analysis/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Malware Analysis",
      pillarHref: "/analysis",
      name: `Report (${id.slice(0, 8)})`,
    };
  }

  if (pathname === "/rules") return { pillar: "Detection & Intel", name: "Detection Rules" };
  if (pathname === "/coverage") return { pillar: "Detection & Intel", name: "ATT&CK Coverage" };
  if (pathname === "/campaigns") return { pillar: "Detection & Intel", name: "Threat Campaigns" };

  if (pathname === "/audit") return { pillar: "Administration", name: "Security Audit" };
  if (pathname === "/settings") return { pillar: "Administration", name: "Settings & Air-Gap" };
  if (pathname === "/search") return { pillar: "Intelligence", name: "Telemetry Search" };
  if (pathname === "/welcome") return { pillar: "Onboarding", name: "Welcome" };
  if (pathname === "/login") return { pillar: "Authentication", name: "Operator Sign-In" };

  return { pillar: "Console", name: "Dashboard" };
}

export default function TopCommandBar() {
  const location = useLocation();
  const navigate = useNavigate();
  const meta = resolveRouteMeta(location.pathname);
  const { range, setRange, preset } = useSocTimeRange();

  const [timeMenuOpen, setTimeMenuOpen] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const timeMenuRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Live alert queue counts for quick status HUD
  const { data: alertQueue } = useQuery({
    queryKey: ["alerts", "queue"],
    queryFn: () => getAlertQueue({ status: "open", limit: 50 }),
    refetchInterval: 10_000,
  });

  const { data: fleet } = useQuery({
    queryKey: ["agents"],
    queryFn: () => getAgents(),
    refetchInterval: 15_000,
  });

  const rawAlerts = Array.isArray(alertQueue) ? alertQueue : (alertQueue?.alerts ?? []);
  const criticalCount = rawAlerts.filter((a) => a.severity === "malicious" && (a.status === "open" || !a.status)).length;
  const highCount = rawAlerts.filter((a) => a.severity === "suspicious" && (a.status === "open" || !a.status)).length;
  const onlineHosts = (fleet?.agents ?? []).filter((a) => a.online).length;
  const totalHosts = (fleet?.agents ?? []).length;

  // Global keyboard shortcuts: "/" focuses search, "Esc" dismisses popovers
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        if (e.key === "Escape") {
          target.blur();
          setTimeMenuOpen(false);
        }
        return;
      }

      if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (e.key === "Escape") {
        setTimeMenuOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Click-away listener for time menu
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (timeMenuRef.current && !timeMenuRef.current.contains(e.target as Node)) {
        setTimeMenuOpen(false);
      }
    };
    if (timeMenuOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [timeMenuOpen]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchInput.trim()) return;
    navigate(`/search?mode=global&q=${encodeURIComponent(searchInput.trim())}`);
  };

  const openPalette = () => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }));
  };

  const openShortcuts = () => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "?", bubbles: true }));
  };

  return (
    <header className="sticky top-0 z-20 hidden h-11 items-center justify-between border-b border-border-subtle bg-bg-surface/90 px-4 backdrop-blur-xl lg:flex shadow-xs font-sans text-xs">
      {/* Left: Breadcrumbs navigation and Scope Indicator */}
      <nav aria-label="Breadcrumbs" className="flex items-center gap-2 text-xs min-w-0">
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="h-2 w-2 rounded-full bg-accent" />
          <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-primary">OutPost</span>
        </div>
        <Icon name="chevronRight" size={11} className="text-text-faint/60 shrink-0" />

        {meta.pillarHref ? (
          <Link
            to={meta.pillarHref}
            className="rounded px-1.5 py-0.5 font-medium text-text-muted transition-colors hover:bg-bg-elevated hover:text-text-primary shrink-0"
          >
            {meta.pillar}
          </Link>
        ) : (
          <span className="font-medium text-text-muted shrink-0">{meta.pillar}</span>
        )}

        <Icon name="chevronRight" size={11} className="text-text-faint/60 shrink-0" />
        <span className="font-bold text-text-primary truncate" title={meta.name}>{meta.name}</span>

        {totalHosts > 0 && (
          <span className="ml-2 hidden xl:inline-flex items-center gap-1 rounded bg-bg-base border border-border-subtle px-1.5 py-0.2 text-[10px] text-text-faint">
            <span className="h-1.5 w-1.5 rounded-full bg-risk-clean" />
            <span>{onlineHosts}/{totalHosts} Hosts</span>
          </span>
        )}
      </nav>

      {/* Center: Global Telemetry Search Input */}
      <div className="flex-1 max-w-md mx-4 hidden md:block">
        <form onSubmit={handleSearchSubmit} className="relative">
          <Icon name="search" size={11} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            ref={searchInputRef}
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search events, IPs, hashes, PIDs across fleet... (Press '/' to focus)"
            className="w-full rounded-md border border-border-subtle bg-bg-base py-1 pl-7 pr-6 text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none transition"
          />
          <kbd className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 rounded border border-border-subtle/80 bg-bg-surface px-1 text-[9px] text-text-faint">
            /
          </kbd>
        </form>
      </div>

      {/* Right: Universal SOC Time-Range Picker, Alert Counters & Commands */}
      <div className="flex items-center gap-2.5 shrink-0">
        {/* Universal Time-Range Dropdown */}
        <div className="relative" ref={timeMenuRef}>
          <button
            onClick={() => setTimeMenuOpen(!timeMenuOpen)}
            className="press flex h-7 items-center gap-1.5 rounded-md border border-border-subtle bg-bg-base px-2 text-[11px] font-medium text-text-primary hover:border-accent/50 hover:bg-bg-elevated/40 transition"
            title="Universal Investigation Time Window"
            aria-label="Universal Time Range"
          >
            <Icon name="clock" size={11} className="text-accent" />
            <span className="font-mono text-[10px] uppercase font-bold">{preset.label}</span>
            <Icon name="chevronDown" size={9} className="text-text-faint" />
          </button>

          {timeMenuOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-52 rounded-xl border border-border-subtle bg-bg-surface p-1 shadow-2xl z-50 animate-fade-in font-mono text-xs">
              <div className="px-2.5 py-1 text-[10px] uppercase font-bold text-text-faint border-b border-border-subtle/50 mb-1">
                Investigation Window
              </div>
              {SOC_TIME_PRESETS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => {
                    setRange(p.id);
                    setTimeMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between rounded-lg px-2.5 py-1.5 text-left text-[11px] transition ${
                    range === p.id
                      ? "bg-accent/15 font-bold text-accent"
                      : "text-text-muted hover:bg-bg-elevated/60 hover:text-text-primary"
                  }`}
                >
                  <span>{p.label}</span>
                  {range === p.id && <span className="text-accent">✓</span>}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Live Stream Pulse Badge */}
        <div
          className="flex items-center gap-1.5 rounded-md border border-risk-clean/30 bg-risk-clean/10 px-2 py-1 text-[10px] font-bold text-risk-clean"
          title="Telemetry Engine is actively processing events"
        >
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/50" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-risk-clean" />
          </span>
          <span className="uppercase tracking-wider">Live Stream</span>
        </div>

        {/* Unresolved Alert HUD Pill */}
        {(criticalCount > 0 || highCount > 0) && (
          <Link
            to="/findings"
            className="hidden sm:inline-flex items-center gap-1.5 rounded-md border border-risk-malicious/40 bg-risk-malicious/10 px-2 py-1 text-[10px] font-bold text-risk-malicious hover:bg-risk-malicious/20 transition"
            title={`${criticalCount} Critical, ${highCount} High open security findings`}
          >
            <span>{criticalCount > 0 ? `${criticalCount} Crit` : ""}</span>
            {criticalCount > 0 && highCount > 0 && <span>·</span>}
            <span>{highCount > 0 ? `${highCount} High` : ""}</span>
          </Link>
        )}

        {/* Global Shortcuts Trigger */}
        <button
          onClick={openShortcuts}
          className="press flex h-7 items-center gap-1 rounded-md border border-border-subtle bg-bg-base px-1.5 text-[10px] font-medium text-text-muted hover:border-accent/40 hover:text-text-primary transition"
          title="View Keyboard Shortcuts (?)"
          aria-label="Keyboard Shortcuts"
        >
          <kbd className="rounded bg-bg-surface px-1 font-mono text-[9px] font-bold text-text-faint border border-border-subtle">?</kbd>
        </button>

        {/* ⌘K Command Palette Quick Launcher */}
        <button
          onClick={openPalette}
          className="press flex h-7 items-center gap-1.5 rounded-md border border-border-subtle bg-bg-base px-2 text-[10px] font-medium text-text-muted hover:border-accent/50 hover:text-text-primary transition"
          title="Quick Jump / Action Search (⌘K)"
          aria-label="Command Palette"
        >
          <Icon name="search" size={10} className="text-text-faint" />
          <kbd className="rounded border border-border-subtle bg-bg-surface px-1 py-0.2 font-mono text-[9px] font-bold text-text-faint">⌘K</kbd>
        </button>
      </div>
    </header>
  );
}
