import { useEffect, useState } from "react";
import { useLocation, Link } from "react-router-dom";
import { Icon } from "./Icon";

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
  if (pathname === "/footprint") return { pillar: "Endpoint Fleet", name: "Digital Footprint" };
  if (pathname === "/watchlist") return { pillar: "Endpoint Fleet", name: "Threat Watchlist" };

  if (pathname === "/samples") return { pillar: "Malware & Lab", name: "Sample Vault" };
  if (pathname.startsWith("/samples/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Sample Vault",
      pillarHref: "/samples",
      name: `Sample Triage (${id.slice(0, 8)})`,
    };
  }
  if (pathname === "/monitor") return { pillar: "Malware & Lab", name: "Simulation Lab" };
  if (pathname === "/history") return { pillar: "Malware & Lab", name: "Detonation Runs" };
  if (pathname.startsWith("/runs/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Detonation Runs",
      pillarHref: "/history",
      name: `Telemetry Run (${id.slice(0, 8)})`,
    };
  }
  if (pathname === "/analysis") return { pillar: "Malware & Lab", name: "Static Analysis" };
  if (pathname.startsWith("/analysis/")) {
    const id = pathname.split("/")[2] || "";
    return {
      pillar: "Static Analysis",
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
  const meta = resolveRouteMeta(location.pathname);

  // Live ticking UTC military clock
  const [utcTime, setUtcTime] = useState(() => new Date().toISOString().slice(11, 19));
  useEffect(() => {
    const timer = setInterval(() => {
      setUtcTime(new Date().toISOString().slice(11, 19));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const openPalette = () => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }));
  };

  const openShortcuts = () => {
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "?", bubbles: true }));
  };

  return (
    <header className="sticky top-0 z-20 hidden h-11 items-center justify-between border-b border-white/[0.07] bg-bg-surface/85 px-4 backdrop-blur-xl lg:flex shadow-[0_1px_12px_rgba(0,0,0,0.4)]">
      {/* Left: Breadcrumbs navigation with tactical styling */}
      <nav aria-label="Breadcrumbs" className="flex items-center gap-2 text-xs">
        <div className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_6px_var(--accent)]" />
          <span className="font-mono text-[11px] font-bold uppercase tracking-widest text-text-primary">OutPost</span>
        </div>
        <Icon name="chevronRight" size={11} className="text-text-faint/60" />

        {meta.pillarHref ? (
          <Link
            to={meta.pillarHref}
            className="rounded px-1.5 py-0.5 font-medium text-text-muted transition-colors hover:bg-bg-elevated hover:text-text-primary"
          >
            {meta.pillar}
          </Link>
        ) : (
          <span className="font-medium text-text-muted">{meta.pillar}</span>
        )}

        <Icon name="chevronRight" size={11} className="text-text-faint/60" />
        <span className="font-semibold text-text-primary">{meta.name}</span>
      </nav>

      {/* Right: Military UTC Clock, SOC Telemetry & Command Triggers */}
      <div className="flex items-center gap-3">
        {/* Military UTC Clock */}
        <div
          className="hidden xl:flex items-center gap-1.5 rounded border border-border-subtle bg-bg-base/60 px-2.5 py-0.5 font-mono text-[11px] text-text-muted"
          title="Current Zulu (UTC) Military Operational Time"
        >
          <span className="text-text-faint font-semibold">UTC</span>
          <span className="font-bold tabular-nums text-text-primary">{utcTime}</span>
        </div>

        {/* Stream Live Pulse */}
        <div
          className="flex items-center gap-1.5 rounded-full border border-risk-clean/30 bg-risk-clean/10 px-2.5 py-0.5 text-[11px] font-medium text-risk-clean"
          title="Telemetry Engine is actively processing events"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/50" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-risk-clean" />
          </span>
          <span className="font-mono text-[10px] tracking-wider uppercase font-bold">Live Stream</span>
        </div>

        {/* Global Shortcuts Trigger */}
        <button
          onClick={openShortcuts}
          className="press flex h-7 items-center gap-1.5 rounded-md border border-border-subtle bg-bg-elevated/50 px-2 text-[11px] font-medium text-text-muted transition-colors hover:border-accent/40 hover:text-text-primary"
          title="View Keyboard Shortcuts (?)"
          aria-label="Keyboard Shortcuts"
        >
          <kbd className="rounded bg-bg-surface px-1 font-mono text-[10px] font-bold text-text-faint border border-border-subtle">?</kbd>
          <span className="hidden xl:inline">Shortcuts</span>
        </button>

        {/* ⌘K Command Palette Quick Launcher */}
        <button
          onClick={openPalette}
          className="press flex h-7 items-center gap-1.5 rounded-md border border-border-subtle bg-bg-elevated/50 px-2.5 text-[11px] font-medium text-text-muted transition-colors hover:border-accent/50 hover:text-text-primary"
          title="Quick Jump / Action Search (⌘K)"
          aria-label="Command Palette"
        >
          <Icon name="search" size={12} className="text-text-faint" />
          <span>Jump</span>
          <kbd className="rounded border border-border-subtle/90 bg-bg-surface px-1.5 py-0.5 font-mono text-[9px] font-bold text-text-faint shadow-xs">⌘K</kbd>
        </button>
      </div>
    </header>
  );
}

