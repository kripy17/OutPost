import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import {
  controlProcessXRay,
  getBehavioralExplanations,
  getEvents,
  getForensicCapsule,
  getHostXRaySnapshot,
  getNetworkMatrix,
  getProcessTree,
  getXRayFullTargetDossier,
} from "../lib/api";
import type { HostPulseMetrics, XRayProcessItem, XRaySocketItem } from "../types";
import { parsePids } from "./eventsHelpers";

function formatUptime(seconds?: number): string {
  if (!seconds || seconds <= 0) return "Just started";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m ${seconds % 60}s`;
}

function platformIcon(platformName?: string): "linux" | "mac" | "windows" | "box" {
  const p = (platformName || "").toLowerCase();
  if (p.includes("linux") || p.includes("arch") || p.includes("ubuntu") || p.includes("debian")) return "linux";
  if (p.includes("darwin") || p.includes("mac") || p.includes("apple")) return "mac";
  if (p.includes("win")) return "windows";
  return "box";
}

type SortField = "cpu" | "memory" | "pid" | "name" | "user";

export default function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();

  // URL search query / pid sync
  const queryParam = searchParams.get("q") || "";
  const pidParam = searchParams.get("pid") || "";
  const initialPids = useMemo(() => parsePids(pidParam), [pidParam]);

  // Live polling controls
  const [isLive, setIsLive] = useState(true);
  const [pollInterval, setPollInterval] = useState<number>(2000);
  const [searchFilter, setSearchFilter] = useState(queryParam || (initialPids.length > 0 ? String(initialPids[0]) : ""));
  const [selectedQuickFilter, setSelectedQuickFilter] = useState<"all" | "high_cpu" | "high_mem" | "unmanaged" | "net">("all");

  // Decks: processes | tree | network | insights | host_info
  const [activeDeck, setActiveDeck] = useState<"processes" | "tree" | "network" | "insights" | "host_info">("processes");

  // Process sorting
  const [sortField, setSortField] = useState<SortField>("cpu");
  const [sortAsc, setSortAsc] = useState(false);

  // Deep Process Inspection Drawer
  const [inspectPid, setInspectPid] = useState<number | null>(() => (initialPids.length > 0 ? initialPids[0] : null));
  const [dossier, setDossier] = useState<any>(null);
  const [dossierLoading, setDossierLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Fetch real Host X-Ray snapshot (metrics, processes, sockets)
  const {
    data: snapshot,
    isLoading: isSnapshotLoading,
    isFetching: isSnapshotFetching,
    refetch: refetchSnapshot,
  } = useQuery({
    queryKey: ["host", "xray", "snapshot"],
    queryFn: getHostXRaySnapshot,
    refetchInterval: isLive ? pollInterval : false,
    staleTime: pollInterval / 2,
  });

  // Fetch process tree
  const { data: treeData } = useQuery({
    queryKey: ["host", "xray", "tree"],
    queryFn: getProcessTree,
    enabled: activeDeck === "tree",
    refetchInterval: isLive ? pollInterval * 2 : false,
  });

  // Fetch network matrix
  const { data: networkMatrix } = useQuery({
    queryKey: ["host", "xray", "network"],
    queryFn: getNetworkMatrix,
    enabled: activeDeck === "network",
    refetchInterval: isLive ? pollInterval * 2 : false,
  });

  // Fetch behavioral insights
  const { data: explanations } = useQuery({
    queryKey: ["host", "xray", "explanations"],
    queryFn: getBehavioralExplanations,
    enabled: activeDeck === "insights",
    refetchInterval: isLive ? pollInterval * 3 : false,
  });

  // Optional fleet event telemetry stream for multi-host correlation
  const { data: fleetEventsData } = useQuery({
    queryKey: ["events", "fleet_summary"],
    queryFn: () => getEvents({ limit: 10 }),
    retry: false,
  });

  // Load detailed target dossier when inspectPid is set
  useEffect(() => {
    if (!inspectPid) {
      setDossier(null);
      return;
    }
    let isCancelled = false;
    async function loadDossier() {
      setDossierLoading(true);
      setActionMessage(null);
      try {
        const data = await getXRayFullTargetDossier(inspectPid!);
        if (!isCancelled) {
          setDossier(data);
        }
      } catch (err: any) {
        if (!isCancelled) {
          setActionMessage(`Failed to inspect PID ${inspectPid}: ${err?.message || "Process terminated"}`);
        }
      } finally {
        if (!isCancelled) setDossierLoading(false);
      }
    }
    loadDossier();
    return () => {
      isCancelled = true;
    };
  }, [inspectPid]);

  // Handle process actions: terminate, kill, freeze, resume
  const handleProcessAction = async (pid: number, action: "terminate" | "kill" | "freeze" | "resume") => {
    try {
      setActionMessage(`Sending ${action.toUpperCase()} signal to PID ${pid}...`);
      const res = await controlProcessXRay(pid, action);
      setActionMessage(res.message);
      void queryClient.invalidateQueries({ queryKey: ["host", "xray"] });
      // Reload current dossier if open
      if (inspectPid === pid) {
        const updated = await getXRayFullTargetDossier(pid);
        setDossier(updated);
      }
    } catch (err: any) {
      setActionMessage(`Signal failed: ${err?.message || "Operation denied"}`);
    }
  };

  const handleExportCapsule = async (pid: number) => {
    try {
      setActionMessage(`Exporting forensic capsule for PID ${pid}...`);
      const capsule = await getForensicCapsule(pid);
      const blob = new Blob([JSON.stringify(capsule, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `outpost-xray-capsule-pid-${pid}.xray.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionMessage(`Capsule downloaded: outpost-xray-capsule-pid-${pid}.xray.json`);
    } catch (err: any) {
      setActionMessage(`Export error: ${err?.message || "Failed to generate capsule"}`);
    }
  };

  const metrics: HostPulseMetrics = snapshot?.metrics || {
    timestamp: new Date().toISOString(),
    platform: "linux",
    hostname: "localhost",
    os_release: "",
    architecture: "",
    cpu_percent: 0,
    cpu_cores: 1,
    memory_used_mb: 0,
    memory_total_mb: 0,
    memory_percent: 0,
    process_count: 0,
    connection_count: 0,
  };

  // Filtered and sorted processes
  const filteredProcesses = useMemo(() => {
    const procs = snapshot?.processes || [];
    return procs
      .filter((p: XRayProcessItem) => {
        // Quick Filters
        if (selectedQuickFilter === "high_cpu" && (p.cpu_percent || 0) < 5.0) return false;
        if (selectedQuickFilter === "high_mem" && (p.memory_mb || 0) < 100.0) return false;
        if (
          selectedQuickFilter === "unmanaged" &&
          p.package_status !== "unmanaged_suspicious" &&
          !p.is_unmanaged
        ) {
          return false;
        }
        if (selectedQuickFilter === "net" && (p.socket_count || 0) === 0) return false;

        // Search Query Filter
        if (!searchFilter.trim()) return true;
        const q = searchFilter.toLowerCase().trim();
        const pidStr = String(p.pid);
        const nameStr = (p.name || "").toLowerCase();
        const cmdStr = Array.isArray(p.cmdline)
          ? p.cmdline.join(" ").toLowerCase()
          : (p.cmdline || "").toLowerCase();
        const userStr = ((p as any).username || p.user || "").toLowerCase();
        const exeStr = (p.exe || "").toLowerCase();

        return (
          pidStr === q ||
          nameStr.includes(q) ||
          cmdStr.includes(q) ||
          userStr.includes(q) ||
          exeStr.includes(q)
        );
      })
      .sort((a: XRayProcessItem, b: XRayProcessItem) => {
        let cmp = 0;
        if (sortField === "cpu") cmp = (b.cpu_percent || 0) - (a.cpu_percent || 0);
        else if (sortField === "memory") cmp = (b.memory_mb || 0) - (a.memory_mb || 0);
        else if (sortField === "pid") cmp = a.pid - b.pid;
        else if (sortField === "name") cmp = a.name.localeCompare(b.name);
        else if (sortField === "user") cmp = ((a as any).username || a.user || "").localeCompare((b as any).username || b.user || "");
        return sortAsc ? -cmp : cmp;
      });
  }, [snapshot?.processes, searchFilter, selectedQuickFilter, sortField, sortAsc]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false); // default desc for metric fields
    }
  };

  // Sync search filter into URL params without reloading
  const handleSearchChange = (val: string) => {
    setSearchFilter(val);
    if (val.trim()) {
      setSearchParams({ q: val.trim() }, { replace: true });
    } else {
      setSearchParams({}, { replace: true });
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 font-sans space-y-6">
      {/* ── Top Header & Host Telemetry ─────────────────────────────── */}
      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-text-faint uppercase tracking-wider">
            <span className="flex h-2 w-2 rounded-full bg-accent animate-pulse" />
            <span>Host X-Ray · Live System Monitor</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-text-primary flex items-center gap-3">
            <span>Host X-Ray &amp; Process Inspector</span>
            <span className="rounded-full bg-accent/15 px-2.5 py-0.5 text-xs font-mono font-semibold text-accent border border-accent/40">
              Live Real-Time
            </span>
          </h1>
          <p className="mt-1 text-xs text-text-muted max-w-3xl">
            Live hardware resource pulse, process causality hierarchy, active listening sockets, and security context across monitored endpoints with 100% real OS data.
          </p>
        </div>

        {/* Action Controls: Live Polling, Interval, Refresh, Host Badge */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Host OS Identity Badge */}
          <div className="flex items-center gap-2 rounded-xl border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs shadow-sm">
            <Icon name={platformIcon(metrics.platform)} size={15} className="text-accent" />
            <div className="flex flex-col">
              <span className="font-bold text-text-primary capitalize leading-none">
                {metrics.hostname} ({metrics.platform})
              </span>
              <span className="text-[10px] text-text-faint leading-none mt-0.5">
                {metrics.os_release ? metrics.os_release.slice(0, 18) : "Kernel"} · up {formatUptime(metrics.uptime_seconds)}
              </span>
            </div>
          </div>

          {/* Polling Toggle */}
          <button
            onClick={() => setIsLive(!isLive)}
            className={`press flex items-center gap-1.5 rounded-xl border px-3 py-1.5 font-mono text-xs font-semibold transition ${
              isLive
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20"
            }`}
            title={isLive ? "Pause real-time updates" : "Resume live telemetry polling"}
          >
            <span className={`h-2 w-2 rounded-full ${isLive ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
            <span>{isLive ? "Live" : "Paused"}</span>
          </button>

          {/* Polling Interval Selector */}
          <select
            value={pollInterval}
            onChange={(e) => setPollInterval(Number(e.target.value))}
            className="rounded-xl border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-hidden focus:border-accent"
            title="Telemetry polling frequency"
          >
            <option value={1000}>1s (Fast)</option>
            <option value={2000}>2s (Balanced)</option>
            <option value={5000}>5s (Relaxed)</option>
          </select>

          {/* Refresh Now Button */}
          <button
            onClick={() => void refetchSnapshot()}
            disabled={isSnapshotFetching}
            className="press flex items-center gap-1 rounded-xl border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary transition"
            title="Trigger instant snapshot refresh"
          >
            <Icon name="refresh" size={13} className={isSnapshotFetching ? "animate-spin text-accent" : ""} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </header>

      {/* ── Executive Pulse HUD (4 KPI Gauges) ───────────────────────── */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
        {/* 1. CPU Utilization */}
        <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-text-faint uppercase font-bold text-[10px]">
              <span>CPU Pulse</span>
              <span className="text-accent">{metrics.cpu_cores} Cores</span>
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className={`text-2xl font-bold tracking-tight ${
                metrics.cpu_percent > 90 ? "text-rose-400" : metrics.cpu_percent > 70 ? "text-amber-400" : "text-text-primary"
              }`}>
                {metrics.cpu_percent}%
              </span>
              <span className="text-[11px] text-text-muted">
                Load: {metrics.load_1m ?? 0} · {metrics.load_5m ?? 0}
              </span>
            </div>
          </div>
          <div className="mt-3">
            <div className="h-2 w-full rounded-full bg-bg-base overflow-hidden border border-border-subtle">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  metrics.cpu_percent > 90 ? "bg-rose-500" : metrics.cpu_percent > 70 ? "bg-amber-500" : "bg-emerald-500"
                }`}
                style={{ width: `${Math.min(100, Math.max(2, metrics.cpu_percent))}%` }}
              />
            </div>
            <div className="mt-1.5 flex justify-between text-[10px] text-text-faint">
              <span>0%</span>
              <span>100% capacity</span>
            </div>
          </div>
        </div>

        {/* 2. RAM & Swap */}
        <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-text-faint uppercase font-bold text-[10px]">
              <span>Memory Active</span>
              <span className="text-cyan-400">{metrics.memory_percent}%</span>
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl font-bold tracking-tight text-text-primary">
                {Math.round(metrics.memory_used_mb)} <span className="text-xs font-normal text-text-muted">MB</span>
              </span>
              <span className="text-[11px] text-text-muted">
                / {Math.round(metrics.memory_total_mb)} MB
              </span>
            </div>
          </div>
          <div className="mt-3">
            <div className="h-2 w-full rounded-full bg-bg-base overflow-hidden border border-border-subtle">
              <div
                className="h-full rounded-full bg-cyan-500 transition-all duration-300"
                style={{ width: `${Math.min(100, Math.max(2, metrics.memory_percent))}%` }}
              />
            </div>
            <div className="mt-1.5 flex justify-between text-[10px] text-text-faint">
              <span>{Math.round(metrics.memory_free_mb || 0)} MB free</span>
              <span>Swap: {Math.round(metrics.swap_used_mb || 0)} MB</span>
            </div>
          </div>
        </div>

        {/* 3. Disk Storage */}
        <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-text-faint uppercase font-bold text-[10px]">
              <span>Storage Volume</span>
              <span className="text-indigo-400">{metrics.disk_percent ?? 0}%</span>
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl font-bold tracking-tight text-text-primary">
                {metrics.disk_used_gb ?? 0} <span className="text-xs font-normal text-text-muted">GB</span>
              </span>
              <span className="text-[11px] text-text-muted">
                / {metrics.disk_total_gb ?? 0} GB
              </span>
            </div>
          </div>
          <div className="mt-3">
            <div className="h-2 w-full rounded-full bg-bg-base overflow-hidden border border-border-subtle">
              <div
                className="h-full rounded-full bg-indigo-500 transition-all duration-300"
                style={{ width: `${Math.min(100, Math.max(2, metrics.disk_percent ?? 0))}%` }}
              />
            </div>
            <div className="mt-1.5 flex justify-between text-[10px] text-text-faint">
              <span>{metrics.disk_free_gb ?? 0} GB free</span>
              <span>Root partition</span>
            </div>
          </div>
        </div>

        {/* 4. Network I/O & Socket Footprint */}
        <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm relative overflow-hidden flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-text-faint uppercase font-bold text-[10px]">
              <span>Network &amp; Sockets</span>
              <span className="text-emerald-400 font-bold">{snapshot?.socket_count ?? 0} Active</span>
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl font-bold tracking-tight text-text-primary">
                {snapshot?.process_count ?? 0} <span className="text-xs font-normal text-text-muted">procs</span>
              </span>
              <span className="text-[11px] text-emerald-400 font-medium">
                {metrics.net_kb_in_sec ?? 0} KB/s in
              </span>
            </div>
          </div>
          <div className="mt-3">
            <div className="flex items-center justify-between text-[11px] rounded bg-bg-base/80 px-2 py-1 border border-border-subtle">
              <span className="text-emerald-400 flex items-center gap-1">
                <span>▼</span> {metrics.net_kb_in_sec ?? 0} KB/s
              </span>
              <span className="text-accent flex items-center gap-1">
                <span>▲</span> {metrics.net_kb_out_sec ?? 0} KB/s
              </span>
            </div>
            <div className="mt-1.5 flex justify-between text-[10px] text-text-faint">
              <span>{snapshot?.socket_count ?? 0} sockets</span>
              <span>Live procfs telemetry</span>
            </div>
          </div>
        </div>
      </section>

      {/* ── Correlated Fleet & Ingested Events (Telemetry Linkage) ────────── */}
      {fleetEventsData?.events && fleetEventsData.events.length > 0 && (
        <section className="rounded-2xl border border-border-subtle bg-bg-surface/70 p-4 font-mono text-xs backdrop-blur-sm space-y-2.5">
          <div className="flex items-center justify-between text-[11px] text-text-faint uppercase">
            <span className="font-bold text-text-primary flex items-center gap-1.5">
              <Icon name="activity" size={13} className="text-accent" />
              <span>Correlated Fleet Events ({fleetEventsData.total})</span>
            </span>
            <span>Historical Ingest Stream</span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {fleetEventsData.events.map((ev) => (
              <span
                key={ev.id}
                className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base/90 px-2.5 py-1 text-[11px]"
              >
                <span className="text-text-muted">{ev.event_type}</span>
                {ev.host_id ? (
                  <Link
                    to={`/hosts/${encodeURIComponent(ev.host_id)}`}
                    className="font-bold text-accent hover:underline"
                  >
                    {ev.host_id}
                  </Link>
                ) : (
                  <span className="text-text-faint">local</span>
                )}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* ── Sub-View Tab Switcher & Universal Filter Ribbon ─────────── */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-2">
          {/* Decks Switcher */}
          <nav className="flex flex-wrap items-center gap-1">
            {[
              { id: "processes", label: "Live Processes", icon: "process", count: snapshot?.processes?.length ?? 0 },
              { id: "tree", label: "Causality Tree", icon: "list", count: treeData?.length ?? 0 },
              { id: "network", label: "Network Matrix", icon: "network", count: networkMatrix?.summary?.total_sockets ?? snapshot?.socket_count ?? 0 },
              { id: "insights", label: "Behavioral Insights", icon: "alert", count: explanations?.length ?? 0 },
              { id: "host_info", label: "Hardware & Platform", icon: "box", count: null },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveDeck(tab.id as any)}
                className={`press flex items-center gap-1.5 rounded-lg px-3 py-2 font-mono text-xs font-semibold transition ${
                  activeDeck === tab.id
                    ? "bg-accent/15 text-accent border border-accent/40 shadow-xs"
                    : "text-text-muted hover:text-text-primary hover:bg-bg-elevated/40 border border-transparent"
                }`}
              >
                <Icon name={tab.icon as any} size={14} />
                <span>{tab.label}</span>
                {tab.count !== null && (
                  <span className="rounded-full bg-bg-base px-1.5 py-0.2 text-[10px] font-bold tabular-nums border border-border-subtle">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </nav>

          {/* Action Message Banner if any */}
          {actionMessage && (
            <div className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1 text-xs font-mono text-accent animate-pulse">
              {actionMessage}
            </div>
          )}
        </div>

        {/* Search & Filter Toolbar (Available across all views) */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs">
          {/* Universal Search Bar */}
          <div className="relative flex-1 min-w-[240px]">
            <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              type="text"
              placeholder="Filter by process name, PID, command line, user, port..."
              value={searchFilter}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="w-full rounded-lg border border-border-subtle bg-bg-base/70 py-1.5 pl-8 pr-8 text-xs text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-hidden"
            />
            {searchFilter && (
              <button
                onClick={() => handleSearchChange("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-faint hover:text-text-primary"
                title="Clear filter"
              >
                ✕
              </button>
            )}
          </div>

          {/* Quick Filter Chips */}
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            {[
              { id: "all", label: "All Procs" },
              { id: "high_cpu", label: "CPU > 5%" },
              { id: "high_mem", label: "RAM > 100MB" },
              { id: "unmanaged", label: "Unmanaged / Temp Path" },
            ].map((chip) => (
              <button
                key={chip.id}
                onClick={() => setSelectedQuickFilter(chip.id as any)}
                className={`press rounded-lg px-2 py-1 transition ${
                  selectedQuickFilter === chip.id
                    ? "bg-accent/20 text-accent font-bold border border-accent/50"
                    : "bg-bg-base/60 text-text-muted hover:text-text-primary border border-border-subtle"
                }`}
              >
                {chip.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* ── Deck 1: Live Processes Table (Default) ──────────────────── */}
      {activeDeck === "processes" && (
        <section className="space-y-3">
          <div className="overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-xs font-mono text-xs">
            <div className="overflow-x-auto max-h-[640px] overflow-y-auto">
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 z-10 bg-bg-base/95 backdrop-blur-md border-b border-border-subtle text-[11px] text-text-muted uppercase">
                  <tr>
                    <th className="py-2.5 px-3 cursor-pointer hover:text-accent" onClick={() => handleSort("pid")}>
                      PID {sortField === "pid" ? (sortAsc ? "▲" : "▼") : ""}
                    </th>
                    <th className="py-2.5 px-3 cursor-pointer hover:text-accent" onClick={() => handleSort("name")}>
                      Process Name &amp; Binary {sortField === "name" ? (sortAsc ? "▲" : "▼") : ""}
                    </th>
                    <th className="py-2.5 px-3 cursor-pointer hover:text-accent" onClick={() => handleSort("user")}>
                      User {sortField === "user" ? (sortAsc ? "▲" : "▼") : ""}
                    </th>
                    <th className="py-2.5 px-3 cursor-pointer hover:text-accent" onClick={() => handleSort("cpu")}>
                      CPU % {sortField === "cpu" ? (sortAsc ? "▲" : "▼") : ""}
                    </th>
                    <th className="py-2.5 px-3 cursor-pointer hover:text-accent" onClick={() => handleSort("memory")}>
                      RAM (MB) {sortField === "memory" ? (sortAsc ? "▲" : "▼") : ""}
                    </th>
                    <th className="py-2.5 px-3">Threads</th>
                    <th className="py-2.5 px-3">Package / Provenance</th>
                    <th className="py-2.5 px-3 text-right">X-Ray Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {isSnapshotLoading ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-text-muted">
                        <Icon name="refresh" size={20} className="mx-auto animate-spin text-accent mb-2" />
                        Scanning live operating system processes...
                      </td>
                    </tr>
                  ) : filteredProcesses.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-12 text-center text-text-muted">
                        No active processes matching filter "{searchFilter}".
                      </td>
                    </tr>
                  ) : (
                    filteredProcesses.map((p: XRayProcessItem) => {
                      const isUnmanaged =
                        p.package_status === "unmanaged_suspicious" ||
                        p.is_unmanaged === true ||
                        (p.package_origin || "").toLowerCase().includes("unmanaged");
                      const packageLabel = p.package_label || p.package_origin || "";

                      return (
                        <tr
                          key={p.pid}
                          className={`hover:bg-bg-elevated/40 transition-colors ${
                            inspectPid === p.pid ? "bg-accent/10" : ""
                          }`}
                        >
                          {/* PID */}
                          <td className="py-2.5 px-3 font-bold text-accent">
                            {p.pid}
                          </td>

                          {/* Process Name & Exe */}
                          <td className="py-2.5 px-3 max-w-xs truncate">
                            <div className="flex items-center gap-1.5">
                              <span className="font-bold text-text-primary truncate">{p.name}</span>
                              <span className="text-[10px] text-text-faint">ppid: {p.ppid}</span>
                            </div>
                            {(() => {
                              const displayCmd = Array.isArray(p.cmdline)
                                ? p.cmdline.join(" ")
                                : p.cmdline || p.exe || "—";
                              return (
                                <div className="text-[10px] text-text-muted truncate max-w-sm" title={displayCmd}>
                                  {displayCmd}
                                </div>
                              );
                            })()}
                          </td>

                          {/* User */}
                          <td className="py-2.5 px-3 text-text-muted">
                            {(p as any).username || p.user || "—"}
                          </td>

                          {/* CPU % */}
                          <td className="py-2.5 px-3 font-medium">
                            <span className={`rounded px-1.5 py-0.5 ${
                              (p.cpu_percent || 0) > 20
                                ? "text-rose-400 font-bold"
                                : (p.cpu_percent || 0) > 5
                                  ? "text-amber-400"
                                  : "text-text-primary"
                            }`}>
                              {(p.cpu_percent || 0).toFixed(1)}%
                            </span>
                          </td>

                          {/* Memory MB */}
                          <td className="py-2.5 px-3 font-medium text-text-primary">
                            {(p.memory_mb || 0).toFixed(1)}
                          </td>

                          {/* Threads */}
                          <td className="py-2.5 px-3 text-text-faint">
                            {p.threads || 1}
                          </td>

                          {/* Package / Provenance */}
                          <td className="py-2.5 px-3">
                            {isUnmanaged ? (
                              <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-2 py-0.5 text-[10px] font-bold text-rose-400 border border-rose-500/30">
                                <span>Unmanaged Binary</span>
                              </span>
                            ) : packageLabel ? (
                              <span className="inline-flex items-center gap-1 rounded bg-bg-base px-2 py-0.5 text-[10px] text-text-muted border border-border-subtle truncate max-w-[150px]">
                                {packageLabel}
                              </span>
                            ) : (
                              <span className="text-[10px] text-text-faint">Standard Binary</span>
                            )}
                          </td>

                          {/* X-Ray Actions */}
                          <td className="py-2.5 px-3 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => setInspectPid(p.pid)}
                                className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-1 text-[10px] font-semibold text-accent hover:bg-accent/20 transition"
                                title={`Inspect full X-Ray dossier for PID ${p.pid}`}
                              >
                                <Icon name="search" size={10} />
                                <span>Inspect</span>
                              </button>
                              <button
                                onClick={() => void handleProcessAction(p.pid, "terminate")}
                                className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-1 text-[10px] text-text-muted hover:border-rose-500/50 hover:text-rose-400 transition"
                                title={`Send SIGTERM to PID ${p.pid}`}
                              >
                                <span>SIGTERM</span>
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-border-subtle bg-bg-base/70 px-4 py-2 text-[11px] text-text-muted">
              <span>Showing {filteredProcesses.length} of {snapshot?.processes?.length ?? 0} processes</span>
              <span>Click any column header to sort</span>
            </div>
          </div>
        </section>
      )}

      {/* ── Deck 2: Process Causality Tree ──────────────────────────── */}
      {activeDeck === "tree" && (
        <section className="rounded-xl border border-border-subtle bg-[#06080d] p-5 font-mono text-xs shadow-inner">
          <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
            <div>
              <span className="font-bold text-accent text-sm">Process Causality Tree</span>
              <p className="text-[11px] text-text-muted mt-0.5">
                Hierarchical execution ancestry mapped from init/systemd down to active user sessions.
              </p>
            </div>
            <span className="text-[11px] text-text-faint">{treeData?.length ?? 0} Root Processes</span>
          </div>

          <div className="max-h-[600px] overflow-y-auto space-y-1.5 pr-2">
            {(!treeData || treeData.length === 0) ? (
              <p className="text-text-muted py-8 text-center">Loading live process causality hierarchy...</p>
            ) : (
              treeData.map((node: any) => (
                <ProcessTreeNode
                  key={node.pid}
                  node={node}
                  depth={0}
                  onInspect={(pid) => setInspectPid(pid)}
                />
              ))
            )}
          </div>
        </section>
      )}

      {/* ── Deck 3: Network Threat Matrix ───────────────────────────── */}
      {activeDeck === "network" && (
        <section className="space-y-4 font-mono text-xs">
          {/* Summary KPIs */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
              <span className="text-[10px] text-text-faint uppercase font-bold">Public Listeners</span>
              <div className="mt-1 text-xl font-bold text-rose-400">
                {networkMatrix?.public_listeners?.length ?? 0}
              </div>
              <span className="text-[10px] text-text-muted">Bound to 0.0.0.0 / external interfaces</span>
            </div>

            <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
              <span className="text-[10px] text-text-faint uppercase font-bold">Local Loopback</span>
              <div className="mt-1 text-xl font-bold text-cyan-400">
                {networkMatrix?.loopback_listeners?.length ?? 0}
              </div>
              <span className="text-[10px] text-text-muted">Bound to 127.0.0.1 / localhost</span>
            </div>

            <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
              <span className="text-[10px] text-text-faint uppercase font-bold">Outbound Connections</span>
              <div className="mt-1 text-xl font-bold text-emerald-400">
                {networkMatrix?.outbound_connections?.length ?? 0}
              </div>
              <span className="text-[10px] text-text-muted">Active external internet &amp; LAN sockets</span>
            </div>
          </div>

          {/* Sockets Table */}
          <div className="overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-xs">
            <div className="max-h-[500px] overflow-y-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="sticky top-0 bg-bg-base/95 backdrop-blur-md border-b border-border-subtle text-[11px] text-text-muted uppercase">
                  <tr>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">Local Endpoint</th>
                    <th className="py-2.5 px-3">Remote Endpoint</th>
                    <th className="py-2.5 px-3">State</th>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">Process Name</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {((snapshot?.sockets as XRaySocketItem[]) || []).length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-10 text-center text-text-muted">
                        No active network sockets detected.
                      </td>
                    </tr>
                  ) : (
                    ((snapshot?.sockets as XRaySocketItem[]) || []).map((s: XRaySocketItem, idx: number) => {
                      const isPublicListen = s.status === "LISTEN" && (s.local_ip === "0.0.0.0" || s.local_ip === "::");
                      return (
                        <tr key={`${s.local_ip}:${s.local_port}-${idx}`} className="hover:bg-bg-elevated/40">
                          <td className="py-2 px-3 uppercase text-[11px] font-bold text-accent">
                            {s.protocol}
                          </td>
                          <td className="py-2 px-3 font-semibold text-text-primary">
                            {s.local_ip}:{s.local_port}
                            {isPublicListen && (
                              <span className="ml-2 rounded bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-400">
                                EXPOSED
                              </span>
                            )}
                          </td>
                          <td className="py-2 px-3 text-text-muted">
                            {s.remote_ip ? `${s.remote_ip}:${s.remote_port}` : "—"}
                          </td>
                          <td className="py-2 px-3">
                            <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                              s.status === "LISTEN" ? "bg-cyan-500/15 text-cyan-400" : "bg-emerald-500/15 text-emerald-400"
                            }`}>
                              {s.status}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-accent font-semibold">
                            {s.pid ?? "—"}
                          </td>
                          <td className="py-2 px-3 text-text-primary">
                            {s.process_name || "—"}
                          </td>
                          <td className="py-2 px-3 text-right">
                            {s.pid ? (
                              <button
                                onClick={() => setInspectPid(s.pid)}
                                className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold text-accent hover:bg-accent/20"
                              >
                                Inspect
                              </button>
                            ) : (
                              "—"
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}

      {/* ── Deck 4: Behavioral Insights & Anomalies ─────────────────── */}
      {activeDeck === "insights" && (
        <section className="space-y-3 font-mono text-xs">
          {(!explanations || explanations.length === 0) ? (
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-8 text-center text-text-muted">
              <Icon name="shield" size={24} className="mx-auto text-emerald-400 mb-2" />
              <p className="font-bold text-text-primary">System Integrity Nominal</p>
              <p className="text-xs text-text-muted mt-1">
                No heuristic anomalies or unmanaged process violations found on this host.
              </p>
            </div>
          ) : (
            explanations.map((item: any, idx: number) => (
              <div
                key={idx}
                className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
              >
                <div className="flex items-start gap-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-500/20 text-amber-400 shrink-0">
                    <Icon name="alert" size={16} />
                  </span>
                  <div>
                    <h4 className="font-bold text-text-primary text-sm">{item.title || "Behavioral Anomaly"}</h4>
                    <p className="text-xs text-text-muted mt-0.5">{item.details || item.description}</p>
                    {item.pid && (
                      <span className="mt-1 inline-block text-[11px] text-accent font-semibold">
                        Associated PID: {item.pid}
                      </span>
                    )}
                  </div>
                </div>

                {item.pid && (
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => setInspectPid(item.pid)}
                      className="press rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25"
                    >
                      X-Ray Inspect
                    </button>
                    <button
                      onClick={() => void handleProcessAction(item.pid, "terminate")}
                      className="press rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 font-bold text-rose-400 hover:bg-rose-500/20"
                    >
                      Terminate
                    </button>
                  </div>
                )}
              </div>
            ))
          )}
        </section>
      )}

      {/* ── Deck 5: Hardware & Platform Specs ───────────────────────── */}
      {activeDeck === "host_info" && (
        <section className="rounded-xl border border-border-subtle bg-bg-surface p-6 font-mono text-xs space-y-6">
          <div className="border-b border-border-subtle pb-3">
            <h3 className="font-bold text-text-primary text-sm">Host System Architecture</h3>
            <p className="text-text-muted text-[11px]">Hardware, virtualization, and kernel telemetry.</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Hostname</span>
              <p className="font-bold text-text-primary text-sm mt-1">{metrics.hostname}</p>
            </div>
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Operating System</span>
              <p className="font-bold text-text-primary text-sm mt-1 capitalize">{metrics.platform} ({metrics.architecture})</p>
            </div>
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Kernel Release</span>
              <p className="font-bold text-text-primary text-sm mt-1">{metrics.os_release || "Standard Release"}</p>
            </div>
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Processor Cores</span>
              <p className="font-bold text-text-primary text-sm mt-1">{metrics.cpu_cores} Cores</p>
            </div>
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Total Physical RAM</span>
              <p className="font-bold text-text-primary text-sm mt-1">{Math.round(metrics.memory_total_mb)} MB</p>
            </div>
            <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold">Root Drive Capacity</span>
              <p className="font-bold text-text-primary text-sm mt-1">{metrics.disk_total_gb} GB</p>
            </div>
          </div>
        </section>
      )}

      {/* ── Slide-Over / Modal: Deep Process X-Ray Target Dossier ───── */}
      {inspectPid !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-xs">
          <div className="h-full w-full max-w-2xl bg-[#090d14] border-l border-white/10 p-6 font-mono text-xs overflow-y-auto shadow-2xl flex flex-col justify-between">
            <div className="space-y-6">
              {/* Dossier Header */}
              <div className="flex items-start justify-between border-b border-white/10 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-accent font-bold text-lg">PID {inspectPid}</span>
                    <span className="rounded bg-white/10 px-2 py-0.5 text-[10px] font-bold uppercase text-text-primary">
                      {dossier?.target?.status || "RUNNING"}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-text-primary mt-1">
                    {dossier?.target?.name || "Process Dossier"}
                  </h3>
                  <p className="text-[11px] text-text-muted mt-0.5 break-all">
                    {dossier?.target?.exe || dossier?.target?.cmdline || "No path recorded"}
                  </p>
                </div>
                <button
                  onClick={() => setInspectPid(null)}
                  className="press rounded-lg border border-white/15 bg-white/5 p-1.5 text-text-muted hover:text-white"
                  title="Close X-Ray Drawer"
                >
                  ✕
                </button>
              </div>

              {dossierLoading ? (
                <div className="py-20 text-center text-text-muted">
                  <Icon name="refresh" size={24} className="mx-auto animate-spin text-accent mb-2" />
                  <p>Extracting kernel capabilities, inodes &amp; sockets for PID {inspectPid}...</p>
                </div>
              ) : dossier ? (
                <>
                  {/* Action Bar */}
                  <div className="flex flex-wrap items-center gap-2 p-3 rounded-xl border border-white/10 bg-white/5">
                    <span className="text-[11px] text-text-muted font-semibold">Signals:</span>
                    <button
                      onClick={() => void handleProcessAction(inspectPid, "terminate")}
                      className="press rounded border border-amber-500/50 bg-amber-500/15 px-2.5 py-1 text-[11px] font-bold text-amber-300 hover:bg-amber-500/25"
                    >
                      SIGTERM
                    </button>
                    <button
                      onClick={() => void handleProcessAction(inspectPid, "kill")}
                      className="press rounded border border-rose-500/50 bg-rose-500/15 px-2.5 py-1 text-[11px] font-bold text-rose-300 hover:bg-rose-500/25"
                    >
                      SIGKILL
                    </button>
                    <button
                      onClick={() => void handleProcessAction(inspectPid, "freeze")}
                      className="press rounded border border-white/15 bg-white/5 px-2.5 py-1 text-[11px] font-bold text-text-muted hover:text-white"
                    >
                      SIGSTOP (Freeze)
                    </button>
                    <button
                      onClick={() => void handleProcessAction(inspectPid, "resume")}
                      className="press rounded border border-white/15 bg-white/5 px-2.5 py-1 text-[11px] font-bold text-text-muted hover:text-white"
                    >
                      SIGCONT (Resume)
                    </button>
                    <button
                      onClick={() => void handleExportCapsule(inspectPid)}
                      className="press ml-auto rounded border border-accent/40 bg-accent/15 px-2.5 py-1 text-[11px] font-bold text-accent hover:bg-accent/25"
                    >
                      Export Capsule (.xray.json)
                    </button>
                  </div>

                  {/* Security Posture & Capabilities */}
                  <div className="space-y-2">
                    <span className="text-[11px] text-text-faint uppercase font-bold">Security Capabilities &amp; Context</span>
                    <div className="rounded-xl border border-white/10 bg-black/40 p-3.5 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-text-muted">User / Effective UID:</span>
                        <span className="font-bold text-text-primary">{dossier?.target?.user || "system"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-text-muted">Provenance:</span>
                        <span className="font-bold text-cyan-400">{dossier?.security?.package_provenance?.label || "Managed"}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-text-muted">Working Directory:</span>
                        <span className="font-mono text-[10px] text-text-primary truncate max-w-xs">{dossier?.target?.cwd || "/"}</span>
                      </div>
                      {dossier?.security?.capabilities_effective && dossier.security.capabilities_effective.length > 0 && (
                        <div>
                          <span className="text-text-muted block mb-1">Effective Capabilities:</span>
                          <div className="flex flex-wrap gap-1">
                            {dossier.security.capabilities_effective.map((c: any, i: number) => (
                              <span
                                key={i}
                                className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${
                                  c.is_dangerous ? "bg-rose-500/20 text-rose-300 border border-rose-500/40" : "bg-white/10 text-text-muted"
                                }`}
                              >
                                {c.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Bound Sockets */}
                  <div className="space-y-2">
                    <span className="text-[11px] text-text-faint uppercase font-bold">
                      Open Network Sockets ({(dossier?.connections || []).length})
                    </span>
                    <div className="rounded-xl border border-white/10 bg-black/40 p-3 max-h-36 overflow-y-auto">
                      {(dossier?.connections || []).length === 0 ? (
                        <p className="text-text-faint text-center py-2">No network sockets allocated.</p>
                      ) : (
                        dossier.connections.map((c: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between text-[11px] py-1 border-b border-white/5 last:border-0">
                            <span className="text-accent font-bold uppercase">{c.protocol}</span>
                            <span className="text-text-primary font-mono">{c.local_ip}:{c.local_port}</span>
                            <span className="text-text-muted">{c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : "LISTEN"}</span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Open File Descriptors / Inodes */}
                  <div className="space-y-2">
                    <span className="text-[11px] text-text-faint uppercase font-bold">
                      Open File Descriptors &amp; Inodes ({(dossier?.files_ipc || []).length})
                    </span>
                    <div className="rounded-xl border border-white/10 bg-black/40 p-3 max-h-48 overflow-y-auto space-y-1">
                      {(dossier?.files_ipc || []).length === 0 ? (
                        <p className="text-text-faint text-center py-2">No file descriptors visible.</p>
                      ) : (
                        dossier.files_ipc.map((f: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between text-[10px] py-0.5 border-b border-white/5 last:border-0">
                            <span className="text-cyan-400 font-mono">fd {f.fd}</span>
                            <span className="text-text-primary truncate max-w-[320px]" title={f.path}>{f.path}</span>
                            {f.is_deleted && (
                              <span className="rounded bg-rose-500/20 px-1 text-[9px] font-bold text-rose-400">
                                DELETED
                              </span>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div className="py-20 text-center text-rose-400">
                  <p>Process PID {inspectPid} could not be found or has terminated.</p>
                </div>
              )}
            </div>

            {/* Close footer */}
            <div className="border-t border-white/10 pt-3 mt-6 flex justify-end">
              <button
                onClick={() => setInspectPid(null)}
                className="press rounded-lg border border-white/15 bg-white/5 px-4 py-2 text-xs font-semibold text-text-primary hover:bg-white/10"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ProcessTreeNode({
  node,
  depth,
  onInspect,
}: {
  node: any;
  depth: number;
  onInspect: (pid: number) => void;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div className="text-xs font-mono">
      <div
        className="flex items-center gap-2 py-1 px-2 rounded-lg hover:bg-white/5 transition cursor-pointer"
        style={{ paddingLeft: `${Math.min(depth * 20 + 8, 120)}px` }}
      >
        {hasChildren ? (
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-4 h-4 flex items-center justify-center text-text-faint hover:text-accent font-bold"
          >
            {expanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-4 h-4 text-center text-text-faint">·</span>
        )}

        <span className="text-accent font-bold">PID {node.pid}</span>
        <span className="font-semibold text-text-primary">{node.name}</span>
        <span className="text-[10px] text-text-muted truncate max-w-xs">{node.cmdline || ""}</span>

        <button
          onClick={(e) => {
            e.stopPropagation();
            onInspect(node.pid);
          }}
          className="press ml-auto rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[9px] font-semibold text-accent hover:bg-accent/20"
        >
          Inspect
        </button>
      </div>

      {hasChildren && expanded && (
        <div className="border-l border-white/10 ml-3">
          {node.children.map((child: any) => (
            <ProcessTreeNode
              key={child.pid}
              node={child}
              depth={depth + 1}
              onInspect={onInspect}
            />
          ))}
        </div>
      )}
    </div>
  );
}
