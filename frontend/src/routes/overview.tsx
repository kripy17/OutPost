import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { RiskGauge, RiskTrendBars, SeverityDonut } from "../components/Posture/Posture";
import { copyToClipboard } from "../lib/clipboard";
import { useSocTimeRange } from "../lib/useSocTimeRange";
import {
  bulkUpdateAlertStatus,
  getAgents,
  getAlertQueue,
  getEvents,
  getHealth,
  getPlatform,
  getProcessSummary,
  getRecentAlerts,
  getRuleMeta,
  getRuns,
  listInvestigations,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import {
  ageBucket,
  aggregateTrend,
  collapseFindings,
  openSince,
  overviewRunParams,
  sortFindingsRiskFirst,
} from "./overviewHelpers";
import type { GlobalAlert, ProcessSummary, QueueAlert, Severity } from "../types";

const ATTACK_TACTICS = [
  { id: "initial-access", label: "Initial Access" },
  { id: "execution", label: "Execution" },
  { id: "persistence", label: "Persistence" },
  { id: "privilege-escalation", label: "Priv Escalation" },
  { id: "defense-evasion", label: "Defense Evasion" },
  { id: "credential-access", label: "Cred Access" },
  { id: "discovery", label: "Discovery" },
  { id: "lateral-movement", label: "Lateral Move" },
  { id: "command-and-control", label: "Command & Control" },
  { id: "exfiltration", label: "Exfiltration" },
  { id: "impact", label: "Impact" },
];

function relativeTime(iso: string): string {
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

interface AlertDrawerState {
  alert: QueueAlert | GlobalAlert;
  ruleMeta?: { tactic: string; technique: string; weight: number };
}

function AlertInspectorDrawer({
  data,
  onClose,
  onAcknowledge,
}: {
  data: AlertDrawerState;
  onClose: () => void;
  onAcknowledge: (id: number | null) => void;
}) {
  const { alert, ruleMeta } = data;
  const isMalicious = alert.severity === "malicious";

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in font-sans"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg bg-bg-surface border-l border-border-subtle shadow-2xl h-full flex flex-col text-xs animate-slide-left"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span
              className={`rounded px-1.5 py-0.5 text-[10px] uppercase font-bold ${
                isMalicious
                  ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/40"
                  : "bg-risk-suspicious/20 text-risk-suspicious border border-risk-suspicious/40"
              }`}
            >
              {alert.severity}
            </span>
            <span className="font-bold text-text-primary text-sm truncate max-w-[280px]" title={alert.rule_name}>
              {alert.rule_name}
            </span>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-bg-base hover:text-text-primary"
            title="Close Drawer"
          >
            <Icon name="x" size={14} />
          </button>
        </div>

        {/* Action Ribbon */}
        <div className="p-3 border-b border-border-subtle bg-bg-base/60 flex flex-wrap items-center gap-1.5 font-sans">
          {alert.id && alert.status === "open" && (
            <button
              onClick={() => onAcknowledge(alert.id)}
              className="press inline-flex items-center gap-1 rounded border border-signal/60 bg-signal/15 px-2.5 py-1 text-[11px] font-semibold text-signal hover:bg-signal/25"
            >
              <Icon name="check" size={11} />
              <span>Acknowledge Alert</span>
            </button>
          )}

          <Link
            to={`/findings?alert_id=${alert.id || ""}`}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] font-semibold text-text-muted hover:border-accent/40 hover:text-text-primary"
          >
            <Icon name="shield" size={11} />
            <span>Triage in Queue</span>
          </Link>

          {alert.related_ip && (
            <Link
              to={`/footprint?target=${encodeURIComponent(alert.related_ip)}`}
              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] font-semibold text-text-muted hover:border-accent/40 hover:text-text-primary"
            >
              <Icon name="globe" size={11} />
              <span>Pivot IP</span>
            </Link>
          )}

          <button
            onClick={() => void copyToClipboard(JSON.stringify(alert, null, 2))}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] font-semibold text-text-muted hover:text-text-primary ml-auto"
          >
            <Icon name="copy" size={11} />
            <span>Copy JSON</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Metadata Grid */}
          <div className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-3 space-y-2">
            <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">Detection Context</span>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-text-faint">Rule ID:</span>
                <p className="font-mono text-xs font-semibold text-accent mt-0.5">{alert.rule_id}</p>
              </div>
              <div>
                <span className="text-text-faint">Triggered Timestamp:</span>
                <p className="font-mono text-xs tabular-nums text-text-primary mt-0.5">
                  {alert.triggered_at?.slice(0, 19).replace("T", " ")} UTC
                </p>
              </div>
              {ruleMeta && (
                <>
                  <div>
                    <span className="text-text-faint">ATT&amp;CK Technique:</span>
                    <p className="font-mono text-xs font-semibold text-text-primary mt-0.5">{ruleMeta.technique}</p>
                  </div>
                  <div>
                    <span className="text-text-faint">ATT&amp;CK Tactic:</span>
                    <p className="font-medium text-text-primary mt-0.5 capitalize">{ruleMeta.tactic}</p>
                  </div>
                </>
              )}
              {alert.related_ip && (
                <div>
                  <span className="text-text-faint">Related Socket IP:</span>
                  <p className="font-mono text-xs font-bold text-risk-malicious mt-0.5">{alert.related_ip}</p>
                </div>
              )}
              {alert.related_pid && (
                <div>
                  <span className="text-text-faint">Related PID:</span>
                  <p className="font-mono text-xs tabular-nums text-text-primary mt-0.5">{alert.related_pid}</p>
                </div>
              )}
            </div>
          </div>

          {/* Details / Message */}
          <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3 space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">Detection Telemetry Details</span>
            <p className="text-[11px] leading-relaxed text-text-primary whitespace-pre-wrap">
              {alert.details || "Behavioral anomaly matched signature criteria."}
            </p>
          </div>

          {/* Raw Payload Block */}
          <div className="rounded-lg border border-border-subtle bg-bg-base p-3 space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">Raw Finding JSON</span>
            <pre className="max-h-48 overflow-y-auto text-[10px] font-mono text-text-muted leading-tight">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

const ACTIONS: { to: string; label: string; desc: string; icon: ReactNode }[] = [
  { to: "/monitor", label: "Detonate Sample", desc: "Dynamic sandbox analysis on local OS host", icon: <Icon name="play" size={13} /> },
  { to: "/events", label: "Telemetry Lake", desc: "Browse every raw kernel and socket event", icon: <Icon name="list" size={13} /> },
  { to: "/history", label: "Compare Sessions", desc: "Cross-run differential forensics analysis", icon: <Icon name="compare" size={13} /> },
  { to: "/watchlist", label: "IOC Watchlist", desc: "Track known-bad IPs, hashes, and domains", icon: <Icon name="star" size={13} /> },
];

export default function OverviewPage() {
  const queryClient = useQueryClient();
  const { preset } = useSocTimeRange();

  const [inspectAlert, setInspectAlert] = useState<AlertDrawerState | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");

  // Process-jump hover preview card state
  const [preview, setPreview] = useState<{ x: number; y: number; data: ProcessSummary } | null>(null);
  const previewTimer = useRef<number | null>(null);

  const showPreview = (e: ReactMouseEvent<HTMLAnchorElement>, pid: number) => {
    if (previewTimer.current !== null) window.clearTimeout(previewTimer.current);
    const r = e.currentTarget.getBoundingClientRect();
    previewTimer.current = window.setTimeout(() => {
      void getProcessSummary(pid)
        .then((data) =>
          setPreview({
            x: Math.max(8, Math.min(r.left, window.innerWidth - 336)),
            y: Math.max(8, Math.min(r.bottom + 8, window.innerHeight - 180)),
            data,
          }),
        )
        .catch(() => setPreview(null));
    }, 250);
  };

  const hidePreview = () => {
    if (previewTimer.current !== null) window.clearTimeout(previewTimer.current);
    setPreview(null);
  };

  // Real-time Event Stream Listener
  useEventStream(() => {
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["events"] });
    void queryClient.invalidateQueries({ queryKey: ["runs"] });
  });

  // Data Queries
  const { data: alertQueue } = useQuery({
    queryKey: ["alerts", "queue"],
    queryFn: () => getAlertQueue({ status: "open", limit: 50 }),
    refetchInterval: 10_000,
  });

  const { data: recentAlerts = [] } = useQuery({
    queryKey: ["alerts", "recent", 25],
    queryFn: () => getRecentAlerts(25),
    refetchInterval: 10_000,
  });

  const { data: fleet } = useQuery({
    queryKey: ["agents"],
    queryFn: () => getAgents(),
    refetchInterval: 15_000,
  });

  const { data: telemetryEvents } = useQuery({
    queryKey: ["events", "recent", 6],
    queryFn: () => getEvents({ limit: 6 }),
    refetchInterval: 5_000,
  });

  const { data: investigations } = useQuery({
    queryKey: ["investigations", "overview"],
    queryFn: () => listInvestigations({ limit: 4 }),
    refetchInterval: 30_000,
  });

  const { data: ruleMetaList = [] } = useQuery({
    queryKey: ["rules", "meta"],
    queryFn: getRuleMeta,
    staleTime: 60_000,
  });

  const { data: runs = [] } = useQuery({
    queryKey: ["runs", "overview"],
    queryFn: () => getRuns(overviewRunParams()),
    refetchInterval: 15_000,
  });

  const { data: hostPlatform } = useQuery({
    queryKey: ["platform"],
    queryFn: getPlatform,
    staleTime: Infinity,
  });

  const { data: engineHealth } = useQuery({
    queryKey: ["health"],
    queryFn: getHealth,
    refetchInterval: 10_000,
  });

  const ruleMap = useMemo(() => {
    const map = new Map<string, { tactic: string; technique: string; weight: number }>();
    for (const r of ruleMetaList) {
      map.set(r.rule_id, { tactic: r.tactic, technique: r.technique, weight: r.weight });
    }
    return map;
  }, [ruleMetaList]);

  // Mutations
  const ackMutation = useMutation({
    mutationFn: (id: number) => bulkUpdateAlertStatus([id], "acknowledged", "Acknowledged in Operations Overview"),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      if (inspectAlert && inspectAlert.alert.id) {
        setInspectAlert(null);
      }
      setActionNotice("Alert acknowledged successfully");
      setTimeout(() => setActionNotice(null), 2500);
    },
  });

  // KPI Calculations
  const rawAlerts = Array.isArray(alertQueue) ? alertQueue : (alertQueue?.alerts ?? []);
  const openAlerts = rawAlerts.filter((a) => a.status === "open" || !a.status);
  const criticalCount = openAlerts.filter((a) => a.severity === "malicious").length;
  const highCount = openAlerts.filter((a) => a.severity === "suspicious").length;

  const totalAgents = (fleet?.agents ?? []).length;
  const onlineAgents = (fleet?.agents ?? []).filter((a) => a.online).length;
  const totalEventsIngested = (fleet?.agents ?? []).reduce((acc, a) => acc + (a.event_count || 0), 0);

  const activeCases = (investigations?.investigations ?? []).filter(
    (i) => i.status !== "closed" && i.status !== "resolved"
  ).length;

  // Visual Posture Calculations
  const trendBars = useMemo(() => aggregateTrend(runs), [runs]);
  const peakRisk = useMemo(() => Math.max(0, ...runs.map((r) => r.risk_score ?? 0)), [runs]);
  const maliciousRuns = runs.filter((r) => r.highest_severity === "malicious").length;
  const suspiciousRuns = runs.filter((r) => r.highest_severity === "suspicious").length;
  const cleanRuns = Math.max(0, runs.length - maliciousRuns - suspiciousRuns);

  // Active ATT&CK Tactics Map
  const activeTactics = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of recentAlerts) {
      const meta = ruleMap.get(a.rule_id);
      if (meta && meta.tactic) {
        const norm = meta.tactic.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        counts.set(norm, (counts.get(norm) || 0) + 1);
      }
    }
    return counts;
  }, [recentAlerts, ruleMap]);

  const triggeredTactics = useMemo(() => {
    return ATTACK_TACTICS.filter((t) => (activeTactics.get(t.id) || 0) > 0);
  }, [activeTactics]);

  // Collapsed & Filtered Findings
  const collapsedFindings = useMemo(() => {
    const groups = collapseFindings(recentAlerts as GlobalAlert[]);
    const filtered = sevFilter === "all" ? groups : groups.filter((g) => g.first.severity === sevFilter);
    return sortFindingsRiskFirst(filtered, ruleMap as any);
  }, [recentAlerts, sevFilter, ruleMap]);

  const now = Date.now();

  const platIcon = hostPlatform ? platformIconName(hostPlatform.os) : "terminal";
  const platLabel = hostPlatform ? hostPlatform.name || hostPlatform.os : "detecting…";

  return (
    <div className="mx-auto max-w-7xl px-6 py-6 lg:px-10 space-y-6 font-sans text-xs">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
        <div>
          <span className="text-[10px] uppercase font-semibold tracking-wider text-text-faint">
            Operations Workstation · Observation Window: {preset.label}
          </span>
          <h1 className="text-xl font-bold text-text-primary tracking-tight">
            Security Operations Overview
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Enterprise threat detection triage, sensor fleet posture, and host telemetry lake.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-muted shadow-xs">
            <span className={`h-2 w-2 rounded-full ${engineHealth ? "bg-signal" : "bg-risk-malicious"}`} />
            <span className="font-semibold text-text-primary">{engineHealth ? "Engine Online" : "Engine Degraded"}</span>
            <span className="text-text-faint">· Live Ingest</span>
          </div>

          <Link
            to="/findings"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-text-muted hover:border-accent/40 hover:text-text-primary font-semibold transition shadow-xs"
          >
            <span>Triage Queue ({openAlerts.length})</span>
            <Icon name="arrowRight" size={11} />
          </Link>
        </div>
      </div>

      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-signal/50 bg-signal/15 px-4 py-2 text-xs text-signal animate-fade-in shadow-xs">
          <span className="font-medium">✓ {actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* Operational Telemetry Summary Ribbon (3 Cards) */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Host Fleet Telemetry */}
        <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface p-5 shadow-xs transition hover:border-accent/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-text-faint">Host Telemetry</span>
            <span className="flex items-center gap-1.5 font-mono text-[10px] text-risk-clean">
              <span className="h-1.5 w-1.5 rounded-full bg-risk-clean animate-pulse" />
              ingestion active
            </span>
          </div>
          <div className="my-3 flex items-baseline gap-3">
            <span className="font-mono text-3xl font-bold tracking-tight text-text-primary">{runs.length}</span>
            <span className="text-xs text-text-muted">monitored sessions</span>
          </div>
          <div className="flex flex-wrap items-center justify-between border-t border-border-subtle/60 pt-3 font-mono text-[11px] text-text-muted">
            <div className="flex items-center gap-2">
              <Link to="/agents" className="hover:text-accent font-semibold">
                {totalAgents || 1} host{totalAgents === 1 ? "" : "s"} enrolled
              </Link>
              <span className="text-text-faint">·</span>
              <span className="text-risk-clean">{onlineAgents || (runs.length > 0 ? 1 : 0)} online</span>
            </div>
            <Link to="/events" className="text-accent hover:underline text-[10px]">
              {totalEventsIngested.toLocaleString()} events →
            </Link>
          </div>
        </div>

        {/* Detection Queue */}
        <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface p-5 shadow-xs transition hover:border-risk-suspicious/40">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-text-faint">Detection Queue</span>
            <Link to="/findings" className="font-mono text-[10px] text-accent hover:underline">
              triage queue →
            </Link>
          </div>
          <div className="my-3 flex items-baseline gap-3">
            <span className={`font-mono text-3xl font-bold tracking-tight ${criticalCount > 0 ? "text-risk-malicious" : "text-text-primary"}`}>
              {openAlerts.length}
            </span>
            <span className="text-xs text-text-muted">active unacknowledged alerts</span>
          </div>
          <div className="flex items-center gap-2 border-t border-border-subtle/60 pt-3 font-mono text-[11px]">
            <span className="inline-flex items-center gap-1 rounded bg-risk-malicious/15 px-2 py-0.5 font-semibold text-risk-malicious border border-risk-malicious/30">
              {criticalCount} critical
            </span>
            <span className="inline-flex items-center gap-1 rounded bg-risk-suspicious/15 px-2 py-0.5 font-semibold text-risk-suspicious border border-risk-suspicious/30">
              {highCount} suspicious
            </span>
            <span className="ml-auto text-[10px] text-text-faint font-sans">
              {ruleMetaList.length} heuristics
            </span>
          </div>
        </div>

        {/* Incident Investigations */}
        <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface p-5 shadow-xs transition hover:border-accent/40 sm:col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-text-faint">Investigations</span>
            <Link to="/investigations" className="font-mono text-[10px] text-accent hover:underline">
              case files →
            </Link>
          </div>
          <div className="my-3 flex items-baseline gap-3">
            <span className="font-mono text-3xl font-bold tracking-tight text-text-primary">{activeCases}</span>
            <span className="text-xs text-text-muted">active case dossiers</span>
          </div>
          <div className="flex items-center justify-between border-t border-border-subtle/60 pt-3 font-mono text-[11px] text-text-muted">
            <span>{cleanRuns} clean baseline sessions</span>
            <span className="text-text-faint">IR SLA tracked</span>
          </div>
        </div>
      </div>

      {/* Threat Posture Visual Deck: Peak Risk Gauge, Severity Donut, and Risk Trend */}
      <div className="rounded-2xl border border-border-subtle bg-bg-surface p-5 shadow-xs">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/60 pb-3">
          <div>
            <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-text-faint">Threat Posture Telemetry</span>
            <h2 className="text-sm font-bold text-text-primary">Fleet Threat Score &amp; Session Distribution</h2>
          </div>
          <Link to="/history" className="font-mono text-[10px] text-accent hover:underline">
            session archive →
          </Link>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-center">
          <div className="lg:col-span-3 flex justify-center lg:justify-start border-b lg:border-b-0 lg:border-r border-border-subtle/60 pb-4 lg:pb-0 lg:pr-6">
            <RiskGauge score={peakRisk} />
          </div>

          <div className="lg:col-span-4 flex justify-center lg:justify-start border-b lg:border-b-0 lg:border-r border-border-subtle/60 pb-4 lg:pb-0 lg:pr-6">
            <SeverityDonut malicious={maliciousRuns} suspicious={suspiciousRuns} clean={cleanRuns} />
          </div>

          <div className="lg:col-span-5">
            <RiskTrendBars bars={trendBars} />
          </div>
        </div>
      </div>

      {/* 2-Column High-Density Operations Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Column 1 (Left 7 cols): High-Priority Alert Feed & Live Telemetry Stream */}
        <div className="lg:col-span-7 space-y-5">
          {/* Live Findings Feed */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs flex flex-col">
            <div className="p-3.5 border-b border-border-subtle bg-bg-elevated/40 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="font-bold text-text-primary text-xs">Live Findings Stream</span>
                <span className="rounded-full bg-bg-base border border-border-subtle px-2 py-0.2 font-mono text-[10px] tabular-nums text-text-muted">
                  {collapsedFindings.length}
                </span>
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-signal ml-1">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal" />
                  live · SSE
                </span>
              </div>

              <div className="flex items-center gap-2">
                {/* Severity Filter Toggle */}
                <div className="flex overflow-hidden rounded-md border border-border-subtle font-mono text-[10px]">
                  {(["all", "malicious", "suspicious"] as const).map((s) => (
                    <button
                      key={s}
                      onClick={() => setSevFilter(s)}
                      className={`px-2 py-0.5 transition-colors ${
                        sevFilter === s
                          ? s === "malicious"
                            ? "bg-risk-malicious/20 text-risk-malicious font-semibold"
                            : s === "suspicious"
                              ? "bg-risk-suspicious/20 text-risk-suspicious font-semibold"
                              : "bg-accent/15 text-accent font-semibold"
                          : "text-text-faint hover:text-text-muted"
                      }`}
                    >
                      {s === "all" ? "all" : s.slice(0, 4)}
                    </button>
                  ))}
                </div>

                <Link
                  to="/findings"
                  className="press text-[11px] font-semibold text-accent hover:underline inline-flex items-center gap-1"
                >
                  <span>Full Queue</span>
                  <Icon name="arrowRight" size={10} />
                </Link>
              </div>
            </div>

            <div className="divide-y divide-border-subtle/40">
              {collapsedFindings.length === 0 ? (
                <div className="px-4 py-12 text-center font-mono text-xs text-text-muted">
                  <p className="font-semibold text-text-primary">Monitoring active — 0 matching findings</p>
                  <p className="mt-1 text-[11px] text-text-faint">
                    No security heuristics or IOC alerts have triggered across ingested host telemetry in this window.
                  </p>
                </div>
              ) : (
                collapsedFindings.slice(0, 7).map((g) => {
                  const a = g.first;
                  const rule = ruleMap.get(a.rule_id);
                  const isMalicious = a.severity === "malicious";
                  const pids = a.related_pids ?? [];
                  const pid = a.related_pid ?? pids[0] ?? null;

                  return (
                    <div
                      key={g.key}
                      onClick={() => setInspectAlert({ alert: a, ruleMeta: rule })}
                      className="cursor-pointer p-3.5 hover:bg-bg-elevated/40 transition group flex flex-col gap-1.5"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`rounded px-1.5 py-0.2 text-[9px] uppercase font-bold shrink-0 ${
                            isMalicious
                              ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/30"
                              : "bg-risk-suspicious/20 text-risk-suspicious border border-risk-suspicious/30"
                          }`}
                        >
                          {a.severity.slice(0, 4)}
                        </span>

                        {/* Process Link with Hover Preview */}
                        {(() => {
                          if (a.rule_id === "enumeration-burst" && pids.length > 1) {
                            return (
                              <Link
                                to={`/events?pid=${pids.join(",")}`}
                                onMouseEnter={(e) => showPreview(e, pids[0])}
                                onMouseLeave={hidePreview}
                                onClick={(e) => e.stopPropagation()}
                                className="press inline-flex items-center gap-1 font-mono text-xs font-semibold text-risk-suspicious hover:underline"
                                title={`Recon sweep — ${pids.length} enumerating processes`}
                              >
                                {a.sample_name || "fleet-agent"}
                                <Icon name="terminal" size={11} className="opacity-80" />
                                <span className="rounded border border-risk-suspicious/50 bg-risk-suspicious/10 px-1 py-px text-[9px] uppercase tracking-wide">
                                  recon · {pids.length}
                                </span>
                              </Link>
                            );
                          }
                          return pid ? (
                            <Link
                              to={`/events?pid=${pid}`}
                              onMouseEnter={(e) => showPreview(e, pid)}
                              onMouseLeave={hidePreview}
                              onClick={(e) => e.stopPropagation()}
                              className="press inline-flex items-center gap-1 font-mono text-xs font-semibold text-text-primary hover:text-accent"
                              title={`Drill down into process ${pid} telemetry`}
                            >
                              {a.sample_name || `PID ${pid}`}
                              <Icon name="process" size={11} className="text-text-faint group-hover:text-accent" />
                            </Link>
                          ) : (
                            <span className="font-mono text-xs font-semibold text-text-primary">
                              {a.sample_name || "fleet-host"}
                            </span>
                          );
                        })()}

                        {/* Duplicate collapse badge */}
                        {g.count > 1 && (
                          <span
                            className="rounded-full border border-border-subtle bg-bg-elevated/70 px-1.5 py-px font-mono text-[10px] tabular-nums text-text-muted"
                            title={`${g.count} identical detections across ${g.runs.size} session(s) in 5 minutes`}
                          >
                            ×{g.count}
                          </span>
                        )}

                        <span className="text-xs font-semibold text-text-muted truncate max-w-xs group-hover:text-accent transition">
                          {a.rule_name}
                        </span>

                        {rule && (
                          <span
                            className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 font-mono text-[10px] text-text-faint ml-auto hidden sm:inline-block"
                            title={`MITRE ATT&CK ${rule.tactic}`}
                          >
                            {rule.technique} · {rule.tactic}
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 pt-0.5 text-[11px] font-mono text-text-faint">
                        <p className="truncate max-w-md text-text-muted leading-tight" title={a.details}>
                          {a.details || "Behavioral anomaly matched signature criteria."}
                        </p>

                        <div className="flex items-center gap-2 ml-auto" onClick={(e) => e.stopPropagation()}>
                          {a.status === "open" && a.id != null && (
                            <button
                              onClick={() => ackMutation.mutate(a.id!)}
                              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-[10px] text-text-muted hover:border-signal/50 hover:text-signal transition"
                              title="Acknowledge alert from dashboard"
                            >
                              <Icon name="check" size={9} />
                              <span>ack</span>
                            </button>
                          )}

                          {a.status === "open" ? (
                            <span
                              className={`rounded-full border px-1.5 py-px text-[9px] ${
                                ageBucket(a, now) === 2
                                  ? "border-risk-malicious/40 bg-risk-malicious/10 text-risk-malicious"
                                  : ageBucket(a, now) === 1
                                    ? "border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
                                    : "border-border-subtle text-text-faint"
                              }`}
                            >
                              {openSince(a, now)}
                            </span>
                          ) : (
                            <span className="text-text-faint uppercase font-bold text-[9px] px-1.5 py-0.5 rounded bg-bg-base border border-border-subtle">
                              {a.status}
                            </span>
                          )}

                          <span className="text-[10px] tabular-nums whitespace-nowrap">
                            {relativeTime(a.triggered_at)}
                          </span>

                          <button
                            onClick={() => setInspectAlert({ alert: a, ruleMeta: rule })}
                            className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] font-semibold text-text-muted hover:border-accent/40 hover:text-accent transition shadow-xs"
                          >
                            Inspect
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Live Ingest Lake Stream */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
            <div className="p-3.5 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-signal" />
                <span className="font-bold text-text-primary text-xs">Live Telemetry Lake Ingest</span>
              </div>
              <Link to="/events" className="press text-[11px] font-semibold text-accent hover:underline inline-flex items-center gap-1">
                <span>Full Telemetry Feed</span>
                <Icon name="arrowRight" size={10} />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-bg-elevated/60 border-b border-border-subtle text-[10px] uppercase font-semibold text-text-faint">
                  <tr>
                    <th className="px-4 py-2">Timestamp</th>
                    <th className="px-4 py-2">Host</th>
                    <th className="px-4 py-2">Event Type</th>
                    <th className="px-4 py-2">Process / Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/40">
                  {(!telemetryEvents || !telemetryEvents.events || telemetryEvents.events.length === 0) ? (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-text-muted font-mono">
                        No telemetry events recorded yet. Enrolled agent sensors push events in real time.
                      </td>
                    </tr>
                  ) : (
                    telemetryEvents.events.slice(0, 6).map((e: any, idx: number) => (
                      <tr key={idx} className="hover:bg-bg-elevated/30 transition">
                        <td className="px-4 py-2.5 font-mono tabular-nums text-text-faint text-[10px] whitespace-nowrap">
                          {e.timestamp ? e.timestamp.slice(11, 19) : "just now"}
                        </td>
                        <td className="px-4 py-2.5 text-text-muted text-[11px] font-mono whitespace-nowrap">
                          {e.host_id ? (
                            <Link to={`/hosts/${encodeURIComponent(e.host_id)}`} className="text-accent hover:underline">
                              {e.host_id}
                            </Link>
                          ) : (
                            "local"
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">
                            {e.event_type || e.type || "process_create"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-text-primary text-[11px] font-mono truncate max-w-xs" title={e.command_line || e.process_name || e.details}>
                          {e.process_name || e.command_line || e.details || "Telemetry record"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Column 2 (Right 5 cols): Sensor Fleet, Threat Posture, & Active Dossiers */}
        <div className="lg:col-span-5 space-y-5">
          {/* Enrolled Sensor Fleet Status */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 shadow-xs space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2.5">
              <div>
                <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">
                  Fleet Posture
                </span>
                <h3 className="font-bold text-text-primary text-xs">
                  Enrolled Endpoint Fleet
                </h3>
              </div>
              <Link to="/agents" className="text-[11px] font-semibold text-accent hover:underline">
                Manage Fleet →
              </Link>
            </div>

            <div className="space-y-2">
              {(!fleet || fleet.agents.length === 0) ? (
                <p className="py-4 text-center text-text-muted text-[11px] font-mono">
                  No sensor endpoints enrolled yet.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {fleet.agents.slice(0, 4).map((a) => (
                    <Link
                      key={a.host_id}
                      to={`/hosts/${encodeURIComponent(a.host_id)}`}
                      className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-base p-2.5 hover:border-accent/40 transition group shadow-xs"
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className={`h-2 w-2 rounded-full ${
                            a.online ? "bg-signal" : a.silent ? "bg-risk-malicious" : "bg-text-faint"
                          }`}
                        />
                        <div>
                          <span className="font-semibold text-text-primary group-hover:text-accent transition font-mono">
                            {a.host_id}
                          </span>
                          <div className="flex items-center gap-1 mt-0.5">
                            {a.platforms.map((p) => (
                              <span key={p} className="text-[10px] text-text-faint capitalize">
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>

                      <div className="text-right text-[11px]">
                        <span className="text-text-primary font-bold font-mono tabular-nums">{a.event_count.toLocaleString()}</span>
                        <span className="text-text-faint block text-[9px]">events</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* ATT&CK Adversarial Tactics & Detections */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 shadow-xs space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2.5">
              <div>
                <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">
                  Threat Framework
                </span>
                <h3 className="font-bold text-text-primary text-xs">
                  MITRE ATT&amp;CK Detections
                </h3>
              </div>
              <Link to="/coverage" className="text-[11px] font-semibold text-accent hover:underline">
                Matrix →
              </Link>
            </div>

            {triggeredTactics.length > 0 ? (
              <div className="space-y-1.5">
                {triggeredTactics.map((t) => (
                  <Link
                    key={t.id}
                    to={`/coverage?tactic=${t.id}`}
                    className="flex items-center justify-between rounded-lg border border-risk-malicious/40 bg-risk-malicious/10 p-2.5 text-xs font-semibold text-risk-malicious hover:bg-risk-malicious/15 transition shadow-xs"
                  >
                    <div className="flex items-center gap-2">
                      <Icon name="target" size={13} className="text-risk-malicious" />
                      <span>{t.label}</span>
                    </div>
                    <span className="font-mono text-[11px] tabular-nums font-bold">
                      {activeTactics.get(t.id)} detections
                    </span>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-border-subtle bg-bg-base/50 p-4 text-center space-y-1.5">
                <div className="flex items-center justify-center gap-1.5 text-signal font-semibold text-xs">
                  <Icon name="check" size={13} />
                  <span>Clean Operational Baseline</span>
                </div>
                <p className="text-[11px] text-text-muted">
                  Zero active adversary tactics triggered in this observation window. {ruleMetaList.length} detection heuristics actively monitoring sensor telemetry.
                </p>
                <Link to="/coverage" className="inline-block mt-1 text-[11px] font-semibold text-accent hover:underline">
                  Inspect Coverage Matrix →
                </Link>
              </div>
            )}

            <div className="pt-2 border-t border-border-subtle/50 flex items-center justify-between text-[10px] text-text-faint">
              <span>{ruleMetaList.length} heuristic signatures enrolled</span>
              <Link to="/rules" className="text-accent font-semibold hover:underline">
                Rule Studio →
              </Link>
            </div>
          </div>

          {/* Active Investigations Dossiers */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 shadow-xs space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2.5">
              <div>
                <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">
                  Case Management
                </span>
                <h3 className="font-bold text-text-primary text-xs">
                  Active Incident Investigations
                </h3>
              </div>
              <Link to="/investigations" className="text-[11px] font-semibold text-accent hover:underline">
                All Cases ({activeCases}) →
              </Link>
            </div>

            {(!investigations || !investigations.investigations || investigations.investigations.length === 0) ? (
              <div className="rounded-lg border border-border-subtle bg-bg-base/50 p-4 text-center">
                <p className="font-mono text-xs text-text-muted">No open investigation dossiers.</p>
                <p className="mt-1 text-[10px] text-text-faint">
                  Promote alerts from the triage queue into an investigation case dossier.
                </p>
              </div>
            ) : (
              <div className="space-y-1.5">
                {investigations.investigations.slice(0, 3).map((inv) => (
                  <Link
                    key={inv.id}
                    to={`/investigations/${inv.id}`}
                    className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-base p-2.5 hover:border-accent/40 transition group shadow-xs"
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-text-primary group-hover:text-accent transition truncate text-xs">
                          {inv.title || `Case #${inv.id.slice(0, 8)}`}
                        </span>
                        <span className="rounded bg-bg-surface border border-border-subtle px-1.5 py-0.2 font-mono text-[9px] uppercase tracking-wide text-text-muted">
                          {inv.status}
                        </span>
                      </div>
                      <span className="text-[10px] text-text-faint block mt-0.5 font-mono">
                        Updated {relativeTime(inv.updated_at || inv.created_at)}
                      </span>
                    </div>

                    <Icon name="arrowRight" size={11} className="text-text-faint group-hover:text-accent shrink-0" />
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Host Environment & Quick Action Strip */}
      <section className="rounded-xl border border-border-subtle bg-bg-surface p-4 shadow-xs" aria-label="Actions and environment">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:gap-6">
          {/* Quick actions */}
          <div className="flex flex-wrap items-center gap-2">
            {ACTIONS.map((a) => (
              <Link
                key={a.to}
                to={a.to}
                title={a.desc}
                className="press group inline-flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-base px-3 py-2 text-xs font-semibold text-text-muted transition hover:border-accent/40 hover:text-text-primary shadow-xs"
              >
                <span className="text-accent">{a.icon}</span>
                <span>{a.label}</span>
                <Icon
                  name="arrowRight"
                  size={10}
                  className="text-text-faint transition group-hover:translate-x-0.5 group-hover:text-accent"
                />
              </Link>
            ))}
          </div>

          {/* Host system environment telemetry */}
          <div className="flex items-center gap-3 border-t border-border-subtle pt-3 lg:ml-auto lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent shadow-xs">
              <Icon name={platIcon} size={15} />
            </span>
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold text-text-primary">{platLabel}</p>
              <p className="truncate font-mono text-[10px] text-text-faint">
                {hostPlatform ? `${hostPlatform.os} ${hostPlatform.release} · ${hostPlatform.machine}` : "detecting…"}
              </p>
            </div>
            <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent font-semibold">
              {hostPlatform?.collector ?? "local"}
            </span>
            <span
              className={`flex items-center gap-1.5 text-[10px] font-medium font-mono ${
                engineHealth ? "text-risk-clean" : "text-risk-malicious"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${engineHealth ? "animate-pulse bg-risk-clean" : "bg-risk-malicious"}`} />
              {engineHealth ? "online" : "offline"}
            </span>
          </div>
        </div>
      </section>

      {/* Floating Process Hover Preview Card */}
      {preview && (
        <div
          role="tooltip"
          className="pointer-events-none fixed z-50 w-80 overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-2xl font-sans"
          style={{ left: preview.x, top: preview.y }}
        >
          <div className="flex items-center gap-2 border-b border-border-subtle bg-bg-elevated/40 px-3 py-2">
            <Icon name="process" size={13} className="shrink-0 text-accent" />
            <span className="truncate font-mono text-xs font-semibold text-text-primary">
              {preview.data.process_name ?? `pid ${preview.data.pid}`}
            </span>
            <span className="ml-auto shrink-0 font-mono text-[10px] text-text-faint">pid {preview.data.pid}</span>
          </div>
          <div className="space-y-2 px-3 py-2.5">
            {preview.data.command_line && (
              <p className="truncate font-mono text-[10px] text-text-muted" title={preview.data.command_line}>
                {preview.data.command_line}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
              <span className="inline-flex items-center gap-1">
                <Icon name={platformIconName(preview.data.platform)} size={10} />
                {preview.data.platform}
              </span>
              <span>
                {preview.data.event_count} event{preview.data.event_count === 1 ? "" : "s"}
              </span>
              {(preview.data.children?.length ?? 0) > 0 && (
                <span>
                  {preview.data.children!.length} child{preview.data.children!.length === 1 ? "" : "ren"}
                </span>
              )}
              {(preview.data.network_connections?.length ?? 0) > 0 && (
                <span>
                  {preview.data.network_connections!.length} socket{preview.data.network_connections!.length === 1 ? "" : "s"}
                </span>
              )}
              <span className={preview.data.alert_count > 0 ? "text-risk-suspicious font-semibold" : ""}>
                {preview.data.alert_count} alert{preview.data.alert_count === 1 ? "" : "s"}
              </span>
            </div>
            {preview.data.run_id && (
              <Link
                to={`/runs/${preview.data.run_id}`}
                className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline"
              >
                {preview.data.sample_name || "run details"}
                <Icon name="arrowRight" size={9} className="opacity-60" />
              </Link>
            )}
          </div>
        </div>
      )}

      {/* Slide-over Alert Inspector Drawer */}
      {inspectAlert && (
        <AlertInspectorDrawer
          data={inspectAlert}
          onClose={() => setInspectAlert(null)}
          onAcknowledge={(id) => {
            if (id) ackMutation.mutate(id);
          }}
        />
      )}
    </div>
  );
}
