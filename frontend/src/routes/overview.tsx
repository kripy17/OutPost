import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { copyToClipboard } from "../lib/clipboard";
import { useSocTimeRange } from "../lib/useSocTimeRange";
import {
  bulkUpdateAlertStatus,
  getAgents,
  getAlertQueue,
  getEvents,
  getRecentAlerts,
  getRuleMeta,
  listInvestigations,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import type { GlobalAlert, QueueAlert } from "../types";

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

export default function OverviewPage() {
  const queryClient = useQueryClient();
  const { preset } = useSocTimeRange();

  const [inspectAlert, setInspectAlert] = useState<AlertDrawerState | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

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
    queryKey: ["alerts", "recent", 15],
    queryFn: () => getRecentAlerts(15),
    refetchInterval: 10_000,
  });

  const { data: fleet } = useQuery({
    queryKey: ["agents"],
    queryFn: () => getAgents(),
    refetchInterval: 15_000,
  });

  const { data: telemetryEvents } = useQuery({
    queryKey: ["events", "recent", 8],
    queryFn: () => getEvents({ limit: 8 }),
    refetchInterval: 5_000,
  });

  const { data: investigations } = useQuery({
    queryKey: ["investigations", "count"],
    queryFn: () => listInvestigations({ limit: 100 }),
    refetchInterval: 30_000,
  });

  const { data: ruleMetaList = [] } = useQuery({
    queryKey: ["rules", "meta"],
    queryFn: getRuleMeta,
    staleTime: 60_000,
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
      setActionNotice("Alert acknowledged");
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
  const coveragePct = totalAgents > 0 ? Math.round((onlineAgents / totalAgents) * 100) : 100;

  const activeCases = (investigations?.investigations ?? []).filter(
    (i) => i.status !== "closed" && i.status !== "resolved"
  ).length;
  const totalEventsIngested = (fleet?.agents ?? []).reduce((acc, a) => acc + (a.event_count || 0), 0);

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

  return (
    <div className="mx-auto max-w-7xl px-6 py-6 lg:px-10 space-y-6 font-sans text-xs">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
        <div>
          <span className="text-[10px] uppercase font-semibold tracking-wider text-text-faint">
            Operations Overview · Time Window: {preset.label}
          </span>
          <h1 className="text-xl font-bold text-text-primary tracking-tight">
            Security Operations Overview
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Enterprise threat detection posture, sensor fleet status, and active security findings.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-muted shadow-xs">
            <span className="h-2 w-2 rounded-full bg-signal" />
            <span className="font-semibold text-text-primary">Engine Online</span>
            <span className="text-text-faint">· Live Ingest</span>
          </div>

          <Link
            to="/findings"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-text-muted hover:border-accent/40 hover:text-text-primary font-semibold transition shadow-xs"
          >
            <span>Triage Queue</span>
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

      {/* KPI Metric Strip (5 Cards) */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Link
          to="/investigations"
          className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs hover:border-accent/40 transition group"
        >
          <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">Active Cases</span>
          <p className="mt-1 text-lg font-bold text-text-primary font-mono tabular-nums">{activeCases}</p>
          <span className="text-[10px] text-text-faint group-hover:text-accent transition">
            {activeCases === 0 ? "Zero open escalations" : "Open incident dossiers"}
          </span>
        </Link>

        <Link
          to="/findings"
          className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs hover:border-accent/40 transition group"
        >
          <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">Unresolved Findings</span>
          <p className="mt-1 text-lg font-bold font-mono tabular-nums">
            <span className={criticalCount > 0 ? "text-risk-malicious" : "text-text-primary"}>
              {openAlerts.length}
            </span>
            <span className="text-[11px] text-text-faint font-normal font-sans ml-1.5">
              ({criticalCount} crit · {highCount} high)
            </span>
          </p>
          <span className="text-[10px] text-text-faint group-hover:text-accent transition">Awaiting analyst triage</span>
        </Link>

        <Link
          to="/agents"
          className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs hover:border-accent/40 transition group"
        >
          <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">Sensor Fleet</span>
          <p className="mt-1 text-lg font-bold text-risk-clean font-mono tabular-nums">
            {coveragePct}%
            <span className="text-[11px] text-text-faint font-normal font-sans ml-1.5">
              ({onlineAgents}/{totalAgents} online)
            </span>
          </p>
          <span className="text-[10px] text-text-faint group-hover:text-accent transition">Monitored endpoints</span>
        </Link>

        <Link
          to="/events"
          className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs hover:border-accent/40 transition group"
        >
          <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">Telemetry Ingested</span>
          <p className="mt-1 text-lg font-bold text-accent font-mono tabular-nums">
            {totalEventsIngested.toLocaleString()}
          </p>
          <span className="text-[10px] text-text-faint group-hover:text-accent transition">Events processed</span>
        </Link>

        <Link
          to="/coverage"
          className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs hover:border-accent/40 transition group"
        >
          <span className="text-[10px] uppercase font-semibold text-text-faint tracking-wider">ATT&amp;CK Techniques</span>
          <p className="mt-1 text-lg font-bold text-text-primary font-mono tabular-nums">
            {ruleMetaList.length}
          </p>
          <span className="text-[10px] text-text-faint group-hover:text-accent transition">Active detection rules</span>
        </Link>
      </div>

      {/* 2-Column Operations Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Column 1 (Left 7 cols): High-Priority Alert Feed & Live Telemetry Stream */}
        <div className="lg:col-span-7 space-y-5">
          {/* High-Priority Security Alerts */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs flex flex-col">
            <div className="p-3.5 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="font-bold text-text-primary text-xs">High-Priority Alert Feed</span>
                <span className="rounded-full bg-bg-base border border-border-subtle px-2 py-0.2 font-mono text-[10px] tabular-nums text-text-muted">
                  {recentAlerts.length}
                </span>
              </div>
              <Link
                to="/findings"
                className="press text-[11px] font-semibold text-accent hover:underline inline-flex items-center gap-1"
              >
                <span>Full Queue</span>
                <Icon name="arrowRight" size={10} />
              </Link>
            </div>

            <div className="flex-1 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-bg-elevated/60 border-b border-border-subtle text-[10px] uppercase font-semibold text-text-faint">
                  <tr>
                    <th className="px-4 py-2">Sev</th>
                    <th className="px-4 py-2">Rule Signature / Technique</th>
                    <th className="px-4 py-2">Host</th>
                    <th className="px-4 py-2">Observed</th>
                    <th className="px-4 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/40">
                  {recentAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-10 text-center text-text-muted">
                        No security alerts triggered in the selected observation window.
                      </td>
                    </tr>
                  ) : (
                    recentAlerts.slice(0, 6).map((a, idx) => {
                      const meta = ruleMap.get(a.rule_id);
                      const isMalicious = a.severity === "malicious";
                      return (
                        <tr
                          key={idx}
                          onClick={() => setInspectAlert({ alert: a, ruleMeta: meta })}
                          className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                        >
                          <td className="px-4 py-2.5">
                            <span
                              className={`rounded px-1.5 py-0.2 text-[9px] uppercase font-bold ${
                                isMalicious
                                  ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/30"
                                  : "bg-risk-suspicious/20 text-risk-suspicious border border-risk-suspicious/30"
                              }`}
                            >
                              {a.severity.slice(0, 4)}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 min-w-48">
                            <div className="font-semibold text-text-primary group-hover:text-accent transition truncate" title={a.rule_name}>
                              {a.rule_name}
                            </div>
                            {meta && (
                              <div className="text-[10px] font-mono text-text-faint mt-0.5">
                                {meta.technique} · {meta.tactic}
                              </div>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-text-muted text-[11px] font-mono">
                            {a.related_ip || "fleet-host"}
                          </td>
                          <td className="px-4 py-2.5 text-text-faint text-[11px] whitespace-nowrap">
                            {relativeTime(a.triggered_at)}
                          </td>
                          <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={() => setInspectAlert({ alert: a, ruleMeta: meta })}
                              className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] font-semibold text-text-muted hover:border-accent/40 hover:text-accent transition shadow-xs"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Live Telemetry Event Stream */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
            <div className="p-3.5 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-signal" />
                <span className="font-bold text-text-primary text-xs">Live Telemetry Event Stream</span>
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
                      <td colSpan={4} className="px-4 py-8 text-center text-text-muted">
                        No telemetry events recorded yet. Enrolled agent sensors push events in real time.
                      </td>
                    </tr>
                  ) : (
                    telemetryEvents.events.slice(0, 5).map((e: any, idx: number) => (
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

        {/* Column 2 (Right 5 cols): Enrolled Endpoint Fleet & ATT&CK Detection Posture */}
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
                <p className="py-4 text-center text-text-muted text-[11px]">
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
        </div>
      </div>

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
