import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import PersistencePanel from "../components/PersistencePanel/PersistencePanel";
import AlertRate from "../components/AlertRate/AlertRate";
import PlantStrip from "../components/PlantStrip/PlantStrip";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { killChainStats } from "../components/KillChain/killChain";
import KillChainStepper from "../components/KillChain/KillChainStepper";
import { Panel, ProvenanceBadge, SourceBadge } from "../components/ui";
import { connectionSources, resolvePids } from "./runDetailHelpers";
import NotesPanel from "../components/NotesPanel/NotesPanel";
import ProcessTree from "../components/ProcessTree/ProcessTree";
import { ProcessGraph } from "../components/ProcessGraph";
import { DetectionStudioModal } from "../components/DetectionStudioModal";
import { AllowlistPanel, QuickAllowlist, SuppressionPanel } from "../components/TriagePanels/TriagePanels";
import RulesPanel from "../components/RulesPanel/RulesPanel";
import TimelineView from "../components/TimelineView/TimelineView";
import Topology from "../components/Topology/Topology";
import { NetworkProtocolInspector } from "../components/NetworkProtocolInspector";
import { RISK_COLORS, enumKindsFromDetails, intelAgeLabel, riskBand } from "../lib/constants";
import { addInvestigationRef, bulkUpdateAlertStatus, getCampaigns, getRunDetail, getRunIocsCsv, getSandboxArtifactUrl, listInvestigations, listSandboxArtifacts, markFalsePositive, reEnrichRun, refreshIpIntel, updateAlertStatus } from "../lib/api";
import type { AlertStatus, NetworkConnection, ProcessNode, Reputation, RunDetail } from "../types";

/* ── Risk gauge — semicircular arc, colored by band ────────────────────── */

function RiskGauge({ score }: { score: number }) {
  const band = riskBand(score);
  const s = score ?? 0;
  const arcLen = Math.PI * 54;
  const frac = Math.min(1, Math.max(0, s / 100));
  const tone = band.color.replace("text-risk-", "");
  return (
    <div className="flex items-center gap-3" title={`Risk score ${s}/100 — ${band.label}`}>
      <svg viewBox="0 0 140 78" className="h-[74px] w-[130px]" role="img" aria-label={`Risk score ${s}/100, ${band.label}`}>
        <path d="M 16 70 A 54 54 0 0 1 124 70" fill="none" stroke="var(--border-strong)" strokeOpacity="0.5" strokeWidth="9" strokeLinecap="round" />
        <path
          d="M 16 70 A 54 54 0 0 1 124 70"
          fill="none"
          stroke={`var(--risk-${tone})`}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${frac * arcLen} ${arcLen}`}
        />
        <text x="70" y="56" textAnchor="middle" className="fill-current font-mono" fontSize="21" fontWeight="700">
          {s}
        </text>
        <text x="70" y="71" textAnchor="middle" fontSize="8" fill="var(--text-faint)">
          {band.label} / 100
        </text>
      </svg>
    </div>
  );
}

/* ── Network — grouped by reputation, so risk reads at a glance ────────── */

const REP_ORDER: Reputation[] = ["malicious", "suspicious", "unknown", "clean"];

const REP_META: Record<Reputation, { label: string; dot: string; text: string; border: string }> = {
  malicious: { label: "Malicious", dot: "bg-risk-malicious", text: "text-risk-malicious", border: "border-risk-malicious/30" },
  suspicious: { label: "Suspicious", dot: "bg-risk-suspicious", text: "text-risk-suspicious", border: "border-risk-suspicious/30" },
  unknown: { label: "Unknown", dot: "bg-text-faint", text: "text-text-muted", border: "border-border-subtle" },
  clean: { label: "Clean", dot: "bg-risk-clean", text: "text-risk-clean", border: "border-risk-clean/30" },
};

function NetworkGroups({ connections, runId }: { connections: NetworkConnection[]; runId: string }) {
  const queryClient = useQueryClient();
  const [refreshingIp, setRefreshingIp] = useState<string | null>(null);
  const refresh = useMutation({
    mutationFn: (ip: string) => refreshIpIntel(runId, ip),
    onMutate: (ip) => setRefreshingIp(ip),
    onSettled: () => {
      setRefreshingIp(null);
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    },
  });

  if (connections.length === 0) return <p className="text-sm text-text-muted">No network connections recorded for this run.</p>;
  const groups = REP_ORDER.map((rep) => ({ rep, items: connections.filter((c) => c.reputation === rep) })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-3">
      {groups.map(({ rep, items }) => {
        const meta = REP_META[rep];
        const flagged = items.filter((c) => (c.vt_malicious_count ?? 0) > 0).length;
        return (
          <section key={rep} className={`rounded-xl border ${meta.border} bg-bg-elevated/30`}>
            <header className={`flex items-center gap-2 border-b ${meta.border} px-3 py-2`}>
              <span className={`h-2 w-2 rounded-full ${meta.dot}`} aria-hidden />
              <span className={`text-xs font-semibold ${meta.text}`}>{meta.label}</span>
              <span className="font-mono text-[10px] text-text-faint">
                {items.length} destination{items.length === 1 ? "" : "s"}
              </span>
              {flagged > 0 && (
                <span className="ml-auto inline-flex items-center gap-1 font-mono text-[10px] text-risk-malicious">
                  <Icon name="alert" size={10} />
                  {flagged} VT-flagged
                </span>
              )}
            </header>
            <ul className="divide-y divide-border-subtle/50">
              {items.map((c) => {
                // Source attribution — why this IP sits in this group: the
                // feeds that produced the verdict (watchlist / AbuseIPDB /
                // VirusTotal / none), on hover over the address.
                const srcParts = connectionSources(c);
                const srcTip = `Reputation ${c.reputation ?? "unknown"} — ${srcParts.join(" · ")}`;
                return (
                <li key={`${c.dest_ip}-${c.dest_port}`} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 font-mono text-xs">
                  <span className={`font-semibold ${RISK_COLORS[c.reputation]}`} title={srcTip}>
                    {c.dest_ip}
                    <Icon name="eye" size={9} className="ml-1 opacity-50" aria-label="Reputation sources" />
                  </span>
                  <span className="text-text-faint">:{c.dest_port ?? "—"}</span>
                  <span className="rounded border border-border-subtle px-1 py-px text-[9px] uppercase text-text-faint">
                    {c.protocol ?? "?"}
                  </span>
                  {c.watchlist && (
                    <span className="inline-flex items-center gap-0.5 text-accent" title={c.watchlist_label ?? "On your watchlist"}>
                      <Icon name="star" size={10} />
                    </span>
                  )}
                  <span className="ml-auto flex items-center gap-3 text-[10px] text-text-faint">
                    {c.abuse_score !== null && <span title="AbuseIPDB score">abuse {c.abuse_score}</span>}
                    {c.vt_malicious_count !== null && (
                      <span className={c.vt_malicious_count > 0 ? "text-risk-malicious" : ""} title="VirusTotal positives">
                        vt {c.vt_malicious_count}
                      </span>
                    )}
                    {c.malware_family && <span className="text-risk-malicious">{c.malware_family}</span>}
                    <span>{c.first_seen.slice(11, 19)}</span>
                    {/* Reputation cache age — "checked 5h ago", so staleness is
                        visible before an analyst trusts a verdict. */}
                    {c.checked_at && (
                      <span title={`Reputation fetched ${c.checked_at} UTC`}>{intelAgeLabel(c.checked_at)}</span>
                    )}
                    {/* Force refresh — bypass the enrichment TTL ONCE for this
                        IP and re-query with the current keys. */}
                    <button
                      onClick={() => refresh.mutate(c.dest_ip)}
                      disabled={refresh.isPending}
                      className="press text-text-faint transition-colors hover:text-accent disabled:opacity-40"
                      title="Force refresh — bypass the reputation cache (TTL) once and re-query with the current keys"
                      aria-label={`Force-refresh reputation for ${c.dest_ip}`}
                    >
                      <Icon name="refresh" size={10} className={refresh.isPending && refreshingIp === c.dest_ip ? "animate-spin" : ""} />
                    </button>
                  </span>
                  {/* Two-click allowlist quick-add — whitelist this destination
                      for the run without opening the panel. */}
                  <QuickAllowlist runId={runId} kind="ip" value={c.dest_ip} />
                </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

/* ── Sample reputation ─────────────────────────────────────────────────── */

function SampleReputation({ rep }: { rep: NonNullable<RunDetail["sample_reputation"]> }) {
  const hasIntel = rep.vt_detections !== null || rep.malware_family !== null;
  return (
    <Panel kicker="Intel · sample" title="Uploaded binary" className="mt-6">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span className="text-text-faint">SHA-256</span>
          <code className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 text-text-primary">
            {rep.sha256.slice(0, 32)}…
          </code>
        </div>
        {hasIntel ? (
          <div className="flex flex-wrap items-center gap-2">
            {rep.malware_family && (
              <span className="rounded border border-risk-malicious/40 bg-risk-malicious/10 px-2 py-0.5 font-mono text-[11px] text-risk-malicious">
                {rep.malware_family}
              </span>
            )}
            <span className="font-mono text-[10px] text-text-faint">
              {rep.vt_detections ?? 0} VirusTotal detection{rep.vt_detections === 1 ? "" : "s"}
            </span>
          </div>
        ) : (
          <p className="text-xs text-text-muted">No external intel configured — YARA scan ran locally.</p>
        )}
        {rep.yara_rules.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {rep.yara_rules.map((r) => (
              <span key={r} className="rounded border border-accent/40 bg-bg-elevated/50 px-2 py-0.5 font-mono text-[10px] text-accent">
                {r}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-xs text-text-muted">No YARA signatures matched this binary.</p>
        )}
      </div>
    </Panel>
  );
}

function KillChainCard({ links }: { links: RunDetail["kill_chain"] }) {
  if (!links || links.length === 0) return null;
  const label = links.map((l) => l.from).concat(links[links.length - 1].to).join(" → ");
  return (
    <Panel kicker="Correlation" title="Kill-chain sequence" className="mt-6">
      <p className="mb-3 font-mono text-xs text-text-primary">{label}</p>
      <ol className="flex flex-wrap items-center gap-1.5">
        {links.map((l, i) => (
          <li key={i} className="flex items-center gap-1.5">
            <span className="rounded border border-accent/50 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
              {l.from}
            </span>
            <span aria-hidden className="font-mono text-[10px] text-text-faint">
              <Icon name="chevronRight" size={10} />
            </span>
            {i === links.length - 1 && (
              <span className="rounded border border-risk-malicious/50 bg-risk-malicious/10 px-2 py-0.5 font-mono text-[10px] text-risk-malicious">
                {l.to}
              </span>
            )}
          </li>
        ))}
      </ol>
    </Panel>
  );
}

/* ── Recon actors — the processes behind a Discovery enumeration sweep ─── */

/** Flatten the process tree into a pid → {name, command} lookup. */
function ReconActorsPanel({
  alerts,
  tree,
  onLocate,
}: {
  alerts: RunDetail["alerts"];
  tree: RunDetail["process_tree"];
  /** Scroll the process tree into view and flash the actor node. */
  onLocate: (pid: number) => void;
}) {
  const burst = alerts.filter((a) => a.rule_id === "enumeration-burst");
  if (burst.length === 0) return null;

  // Union of all enumerating pids across bursts, in first-seen order.
  const pids: number[] = [];
  for (const a of burst) {
    for (const p of a.related_pids ?? []) if (!pids.includes(p)) pids.push(p);
  }
  const actors = [...resolvePids(tree, pids).values()];
  const kinds = enumKindsFromDetails(burst[0].details);

  return (
    <Panel
      kicker="Recon · T1082"
      title="Recon actors"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {burst.length} sweep{burst.length === 1 ? "" : "s"} · {pids.length} process{pids.length === 1 ? "" : "es"}
        </span>
      }
    >
      {kinds.length > 0 && (
        <p className="mb-3 flex flex-wrap gap-1.5">
          {kinds.map((k) => (
            <span
              key={k}
              className="rounded border border-risk-suspicious/40 bg-risk-suspicious/10 px-1.5 py-0.5 font-mono text-[9px] text-risk-suspicious"
            >
              {k}
            </span>
          ))}
        </p>
      )}
      {actors.length === 0 ? (
        <p className="text-xs text-text-muted">
          The sweep fired, but its actor processes are outside this run's recorded tree.
        </p>
      ) : (
        <ul className="divide-y divide-border-subtle/60">
          {actors.map((a) => (
            <li key={a.pid}>
              <button
                onClick={() => onLocate(a.pid)}
                className="press group flex w-full items-center gap-2 rounded px-1 py-1.5 text-left font-mono text-xs transition-colors hover:bg-bg-elevated"
                title={`Locate ${a.process_name ?? `pid ${a.pid}`} in the process tree`}
              >
                <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-dashed border-risk-suspicious/70 px-1.5 py-0.5 font-mono text-[9px] text-risk-suspicious">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-risk-suspicious" aria-hidden />
                  recon
                </span>
                <span className="text-text-primary">{a.process_name ?? "—"}</span>
                <span className="text-text-faint">[{a.pid}]</span>
                {a.command_line && <span className="truncate text-[10px] text-text-muted">{a.command_line}</span>}
                <Icon
                  name="arrowRight"
                  size={12}
                  className="ml-auto shrink-0 text-text-faint transition-colors group-hover:text-accent"
                />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/* ── Page ──────────────────────────────────────────────────────────────── */

export default function RunDetailPage() {
  const { runId = "" } = useParams();
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRunDetail(runId),
    refetchInterval: (query) => {
      const run = query.state.data?.run;
      return run && run.completed_at === null ? 3000 : false;
    },
  });

  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: () => getCampaigns() });

  // Re-enrich: clears the run's cached intel on the backend, then refetches
  // this page so the network table shows the freshly-queried badges.
  const reEnrich = useMutation({
    mutationFn: (rid: string) => reEnrichRun(rid),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["run", runId] }),
  });

  // All hooks above the early returns — Rules of Hooks. Flash target for the
  // recon-actors list: clicking an actor scrolls to the process tree and
  // rings its node once. Cleared after the 1.4s animation.
  const [flashPid, setFlashPid] = useState<number | null>(null);
  const flashTimer = useRef<number | null>(null);
  useEffect(() => () => {
    if (flashTimer.current !== null) window.clearTimeout(flashTimer.current);
  }, []);
  const onLocate = (pid: number) => {
    document.getElementById("process-tree-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
    setFlashPid(pid);
    if (flashTimer.current !== null) window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlashPid(null), 1500);
  };

  // Select-to-filter (the spec's highest-value interaction): clicking a
  // process node narrows the network + timeline panels to what THAT pid did.
  // Network rows don't carry a pid, so the filter uses the node's reached
  // IPs — the same list the halo annotation comes from.
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  // Memoized so the `?? []` fallback never hands the walk useMemo a fresh
  // array identity on every render (that would defeat its caching and re-walk
  // the whole tree each render).
  const treeData = useMemo(() => data?.process_tree ?? [], [data]);
  const timelineEvents = data?.timeline ?? [];
  const netData = data?.network_connections ?? [];
  const selectedNode = useMemo(() => {
    if (selectedPid === null) return null;
    const walk = (ns: RunDetail["process_tree"]): ProcessNode | null => {
      for (const n of ns) {
        if (n.pid === selectedPid) return n;
        const hit = walk(n.children);
        if (hit) return hit;
      }
      return null;
    };
    return walk(treeData);
  }, [selectedPid, treeData]);
  const selectedIps = useMemo(() => new Set(selectedNode?.network_ips ?? []), [selectedNode]);
  const filteredTimeline = selectedPid === null ? timelineEvents : timelineEvents.filter((e) => e.pid === selectedPid);
  // Plant focus (recurring fan-out): clicking a plant IP in the strip pins
  // the network table to just that destination — takes priority over the
  // process filter since the plant IP is the finding.
  const [focusIp, setFocusIp] = useState<string | null>(null);
  const [showRulesStudio, setShowRulesStudio] = useState(false);
  const [showAttachCase, setShowAttachCase] = useState(false);
  const [attachingCaseId, setAttachingCaseId] = useState<string>("");
  const [attachMsg, setAttachMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [processViewMode, setProcessViewMode] = useState<"tree" | "graph">("graph");

  const { data: investigationsData } = useQuery({
    queryKey: ["investigations", "all"],
    queryFn: () => listInvestigations({ limit: 50 }),
    enabled: showAttachCase,
  });
  const { data: runArtifacts = [] } = useQuery({
    queryKey: ["sandbox", "artifacts", runId],
    queryFn: () => listSandboxArtifacts(runId),
    enabled: Boolean(runId),
  });
  const filteredConnections =
    focusIp !== null
      ? netData.filter((c) => c.dest_ip === focusIp)
      : selectedPid === null || selectedIps.size === 0
        ? netData
        : netData.filter((c) => selectedIps.has(c.dest_ip));

  // Small "focusing on …" bar above the filtered panels (a JSX value, not a
  // render-time component — creating components in render remounts them).
  const focusBar =
    selectedPid !== null || focusIp !== null ? (
      <p className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent/5 px-3 py-1.5 font-mono text-[11px] text-accent">
        {focusIp !== null ? (
          <span>
            <Icon name="network" size={12} className="mr-1.5" />
            focusing on plant IP <span className="text-text-primary">{focusIp}</span>
          </span>
        ) : (
          <span>
            <Icon name="process" size={12} />
            focusing on {selectedNode?.process_name ?? `pid ${selectedPid}`}
            <span className="text-text-faint"> [{selectedPid}]</span>
          </span>
        )}
        <span className="text-text-faint">
          · {filteredTimeline.length} timeline event{filteredTimeline.length === 1 ? "" : "s"}
          · {filteredConnections.length} connection{filteredConnections.length === 1 ? "" : "s"}
        </span>
        <button
          onClick={() => {
            setSelectedPid(null);
            setFocusIp(null);
          }}
          className="press ml-auto inline-flex items-center gap-1 rounded border border-border-subtle px-2 py-0.5 text-[10px] text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
        >
          <Icon name="x" size={10} />
          clear focus
        </button>
      </p>
    ) : null;

  // Recon ring in the tree (matches the Monitor): pids behind enumeration-burst.
  const reconPids = useMemo(() => {
    const set = new Set<number>();
    for (const a of (data?.alerts ?? [])) {
      if (a.rule_id === "enumeration-burst") (a.related_pids ?? []).forEach((p) => set.add(p));
    }
    return set;
  }, [data?.alerts]);

  // Alert triage: status transitions invalidate the run query so the pills,
  // the open-count header, and the kill chain all re-read fresh state.
  const onAlertStatus = useCallback(
    (alertId: number, status: AlertStatus, comment?: string) => {
      void updateAlertStatus(alertId, status, comment)
        .then(() => queryClient.invalidateQueries({ queryKey: ["run", runId] }))
        .catch(() => undefined);
    },
    [runId, queryClient],
  );

  // Bulk triage — one Ack/Resolve across many selected alerts.
  const onBulkAlertStatus = useCallback(
    (ids: number[], status: AlertStatus) => {
      void bulkUpdateAlertStatus(ids, status)
        .then(() => queryClient.invalidateQueries({ queryKey: ["run", runId] }))
        .catch(() => undefined);
    },
    [runId, queryClient],
  );

  // FP feedback loop — resolve as false positive, bump the rule's FP counter,
  // return the tuning/suppression suggestions for one-click follow-ups.
  const onMarkFalsePositive = useCallback(
    async (alertId: number, comment?: string) => {
      const resp = await markFalsePositive(alertId, comment ?? "");
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
      void queryClient.invalidateQueries({ queryKey: ["rules-meta"] });
      return resp;
    },
    [runId, queryClient],
  );

  if (isLoading) return <p className="p-8 text-sm text-text-muted">Loading run…</p>;
  if (isError || !data) {
    return (
      <p className="p-8 text-sm text-risk-malicious">
        Couldn't load run <span className="font-mono">{runId}</span>.
      </p>
    );
  }

  const { run, process_tree, network_connections, alerts, kill_chain, sample_reputation, effective_tuning = {}, suppressed_alerts = {} } = data;
  const inProgress = run.completed_at === null;
  const chain = killChainStats(alerts);
  const campaign = campaigns.find((c) => c.runs.some((r) => r.run_id === runId));

  return (
    <div className="mx-auto max-w-7xl px-5 py-8 lg:px-8">
      <nav className="mb-6 flex items-center gap-2 text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/history" className="transition-colors hover:text-accent">
          Session history
        </Link>
        <span aria-hidden>/</span>
        <span className="font-mono text-text-primary">{run.sample_name}</span>
      </nav>

      <header className="mb-6 flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
        <div className="min-w-0">
          <p className="kicker">Analysis · {run.run_id.slice(0, 12)}</p>
          <h1 className="display mt-1.5">{run.sample_name}</h1>
          <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-text-muted">
            <span className="inline-flex items-center gap-1.5 rounded border border-border-subtle px-1.5 py-0.5 font-mono uppercase">
              <Icon name={platformIconName(run.platform)} size={11} className="text-signal" />
              {run.platform}
            </span>
            <SourceBadge source={run.source} />
            <ProvenanceBadge source={run.source} />
            {(run.host_ids ?? []).map((h) => (
              <span key={h} className="inline-flex items-center gap-1">
                <Link
                  to={`/hosts/${encodeURIComponent(h)}`}
                  className="inline-flex items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-muted transition-colors hover:border-accent/50 hover:text-accent"
                  title={`The aggregate timeline — everything OutPost knows about ${h}`}
                >
                  <Icon name="terminal" size={10} className="opacity-60" />
                  {h}
                </Link>
                <Link
                  to={`/history?host=${encodeURIComponent(h)}`}
                  className="inline-flex items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint transition-colors hover:border-accent/50 hover:text-accent"
                  title={`All runs from host ${h}`}
                >
                  <Icon name="clock" size={10} />
                  runs
                </Link>
              </span>
            ))}
            <span>{run.session_type}</span>
            <span>started {run.started_at.slice(0, 19).replace("T", " ")} UTC</span>
            {inProgress ? (
              <span className="inline-flex items-center gap-1.5 animate-outpost-pulse text-signal">
                <Icon name="activity" size={12} />
                still tracing
              </span>
            ) : (
              <span>
                · ended {run.completed_at?.slice(0, 19).replace("T", " ")} UTC
              </span>
            )}
          </p>
          {campaign && (
            <Link
              to="/campaigns"
              className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-accent/50 bg-accent/10 px-2.5 py-1 font-mono text-[10px] text-accent transition-all duration-150 hover:bg-accent/20 hover:shadow-[var(--glow-accent)]"
              title={`Member of the campaign clustering around ${campaign.key}`}
            >
              <Icon name="flag" size={11} />
              Campaign · {campaign.key} · {campaign.runs.length} run{campaign.runs.length === 1 ? "" : "s"}
            </Link>
          )}
        </div>
        <div className="flex items-center gap-6">
          <RiskGauge score={run.risk_score} />
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAttachCase(true)}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-all duration-150 hover:border-accent/80 hover:text-accent"
              title="Attach this run as evidence to an incident investigation case"
            >
              <Icon name="notes" size={12} />
              Attach to Case
            </button>
            <button
              onClick={() => setShowRulesStudio(true)}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-2 font-mono text-xs font-semibold text-accent shadow-[var(--glow-accent)] transition-all duration-150 hover:bg-accent/25 hover:border-accent"
              title="Open Detection Rule Synthesis Studio (Sigma, Suricata, YARA)"
            >
              <Icon name="shield" size={12} />
              Detection Studio
            </button>
            <ExportButton
              runId={runId}
              label="IOCs CSV"
              filename={`outpost-iocs-${runId.slice(0, 12)}.csv`}
              fetcher={getRunIocsCsv}
            />
            <ExportButton runId={runId} />
            {/* PDF = browser print-to-file: the @media print stylesheet in
                index.css re-themes the report ink-on-paper (light, chrome
                hidden), then the OS Save-as-PDF does the rest. Zero deps. */}
            <button
              onClick={() => window.print()}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              title="Print / Save as PDF — print-optimized ink-on-paper layout of this report"
            >
              <Icon name="download" size={12} />
              Export PDF
            </button>
            {/* Re-enrich: drop this run's cached IP/hash intel and re-run
                enrichment with the CURRENT keys (the 'I just added a key'
                button) — fresh badges on the next fetch. */}
            <button
              onClick={() => reEnrich.mutate(runId)}
              disabled={reEnrich.isPending}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:opacity-50"
              title="Clear this run's cached reputation and re-query AbuseIPDB/VirusTotal with the currently configured keys"
            >
              <Icon name={reEnrich.isPending ? "refresh" : "refresh"} size={12} className={reEnrich.isPending ? "animate-spin" : ""} />
              {reEnrich.isPending ? "Re-enriching…" : "Re-enrich intel"}
            </button>
          </div>
        </div>
      </header>

      {/* Rule context — the tuned thresholds this run was scored under, so a
          tuned finding explains itself (webapp + CLI + export parity). */}
      <div
        className="mb-6 flex flex-wrap items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2"
        title="Effective rule tuning captured at this run's evaluation — the exact thresholds its findings were scored under"
      >
        {Object.keys(effective_tuning).length > 0 ? (
          <>
            <span className="font-mono text-[10px] uppercase tracking-wide text-accent">scored under</span>
            {Object.entries(effective_tuning).map(([param, value]) => (
              <span
                key={param}
                className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent"
                title={`Tuning override in effect for this run`}
              >
                {param}={String(value)}
              </span>
            ))}
          </>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">
            scored under stock thresholds — no tuning overrides in effect
          </span>
        )}
        {Object.keys(suppressed_alerts).length > 0 && (
          <span className="ml-1 flex items-center gap-1.5 border-l border-border-subtle pl-3">
            <span className="font-mono text-[10px] uppercase tracking-wide text-risk-suspicious">
              cap held back
            </span>
            {Object.entries(suppressed_alerts).map(([rule, count]) => (
              <span
                key={rule}
                className="rounded border border-risk-suspicious/40 bg-risk-suspicious/10 px-1.5 py-0.5 font-mono text-[10px] text-risk-suspicious"
                title={`${count} additional ${rule} alert(s) suppressed by the per-run storm cap`}
              >
                {rule} −{String(count)}
              </span>
            ))}
          </span>
        )}
      </div>

      <div className="mb-6 space-y-6">
        <AlertRate alerts={alerts} />
        <PlantStrip
          alerts={alerts}
          onFocus={(ip) => {
            setSelectedPid(null);
            setFocusIp(ip);
            // Instant jump (no smooth/rAF — both depend on the compositor,
            // which some environments don't run). The panel's position is
            // stable regardless of the filter state, so a synchronous jump is
            // safe and reliable everywhere.
            document.getElementById("network-panel")?.scrollIntoView({ block: "start" });
          }}
        />
        <Panel
          kicker="Tactics"
          title="Kill chain"
          right={
            <span className="font-mono text-[10px] text-text-faint">
              {chain.fired} of {alerts.length} alerts mapped to {chain.stages} stage{chain.stages === 1 ? "" : "s"}
            </span>
          }
        >
          <KillChainStepper alerts={alerts} />
        </Panel>
        <AlertBanner
          alerts={alerts}
          triage
          runId={runId}
          sampleName={run.sample_name}
          onStatus={onAlertStatus}
          onBulkStatus={onBulkAlertStatus}
          onFalsePositive={onMarkFalsePositive}
        />
      </div>

      {network_connections.length > 0 && (
        <Panel
          kicker="Behavior · graph"
          title="Connection topology"
          className="mb-6"
          right={
            <span className="inline-flex items-center gap-1 font-mono text-[10px] text-signal">
              <Icon name="network" size={11} />
              processes → destinations
            </span>
          }
        >
          <Topology tree={process_tree} connections={network_connections} />
        </Panel>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        <div id="process-tree-panel" className="scroll-mt-24 min-w-0">
          <Panel
            kicker="Behavior"
            title="Process Ancestry & Flow"
            right={
              <div className="flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface p-0.5">
                <button
                  onClick={() => setProcessViewMode("graph")}
                  className={`press inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] transition-colors ${
                    processViewMode === "graph"
                      ? "bg-accent/20 font-semibold text-accent"
                      : "text-text-muted hover:text-text-primary"
                  }`}
                  title="Interactive SVG Ancestry Graph"
                >
                  <Icon name="activity" size={10} />
                  Graph
                </button>
                <button
                  onClick={() => setProcessViewMode("tree")}
                  className={`press inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] transition-colors ${
                    processViewMode === "tree"
                      ? "bg-accent/20 font-semibold text-accent"
                      : "text-text-muted hover:text-text-primary"
                  }`}
                  title="Collapsible Tree View"
                >
                  <Icon name="terminal" size={10} />
                  Tree
                </button>
              </div>
            }
          >
            {processViewMode === "graph" ? (
              <ProcessGraph
                nodes={process_tree}
                selectedPid={selectedPid}
                onSelectPid={(pid) => setSelectedPid(pid)}
                alerts={alerts}
                events={timelineEvents}
              />
            ) : (
              <ProcessTree
                roots={process_tree}
                reconPids={reconPids}
                highlightPid={flashPid}
                selectedPid={selectedPid}
                onSelect={(pid) => setSelectedPid((cur) => (cur === pid ? null : pid))}
                allowlistForRun={runId}
              />
            )}
            {/* Detection-awareness honesty (docs): the collector runs INSIDE the
                guest, so sophisticated malware can observe or evade it — the
                hypervisor-introspection alternative (DRAKVUF) watches from
                outside the VM instead. */}
            <p className="mt-3 border-t border-border-subtle pt-2 font-mono text-[10px] leading-relaxed text-text-faint">
              Collector runs in-guest — well-built malware can detect it. Hypervisor-introspection sandboxes (e.g. DRAKVUF)
              watch from outside the VM instead; a future integration could detonate here invisibly.
            </p>
          </Panel>
        </div>

        <div className="min-w-0 space-y-6">
          <ReconActorsPanel alerts={alerts} tree={process_tree} onLocate={onLocate} />
          <PersistencePanel alerts={alerts} events={timelineEvents} />
          <AllowlistPanel runId={runId} />
          <SuppressionPanel runId={runId} alerts={alerts} sampleName={run.sample_name} />
          <Panel
            id="network-panel"
            kicker="Network"
            title="Connections"
            right={
              selectedPid !== null ? (
                <button
                  onClick={() => setSelectedPid(null)}
                  className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline"
                >
                  <Icon name="x" size={10} />
                  clear focus
                </button>
              ) : (
                <span className="inline-flex items-center gap-1 font-mono text-[10px] text-signal">
                  <Icon name="network" size={11} />
                  {network_connections.length}
                </span>
              )
            }
          >
            {focusBar}
            <NetworkGroups connections={filteredConnections} runId={runId} />
          </Panel>

          <Panel kicker="Sequence" title="Timeline">
            {focusBar}
            <TimelineView events={filteredTimeline} />
          </Panel>
        </div>
      </div>

      <div className="mt-6 space-y-6">
        <Panel kicker="Protocol Intelligence" title="Network Conversation Flows & C2 Beaconing">
          <NetworkProtocolInspector runId={runId} />
        </Panel>

        {runArtifacts.length > 0 && (
          <Panel kicker="Forensics · Sandbox" title={`Captured Sandbox Artifacts (${runArtifacts.length})`}>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
              {runArtifacts.map((art) => (
                <div key={art.filename} className="flex items-center justify-between rounded-xl border border-border-subtle bg-bg-surface p-3 hover:border-accent/50 transition">
                  <div className="min-w-0 flex-1 mr-2">
                    <span className="font-bold text-text-primary truncate block">{art.filename}</span>
                    <span className="text-[10px] text-text-faint">{art.size_bytes} bytes</span>
                  </div>
                  <a
                    href={getSandboxArtifactUrl(runId, art.filename)}
                    download
                    className="press shrink-0 inline-flex items-center gap-1 rounded-lg border border-accent/60 bg-accent/15 px-2.5 py-1 text-[11px] font-semibold text-accent hover:bg-accent/25"
                  >
                    <Icon name="download" size={11} />
                    <span>Download</span>
                  </a>
                </div>
              ))}
            </div>
          </Panel>
        )}
        <NotesPanel runId={runId} />
        <RulesPanel runId={runId} />
      </div>

      {sample_reputation && <SampleReputation rep={sample_reputation} />}
      <KillChainCard links={kill_chain} />

      <DetectionStudioModal
        runId={runId}
        isOpen={showRulesStudio}
        onClose={() => setShowRulesStudio(false)}
      />

      {showAttachCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg-base/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-xl border border-border-subtle bg-bg-surface p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <h3 className="flex items-center gap-2 font-mono text-sm font-semibold text-text-primary">
                <Icon name="notes" size={14} className="text-accent" />
                Attach Run to Investigation
              </h3>
              <button
                onClick={() => {
                  setShowAttachCase(false);
                  setAttachMsg(null);
                }}
                className="text-text-faint hover:text-text-primary"
              >
                <Icon name="x" size={14} />
              </button>
            </div>
            <div className="mt-4 space-y-4 font-mono text-xs">
              <p className="text-text-muted">
                Select an open investigation case to attach this run (<span className="text-accent">{runId.slice(0, 12)}</span>) as an evidence reference.
              </p>
              {investigationsData?.investigations && investigationsData.investigations.length > 0 ? (
                <div>
                  <label className="mb-1 block text-[10px] uppercase tracking-wide text-text-faint">Select Case</label>
                  <select
                    value={attachingCaseId}
                    onChange={(e) => setAttachingCaseId(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-base p-2 text-text-primary outline-none focus:border-accent"
                  >
                    <option value="">— Select an existing case —</option>
                    {investigationsData.investigations.map((inv) => (
                      <option key={inv.id} value={inv.id}>
                        {inv.title} [{inv.status.toUpperCase()}]
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="rounded-lg border border-border-subtle/60 bg-bg-base/40 p-3 text-text-faint">
                  No active investigations found. You can create one from the{" "}
                  <Link to="/investigations" className="text-accent underline">
                    Investigations
                  </Link>{" "}
                  page.
                </div>
              )}
              {attachMsg && (
                <p className={`text-xs ${attachMsg.ok ? "text-risk-clean" : "text-risk-malicious"}`}>
                  {attachMsg.text}
                </p>
              )}
            </div>
            <div className="mt-6 flex items-center justify-end gap-2 border-t border-border-subtle pt-3">
              <button
                onClick={() => {
                  setShowAttachCase(false);
                  setAttachMsg(null);
                }}
                className="press rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (!attachingCaseId) return;
                  try {
                    await addInvestigationRef(attachingCaseId, { ref_type: "run", ref_id: runId });
                    setAttachMsg({ ok: true, text: "Successfully attached to investigation!" });
                    void queryClient.invalidateQueries({ queryKey: ["investigation", attachingCaseId] });
                    setTimeout(() => {
                      setShowAttachCase(false);
                      setAttachMsg(null);
                    }, 1200);
                  } catch (err: unknown) {
                    setAttachMsg({
                      ok: false,
                      text: err instanceof Error ? err.message : "Failed to attach run to case",
                    });
                  }
                }}
                disabled={!attachingCaseId}
                className="press rounded-lg border border-accent bg-accent/20 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/30 disabled:opacity-40"
              >
                Confirm Attach
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
