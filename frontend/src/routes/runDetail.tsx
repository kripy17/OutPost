import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon, platformIconName } from "../components/Icon";
import KillChainStepper, { killChainStats } from "../components/KillChain/KillChainStepper";
import { Panel } from "../components/ui";
import NotesPanel from "../components/NotesPanel/NotesPanel";
import ProcessTree from "../components/ProcessTree/ProcessTree";
import { AllowlistPanel, SuppressionPanel } from "../components/TriagePanels/TriagePanels";
import RulesPanel from "../components/RulesPanel/RulesPanel";
import TimelineView from "../components/TimelineView/TimelineView";
import { RISK_COLORS, enumKindsFromDetails, riskBand } from "../lib/constants";
import { bulkUpdateAlertStatus, getCampaigns, getRunDetail, getRunIocsCsv, updateAlertStatus } from "../lib/api";
import type { AlertStatus, NetworkConnection, Reputation, RunDetail } from "../types";

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

function NetworkGroups({ connections }: { connections: NetworkConnection[] }) {
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
              {items.map((c) => (
                <li key={`${c.dest_ip}-${c.dest_port}`} className="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 font-mono text-xs">
                  <span className={`font-semibold ${RISK_COLORS[c.reputation]}`}>{c.dest_ip}</span>
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
                  </span>
                </li>
              ))}
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

interface ReconActor {
  pid: number;
  process_name: string | null;
  command_line: string | null;
}

/** Flatten the process tree into a pid → {name, command} lookup. */
function resolvePids(roots: RunDetail["process_tree"], pids: number[]): Map<number, ReconActor> {
  const out = new Map<number, ReconActor>();
  const walk = (ns: RunDetail["process_tree"]) => {
    for (const n of ns) {
      if (n.pid !== undefined) out.set(n.pid, { pid: n.pid, process_name: n.process_name, command_line: n.command_line });
      walk(n.children);
    }
  };
  walk(roots);
  // Keep only the requested pids, preserving alert order.
  const kept = new Map<number, ReconActor>();
  for (const p of pids) if (out.has(p)) kept.set(p, out.get(p)!);
  return kept;
}

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

  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: getCampaigns });

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

  if (isLoading) return <p className="p-8 text-sm text-text-muted">Loading run…</p>;
  if (isError || !data) {
    return (
      <p className="p-8 text-sm text-risk-malicious">
        Couldn't load run <span className="font-mono">{runId}</span>.
      </p>
    );
  }

  const { run, process_tree, network_connections, timeline, alerts, kill_chain, sample_reputation } = data;
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
            <span>{run.session_type}</span>
            <span>started {run.started_at.slice(0, 19).replace("T", " ")} UTC</span>
            {inProgress && (
              <span className="inline-flex items-center gap-1.5 animate-outpost-pulse text-signal">
                <Icon name="activity" size={12} />
                still tracing
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
            <ExportButton
              runId={runId}
              label="IOCs CSV"
              filename={`outpost-iocs-${runId.slice(0, 12)}.csv`}
              fetcher={getRunIocsCsv}
            />
            <ExportButton runId={runId} />
          </div>
        </div>
      </header>

      <div className="mb-6 space-y-6">
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
        <AlertBanner alerts={alerts} triage onStatus={onAlertStatus} onBulkStatus={onBulkAlertStatus} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        <div id="process-tree-panel" className="scroll-mt-24">
          <Panel kicker="Behavior" title="Process tree">
            <ProcessTree roots={process_tree} reconPids={reconPids} highlightPid={flashPid} />
          </Panel>
        </div>

        <div className="space-y-6">
          <ReconActorsPanel alerts={alerts} tree={process_tree} onLocate={onLocate} />
          <AllowlistPanel runId={runId} />
          <SuppressionPanel runId={runId} alerts={alerts} />
          <Panel
            kicker="Network"
            title="Connections"
            right={
              <span className="inline-flex items-center gap-1 font-mono text-[10px] text-signal">
                <Icon name="network" size={11} />
                {network_connections.length}
              </span>
            }
          >
            <NetworkGroups connections={network_connections} />
          </Panel>

          <Panel kicker="Sequence" title="Timeline">
            <TimelineView events={timeline} />
          </Panel>
        </div>
      </div>

      <div className="mt-6 space-y-6">
        <NotesPanel runId={runId} />
        <RulesPanel runId={runId} />
      </div>

      {sample_reputation && <SampleReputation rep={sample_reputation} />}
      <KillChainCard links={kill_chain} />
    </div>
  );
}
