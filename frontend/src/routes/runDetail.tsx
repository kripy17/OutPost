import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import ExportButton from "../components/ExportButton/ExportButton";
import KillChainStepper, { killChainStats } from "../components/KillChain/KillChainStepper";
import { Panel } from "../components/ui";
import NetworkTable from "../components/NetworkTable/NetworkTable";
import NotesPanel from "../components/NotesPanel/NotesPanel";
import ProcessTree from "../components/ProcessTree/ProcessTree";
import RulesPanel from "../components/RulesPanel/RulesPanel";
import TimelineView from "../components/TimelineView/TimelineView";
import { riskBand } from "../lib/constants";
import { getCampaigns, getRunDetail, getRunIocsCsv } from "../lib/api";
import type { RunDetail } from "../types";

function RiskGauge({ score }: { score: number }) {
  const band = riskBand(score);
  const s = score ?? 0;
  return (
    <div className="flex items-center gap-3" title={`Risk score ${s}/100 — ${band.label}`}>
      <span className={`font-mono text-2xl font-semibold tabular-nums ${band.color}`}>{s}</span>
          <div className="h-1.5 w-24 overflow-hidden rounded-full bg-bg-elevated">
            <div
              className={`h-full rounded-full transition-[width] duration-500 ease-out ${band.bg}`}
              style={{ width: `${Math.min(100, s)}%` }}
            />
          </div>
          <span className={`font-mono text-[10px] uppercase tracking-wide ${band.color}`}>{band.label}</span>
    </div>
  );
}

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
              <span
                key={r}
                className="rounded border border-accent-amber/40 bg-bg-elevated/50 px-2 py-0.5 font-mono text-[10px] text-accent-amber"
              >
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
    <Panel kicker="Correlation · 2.4" title="Kill-chain sequence" className="mt-6">
      <p className="mb-3 font-mono text-xs text-text-primary">{label}</p>
      <ol className="flex flex-wrap items-center gap-1.5">
        {links.map((l, i) => (
          <li key={i} className="flex items-center gap-1.5">
            <span className="rounded border border-accent-amber/50 bg-accent-amber/10 px-2 py-0.5 font-mono text-[10px] text-accent-amber">
              {l.from}
            </span>
            <span aria-hidden className="font-mono text-[10px] text-text-faint">→</span>
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

export default function RunDetailPage() {
  const { runId = "" } = useParams();

  // Poll while the run is still in progress (live sessions update continuously).
  const { data, isLoading, isError } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRunDetail(runId),
    refetchInterval: (query) => {
      const run = query.state.data?.run;
      return run && run.completed_at === null ? 3000 : false;
    },
  });

  // Campaign membership — shared queryKey with the Campaigns page so this is
  // one cached fetch across the app. Declared above the early returns: hook
  // count must stay identical across renders (Rules of Hooks).
  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: getCampaigns });

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

  // A run in no campaign simply shows nothing.
  const campaign = campaigns.find((c) => c.runs.some((r) => r.run_id === runId));

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10">
      <nav className="mb-6 flex items-center gap-2 font-mono text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent-amber">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/history" className="transition-colors hover:text-accent-amber">
          Session history
        </Link>
        <span aria-hidden>/</span>
        <span className="text-text-primary">{run.sample_name}</span>
      </nav>

      <header className="mb-6 flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
        <div className="min-w-0">
          <p className="kicker">Analysis · {run.run_id.slice(0, 12)}</p>
          <h1 className="display mt-1.5">{run.sample_name}</h1>
          <p className="mt-2 flex flex-wrap items-center gap-2 font-mono text-xs text-text-muted">
            <span className="rounded border border-border-subtle px-1.5 py-0.5 uppercase">{run.platform}</span>
            <span>{run.session_type}</span>
            <span>started {run.started_at.slice(0, 19).replace("T", " ")} UTC</span>
            {inProgress && (
              <span className="animate-outpost-pulse text-accent-amber">● still tracing</span>
            )}
          </p>
          {campaign && (
            <Link
              to="/campaigns"
              className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-accent-amber/50 bg-accent-amber/10 px-2.5 py-1 font-mono text-[10px] text-accent-amber transition-all duration-150 hover:bg-accent-amber/20 hover:shadow-[var(--glow-amber)]"
              title={`Member of the campaign clustering around ${campaign.key}`}
            >
              <span aria-hidden>✸</span>
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
        <AlertBanner alerts={alerts} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        <Panel kicker="Behavior" title="Process tree">
          <ProcessTree roots={process_tree} />
        </Panel>

        <div className="space-y-6">
          <Panel kicker="Network" title="Connections">
            <NetworkTable connections={network_connections} />
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
