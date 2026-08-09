import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import DetectionVolume from "../components/DetectionVolume/DetectionVolume";
import RiskTimeline from "../components/RiskTimeline/RiskTimeline";
import RunList from "../components/RunHistory/RunList";
import { PageHeader, Panel, Stat } from "../components/ui";
import { TREND_WINDOWS, type TrendWindow } from "../lib/constants";
import { BASE_URL, getRuns } from "../lib/api";

export default function RunHistoryPage() {
  // ?q=<sample> pre-filters the archive to one binary (Overview risk bars),
  // ?host=<host_id> to one fleet host (Agents page). Both combine.
  const [searchParams, setSearchParams] = useSearchParams();
  const q = (searchParams.get("q") ?? "").trim();
  const host = (searchParams.get("host") ?? "").trim();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["runs", "q", q, "host", host],
    queryFn: () => getRuns({ q, host }),
  });
  const [windowKey, setWindowKey] = useState<TrendWindow>("24h");

  const runs = data ?? [];
  const totalAlerts = runs.reduce((n, r) => n + r.alert_count, 0);
  const malicious = runs.filter((r) => r.highest_severity === "malicious").length;
  const totalRisk = runs.reduce((n, r) => n + (r.risk_score ?? 0), 0);

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Operations · archive"
        title="Session history"
        lede="Live monitoring sessions and bounded analyses, newest first."
      />

      {(q || host) && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
          <Icon name="filter" size={12} className="text-accent" />
          <span className="text-xs text-text-muted">
            {q && (
              <>
                Filtered to sample <span className="font-mono text-text-primary">{q}</span>
              </>
            )}
            {q && host && <span className="mx-1 text-text-faint">·</span>}
            {host && (
              <>
                host <span className="inline-flex items-center gap-1 font-mono text-text-primary"><Icon name="terminal" size={10} />{host}</span>
              </>
            )}{" "}
            — {runs.length} session{runs.length === 1 ? "" : "s"}
          </span>
          <button
            onClick={() => setSearchParams({}, { replace: true })}
            className="press ml-auto inline-flex items-center gap-1 rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/50 hover:text-accent"
          >
            <Icon name="x" size={10} />
            clear filter
          </button>
        </div>
      )}

      {!isLoading && !isError && (
        <Panel className="mb-6 overflow-hidden" pad={false}>
          <dl className="grid grid-cols-2 divide-border-subtle sm:grid-cols-4 sm:divide-x">
            <div className="px-5 py-4">
              <Stat label="sessions" value={runs.length} />
            </div>
            <div className="px-5 py-4">
              <Stat label="alerts" value={totalAlerts} />
            </div>
            <div className="px-5 py-4">
              <Stat label="malicious" value={malicious} tone="malicious" />
            </div>
            <div className="px-5 py-4">
              <Stat label="cumulative risk" value={totalRisk} />
            </div>
          </dl>
        </Panel>
      )}

      {isLoading && <p className="text-sm text-text-muted">Loading…</p>}
      {isError && (
        <Panel className="border-risk-malicious/40">
          <p className="text-sm text-risk-malicious">
            Couldn't reach the OutPost backend — is it running on <span className="font-mono">{BASE_URL}</span>?
          </p>
        </Panel>
      )}

      {data && (
        <>
          {/* Trend charts — risk per session + detection density. The bars are
              the analytical view; they live here with the archive rather than
              on the lean Overview dashboard. */}
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <p className="kicker">Trend</p>
            <div
              role="group"
              aria-label="Trend time window"
              className="flex items-center gap-0.5 rounded-lg border border-border-subtle bg-bg-elevated/40 p-0.5"
            >
              {TREND_WINDOWS.map((w) => (
                <button
                  key={w.key}
                  onClick={() => setWindowKey(w.key)}
                  aria-pressed={windowKey === w.key}
                  className={`press rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                    windowKey === w.key
                      ? "bg-accent/15 font-semibold text-accent"
                      : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>
          <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-[1.7fr_1fr]">
            <RiskTimeline runs={runs} windowKey={windowKey} />
            <DetectionVolume windowKey={windowKey} />
          </div>
          <RunList runs={data} />
        </>
      )}
    </div>
  );
}
