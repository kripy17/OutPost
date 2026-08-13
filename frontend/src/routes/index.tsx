import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import DetectionVolume from "../components/DetectionVolume/DetectionVolume";
import RiskTimeline from "../components/RiskTimeline/RiskTimeline";
import RunList from "../components/RunHistory/RunList";
import { PageHeader, Panel, Stat } from "../components/ui";
import { TREND_WINDOWS, type TrendWindow } from "../lib/constants";
import ComparePanel from "../components/ComparePanel/ComparePanel";
import { BASE_URL, getRuns } from "../lib/api";

export default function RunHistoryPage() {
  // ?q=<sample> pre-filters the archive to one binary (Overview risk bars),
  // ?host=<host_id> to one fleet host (Agents page). Both combine.
  const [searchParams, setSearchParams] = useSearchParams();
  const q = (searchParams.get("q") ?? "").trim();
  const host = (searchParams.get("host") ?? "").trim();
  // The archive reads as real telemetry first — synthetic provenance (seeds /
  // webapp detonations / the sandbox demo) AND soak-named collector baselines
  // (soak-…) are hidden unless the operator asks.
  const [includeSynthetic, setIncludeSynthetic] = useState(() => localStorage.getItem("outpost-history-synthetic") === "1");
  const [includeSoak, setIncludeSoak] = useState(() => localStorage.getItem("outpost-history-soak") === "1");
  useEffect(() => {
    try {
      localStorage.setItem("outpost-history-synthetic", includeSynthetic ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [includeSynthetic]);
  useEffect(() => {
    try {
      localStorage.setItem("outpost-history-soak", includeSoak ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [includeSoak]);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["runs", "q", q, "host", host, "syn", includeSynthetic, "soak", includeSoak],
    queryFn: () => getRuns({ q, host, include_synthetic: includeSynthetic, include_soak: includeSoak }),
  });
  const [windowKey, setWindowKey] = useState<TrendWindow>(() => {
    const saved = localStorage.getItem("outpost-history-window");
    return (TREND_WINDOWS.some((w) => w.key === saved) ? saved : "24h") as TrendWindow;
  });

  useEffect(() => {
    try {
      localStorage.setItem("outpost-history-window", windowKey);
    } catch {
      /* storage unavailable — window still works for this visit */
    }
  }, [windowKey]);

  // Keyboard parity with the Event Log: ↑/↓ move the selection through the
  // run list, Enter opens the highlighted session. Never fires while typing
  // in a field.
  const navigate = useNavigate();
  const runs = useMemo(() => data ?? [], [data]);
  const [selectedIdx, setSelectedIdx] = useState(-1);
  useEffect(() => {
    if (runs.length === 0) return;
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIdx((i) => Math.min(i + 1, runs.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && selectedIdx >= 0) {
        e.preventDefault();
        const run = runs[selectedIdx];
        if (run) navigate(`/runs/${run.run_id}`);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [runs, selectedIdx, navigate]);

  // Keep the highlighted row in view as the selection moves.
  useEffect(() => {
    if (selectedIdx < 0) return;
    const row = document.querySelector(`[aria-current="true"]`);
    row?.scrollIntoView({ block: "nearest" });
  }, [selectedIdx]);

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
            <div className="flex flex-wrap items-center gap-2">
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
              <button
                onClick={() => setIncludeSynthetic((v) => !v)}
                aria-pressed={includeSynthetic}
                title={includeSynthetic ? "Hide demo/synthetic runs again" : "Include seeded demo runs and webapp-synthetic detonations"}
                className={`press rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                  includeSynthetic ? "border border-accent/50 bg-accent/10 text-accent" : "border border-border-subtle text-text-faint hover:text-text-primary"
                }`}
              >
                {includeSynthetic ? "●" : "○"} show synthetic
              </button>
              <button
                onClick={() => setIncludeSoak((v) => !v)}
                aria-pressed={includeSoak}
                title={includeSoak ? "Hide soak baseline runs again" : "Include soak-named collector baselines (soak-linux-… / soak-windows-…)"}
                className={`press rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                  includeSoak ? "border border-accent/50 bg-accent/10 text-accent" : "border border-border-subtle text-text-faint hover:text-text-primary"
                }`}
              >
                {includeSoak ? "●" : "○"} show soak runs
              </button>
            </div>
          </div>
          <div className="mb-6 grid grid-cols-1 gap-6 xl:grid-cols-[1.7fr_1fr]">
            <RiskTimeline runs={runs} windowKey={windowKey} />
            <DetectionVolume windowKey={windowKey} />
          </div>
          {/* Keyboard parity hints — same interaction as the Event Log. */}
          <p className="mb-3 font-mono text-[10px] text-text-faint">
            <kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px">↑</kbd>{" "}
            <kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px">↓</kbd> select session ·{" "}
            <kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px">Enter</kbd> open
          </p>
          <RunList runs={data} highlightId={selectedIdx >= 0 ? (runs[selectedIdx]?.run_id ?? null) : null} />
          {/* Keyed by the ?a=&b= preset so a campaign compare jump remounts with
              its pair pre-selected. */}
          <ComparePanel
            key={`${searchParams.get("a") ?? ""}-${searchParams.get("b") ?? ""}`}
            runs={data}
            initialA={searchParams.get("a") ?? ""}
            initialB={searchParams.get("b") ?? ""}
          />
        </>
      )}
    </div>
  );
}
