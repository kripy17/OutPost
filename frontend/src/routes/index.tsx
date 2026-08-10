import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import DetectionVolume from "../components/DetectionVolume/DetectionVolume";
import RiskTimeline from "../components/RiskTimeline/RiskTimeline";
import RunList from "../components/RunHistory/RunList";
import { PageHeader, Panel, Stat } from "../components/ui";
import { TREND_WINDOWS, type TrendWindow } from "../lib/constants";
import { BASE_URL, compareRuns, getRuns } from "../lib/api";
import type { RunSummary } from "../types";

/** Compare two sessions — the former /compare page folded into the archive.
 *  Pick any two runs and see what processes/IPs each has that the other
 *  doesn't (variant A vs variant B, before vs after a patch, …). */
function ComparePanel({ runs, initialA = "", initialB = "" }: { runs: RunSummary[]; initialA?: string; initialB?: string }) {
  const [a, setA] = useState(initialA);
  const [b, setB] = useState(initialB);
  const { data, isFetching } = useQuery({
    queryKey: ["compare", a, b],
    queryFn: () => compareRuns(a, b),
    enabled: a !== "" && b !== "" && a !== b,
  });

  const col = (kind: "a" | "shared" | "b", items: string[]) => {
    const tone =
      kind === "a"
        ? "border-risk-malicious/30 bg-risk-malicious/5 text-risk-malicious"
        : kind === "b"
          ? "border-accent/30 bg-accent/5 text-accent"
          : "border-border-subtle bg-bg-elevated/40 text-text-muted";
    return (
      <div className="min-w-0">
        <p className={`mb-1.5 font-mono text-[9px] font-semibold uppercase tracking-wider ${tone} !bg-transparent !border-0`}>
          {kind === "a" ? "only A" : kind === "b" ? "only B" : "shared"}{" "}
          <span className="text-text-faint">({items.length})</span>
        </p>
        {items.length === 0 ? (
          <p className="font-mono text-[10px] text-text-faint">—</p>
        ) : (
          <ul className="space-y-1">
            {items.slice(0, 12).map((v) => (
              <li key={v} className={`truncate rounded border px-2 py-1 font-mono text-[10px] ${tone}`} title={v}>
                {v}
              </li>
            ))}
            {items.length > 12 && <li className="font-mono text-[10px] text-text-faint">+{items.length - 12} more</li>}
          </ul>
        )}
      </div>
    );
  };

  return (
    <Panel kicker="Analysis · diff" title="Compare two sessions" className="mt-8">
      <div className="flex flex-wrap items-end gap-3">
        {(["A", "B"] as const).map((side) => (
          <label key={side} className="block min-w-52 flex-1">
            <span className="kicker mb-1 block">Session {side}</span>
            <select
              value={side === "A" ? a : b}
              onChange={(e) => (side === "A" ? setA(e.target.value) : setB(e.target.value))}
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-colors focus:border-accent/60 focus:outline-none"
              aria-label={`Pick session ${side}`}
            >
              <option value="">— pick a session —</option>
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.sample_name} · {r.run_id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
        ))}
        {isFetching && <span className="pb-2 text-xs text-text-muted">comparing…</span>}
      </div>
      {a !== "" && b !== "" && a === b && (
        <p className="mt-3 text-xs text-risk-malicious">Pick two different sessions.</p>
      )}
      {data && (
        <div className="mt-5 grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <p className="kicker mb-2">Processes</p>
            <div className="grid grid-cols-3 gap-3">
              {col("a", data.processes.only_a)}
              {col("shared", data.processes.shared)}
              {col("b", data.processes.only_b)}
            </div>
          </div>
          <div>
            <p className="kicker mb-2">IPs</p>
            <div className="grid grid-cols-3 gap-3">
              {col("a", data.ips.only_a)}
              {col("shared", data.ips.shared)}
              {col("b", data.ips.only_b)}
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

export default function RunHistoryPage() {
  // ?q=<sample> pre-filters the archive to one binary (Overview risk bars),
  // ?host=<host_id> to one fleet host (Agents page). Both combine.
  const [searchParams, setSearchParams] = useSearchParams();
  const q = (searchParams.get("q") ?? "").trim();
  const host = (searchParams.get("host") ?? "").trim();
  // The archive reads as real telemetry first — synthetic provenance (seeds /
  // webapp detonations / the sandbox demo) is hidden unless the operator asks.
  const [includeSynthetic, setIncludeSynthetic] = useState(() => localStorage.getItem("outpost-history-synthetic") === "1");
  useEffect(() => {
    try {
      localStorage.setItem("outpost-history-synthetic", includeSynthetic ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [includeSynthetic]);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["runs", "q", q, "host", host, "syn", includeSynthetic],
    queryFn: () => getRuns({ q, host, include_synthetic: includeSynthetic }),
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
  const runs = data ?? [];
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
