import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { Chip, PageHeader, Panel } from "../components/ui";
import { deleteSample, detonateDynamic, detonateSample, downloadSample, getRuns, getSample, getSampleStatic, getSandboxArtifactUrl, getSandboxProviders, getSandboxTask, getSimilarSamples, sandboxDetonate, watchlistAdd } from "../lib/api";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import { NetworkProtocolInspector } from "../components/NetworkProtocolInspector";
import type { Platform, RunSummary, SampleDetonationResult, SampleStatic, SandboxTask } from "../types";
import { filterStrings, formatBytes, getVirusTotalFileUrl, getVirusTotalIocUrl, iocTotal } from "./samplesHelpers";

/* ── Static analysis (strings / IOCs / PE / ELF) ─────────────────────────── */

function StaticAnalysis({ sample }: { sample: { sample_id: string; sha256: string } }) {
  const queryClient = useQueryClient();
  const [stringsFilter, setStringsFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [watchlisted, setWatchlisted] = useState<Set<string>>(new Set());
  const [watchlistError, setWatchlistError] = useState<string | null>(null);

  const { data: st, isLoading, isError } = useQuery({
    queryKey: ["sample", "static", sample.sample_id],
    queryFn: () => getSampleStatic(sample.sample_id),
    // Bytes-not-stored is now a 200 with `available: false` (data-driven
    // state, no console noise); 404 only remains for an unknown sample.
    retry: false,
  });
  // A known sample without stored bytes renders its re-upload state from
  // data — not from a fetch error.
  const unavailable = st !== undefined && st.available === false;

  const filteredStrings = useMemo(() => (st ? filterStrings(st.strings, stringsFilter) : []), [st, stringsFilter]);

  const addToWatchlist = async (value: string) => {
    try {
      await watchlistAdd(value, `from ${sample.sample_id}`);
      setWatchlisted((prev) => new Set(prev).add(value));
      setWatchlistError(null);
      void queryClient.invalidateQueries({ queryKey: ["watchlist"] });
    } catch {
      setWatchlistError(`Couldn't watchlist ${value}`);
    }
  };

  const visibleStrings = showAll ? filteredStrings : filteredStrings.slice(0, 80);
  const totalIocs = st ? iocTotal(st.iocs) : 0;

  return (
    <div className="mt-6 space-y-6">
      {/* Safe SOC Static Triage Status Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 font-mono text-xs">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/20 text-emerald-400">
            <Icon name="shield" size={14} />
          </span>
          <div>
            <span className="font-bold text-emerald-300">Mode 1: Safe Static Triage (Zero Execution Risk)</span>
            <p className="text-[11px] text-text-muted">
              Deep binary telemetry extracted directly from raw file bytes without executing. External threat pivots linked to VirusTotal.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={getVirusTotalFileUrl(sample.sha256)}
            target="_blank"
            rel="noopener noreferrer"
            title="Inspect SHA-256 file report on VirusTotal"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-1.5 text-[11px] font-bold text-accent transition hover:bg-accent/25 hover:shadow-[var(--glow-accent)]"
          >
            <span>VirusTotal Intelligence</span>
            <Icon name="external" size={11} />
          </a>
          <span className="rounded bg-emerald-500/20 px-2 py-1 text-[10px] font-bold text-emerald-400 uppercase">
            Static Safe
          </span>
        </div>
      </div>

      <Panel
        kicker="Static · on-demand"
        title="Strings & candidate IOCs"
        right={
          st && st.available ? (
            <span className="font-mono text-[10px] text-text-faint">
              {st.strings.length} strings · {totalIocs} IOCs
            </span>
          ) : undefined
        }
      >
        {isLoading && <p className="text-sm text-text-muted">Analyzing bytes…</p>}
        {isError && (
          <p className="text-sm text-text-muted">
            Static analysis unavailable — {sample.sample_id} could not be analyzed.
          </p>
        )}
        {unavailable && (
          <p className="text-sm text-text-muted">
            Static analysis unavailable — {sample.sample_id} was uploaded before byte persistence. Re-upload the file to enable it.
          </p>
        )}
        {st && st.available && (
          <>
            {/* IOC buckets — each chip jumps to internal search, external VirusTotal pivot, or watchlist. */}
            {totalIocs > 0 ? (
              <div className="mb-5 space-y-3">
                {(
                  [
                    { key: "urls", label: "URLs", icon: "globe" as const, tone: "accent" as const },
                    { key: "ips", label: "IPs", icon: "network" as const, tone: "suspicious" as const },
                    { key: "domains", label: "Domains", icon: "globe" as const, tone: "muted" as const },
                    { key: "hashes", label: "Hashes", icon: "copy" as const, tone: "muted" as const },
                    { key: "emails", label: "Emails", icon: "notes" as const, tone: "muted" as const },
                  ] as const
                ).map(
                  (g) =>
                    st.iocs[g.key].length > 0 && (
                      <div key={g.key} className="flex flex-wrap items-start gap-1.5">
                        <span className="mt-1 w-20 shrink-0 font-mono text-[10px] uppercase tracking-wide text-text-faint">
                          {g.label}
                        </span>
                        {st.iocs[g.key].slice(0, 40).map((v) => (
                          <span key={`${g.key}-${v}`} className="group inline-flex items-center gap-1">
                            <Link
                              to={`/search?q=${encodeURIComponent(v)}`}
                              title={`Search OutPost event history for ${v}`}
                              className="press inline-flex max-w-[260px] items-center gap-1 truncate rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                            >
                              <Icon name={g.icon} size={10} className="text-text-faint" />
                              <span className="truncate">{v}</span>
                            </Link>
                            <a
                              href={getVirusTotalIocUrl(g.key, v)}
                              target="_blank"
                              rel="noopener noreferrer"
                              title={`VirusTotal external threat intelligence lookup for ${v}`}
                              aria-label={`VirusTotal external threat intelligence lookup for ${v}`}
                              className="press inline-flex h-5 items-center gap-0.5 rounded border border-accent/40 bg-accent/10 px-1.5 font-mono text-[9px] font-semibold text-accent transition-colors duration-150 hover:border-accent hover:bg-accent/20"
                            >
                              <span>VT</span>
                              <Icon name="external" size={9} />
                            </a>
                            <button
                              onClick={() => void addToWatchlist(v)}
                              disabled={watchlisted.has(v)}
                              title={watchlisted.has(v) ? "On watchlist" : "Add to watchlist"}
                              className="press inline-flex h-5 w-5 items-center justify-center rounded border border-border-subtle text-text-faint transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:cursor-default disabled:text-risk-clean"
                            >
                              <Icon name={watchlisted.has(v) ? "check" : "plus"} size={9} />
                            </button>
                          </span>
                        ))}
                        {st.iocs[g.key].length > 40 && (
                          <span className="font-mono text-[10px] text-text-faint">+{st.iocs[g.key].length - 40} more</span>
                        )}
                      </div>
                    ),
                )}
                {watchlistError && <p className="text-[11px] text-risk-malicious">{watchlistError}</p>}
              </div>
            ) : (
              <p className="mb-4 text-sm text-text-muted">No URLs, IPs, domains, hashes, or emails embedded in the bytes.</p>
            )}

            {/* Categorized Strings Explorer */}
            {st.categorized_strings ? (
              <CategorizedStringsPanel categorized={st.categorized_strings} rawStrings={st.strings} />
            ) : (
              /* Strings — filterable, collapsible, mono. */
              <div className="border-t border-border-subtle pt-4">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">
                    Strings ({st.strings.length})
                  </span>
                  <div className="flex items-center gap-2">
                    <div className="relative">
                      <Icon name="search" size={11} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-text-faint" />
                      <input
                        value={stringsFilter}
                        onChange={(e) => setStringsFilter(e.target.value)}
                        placeholder="filter…"
                        className="w-40 rounded border border-border-subtle bg-bg-base py-1 pl-6 pr-2 font-mono text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                        aria-label="Filter strings"
                      />
                    </div>
                    {filteredStrings.length > 80 && (
                      <button
                        onClick={() => setShowAll((v) => !v)}
                        className="press font-mono text-[10px] text-text-muted transition-colors hover:text-accent"
                      >
                        {showAll ? "collapse" : `show all ${filteredStrings.length}`}
                      </button>
                    )}
                  </div>
                </div>
                <div className="max-h-64 overflow-y-auto rounded-lg border border-border-subtle bg-bg-elevated/30 p-3">
                  {visibleStrings.length === 0 ? (
                    <p className="text-[11px] text-text-faint">No strings match the filter.</p>
                  ) : (
                    <pre className="font-mono text-[10px] leading-relaxed text-text-muted">
                      {visibleStrings.map((s) => (
                        <div key={s}>{s}</div>
                      ))}
                    </pre>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      {/* Binary Entropy & Inferred Capabilities */}
      {st && st.available && (st.entropy !== undefined || (st.capabilities && st.capabilities.length > 0)) && (
        <Panel kicker="Static · inspection" title="Entropy & Inferred Capabilities">
          <div className="space-y-4">
            {st.entropy !== undefined && (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-border-subtle bg-bg-base p-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-text-primary">Shannon Entropy:</span>
                    <span className="font-mono text-xs text-accent font-bold">{st.entropy} / 8.0</span>
                    {st.is_packed && (
                      <span className="rounded bg-risk-malicious/15 px-1.5 py-0.5 font-mono text-[10px] font-medium text-risk-malicious">
                        High Entropy (Packed / Encrypted)
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-text-muted">
                    Measures byte randomness. Values above 7.0 indicate compression, packing (e.g. UPX), or encryption.
                  </p>
                </div>
                <div className="h-2 w-36 overflow-hidden rounded-full bg-bg-elevated">
                  <div
                    className={`h-full rounded-full ${st.is_packed ? "bg-risk-malicious" : "bg-accent"}`}
                    style={{ width: `${Math.min(100, (st.entropy / 8.0) * 100)}%` }}
                  />
                </div>
              </div>
            )}

            {/* Sliding Window Section Entropy Histogram */}
            <EntropyHistogramChart histogram={st.entropy_histogram} />

            {/* Static Risk Factors & Capabilities */}
            {st.risk_factors && st.risk_factors.length > 0 && (
              <div className="rounded-xl border border-risk-malicious/30 bg-risk-malicious/5 p-3 space-y-1.5 font-mono text-xs">
                <div className="flex items-center justify-between font-bold">
                  <span className="text-risk-malicious flex items-center gap-1.5">
                    <Icon name="alert" size={13} />
                    Static Threat Assessment Factors
                  </span>
                  <span className="text-[10px] rounded bg-risk-malicious/20 px-2 py-0.5 text-risk-malicious uppercase">
                    Risk Score: {st.static_risk_score ?? 0}/100 ({st.static_severity})
                  </span>
                </div>
                <ul className="list-disc list-inside space-y-1 text-[11px] text-text-muted">
                  {st.risk_factors.map((rf, idx) => (
                    <li key={idx}>{rf}</li>
                  ))}
                </ul>
              </div>
            )}

            {st.capabilities && st.capabilities.length > 0 && (
              <div className="space-y-2">
                <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">
                  Inferred Capabilities ({st.capabilities.length})
                </span>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  {st.capabilities.map((cap, i) => (
                    <div key={i} className="rounded border border-border-subtle bg-bg-base/60 p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold text-text-primary">{cap.category}</span>
                        <span className="font-mono text-[10px] text-risk-suspicious uppercase">{cap.confidence}</span>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {cap.matched.map((m) => (
                          <span key={m} className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-muted">
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {st.fuzzy_hash && (
              <div className="flex flex-wrap items-center gap-2 rounded border border-border-subtle bg-bg-base/60 p-2.5 font-mono text-[11px]">
                <span className="text-text-faint">CTPH / Fuzzy Hash:</span>
                <span className="text-text-muted select-all truncate max-w-xl">{st.fuzzy_hash}</span>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Binary Similarity & Fuzzy Hash Matching */}
      <SimilarSamplesPanel sampleId={sample.sample_id} />

      {/* Executable metadata — PE or ELF, whichever the bytes actually are. */}
      {(st?.pe || st?.elf) && (
        <Panel kicker="Static · format" title={st.pe ? "PE metadata" : "ELF metadata"}>
          <PeElfTable st={st} />
        </Panel>
      )}
    </div>
  );
}

function EntropyHistogramChart({ histogram }: { histogram?: number[] }) {
  if (!histogram || histogram.length === 0) return null;
  return (
    <div className="space-y-1.5 border-t border-border-subtle pt-3">
      <div className="flex items-center justify-between font-mono text-[10px] text-text-faint">
        <span>Section Entropy Sliding Histogram (32 Sequential Byte Chunks)</span>
        <span className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> &lt;5.5 Code</span>
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> 5.5-7.0 Data</span>
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-rose-500" /> &gt;7.0 Packed</span>
        </span>
      </div>
      <div className="flex h-12 items-end gap-1 rounded-lg border border-border-subtle bg-[#0a0c10] p-1.5">
        {histogram.map((val, idx) => {
          const pct = Math.min(100, (val / 8.0) * 100);
          const color = val > 7.0 ? "bg-rose-500 shadow-[var(--glow-malicious)]" : val > 5.5 ? "bg-amber-400" : "bg-emerald-400";
          return (
            <div
              key={idx}
              className={`flex-1 rounded-t transition-all hover:opacity-80 ${color}`}
              style={{ height: `${Math.max(8, pct)}%` }}
              title={`Chunk #${idx + 1}: ${val} / 8.0`}
            />
          );
        })}
      </div>
    </div>
  );
}

function CategorizedStringsPanel({ categorized, rawStrings }: { categorized?: SampleStatic["categorized_strings"]; rawStrings: string[] }) {
  const [activeTab, setActiveTab] = useState<"all" | "network" | "file_paths" | "commands" | "registry" | "security_apis">("all");
  const [search, setSearch] = useState("");

  const currentList = useMemo(() => {
    let list: string[] = [];
    if (activeTab === "all") list = rawStrings;
    else if (categorized && categorized[activeTab]) list = categorized[activeTab];
    if (!search) return list;
    const q = search.toLowerCase();
    return list.filter((s) => s.toLowerCase().includes(q));
  }, [activeTab, categorized, rawStrings, search]);

  return (
    <div className="space-y-3 border-t border-border-subtle pt-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1 font-mono text-[10px]">
          {[
            { id: "all", label: `All (${rawStrings.length})` },
            { id: "network", label: `Network (${categorized?.network?.length ?? 0})` },
            { id: "file_paths", label: `File Paths (${categorized?.file_paths?.length ?? 0})` },
            { id: "commands", label: `Commands (${categorized?.commands?.length ?? 0})` },
            { id: "registry", label: `Registry (${categorized?.registry?.length ?? 0})` },
            { id: "security_apis", label: `Security APIs (${categorized?.security_apis?.length ?? 0})` },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`rounded-lg px-2.5 py-1 transition ${
                activeTab === t.id
                  ? "bg-accent/15 font-bold text-accent shadow-sm"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter string list..."
          className="rounded-lg border border-border-subtle bg-bg-base px-2 py-1 font-mono text-xs text-text-primary focus:border-accent/60 outline-none"
        />
      </div>

      <div className="max-h-64 overflow-y-auto rounded-xl border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-[11px] leading-relaxed text-[#c9d1d9]">
        {currentList.length === 0 ? (
          <p className="text-text-faint text-center py-4">No strings found in this category.</p>
        ) : (
          currentList.slice(0, 150).map((s, idx) => (
            <div key={idx} className="hover:bg-accent/10 rounded px-1.5 py-0.5 truncate">
              {s}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function LiveDynamicSandboxCockpit({ sample }: { sample: { sample_id: string; original_name: string; detected_platform: string } }) {
  const queryClient = useQueryClient();
  const [detonating, setDetonating] = useState(false);
  const [isolationDriver, setIsolationDriver] = useState<string>("auto");
  const [timeoutSeconds, setTimeoutSeconds] = useState<number>(15);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SampleDetonationResult | null>(null);
  const [inspectorTab, setInspectorTab] = useState<"files" | "processes" | "network" | "detections" | "syscalls" | "timeline">("files");
  const [copiedTerminal, setCopiedTerminal] = useState(false);
  const [executionTimer, setExecutionTimer] = useState<number>(0);
  const timerIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const handleDetonateLive = async () => {
    setDetonating(true);
    setError(null);
    setExecutionTimer(0);
    const startTime = Date.now();
    timerIntervalRef.current = setInterval(() => {
      setExecutionTimer(Math.floor((Date.now() - startTime) / 1000));
    }, 250);

    try {
      const res = await detonateSample(sample.sample_id, timeoutSeconds, isolationDriver);
      setResult(res);
      if ((res.alerts || []).length > 0) {
        setInspectorTab("detections");
      } else if ((res.dropped_artifacts || []).length > 0) {
        setInspectorTab("files");
      } else {
        setInspectorTab("timeline");
      }
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Detonation failed");
    } finally {
      if (timerIntervalRef.current) {
        clearInterval(timerIntervalRef.current);
        timerIntervalRef.current = null;
      }
      setDetonating(false);
    }
  };

  const handleResetCockpit = () => {
    setResult(null);
    setError(null);
    setExecutionTimer(0);
  };

  const handleCopyTerminal = () => {
    const text = result?.terminal_output || "";
    if (!text) return;
    void navigator.clipboard.writeText(text);
    setCopiedTerminal(true);
    setTimeout(() => setCopiedTerminal(false), 2000);
  };

  const displayFiles = result?.dropped_artifacts || [];
  const displayProcesses = result?.process_tree || [];
  const displayNetwork = [
    ...(result?.sinkhole_traffic || []),
    ...((result?.events || []).filter((e) => e.event_type === "network_connection" || e.event_type === "socket_listen")),
  ];
  const displayAlerts = result?.alerts || [];

  return (
    <div className="space-y-4 font-mono">
      {/* Cockpit Shell */}
      <div className="overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface/90 shadow-xl backdrop-blur">
        {/* Cockpit Status Header Strip */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-base/80 px-5 py-3.5 text-xs">
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent shadow-[var(--glow-accent)]">
              <Icon name="play" size={15} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-text-primary text-sm">Mode 2: Dynamic Sandbox Cockpit</span>
                <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent uppercase">
                  Isolated Flight Recorder
                </span>
              </div>
              <p className="text-[11px] text-text-muted">
                Live sandbox cage execution · Files, processes, network egress &amp; detection rules tracked in real time
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {result && (
              <button
                onClick={handleResetCockpit}
                disabled={detonating}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-muted transition hover:border-accent/40 hover:text-text-primary disabled:opacity-50"
              >
                <Icon name="refresh" size={12} />
                <span>Reset to Standby</span>
              </button>
            )}
            <button
              onClick={() => void handleDetonateLive()}
              disabled={detonating}
              className="press inline-flex items-center gap-2 rounded-xl border border-accent/70 bg-accent/20 px-4 py-2 text-xs font-bold text-accent transition hover:bg-accent/30 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
            >
              <Icon name={detonating ? "refresh" : "play"} size={13} className={detonating ? "animate-spin" : ""} />
              <span>{detonating ? `Executing in Sandbox (${executionTimer}s)...` : result ? "Re-Detonate in Sandbox" : "Detonate Live Now"}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="mx-5 mt-4 rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-3 text-xs text-risk-malicious flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="press text-text-muted hover:text-text-primary">
              <Icon name="x" size={12} />
            </button>
          </div>
        )}

        {/* Dual-Deck Grid Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-border-subtle">
          {/* ── LEFT DECK: Sandbox Terminal Console (7 Cols) ───── */}
          <div className="lg:col-span-7 flex flex-col justify-between bg-[#04060a] p-4 text-xs">
            <div className="space-y-3">
              {/* Terminal Title & Controls Bar */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-2.5">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5" aria-hidden>
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
                  </div>
                  <span className="text-[11px] font-bold text-[#c9d1d9] pl-1">
                    cage:~/sandbox/{sample.original_name}
                  </span>
                  <span className={`ml-1 inline-flex items-center gap-1 rounded px-2 py-0.5 text-[9px] font-bold uppercase ${
                    detonating
                      ? "bg-amber-500/20 text-amber-300 animate-pulse"
                      : result
                        ? result.exit_code === 0
                          ? "bg-emerald-500/20 text-emerald-400"
                          : "bg-rose-500/20 text-rose-400"
                        : "bg-white/10 text-text-muted"
                  }`}>
                    {detonating ? "Cage Active" : result ? `Exit: ${result.exit_code}` : "Standby"}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {/* Isolation Driver Dropdown */}
                  <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                    <label className="text-[10px] text-text-faint">Driver:</label>
                    <select
                      value={isolationDriver}
                      onChange={(e) => setIsolationDriver(e.target.value)}
                      disabled={detonating}
                      className="rounded border border-white/15 bg-bg-surface px-2 py-1 text-[11px] text-text-primary outline-none focus:border-accent"
                    >
                      <option value="auto">Auto-Detect</option>
                      <option value="bubblewrap">Bubblewrap Micro-Sandbox</option>
                      <option value="wine">Headless Wine Emulation</option>
                      <option value="tempdir">Standard TempDir Cage</option>
                    </select>
                  </div>

                  {/* Timeout Dropdown */}
                  <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                    <label className="text-[10px] text-text-faint">Timeout:</label>
                    <select
                      value={timeoutSeconds}
                      onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                      disabled={detonating}
                      className="rounded border border-white/15 bg-bg-surface px-2 py-1 text-[11px] text-text-primary outline-none focus:border-accent"
                    >
                      <option value={5}>5s</option>
                      <option value={15}>15s</option>
                      <option value={30}>30s</option>
                      <option value={60}>60s</option>
                    </select>
                  </div>

                  <button
                    onClick={handleCopyTerminal}
                    disabled={!result}
                    className="press rounded border border-white/15 bg-white/5 px-2 py-1 text-[10px] text-text-muted hover:text-text-primary disabled:opacity-30"
                    title="Copy terminal console log"
                  >
                    {copiedTerminal ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>

              {/* Terminal Screen Console */}
              <div className="rounded-xl border border-white/10 bg-[#06080d] p-4 font-mono text-[11px] leading-relaxed max-h-[420px] overflow-y-auto shadow-inner selection:bg-accent selection:text-black">
                {detonating ? (
                  <div className="space-y-2 py-12 text-center text-accent">
                    <Icon name="refresh" size={24} className="mx-auto animate-spin" />
                    <p className="font-bold">Detonating {sample.original_name} in isolated sandbox cage...</p>
                    <p className="text-[10px] text-text-muted">
                      Trapping process creation, disk writes, and socket connections ({executionTimer}s elapsed)
                    </p>
                  </div>
                ) : result ? (
                  <div className="space-y-1">
                    <div className="text-emerald-400 font-bold mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      <span>[OutPost Dynamic Sandbox Cage Active · Process PID Isolated]</span>
                    </div>
                    {(result.terminal_lines || (result.terminal_output ? result.terminal_output.split("\n") : [])).map((line, lidx) => {
                      const isCmd = line.startsWith("$") || line.includes("Executing") || line.startsWith(">>>");
                      const isErr = line.toLowerCase().includes("error") || line.toLowerCase().includes("stderr") || line.includes("[!]");
                      const isInfo = line.startsWith("[*]") || line.startsWith("[OutPost");
                      return (
                        <div
                          key={lidx}
                          className={`whitespace-pre-wrap break-all ${
                            isCmd
                              ? "text-accent font-bold"
                              : isErr
                                ? "text-rose-400"
                                : isInfo
                                  ? "text-emerald-400"
                                  : "text-[#c9d1d9]"
                          }`}
                        >
                          {line}
                        </div>
                      );
                    })}
                    <div ref={terminalEndRef} />
                  </div>
                ) : (
                  /* Standby Readiness State */
                  <div className="flex flex-col items-center justify-center min-h-[260px] text-center space-y-3 py-8">
                    <div className="h-12 w-12 rounded-2xl border border-accent/40 bg-accent/10 flex items-center justify-center text-accent shadow-[var(--glow-accent)]">
                      <Icon name="terminal" size={24} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-text-primary font-bold text-sm">Sandbox Terminal Standby</p>
                      <p className="text-text-muted text-xs max-w-sm">
                        Binary has been safely triaged statically. Click <span className="text-accent font-bold">"Detonate Live Now"</span> above to execute in the isolated cage and stream live flight telemetry.
                      </p>
                    </div>
                    <div className="rounded-lg bg-bg-surface border border-border-subtle px-3 py-1.5 text-[11px] text-accent">
                      outpost-sandbox:~$ <span className="animate-pulse">_</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Terminal Status Strip */}
            <div className="mt-3 pt-2.5 border-t border-white/10 flex items-center justify-between text-[10px] text-text-faint">
              <span className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${result ? "bg-emerald-400" : detonating ? "bg-amber-400 animate-pulse" : "bg-text-faint"}`} />
                <span>Target: {sample.original_name} ({sample.detected_platform})</span>
              </span>
              <span>Isolation: {result?.isolation_driver || isolationDriver}</span>
            </div>
          </div>

          {/* ── RIGHT DECK: Live Behavioral Flight Recorder (5 Cols) ───── */}
          <div className="lg:col-span-5 flex flex-col justify-between bg-bg-surface p-4 text-xs space-y-4">
            <div className="space-y-4">
              {/* 4 Real-Time Behavioral KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-2 gap-2 text-center">
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-accent text-[11px]">
                    <Icon name="file" size={13} />
                    <span className="font-bold">Files Created</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayFiles.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">on disk</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-cyan-400 text-[11px]">
                    <Icon name="process" size={13} />
                    <span className="font-bold">Processes</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayProcesses.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">spawned</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-emerald-400 text-[11px]">
                    <Icon name="network" size={13} />
                    <span className="font-bold">Network Sockets</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayNetwork.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">outbound</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-rose-400 text-[11px]">
                    <Icon name="alert" size={13} />
                    <span className="font-bold">Rule Hits</span>
                  </div>
                  <div className={`text-lg font-bold ${displayAlerts.length > 0 ? "text-rose-400" : "text-text-primary"}`}>
                    {displayAlerts.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">detections</span>
                </div>
              </div>

              {/* Inspector Sub-Tabs */}
              <div className="flex flex-wrap items-center gap-1 border-b border-border-subtle pb-2 text-[11px]">
                <button
                  onClick={() => setInspectorTab("files")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "files" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="file" size={12} />
                  <span>Files ({displayFiles.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("processes")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "processes" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="process" size={12} />
                  <span>Processes ({displayProcesses.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("network")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "network" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="network" size={12} />
                  <span>Network ({displayNetwork.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("detections")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "detections" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="alert" size={12} />
                  <span>Rules ({displayAlerts.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("syscalls")}
                  className={`flex items-center gap-1 rounded-lg px-2 py-1 transition ${
                    inspectorTab === "syscalls" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <span>Syscalls</span>
                </button>
                <button
                  onClick={() => setInspectorTab("timeline")}
                  className={`flex items-center gap-1 rounded-lg px-2 py-1 transition ${
                    inspectorTab === "timeline" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <span>Timeline</span>
                </button>
              </div>

              {/* Tab 1: Files Created & Dropped Artifacts */}
              {inspectorTab === "files" && (
                <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
                  {displayFiles.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="file" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Dropped Files Detected</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        When the sample writes canary payloads, drops second-stage tools, or modifies disk files, they will appear here.
                      </p>
                    </div>
                  ) : (
                    displayFiles.map((art, fidx) => (
                      <div
                        key={fidx}
                        className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-2 hover:border-accent/40 transition"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-0.5 truncate">
                            <div className="flex items-center gap-1.5 font-bold text-text-primary">
                              <Icon name="file" size={12} className="text-accent shrink-0" />
                              <span className="truncate">{art.name}</span>
                            </div>
                            <div className="flex items-center gap-2 text-[10px] text-text-faint">
                              <span>{art.size_bytes} bytes</span>
                              {art.is_high_entropy && (
                                <span className="rounded bg-rose-500/20 px-1 py-0.2 text-[9px] font-bold text-rose-400">
                                  High Entropy ({art.entropy}/8.0)
                                </span>
                              )}
                            </div>
                          </div>
                          {result && (
                            <a
                              href={getSandboxArtifactUrl(result.run_id, art.filename)}
                              download
                              className="press shrink-0 inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/20"
                            >
                              <Icon name="download" size={10} />
                              <span>Download</span>
                            </a>
                          )}
                        </div>

                        {/* Shannon Entropy Visual Bar */}
                        <div className="space-y-1">
                          <div className="flex justify-between text-[9px] text-text-faint">
                            <span>Entropy: {art.entropy} / 8.0</span>
                            <span>{art.entropy > 7.0 ? "Encrypted / Packed" : art.entropy > 5.0 ? "Binary / Code" : "Plaintext"}</span>
                          </div>
                          <div className="h-1.5 w-full bg-border-subtle rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                art.entropy > 7.0 ? "bg-rose-500" : art.entropy > 5.0 ? "bg-amber-400" : "bg-emerald-400"
                              }`}
                              style={{ width: `${Math.min(100, (art.entropy / 8.0) * 100)}%` }}
                            />
                          </div>
                        </div>

                        <div className="text-[10px] text-text-muted bg-bg-surface p-2 rounded border border-border-subtle/50 space-y-0.5">
                          <div className="truncate"><span className="text-text-faint uppercase text-[9px]">SHA256:</span> {art.sha256}</div>
                          <div className="truncate"><span className="text-text-faint uppercase text-[9px]">MD5:</span> {art.md5}</div>
                        </div>

                        {art.preview && art.preview.length > 0 && (
                          <div className="bg-[#0a0c10] p-2 rounded text-[10px] font-mono text-emerald-400 max-h-20 overflow-y-auto space-y-0.5">
                            {art.preview.slice(0, 5).map((p, pidx) => (
                              <div key={pidx} className="truncate">{p}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 2: Process Causality Tree */}
              {inspectorTab === "processes" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {displayProcesses.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="process" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Processes Spawned</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Any child processes, shell commands, or subprocess forks will populate the causality tree here.
                      </p>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-border-subtle bg-bg-base/80 p-3">
                      <ProcessCausalityTree nodes={displayProcesses} />
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Network Sockets & Sinkhole */}
              {inspectorTab === "network" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {displayNetwork.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="network" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">Zero Outbound Egress</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Outbound socket connections, C2 beacons, or DNS queries will be intercepted and listed here.
                      </p>
                    </div>
                  ) : (
                    displayNetwork.map((net: any, nidx: number) => (
                      <div
                        key={nidx}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-2.5 text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-bold text-amber-400 uppercase">
                            {net.type ? net.type.replace("_", " ") : net.protocol || "SOCKET"}
                          </span>
                          <span className="font-bold text-text-primary">
                            {net.target || `${net.dest_ip}:${net.dest_port}`}
                          </span>
                        </div>
                        <span className="text-[10px] text-amber-300">
                          {net.intercepted_response || "Sinkholed / Intercepted"}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 4: Detection Rules Fired */}
              {inspectorTab === "detections" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {displayAlerts.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="shield" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Detection Rules Triggered</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        When behavior matches OutPost heuristic detection rules or Sigma signatures, alerts fire here.
                      </p>
                    </div>
                  ) : (
                    displayAlerts.map((al: any, aidx: number) => {
                      const isMal = al.severity === "malicious";
                      return (
                        <div
                          key={aidx}
                          className={`rounded-lg border p-2.5 text-xs space-y-1 ${
                            isMal
                              ? "border-rose-500/40 bg-rose-500/10"
                              : "border-amber-500/40 bg-amber-500/10"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-text-primary">{al.rule_name}</span>
                            <span className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                              isMal ? "bg-rose-500/20 text-rose-400" : "bg-amber-500/20 text-amber-400"
                            }`}>
                              {al.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-text-muted">{al.details}</p>
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Tab 5: Syscalls */}
              {inspectorTab === "syscalls" && (
                <div className="max-h-[300px] overflow-y-auto pr-1">
                  {(!result?.syscalls || result.syscalls.length === 0) ? (
                    <p className="text-xs text-text-muted py-6 text-center">No system calls recorded yet.</p>
                  ) : (
                    <div className="rounded-xl border border-border-subtle bg-[#0a0c10] p-2.5 font-mono text-[10px]">
                      <div className="grid grid-cols-12 gap-1 border-b border-border-subtle pb-1 font-bold text-text-faint uppercase text-[9px]">
                        <span className="col-span-1">PID</span>
                        <span className="col-span-2">Call</span>
                        <span className="col-span-6">Args</span>
                        <span className="col-span-1">Res</span>
                        <span className="col-span-2">Type</span>
                      </div>
                      {result.syscalls.slice(0, 100).map((sc, scidx) => (
                        <div key={scidx} className="grid grid-cols-12 gap-1 py-0.5 border-b border-white/5 text-[#c9d1d9]">
                          <span className="col-span-1 text-text-faint">{sc.pid ?? "-"}</span>
                          <span className="col-span-2 font-bold text-accent">{sc.syscall}</span>
                          <span className="col-span-6 truncate text-text-muted" title={sc.arguments}>{sc.arguments}</span>
                          <span className="col-span-1 text-emerald-400">{sc.result}</span>
                          <span className="col-span-2 capitalize text-text-faint">{sc.category}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 6: Timeline */}
              {inspectorTab === "timeline" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {(!result?.timeline || result.timeline.length === 0) ? (
                    <p className="text-xs text-text-muted py-6 text-center">No timeline events recorded yet.</p>
                  ) : (
                    result.timeline.map((ev, tidx) => (
                      <div
                        key={tidx}
                        className="flex items-start gap-2.5 rounded-lg border border-border-subtle bg-bg-base/40 p-2 text-xs"
                      >
                        <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[9px] font-bold text-text-faint">
                          +{((ev.elapsed_ms || 0) / 1000).toFixed(2)}s
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-text-primary">{ev.title}</span>
                            <span className="rounded bg-bg-elevated px-1 py-0.2 text-[8px] text-text-muted uppercase">
                              {ev.severity}
                            </span>
                          </div>
                          <p className="text-[10px] text-text-muted truncate">{ev.details}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            {/* Right Deck Footer Actions */}
            {result && (
              <div className="mt-3 pt-2.5 border-t border-border-subtle flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div className="flex items-center gap-2">
                  <Link to={`/runs/${result.run_id}`} className="press text-accent hover:underline flex items-center gap-1">
                    <span>Run Dossier</span>
                    <Icon name="arrowRight" size={11} />
                  </Link>
                  <span className="text-text-faint">·</span>
                  <Link to={`/events?run_id=${result.run_id}`} className="press text-text-muted hover:text-accent">
                    Host Events
                  </Link>
                </div>
                {(result.alerts || []).length > 0 && (
                  <Link
                    to={`/investigations?create=1&run_id=${result.run_id}&title=${encodeURIComponent(sample.original_name + " Detonation Analysis")}`}
                    className="press inline-flex items-center gap-1 rounded bg-rose-500/15 border border-rose-500/40 px-2.5 py-0.5 font-bold text-rose-400 hover:bg-rose-500/25"
                  >
                    <Icon name="shield" size={11} />
                    <span>Escalate to Case</span>
                  </Link>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


function SimilarSamplesPanel({ sampleId }: { sampleId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["sample", "similar", sampleId],
    queryFn: () => getSimilarSamples(sampleId, 20),
  });

  if (isLoading) {
    return (
      <Panel kicker="Static · similarity" title="Binary Similarity & Fuzzy Hash Matching">
        <p className="text-xs text-text-muted">Comparing context-triggered piecewise hashes across sample vault…</p>
      </Panel>
    );
  }

  const matches = data?.similar || [];

  return (
    <Panel
      kicker="Static · similarity"
      title="Binary Similarity & Fuzzy Hash Matching"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {matches.length} matching sample{matches.length === 1 ? "" : "s"}
        </span>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3 text-xs">
          {data?.target_imphash && (
            <div className="rounded border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[11px]">
              <span className="text-text-faint">Target imphash: </span>
              <span className="text-accent font-bold">{data.target_imphash}</span>
            </div>
          )}
          {data?.target_fuzzy_hash && (
            <div className="rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] truncate max-w-md">
              <span className="text-text-faint">Target CTPH: </span>
              <span className="text-text-muted">{data.target_fuzzy_hash}</span>
            </div>
          )}
        </div>

        {matches.length === 0 ? (
          <p className="text-xs text-text-muted py-2">
            No related binary variants detected in the vault above the 20% similarity threshold.
          </p>
        ) : (
          <div className="space-y-2">
            {matches.map((m: any) => (
              <div key={m.sample_id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border-subtle bg-bg-base/60 p-3 hover:border-accent/40">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/samples/${m.sample_id}`}
                      className="font-mono text-xs font-semibold text-text-primary hover:text-accent truncate"
                    >
                      {m.original_name}
                    </Link>
                    {m.imphash_match && (
                      <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-accent">
                        IMPHASH MATCH
                      </span>
                    )}
                  </div>
                  <p className="font-mono text-[10px] text-text-faint truncate">
                    SHA256: {m.sha256}
                  </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <span className="font-mono text-xs font-bold text-accent">{m.similarity}%</span>
                    <span className="block font-mono text-[10px] text-text-faint">similarity</span>
                  </div>
                  <div className="h-1.5 w-20 overflow-hidden rounded-full bg-bg-elevated">
                    <div
                      className="h-full rounded-full bg-accent"
                      style={{ width: `${m.similarity}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ── Sandbox detonation (roadmap 3.3) ───────────────────────────────────── */

const SANDBOX_PLATFORMS: { value: Platform | ""; label: string }[] = [
  { value: "", label: "Use sample OS" },
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
  { value: "macos", label: "macOS" },
];

function SandboxDetonation({ sample }: { sample: { sample_id: string; original_name: string; detected_platform: string } }) {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState("auto");
  const [platform, setPlatform] = useState<Platform | "">("");
  const [task, setTask] = useState<SandboxTask | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const mounted = useRef(true);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: providers } = useQuery({
    queryKey: ["sandbox", "providers"],
    queryFn: getSandboxProviders,
  });

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, []);

  const poll = async (taskId: string, attempt = 0) => {
    if (!mounted.current || attempt >= 120) {
      if (mounted.current) setPolling(false);
      return;
    }
    try {
      const t = await getSandboxTask(taskId);
      if (!mounted.current) return;
      setTask(t);
      if (t.status === "completed" || t.status === "error") {
        setPolling(false);
        void queryClient.invalidateQueries({ queryKey: ["runs", "q", sample.original_name] });
        return;
      }
    } catch {
      /* transient poll failure — keep trying */
    }
    pollRef.current = setTimeout(() => void poll(taskId, attempt + 1), 2500);
  };

  const detonate = async () => {
    setError(null);
    setTask(null);
    try {
      const t = await sandboxDetonate({
        sample_id: sample.sample_id,
        provider,
        platform: platform || undefined,
      });
      if (!mounted.current) return;
      setTask(t);
      if (t.status === "submitted" || t.status === "running") {
        setPolling(true);
        void poll(t.task_id);
      } else {
        void queryClient.invalidateQueries({ queryKey: ["runs", "q", sample.original_name] });
      }
    } catch (e) {
      if (mounted.current) setError(e instanceof Error ? e.message : "Detonation failed");
    }
  };

  const providerName = (id: string) => providers?.providers.find((p) => p.id === id)?.name ?? id;
  const isBusy = polling || task?.status === "submitted" || task?.status === "running";

  return (
    <Panel
      kicker="Sandbox · roadmap"
      title="Detonate in an external sandbox"
      className="mt-6"
      right={
        providers ? (
          <span
            className={`inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide ${
              providers.mode === "live" ? "text-risk-clean" : "text-text-faint"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                providers.mode === "live" ? "bg-risk-clean" : "bg-text-faint"
              }`}
              aria-hidden
            />
            {providers.mode === "live"
              ? `live · ${providerName(providers.active)}`
              : "roadmap · no provider configured"}
          </span>
        ) : undefined
      }
    >
      <p className="mb-4 max-w-2xl text-sm text-text-muted">
        Push the sample to an external sandbox (Any.Run, Triage, or Joe) and stream the report back
        through the detection pipeline as a normal run.
      </p>

      {providers && providers.mode !== "live" && (
        <div className="mb-4 rounded-xl border border-accent/30 bg-accent/5 p-4 font-mono text-xs text-text-muted">
          <p className="font-semibold text-text-primary flex items-center gap-1.5">
            <Icon name="box" size={14} className="text-accent" />
            Local Isolated Sandbox Active
          </p>
          <p className="mt-1 text-[11px] text-text-faint">
            Detonating runs directly in OutPost's local isolated subprocess sandbox with live process tracing, stdout/stderr capture, and detection rule evaluation. To optionally forward samples to external cloud sandboxes (Any.Run, Hatching Triage, Joe Sandbox), configure API keys in{" "}
            <Link to="/settings" className="text-accent underline hover:text-accent-hover">
              Settings
            </Link>
            .
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <button
          onClick={() => setProvider("auto")}
          disabled={isBusy}
          className={`press rounded border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
            provider === "auto"
              ? "border-accent/60 bg-accent/10 text-accent"
              : "border-border-subtle text-text-muted hover:border-accent/40 hover:text-accent"
          }`}
        >
          auto
        </button>
        {providers?.providers.map((p) => (
          <button
            key={p.id}
            onClick={() => setProvider(p.id)}
            disabled={isBusy}
            className={`press inline-flex items-center gap-1.5 rounded border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
              provider === p.id
                ? "border-accent/60 bg-accent/10 text-accent"
                : "border-border-subtle text-text-muted hover:border-accent/40 hover:text-accent"
            }`}
            title={p.configured ? `Live detonation via ${p.name}` : `${p.name} needs an API key — use demo instead`}
          >
            {p.id === "demo" ? <Icon name="terminal" size={10} /> : <Icon name="box" size={10} />}
            {p.id}
            <span
              className={`rounded px-1 py-px text-[9px] uppercase tracking-wide ${
                p.configured ? "bg-risk-clean/15 text-risk-clean" : "bg-bg-elevated/60 text-text-faint"
              }`}
            >
              {p.configured ? "live" : "off"}
            </span>
          </button>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 font-mono text-[11px] text-text-muted">
          <Icon name="linux" size={11} className="text-text-faint" />
          Detonation OS
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value as Platform | "")}
            disabled={isBusy}
            className="rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
            aria-label="Detonation OS"
          >
            {SANDBOX_PLATFORMS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.value === "" ? `${o.label} (${sample.detected_platform})` : o.label}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={() => void detonate()}
          disabled={isBusy}
          className="press inline-flex items-center gap-1.5 rounded border border-accent/60 bg-accent/10 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/20 disabled:cursor-default disabled:opacity-50"
        >
          <Icon name={isBusy ? "refresh" : "play"} size={12} className={isBusy ? "animate-spin" : undefined} />
          {isBusy ? "detonating…" : "detonate"}
        </button>
      </div>

      {error && <p className="mb-3 font-mono text-[11px] text-risk-malicious">{error}</p>}

      {task && (
        <div className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span
              className={`font-mono text-[10px] uppercase tracking-wide ${
                task.status === "completed"
                  ? "text-risk-clean"
                  : task.status === "error"
                    ? "text-risk-malicious"
                    : "text-accent"
              }`}
            >
              {task.status === "completed" ? "● completed" : task.status === "error" ? "● error" : `● ${task.status}`}
            </span>
            <span className="font-mono text-[10px] text-text-faint">
              {providerName(task.provider)} · {task.platform} · {task.task_id}
            </span>
          </div>
          {task.status === "completed" ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-xs text-text-primary">
                {task.events} events · {task.alerts} alerts · risk {task.risk_score}
              </span>
              <Link
                to={`/runs/${task.run_id}`}
                className="press inline-flex items-center gap-1 font-mono text-[11px] text-accent transition-colors hover:underline"
              >
                open run
                <Icon name="arrowRight" size={11} />
              </Link>
            </div>
          ) : task.status === "error" ? (
            <p className="font-mono text-[11px] text-risk-malicious">{task.error}</p>
          ) : (
            <p className="font-mono text-[11px] text-text-muted">Waiting for the sandbox report…</p>
          )}
        </div>
      )}
    </Panel>
  );
}

function PeElfTable({ st }: { st: SampleStatic }) {
  const pe = st.pe;
  const elf = st.elf;
  return (
    <div className="space-y-4">
      {pe && (
        <div className="flex flex-wrap items-center gap-2">
          <Chip tone="accent" dot>
            {pe.machine} · {pe.bits ?? "?"}-bit
          </Chip>
          {pe.entry_point_rva !== null && (
            <span className="font-mono text-[11px] text-text-muted">entry RVA 0x{pe.entry_point_rva.toString(16)}</span>
          )}
          {pe.imphash && (
            <span className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
              imphash: {pe.imphash}
            </span>
          )}
          {pe.authenticode && (
            <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${
              pe.authenticode.signed
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                : "border-border-subtle bg-bg-elevated/40 text-text-faint"
            }`}>
              {pe.authenticode.signed ? `Authenticode Signed (${pe.authenticode.cert_size} B)` : "Unsigned Binary"}
            </span>
          )}
          {pe.rich_header?.present && (
            <span className="rounded border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 font-mono text-[10px] text-purple-300" title={`XOR Key ${pe.rich_header.xor_key} · ${pe.rich_header.records_count} compiler entries`}>
              Rich Hash: {pe.rich_header.hash.slice(0, 10)}…
            </span>
          )}
          <span className="font-mono text-[10px] text-text-faint">
            {pe.imports.length} import DLL{pe.imports.length === 1 ? "" : "s"}
          </span>
        </div>
      )}
      {pe?.mitigations && pe.mitigations.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="font-mono text-[10px] uppercase font-bold text-text-faint">Exploit Mitigations:</span>
          {pe.mitigations.map((m) => (
            <span key={m} className="rounded border border-signal/40 bg-signal/10 px-2 py-0.5 font-mono text-[10px] font-medium text-signal">
              ✓ {m}
            </span>
          ))}
        </div>
      )}
      {pe && pe.sections.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[420px] text-left text-xs">
            <thead className="border-b border-border-subtle">
              <tr className="text-[10px] uppercase tracking-wide text-text-faint">
                <th className="px-3 py-1.5 font-normal">Section</th>
                <th className="px-3 py-1.5 text-right font-normal">Virtual</th>
                <th className="px-3 py-1.5 text-right font-normal">Raw</th>
                <th className="px-3 py-1.5 font-normal">Flags</th>
              </tr>
            </thead>
            <tbody>
              {pe.sections.map((s) => (
                <tr key={s.name} className="border-b border-border-subtle/50 last:border-0">
                  <td className="px-3 py-1.5 font-mono text-text-primary">{s.name || "(null)"}</td>
                  <td className="px-3 py-1.5 text-right font-mono text-text-muted">0x{s.virtual_size.toString(16)}</td>
                  <td className="px-3 py-1.5 text-right font-mono text-text-muted">0x{s.raw_size.toString(16)}</td>
                  <td className="px-3 py-1.5">
                    <span className="font-mono text-[10px] text-text-faint">{s.flags.join(" · ") || "—"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pe && pe.imports.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {pe.imports.map((dll) => (
            <span key={dll} className="rounded border border-accent/40 bg-accent/5 px-2 py-0.5 font-mono text-[10px] text-accent">
              {dll}
            </span>
          ))}
        </div>
      )}
      {elf && (
        <div className="flex flex-wrap items-center gap-2">
          <Chip tone="clean" dot>
            {elf.machine} · ELF{elf.class} · {elf.type}
          </Chip>
          <span className="font-mono text-[11px] text-text-muted">entry 0x{elf.entry_point.toString(16)}</span>
          <span className="font-mono text-[10px] text-text-faint">{elf.sections.length} sections · {elf.endian}-endian</span>
        </div>
      )}
      {elf && elf.sections.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {elf.sections.slice(0, 40).map((s) => (
            <span key={`${s.name}-${s.type}`} className="rounded border border-border-subtle bg-bg-elevated/40 px-2 py-0.5 font-mono text-[10px] text-text-muted" title={`type ${s.type} · ${s.size} bytes`}>
              {s.name || "(anon)"}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SampleDetailPage() {
  const navigate = useNavigate();
  const { sampleId = "" } = useParams();
  const [copied, setCopied] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [detonating, setDetonating] = useState(false);
  const [detonationError, setDetonationError] = useState<string | null>(null);
  const [dossierTab, setDossierTab] = useState<"static" | "dynamic" | "history" | "similarity">("static");

  const { data: sample, isLoading, isError } = useQuery({
    queryKey: ["sample", sampleId],
    queryFn: () => getSample(sampleId),
  });

  // Runs that detonated this binary — filtered by its sample name.
  const { data: runs = [] } = useQuery({
    queryKey: ["runs", "q", sample?.original_name ?? ""],
    queryFn: () => getRuns({ q: sample?.original_name ?? "" }),
    enabled: sample !== undefined,
  });

  const copyHash = async () => {
    if (!sample) return;
    try {
      await navigator.clipboard.writeText(sample.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable — the title tooltip still carries the hash */
    }
  };

  if (isLoading) return <p className="p-8 text-sm text-text-muted font-mono">Loading sample…</p>;
  if (isError || !sample) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-12">
        <Panel kicker="Sample Vault · 404" title="Sample not found">
          <p className="text-sm text-text-muted">
            Couldn't find sample <span className="font-mono text-text-primary">{sampleId}</span> in the vault.
          </p>
          <div className="mt-4">
            <Link to="/samples" className="press inline-flex items-center gap-1.5 font-mono text-xs text-accent underline">
              <Icon name="chevronLeft" size={12} />
              Return to Sample Vault
            </Link>
          </div>
        </Panel>
      </div>
    );
  }

  const platName = sample.detected_platform === "windows" ? "Windows" : sample.detected_platform === "linux" ? "Linux" : sample.detected_platform === "macos" ? "macOS" : "unknown";
  const platIcon = sample.detected_platform === "macos" || sample.detected_platform === "windows" || sample.detected_platform === "linux" ? platformIconName(sample.detected_platform) : "terminal";

  return (
    <div className="mx-auto max-w-5xl px-6 py-8 lg:px-10">
      <nav className="mb-6 flex items-center gap-2 font-mono text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/samples" className="transition-colors hover:text-accent">
          Sample vault
        </Link>
        <span aria-hidden>/</span>
        <span className="text-text-primary">{sample.original_name}</span>
      </nav>

      <PageHeader
        kicker="Intelligence · sample"
        title={
          <>
            {sample.original_name}{" "}
            <span className="font-normal text-text-muted">— {sample.family ?? "untyped"}</span>
          </>
        }
        lede={`Detected ${sample.detected_platform} from magic bytes · ${formatBytes(sample.size)} · uploaded ${sample.created_at.slice(0, 19).replace("T", " ")} UTC`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={async () => {
                setDetonationError(null);
                setDetonating(true);
                try {
                  const res = await detonateDynamic({ sample_id: sample.sample_id });
                  navigate(`/runs/${res.run_id}`);
                } catch (e: unknown) {
                  setDetonationError(e instanceof Error ? e.message : "Detonation failed");
                } finally {
                  setDetonating(false);
                }
              }}
              disabled={detonating}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-4 py-2 font-mono text-xs font-semibold text-accent transition-all duration-150 hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
              title="Detonate sample in local isolated dynamic sandbox"
            >
              <Icon name="play" size={12} />
              {detonating ? "Detonating..." : "Detonate in sandbox"}
            </button>
            <Link
              to={`/footprint?sample=${sample.sample_id}`}
              className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            >
              Digital footprint
              <Icon name="arrowRight" size={12} />
            </Link>
            <span className="flex items-center gap-2">
              {downloadError && <span className="font-mono text-[10px] text-risk-malicious">{downloadError}</span>}
              {detonationError && <span className="font-mono text-[10px] text-risk-malicious">{detonationError}</span>}
              <button
                onClick={() => void downloadSample(sample.sample_id, sample.original_name).catch(() => setDownloadError("Download failed — bytes not stored?"))}
                className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                title={`Download ${sample.original_name}`}
              >
                <Icon name="download" size={12} />
                download
              </button>
            </span>
            <button
              onClick={() => void copyHash()}
              className="press inline-flex items-center gap-1.5 rounded border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10"
              title={sample.sha256}
            >
              <Icon name={copied ? "check" : "copy"} size={12} />
              {copied ? "copied" : "copy hash"}
            </button>
            <button
              onClick={async () => {
                if (!window.confirm(`Delete sample ${sample.original_name} from vault?`)) return;
                try {
                  await deleteSample(sample.sample_id);
                  navigate("/samples");
                } catch {
                  setDownloadError("Delete failed");
                }
              }}
              className="press inline-flex items-center gap-1.5 rounded border border-risk-malicious/40 bg-risk-malicious/10 px-4 py-2 font-mono text-xs text-risk-malicious transition-colors duration-150 hover:bg-risk-malicious/20"
              title={`Delete ${sample.original_name}`}
            >
              <Icon name="x" size={12} />
              delete
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Panel kicker="Signature" title="Full SHA-256">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <code className="min-w-0 flex-1 break-all rounded border border-border-subtle bg-bg-elevated/50 px-3 py-2 font-mono text-xs leading-relaxed text-text-primary">
              {sample.sha256}
            </code>
            <a
              href={getVirusTotalFileUrl(sample.sha256)}
              target="_blank"
              rel="noopener noreferrer"
              title="Inspect file hash report on VirusTotal"
              className="press inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-2 font-mono text-xs font-bold text-accent transition-all hover:bg-accent/25 hover:shadow-[var(--glow-accent)]"
            >
              <span>VirusTotal Intel</span>
              <Icon name="external" size={12} />
            </a>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Chip tone={sample.detected_platform === "macos" ? "suspicious" : sample.detected_platform === "linux" ? "clean" : "accent"} dot title={`Detected ${sample.detected_platform}`}>
              <Icon name={platIcon} size={11} />
              {platName}
            </Chip>
            {sample.malware_family && (
              <Chip tone="malicious" dot title="VirusTotal family">
                {sample.malware_family}
              </Chip>
            )}
            {sample.vt_detections !== null ? (
              <a
                href={getVirusTotalFileUrl(sample.sha256)}
                target="_blank"
                rel="noopener noreferrer"
                title="View VirusTotal detection report"
              >
                <Chip tone={sample.vt_detections > 0 ? "malicious" : "clean"} dot>
                  {sample.vt_detections} VT detection{sample.vt_detections === 1 ? "" : "s"} ↗
                </Chip>
              </a>
            ) : (
              <Chip tone="muted">no VT intel</Chip>
            )}
          </div>
        </Panel>

        <Panel kicker="YARA" title={`Signatures matched (${sample.yara_rules.length})`}>
          {sample.yara_rules.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {sample.yara_rules.map((r) => (
                <span
                  key={r}
                  className="rounded border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[11px] text-accent"
                >
                  {r}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No bundled YARA rules matched this binary.</p>
          )}
        </Panel>
      </div>

      {/* Analysis Workspace Mode Switcher */}
      <div className="mt-8 rounded-2xl border border-border-subtle bg-bg-surface/80 p-2 shadow-sm font-mono">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <button
            onClick={() => setDossierTab("static")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "static"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-[var(--glow-accent)]"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-bold">
                <Icon name="box" size={14} />
                Mode 1: Static Triage
              </span>
              <span className="rounded bg-emerald-500/20 px-1.5 py-0.2 text-[9px] font-bold text-emerald-400 uppercase">
                Safe · No Exec
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Raw bytes inspection, Shannon entropy, YARA rules &amp; VirusTotal pivots.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("dynamic")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "dynamic"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-[var(--glow-accent)]"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-bold">
                <Icon name="play" size={14} />
                Mode 2: Dynamic Sandbox
              </span>
              <span className="rounded bg-accent/20 px-1.5 py-0.2 text-[9px] font-bold text-accent uppercase">
                Live Cockpit
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Isolated cage execution with real-time flight recorder of files, processes &amp; sockets.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("history")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "history"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-[var(--glow-accent)]"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-bold">
                <Icon name="activity" size={14} />
                Detonation Runs ({runs.length})
              </span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] font-bold text-text-faint uppercase">
                History
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Historical sandbox runs, risk scores, and protocol network forensics.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("similarity")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "similarity"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-[var(--glow-accent)]"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-bold">
                <Icon name="copy" size={14} />
                Binary Similarity
              </span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] font-bold text-text-faint uppercase">
                CTPH
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Fuzzy hash comparison across vault samples for shared code reuse.
            </p>
          </button>
        </div>
      </div>

      {dossierTab === "static" && <StaticAnalysis sample={sample} />}

      {dossierTab === "dynamic" && (
        <div className="mt-6 space-y-6">
          <LiveDynamicSandboxCockpit sample={sample} />
          <details className="rounded-xl border border-border-subtle bg-bg-surface/60 p-4 transition">
            <summary className="cursor-pointer font-mono text-xs text-text-muted hover:text-accent select-none">
              ▸ Advanced Sandbox Task Dispatcher (Asynchronous Background Jobs)
            </summary>
            <div className="mt-4">
              <SandboxDetonation sample={sample} />
            </div>
          </details>
        </div>
      )}

      {dossierTab === "similarity" && (
        <div className="mt-6">
          <SimilarSamplesPanel sampleId={sample.sample_id} />
        </div>
      )}

      {dossierTab === "history" && (
        <Panel kicker="Detonations" title={`Runs of ${sample.original_name}`} className="mt-6" pad={false}>
          {runs.length === 0 ? (
            <p className="p-6 text-sm text-text-muted">This sample hasn't been detonated yet — click "Detonate in sandbox" to analyze live.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="border-b border-border-subtle">
                  <tr className="text-xs font-semibold text-text-muted">
                    <th className="px-4 py-2.5">Run</th>
                    <th className="px-4 py-2.5">Started</th>
                    <th className="px-4 py-2.5">Alerts</th>
                    <th className="px-4 py-2.5">Severity</th>
                    <th className="px-4 py-2.5 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r: RunSummary) => (
                    <tr key={r.run_id} className="border-b border-border-subtle/50 transition-colors hover:bg-bg-elevated/30">
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/runs/${r.run_id}`}
                          className="press font-mono text-xs text-accent transition-colors hover:underline"
                        >
                          {r.run_id.slice(0, 12)}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">
                        {r.started_at.slice(0, 19).replace("T", " ")}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">{r.alert_count}</td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`font-mono text-[10px] ${
                            r.highest_severity === "malicious"
                              ? "text-risk-malicious"
                              : r.highest_severity === "suspicious"
                                ? "text-risk-suspicious"
                                : "text-risk-clean"
                          }`}
                        >
                          ● {r.highest_severity ?? "clean"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-[11px] text-text-primary">{r.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {runs && runs.length > 0 && (
        <Panel kicker="Protocol Forensics" title="Aggregated Network & C2 Conversation Analysis">
          <NetworkProtocolInspector sampleId={sampleId} />
        </Panel>
      )}
    </div>
  );
}

