import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { Chip, PageHeader, Panel } from "../components/ui";
import { deleteSample, detonateDynamic, detonateSample, downloadSample, getRuns, getSample, getSampleStatic, getSandboxArtifactUrl, getSandboxProviders, getSandboxTask, getSimilarSamples, sandboxDetonate, watchlistAdd } from "../lib/api";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import type { Platform, RunSummary, SampleDetonationResult, SampleStatic, SandboxTask } from "../types";
import { filterStrings, formatBytes, iocTotal } from "./samplesHelpers";

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
            {/* IOC buckets — each chip jumps to search (pre-filled) or watchlists. */}
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
                              title={`Search history for ${v}`}
                              className="press inline-flex max-w-[260px] items-center gap-1 truncate rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                            >
                              <Icon name={g.icon} size={10} className="text-text-faint" />
                              <span className="truncate">{v}</span>
                            </Link>
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
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SampleDetonationResult | null>(null);
  const [simTab, setSimTab] = useState<"timeline" | "tree" | "artifacts" | "alerts" | "syscalls" | "sinkhole" | "terminal" | "delta">("timeline");

  const handleDetonateLive = async () => {
    setDetonating(true);
    setError(null);
    try {
      const res = await detonateSample(sample.sample_id, 15, isolationDriver);
      setResult(res);
      setSimTab("timeline");
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Detonation failed");
    } finally {
      setDetonating(false);
    }
  };

  return (
    <Panel kicker="Dynamic Execution · Sandbox" title="Live Isolated Execution & Dynamic Trace">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-bg-base/60 p-4">
          <div>
            <h4 className="font-mono text-xs font-bold text-text-primary">Instant Sandbox Detonation</h4>
            <p className="mt-0.5 text-[11px] text-text-muted">
              Executes binary in an isolated micro-environment, tracking process creation, disk I/O, network sockets, and behavioral detection alerts.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <label className="font-mono text-[11px] text-text-muted">Isolation Driver:</label>
              <select
                value={isolationDriver}
                onChange={(e) => setIsolationDriver(e.target.value)}
                className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-xs text-text-primary outline-none focus:border-accent/60"
              >
                <option value="auto">Auto-Detect Best Driver</option>
                <option value="bubblewrap">Bubblewrap Micro-Sandbox (bwrap)</option>
                <option value="wine">Headless Wine Emulation</option>
                <option value="tempdir">Standard Isolation (Tempdir)</option>
              </select>
            </div>
          </div>
          <button
            onClick={() => void handleDetonateLive()}
            disabled={detonating}
            className="press inline-flex items-center gap-1.5 rounded-xl border border-accent/60 bg-accent/15 px-4 py-2 font-mono text-xs font-bold text-accent transition hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
          >
            <Icon name={detonating ? "refresh" : "play"} size={13} className={detonating ? "animate-spin" : ""} />
            <span>{detonating ? "Executing in Sandbox..." : "Detonate Live Now"}</span>
          </button>
        </div>

        {error && <p className="font-mono text-xs text-risk-malicious">{error}</p>}

        {result && (
          <div className="space-y-4 rounded-xl border border-border-subtle bg-bg-surface p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle pb-3">
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="h-2 w-2 rounded-full bg-signal animate-pulse" />
                <span className="font-bold text-text-primary">Execution Result (Exit Code {result.exit_code})</span>
                <span className="rounded bg-accent/20 px-2 py-0.5 text-[10px] font-bold text-accent">
                  Risk: {result.risk_score}/100
                </span>
              </div>
              <div className="flex items-center gap-2">
                {(result.alerts || []).length > 0 && (
                  <Link
                    to={`/investigations?create=1&run_id=${result.run_id}&title=${encodeURIComponent(sample.original_name + " Malware Detonation")}`}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-risk-malicious/50 bg-risk-malicious/15 px-3 py-1 font-mono text-xs font-semibold text-risk-malicious hover:bg-risk-malicious/25"
                  >
                    <Icon name="shield" size={12} />
                    Escalate to Case Dossier
                  </Link>
                )}
                <Link to={`/runs/${result.run_id}`} className="font-mono text-xs text-accent hover:underline">
                  Open Full Run Dossier →
                </Link>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 font-mono text-xs">
              {[
                { id: "timeline", label: `Timeline (${result.timeline?.length ?? 0})` },
                { id: "tree", label: `Process Tree (${result.process_tree?.length ?? 0})` },
                { id: "artifacts", label: `Dropped Files (${result.dropped_artifacts?.length ?? 0})` },
                { id: "alerts", label: `Alerts (${result.alerts?.length ?? 0})` },
                { id: "syscalls", label: `Syscalls (${result.syscalls?.length ?? 0})` },
                { id: "sinkhole", label: `C2 Sinkhole (${result.sinkhole_traffic?.length ?? 0})` },
                { id: "terminal", label: "Terminal Log" },
                { id: "delta", label: "Baseline Delta" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSimTab(tab.id as any)}
                  className={`rounded-lg px-3 py-1.5 transition ${
                    simTab === tab.id ? "bg-accent/15 font-bold text-accent shadow-sm" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {simTab === "timeline" && (
              <div className="space-y-3 font-mono text-xs">
                {(!result.timeline || result.timeline.length === 0) ? (
                  <p className="text-xs text-text-muted py-4 text-center">No behavioral timeline events recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {result.timeline.map((ev, i) => {
                      const isMal = ev.severity === "malicious";
                      const isSus = ev.severity === "suspicious";
                      return (
                        <div
                          key={i}
                          className={`flex items-start gap-3 rounded-xl border p-3.5 transition ${
                            isMal
                              ? "border-risk-malicious/40 bg-risk-malicious/10"
                              : isSus
                              ? "border-amber-500/40 bg-amber-500/10"
                              : "border-border-subtle bg-bg-base/50"
                          }`}
                        >
                          <div className="shrink-0 flex flex-col items-center">
                            <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] font-bold text-text-faint">
                              +{((ev.elapsed_ms || 0) / 1000).toFixed(2)}s
                            </span>
                            <span className="mt-1 text-[9px] uppercase tracking-wider text-text-faint font-semibold">
                              {ev.category}
                            </span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-text-primary">{ev.title}</span>
                              <span
                                className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                                  isMal
                                    ? "bg-risk-malicious/20 text-risk-malicious"
                                    : isSus
                                    ? "bg-amber-500/20 text-amber-400"
                                    : "bg-bg-elevated text-text-muted"
                                }`}
                              >
                                {ev.severity}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] text-text-muted break-words">{ev.details}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {simTab === "artifacts" && (
              <div className="space-y-3 font-mono text-xs">
                {(!result.dropped_artifacts || result.dropped_artifacts.length === 0) ? (
                  <p className="text-xs text-text-muted py-6 text-center border border-border-subtle rounded-xl bg-bg-base/30">
                    No files or payload artifacts were dropped to disk during this sandbox execution.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {result.dropped_artifacts.map((art, idx) => (
                      <div
                        key={idx}
                        className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3 hover:border-accent/50 transition"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <Icon name="file" size={14} className="text-accent" />
                            <span className="font-bold text-text-primary">{art.name}</span>
                            <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-text-faint">
                              {art.size_bytes} bytes
                            </span>
                            {art.is_high_entropy && (
                              <span className="rounded bg-risk-malicious/20 border border-risk-malicious/40 px-2 py-0.5 text-[9px] font-bold text-risk-malicious uppercase">
                                High Entropy ({art.entropy}/8.0)
                              </span>
                            )}
                          </div>

                          <a
                            href={getSandboxArtifactUrl(result.run_id, art.filename)}
                            download
                            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-1 text-[11px] font-bold text-accent hover:bg-accent/25"
                          >
                            <Icon name="download" size={11} />
                            <span>Download File</span>
                          </a>
                        </div>

                        {/* Shannon Entropy Bar */}
                        <div className="space-y-1">
                          <div className="flex justify-between text-[10px] text-text-faint">
                            <span>Shannon Entropy: {art.entropy} / 8.0</span>
                            <span>{art.entropy > 7.0 ? "Encrypted / Packed / Shellcode" : art.entropy > 5.0 ? "Structured Binary / Script" : "Plaintext / Sparse"}</span>
                          </div>
                          <div className="h-2 w-full bg-border-subtle rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                art.entropy > 7.0 ? "bg-risk-malicious" : art.entropy > 5.0 ? "bg-amber-400" : "bg-signal"
                              }`}
                              style={{ width: `${Math.min(100, (art.entropy / 8.0) * 100)}%` }}
                            />
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-text-muted bg-bg-surface p-2.5 rounded-lg border border-border-subtle">
                          <div>
                            <span className="text-text-faint uppercase text-[9px] block">SHA-256</span>
                            <span className="break-all font-mono">{art.sha256}</span>
                          </div>
                          <div>
                            <span className="text-text-faint uppercase text-[9px] block">MD5</span>
                            <span className="break-all font-mono">{art.md5}</span>
                          </div>
                        </div>

                        {art.preview && art.preview.length > 0 && (
                          <div>
                            <span className="text-text-faint text-[10px] block mb-1">Extracted Strings Preview:</span>
                            <div className="bg-[#0a0c10] p-2 rounded text-[10px] font-mono text-emerald-400 max-h-24 overflow-y-auto space-y-0.5">
                              {art.preview.map((line, lidx) => (
                                <div key={lidx} className="truncate">{line}</div>
                              ))}
                            </div>
                          </div>
                        )}

                        {art.config && (
                          <div className="rounded-lg border border-accent/30 bg-accent/5 p-3 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold uppercase tracking-wider text-accent">
                                Extracted Malware Configuration & Threat Indicators
                              </span>
                              <span
                                className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                                  art.config.verdict === "MALICIOUS"
                                    ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/40"
                                    : art.config.verdict === "SUSPICIOUS"
                                      ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                                      : "bg-risk-clean/20 text-risk-clean border border-risk-clean/40"
                                }`}
                              >
                                {art.config.verdict} (Score: {art.config.threat_score}/100)
                              </span>
                            </div>

                            {art.config.c2_ips && art.config.c2_ips.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-[10px] text-text-faint">C2 Endpoints:</span>
                                {art.config.c2_ips.map((ip: string) => (
                                  <span key={ip} className="rounded bg-bg-surface border border-border-subtle px-1.5 py-0.5 text-[10px] font-mono text-cyan-400">
                                    {ip}
                                  </span>
                                ))}
                              </div>
                            )}

                            {art.config.crypto_wallets && art.config.crypto_wallets.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-[10px] text-text-faint">Ransom Wallets:</span>
                                {art.config.crypto_wallets.map((w: string) => (
                                  <span key={w} className="rounded bg-bg-surface border border-border-subtle px-1.5 py-0.5 text-[10px] font-mono text-amber-400">
                                    {w}
                                  </span>
                                ))}
                              </div>
                            )}

                            {art.config.behavioral_indicators && art.config.behavioral_indicators.length > 0 && (
                              <ul className="text-[10px] text-text-muted list-disc list-inside space-y-0.5">
                                {art.config.behavioral_indicators.map((ind: string, iidx: number) => (
                                  <li key={iidx}>{ind}</li>
                                ))}
                              </ul>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {simTab === "terminal" && (
              <pre className="max-h-72 overflow-y-auto rounded-xl border border-border-subtle bg-[#0a0c10] p-4 font-mono text-xs text-[#c9d1d9]">
                {result.terminal_output}
              </pre>
            )}

            {simTab === "tree" && (
              <div className="rounded-xl border border-border-subtle bg-bg-base/80 p-4">
                <ProcessCausalityTree nodes={result.process_tree || []} />
              </div>
            )}

            {simTab === "alerts" && (
              <div className="space-y-2">
                {(result.alerts || []).length === 0 ? (
                  <p className="text-xs text-text-muted">Zero heuristics triggered for this execution.</p>
                ) : (
                  (result.alerts || []).map((al: any, idx: number) => (
                    <div key={idx} className="flex items-center justify-between rounded-lg border border-risk-malicious/30 bg-risk-malicious/10 p-3 text-xs">
                      <div>
                        <span className="font-bold text-text-primary">{al.rule_name}</span>
                        <p className="text-[11px] text-text-muted">{al.details}</p>
                      </div>
                      <span className="rounded bg-risk-malicious/20 px-2 py-0.5 text-[9px] uppercase font-bold text-risk-malicious">
                        {al.severity}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {simTab === "delta" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div className="rounded-lg border border-border-subtle bg-bg-base/50 p-3">
                  <span className="font-bold text-signal">+ Spawned Processes ({result.detonation_delta?.new_processes?.length ?? 0})</span>
                  {(result.detonation_delta?.new_processes || []).map((p: any, i: number) => (
                    <div key={i} className="mt-1 text-[11px] text-text-muted">PID {p.pid}: {p.name}</div>
                  ))}
                </div>
                <div className="rounded-lg border border-border-subtle bg-bg-base/50 p-3">
                  <span className="font-bold text-accent">+ Opened Sockets ({result.detonation_delta?.new_sockets?.length ?? 0})</span>
                  {(result.detonation_delta?.new_sockets || []).map((s: any, i: number) => (
                    <div key={i} className="mt-1 text-[11px] text-text-muted">{s.protocol} {s.local_ip}:{s.local_port}</div>
                  ))}
                </div>
              </div>
            )}

            {simTab === "syscalls" && (
              <div className="space-y-2">
                {(!result.syscalls || result.syscalls.length === 0) ? (
                  <p className="text-xs text-text-muted py-3">No low-level system call traces captured in this run.</p>
                ) : (
                  <div className="max-h-72 overflow-y-auto rounded-xl border border-border-subtle bg-[#0a0c10] p-3 font-mono text-[11px]">
                    <div className="grid grid-cols-12 gap-2 border-b border-border-subtle pb-1.5 font-bold text-text-faint uppercase text-[9px]">
                      <span className="col-span-1">PID</span>
                      <span className="col-span-2">Syscall</span>
                      <span className="col-span-6">Arguments</span>
                      <span className="col-span-1">Result</span>
                      <span className="col-span-2">Category</span>
                    </div>
                    {result.syscalls.map((sc, i) => (
                      <div key={i} className="grid grid-cols-12 gap-2 py-1 border-b border-border-subtle/30 text-[#c9d1d9] hover:bg-accent/5">
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

            {simTab === "sinkhole" && (
              <div className="space-y-2">
                {(!result.sinkhole_traffic || result.sinkhole_traffic.length === 0) ? (
                  <p className="text-xs text-text-muted py-3">Zero outbound DNS/C2 beacon requests intercepted by sandbox sinkhole.</p>
                ) : (
                  <div className="space-y-1.5 font-mono text-xs">
                    {result.sinkhole_traffic.map((req, i) => (
                      <div key={i} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5">
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-bold text-amber-400 uppercase">
                            {req.type.replace("_", " ")}
                          </span>
                          <span className="font-bold text-text-primary">{req.target}</span>
                          {req.method && <span className="text-text-muted">({req.method} {req.path})</span>}
                        </div>
                        <span className="text-[10px] text-amber-300/80">{req.intercepted_response}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
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

  const [dossierTab, setDossierTab] = useState<"static" | "dynamic" | "history" | "similarity">("static");

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
          <code className="block break-all rounded border border-border-subtle bg-bg-elevated/50 px-3 py-2 font-mono text-xs leading-relaxed text-text-primary">
            {sample.sha256}
          </code>
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
              <Chip tone={sample.vt_detections > 0 ? "malicious" : "clean"} dot>
                {sample.vt_detections} VT detection{sample.vt_detections === 1 ? "" : "s"}
              </Chip>
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
      <div className="mt-8 flex flex-wrap items-center gap-2 border-b border-border-subtle pb-3 font-mono text-xs">
        {[
          { id: "static", label: "Static Analysis & Dossier", icon: "box" },
          { id: "dynamic", label: "Live Dynamic Sandbox", icon: "play" },
          { id: "history", label: `Detonation Runs (${runs.length})`, icon: "timeline" },
          { id: "similarity", label: "Binary Similarity (CTPH)", icon: "copy" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setDossierTab(tab.id as any)}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 font-medium transition-all ${
              dossierTab === tab.id
                ? "bg-accent/15 font-bold text-accent shadow-[var(--glow-accent)]"
                : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <Icon name={tab.icon as any} size={13} />
            {tab.label}
          </button>
        ))}
      </div>

      {dossierTab === "static" && <StaticAnalysis sample={sample} />}

      {dossierTab === "dynamic" && (
        <div className="mt-6 space-y-6">
          <LiveDynamicSandboxCockpit sample={sample} />
          <SandboxDetonation sample={sample} />
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
    </div>
  );
}

