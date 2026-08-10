import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Icon, platformIconName } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { downloadSample, getRuns, getSample, getSampleStatic, getSandboxProviders, getSandboxTask, sandboxDetonate, watchlistAdd } from "../lib/api";
import type { Platform, RunSummary, SampleStatic, SandboxTask } from "../types";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

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

  const filteredStrings = useMemo(() => {
    if (!st) return [];
    const q = stringsFilter.trim().toLowerCase();
    return q ? st.strings.filter((s) => s.toLowerCase().includes(q)) : st.strings;
  }, [st, stringsFilter]);

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
  const iocTotal = st ? st.iocs.urls.length + st.iocs.ips.length + st.iocs.domains.length + st.iocs.hashes.length + st.iocs.emails.length : 0;

  return (
    <div className="mt-6 space-y-6">
      <Panel
        kicker="Static · on-demand"
        title="Strings & candidate IOCs"
        right={
          st && st.available ? (
            <span className="font-mono text-[10px] text-text-faint">
              {st.strings.length} strings · {iocTotal} IOCs
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
            {iocTotal > 0 ? (
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

            {/* Strings — filterable, collapsible, mono. */}
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
          </>
        )}
      </Panel>

      {/* Executable metadata — PE or ELF, whichever the bytes actually are. */}
      {(st?.pe || st?.elf) && (
        <Panel kicker="Static · format" title={st.pe ? "PE metadata" : "ELF metadata"}>
          <PeElfTable st={st} />
        </Panel>
      )}
    </div>
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
        through the detection pipeline as a normal run. This is a roadmap integration: until an API
        key is configured (<code className="font-mono text-accent">ANYRUN_API_KEY</code> /{" "}
        <code className="font-mono text-accent">TRIAGE_API_KEY</code> /{" "}
        <code className="font-mono text-accent">JOE_API_KEY</code>) the labeled demo detonates locally —
        same pipeline, clearly marked.
      </p>

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
          <span className="font-mono text-[10px] text-text-faint">
            {pe.imports.length} import DLL{pe.imports.length === 1 ? "" : "s"}
          </span>
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
  const { sampleId = "" } = useParams();
  const [copied, setCopied] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

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

  if (isLoading) return <p className="p-8 text-sm text-text-muted">Loading sample…</p>;
  if (isError || !sample) {
    return (
      <p className="p-8 text-sm text-risk-malicious">
        Couldn't load sample <span className="font-mono">{sampleId}</span>.
      </p>
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
          <div className="flex items-center gap-2">
            <Link
              to={`/footprint?sample=${sample.sample_id}`}
              className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            >
              Digital footprint
              <Icon name="arrowRight" size={12} />
            </Link>
            <span className="flex items-center gap-2">
              {downloadError && <span className="font-mono text-[10px] text-risk-malicious">{downloadError}</span>}
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

      <StaticAnalysis sample={sample} />

      <SandboxDetonation sample={sample} />

      <Panel kicker="Detonations" title={`Runs of ${sample.original_name}`} className="mt-6" pad={false}>
        {runs.length === 0 ? (
          <p className="p-6 text-sm text-text-muted">This sample hasn't been detonated yet — head to Monitor to run it.</p>
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
    </div>
  );
}
