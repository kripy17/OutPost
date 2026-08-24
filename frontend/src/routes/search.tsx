// Search — two scopes on one page (the nav's "IOC Search" entry).
//
// IOC scope (default): the legacy event-scoped /ioc/search — "have I seen
// this before?" across every run. All deep-link behavior (?q=…) is preserved
// exactly; a bare visit re-runs the saved draft.
//
// Global scope: the P0.5 grouped GET /search over every analyst-facing
// resource (findings, iocs, artifacts, hosts, sessions/jobs, investigations,
// campaigns), qualifier-aware (type: status: severity: disposition: host:
// rule: case:), with each hit deep-linking into its workspace. The mode is
// deep-linkable (?mode=global) and remembered per browser.

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon, type IconName } from "../components/Icon";
import { EVENT_ICON, platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import { intelAgeLabel, RISK_COLORS } from "../lib/constants";
import { toneFill, toneForReputation } from "../lib/fillPatterns";
import { globalSearch, searchIocs } from "../lib/api";
import type { IocSearchResponse, Reputation, SearchGroup, SearchHit, SearchResponse } from "../types";
import { platformTone, readSavedQuery, writeSavedQuery } from "./searchHelpers";
import NetworkContextModal from "../components/NetworkContextModal";
import ProcessContextModal from "../components/ProcessContextModal";

type Scope = "ioc" | "global";

const SCOPE_KEY = "outpost-search-scope";

/** Canonical group order + labels + deep-links. The links target the
 *  workspace each group's payload maps to (no fabricated routes — hosts land
 *  on the fleet page until the P1.4 host workspace exists, campaigns on the
 *  clusters page, iocs on the pre-filled legacy search). */
const GROUPS: { key: SearchGroup; label: string; icon: IconName; link: (h: SearchHit) => string }[] = [
  { key: "findings", label: "Findings", icon: "alert", link: (h) => `/runs/${h.payload.run_id}` },
  { key: "iocs", label: "IOCs", icon: "search", link: (h) => `/search?q=${encodeURIComponent(String(h.payload.value ?? ""))}` },
  { key: "artifacts", label: "Artifacts", icon: "box", link: (h) => `/samples/${h.payload.sample_id}` },
  { key: "hosts", label: "Hosts", icon: "terminal", link: (h) => `/hosts/${encodeURIComponent(String(h.payload.host_id ?? ""))}` },
  {
    key: "sessions",
    label: "Sessions & jobs",
    icon: "clock",
    // Analysis jobs land on the P1.2 analysis workspace; monitoring sessions
    // on the run detail.
    link: (h) => (h.payload.kind === "analysis_job" ? `/analysis/${h.payload.run_id}` : `/runs/${h.payload.run_id}`),
  },
  { key: "investigations", label: "Investigations", icon: "notes", link: (h) => `/investigations/${h.payload.investigation_id}` },
  { key: "campaigns", label: "Campaigns", icon: "flag", link: () => `/campaigns` },
];

const GROUP_META = new Map(GROUPS.map((g) => [g.key, g]));

function readScope(params: URLSearchParams): Scope {
  if (params.get("mode") === "global") return "global";
  try {
    return localStorage.getItem(SCOPE_KEY) === "global" ? "global" : "ioc";
  } catch {
    return "ioc";
  }
}

/** A generic kind chip — severity for findings, entity type for iocs,
 *  platform for artifacts, status for investigations, run kind for sessions. */
function KindChip({ hit }: { hit: SearchHit }) {
  const kind = hit.kind;
  if (!kind) return null;
  const tone =
    hit.group === "findings"
      ? kind === "malicious"
        ? "border-risk-malicious/40 text-risk-malicious"
        : "border-risk-suspicious/40 text-risk-suspicious"
      : "border-border-subtle text-text-faint";
  return <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${tone}`}>{kind}</span>;
}

function GlobalResultRow({
  hit,
  onInspectIp,
  onInspectPid,
}: {
  hit: SearchHit;
  onInspectIp?: (ip: string) => void;
  onInspectPid?: (pid: number) => void;
}) {
  const meta = GROUP_META.get(hit.group);
  const to = meta?.link(hit) ?? "#";
  const payload = hit.payload as Record<string, string | number | undefined>;
  const rawIp = String(payload.dest_ip ?? (hit.group === "iocs" && hit.kind === "ip" ? payload.value : ""));
  const destIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(rawIp) ? rawIp : undefined;
  const pid = payload.pid ? Number(payload.pid) : undefined;

  return (
    <div className="group flex items-center justify-between gap-3 px-4 py-2.5 transition-colors hover:bg-bg-elevated/40 border-b border-border-subtle/30 last:border-0">
      <Link
        to={to}
        className="flex min-w-0 flex-1 items-center gap-3"
        title={hit.subtitle ?? undefined}
      >
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-text-primary group-hover:text-accent">{hit.title}</span>
            <KindChip hit={hit} />
            {hit.group === "findings" && payload.severity && (
              <span
                className={`h-1.5 w-1.5 rounded-full ${payload.severity === "malicious" ? "bg-risk-malicious" : "bg-risk-suspicious"}`}
                aria-hidden
              />
            )}
          </span>
          <span className="mt-0.5 block truncate font-mono text-[10px] text-text-faint">
            {hit.subtitle ?? hit.id}
          </span>
        </span>
      </Link>

      <div className="flex shrink-0 items-center gap-2">
        {pid !== undefined && onInspectPid && (
          <button
            onClick={() => onInspectPid(pid)}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-elevated/60 px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/40 hover:text-accent"
            title={`Investigate process context for PID ${pid}`}
          >
            <Icon name="terminal" size={10} />
            PID {pid}
          </button>
        )}
        {destIp && onInspectIp && (
          <button
            onClick={() => onInspectIp(destIp)}
            className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20"
            title={`Investigate network context for ${destIp}`}
          >
            <Icon name="activity" size={10} />
            Context
          </button>
        )}
        <Link to={to}>
          <Icon name="chevronRight" size={13} className="shrink-0 text-text-faint transition-colors group-hover:text-accent" />
        </Link>
      </div>
    </div>
  );
}

function GlobalResults({
  data,
  onInspectIp,
  onInspectPid,
}: {
  data: SearchResponse;
  onInspectIp?: (ip: string) => void;
  onInspectPid?: (pid: number) => void;
}) {
  const groupsWithHits = GROUPS.filter((g) => (data.groups[g.key]?.total ?? 0) > 0);
  const totalMatches = GROUPS.reduce((n, g) => n + (data.groups[g.key]?.total ?? 0), 0);
  const quals = Object.entries(data.qualifiers ?? {});

  if (groupsWithHits.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-12 text-center">
        <Icon name="search" size={26} className="mx-auto text-text-faint" />
        <p className="mt-3 text-sm text-text-muted">No matches across any resource for <span className="font-mono text-text-primary">{data.q}</span>.</p>
        <p className="mt-1 text-[11px] text-text-faint">Try a different value, or add a qualifier (type: status: severity: host: rule: case:).</p>
      </div>
    );
  }

  return (
    <div className="mt-8 space-y-6">
      <p className="flex items-center gap-2 text-xs text-text-muted">
        <Icon name="zap" size={12} className="text-signal" />
        {totalMatches} match{totalMatches === 1 ? "" : "es"} across {groupsWithHits.length} resource
        {groupsWithHits.length === 1 ? "" : "s"} for <span className="font-mono text-text-primary">{data.q}</span>
      </p>

      {quals.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-text-faint">qualifiers</span>
          {quals.map(([k, v]) => (
            <span key={k} className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent">
              {k}:{v}
            </span>
          ))}
        </div>
      )}

      {groupsWithHits.map((g) => {
        const res = data.groups[g.key];
        return (
          <section key={g.key} className="rounded-2xl border border-border-subtle bg-bg-surface">
            <header className="flex items-center gap-2 border-b border-border-subtle px-4 py-2.5">
              <Icon name={g.icon} size={13} className="text-signal" />
              <span className="text-xs font-semibold text-text-muted">{g.label}</span>
              <span className="ml-auto rounded border border-border-subtle px-1.5 font-mono text-[10px] text-text-faint">
                {res?.total ?? 0}
              </span>
            </header>
            <div className="divide-y divide-border-subtle/60">
              {(res?.hits ?? []).map((h) => (
                <GlobalResultRow
                  key={`${h.group}-${h.id}`}
                  hit={h}
                  onInspectIp={onInspectIp}
                  onInspectPid={onInspectPid}
                />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}

export default function SearchPage() {
  const [params] = useSearchParams();
  const [scope, setScope] = useState<Scope>(() => readScope(params));
  const [value, setValue] = useState(params.get("q") ?? readSavedQuery());
  const [result, setResult] = useState<IocSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [globalResult, setGlobalResult] = useState<SearchResponse | null>(null);
  const [globalLoading, setGlobalLoading] = useState(false);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const [inspectPid, setInspectPid] = useState<number | null>(null);

  // Deep-link support: ?q= (IOC scope) or ?q=+?mode=global (global scope)
  // run once on mount; a bare visit re-runs the last saved query in the
  // saved scope (same resume-mid-thought UX as before).
  useEffect(() => {
    const query = (params.get("q") ?? "").trim();
    if (query) {
      if (scope === "global") void runGlobalSearch(query);
      else void runIocSearch(query);
    } else {
      const saved = readSavedQuery().trim();
      if (saved) {
        if (scope === "global") void runGlobalSearch(saved);
        else void runIocSearch(saved);
      }
    }
  }, [params, scope]);

  function persistScope(next: Scope) {
    setScope(next);
    try {
      localStorage.setItem(SCOPE_KEY, next);
    } catch {
      /* storage unavailable — the toggle still applies this session */
    }
  }

  async function runIocSearch(query: string) {
    setValue(query);
    writeSavedQuery(query.trim());
    setLoading(true);
    setError(null);
    try {
      setResult(await searchIocs(query));
    } catch {
      setError("Search failed — is the OutPost backend running?");
    } finally {
      setLoading(false);
    }
  }

  async function runGlobalSearch(query: string) {
    setValue(query);
    writeSavedQuery(query.trim());
    setGlobalLoading(true);
    setGlobalError(null);
    try {
      setGlobalResult(await globalSearch(query, 10));
    } catch {
      setGlobalError("Search failed — is the OutPost backend running?");
    } finally {
      setGlobalLoading(false);
    }
  }

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const query = value.trim();
    if (!query) return;
    if (scope === "global") void runGlobalSearch(query);
    else void runIocSearch(query);
  };

  return (
    <div className="mx-auto max-w-5xl px-5 py-8 lg:px-8">
      <PageHeader
        kicker={scope === "global" ? "Intelligence · global search" : "Intelligence · search"}
        title={
          scope === "global" ? (
            "Global search"
          ) : (
            <>
              IOC search <span className="font-normal text-text-muted">— have I seen this before?</span>
            </>
          )
        }
        lede={
          scope === "global"
            ? "One query across every analyst-facing resource — findings, IOCs, artifacts, hosts, sessions, investigations, campaigns — with qualifiers (type: status: severity: disposition: host: rule: case:) and direct navigation into each result."
            : "Search any IP, process name, file path, or registry key across every run in your history."
        }
      />

      {/* Scope toggle — IOC (legacy event-scoped) vs Global (grouped resources). */}
      <div className="mt-2 inline-flex rounded-lg border border-border-subtle bg-bg-elevated/40 p-0.5" role="tablist" aria-label="Search scope">
        <button
          role="tab"
          aria-selected={scope === "ioc"}
          onClick={() => persistScope("ioc")}
          className={`rounded-md px-3 py-1 text-[11px] font-medium transition-colors ${scope === "ioc" ? "bg-accent/15 text-accent" : "text-text-muted hover:text-text-primary"}`}
        >
          IOC search
        </button>
        <button
          role="tab"
          aria-selected={scope === "global"}
          onClick={() => persistScope("global")}
          className={`rounded-md px-3 py-1 text-[11px] font-medium transition-colors ${scope === "global" ? "bg-accent/15 text-accent" : "text-text-muted hover:text-text-primary"}`}
        >
          Global search
        </button>
      </div>

      <form onSubmit={onSearch} className="mt-6 flex gap-2">
        <div className="relative w-full max-w-md">
          <Icon name="search" size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={scope === "global" ? "e.g. 203.0.113.88  or  type:finding status:open beaconing" : "e.g. 185.220.101.34"}
            className="w-full rounded-lg border border-border-subtle bg-bg-surface py-2 pl-9 pr-3 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          disabled={scope === "global" ? globalLoading : loading}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
        >
          <Icon name={(scope === "global" ? globalLoading : loading) ? "refresh" : "search"} size={12} className={(scope === "global" ? globalLoading : loading) ? "animate-spin" : ""} />
          {(scope === "global" ? globalLoading : loading) ? "Searching…" : "Search"}
        </button>
      </form>

      {scope === "ioc" ? (
        <>
          {error && (
            <p className="mt-4 inline-flex items-center gap-1.5 text-sm text-risk-malicious">
              <Icon name="alert" size={13} />
              {error}
            </p>
          )}

          {result && (
            <div className="mt-8 space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="flex items-center gap-2 text-xs text-text-muted">
                  <Icon name="zap" size={12} className="text-signal" />
                  {result.count} match{result.count === 1 ? "" : "es"} for <span className="font-mono text-text-primary">{result.value}</span>
                  {result.returned < result.count && ` — showing first ${result.returned}`}
                </p>
                {/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(result.value) && (
                  <button
                    onClick={() => setInspectIp(result.value)}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-xs text-accent hover:bg-accent/20"
                  >
                    <Icon name="activity" size={12} />
                    Investigate Network Context
                  </button>
                )}
              </div>

              {/* Reputation ride-along: the cached enrichment verdict for an IP
                  search surfaces with the matches — same evidence the run-detail
                  network table shows (abuse score, VT positives, checked age). */}
              {result.reputation && (
                <section className="rounded-2xl border border-border-subtle bg-bg-surface px-4 py-3">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                    <span className="font-mono text-xs text-text-faint" title="Cached enrichment verdict">reputation</span>
                    <span
                      className={`inline-flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-wide ${RISK_COLORS[(result.reputation.reputation ?? "unknown") as Reputation]}`}
                    >
                      <span
                        className="h-2 w-2 rounded-full"
                        style={toneFill(toneForReputation((result.reputation.reputation ?? "unknown") as Reputation))}
                        aria-hidden
                      />
                      {result.reputation.reputation ?? "unknown"}
                    </span>
                    {result.reputation.abuse_score !== null && result.reputation.abuse_score !== undefined && (
                      <span className="font-mono text-[11px] text-text-muted" title="AbuseIPDB abuse score">
                        abuse {result.reputation.abuse_score}
                      </span>
                    )}
                    {result.reputation.vt_malicious_count !== null && result.reputation.vt_malicious_count !== undefined && (
                      <span
                        className={`font-mono text-[11px] ${result.reputation.vt_malicious_count > 0 ? "text-risk-malicious" : "text-text-muted"}`}
                        title="VirusTotal positives"
                      >
                        vt {result.reputation.vt_malicious_count}
                      </span>
                    )}
                    {result.reputation.checked_at && (
                      <span className="font-mono text-[10px] text-text-faint" title={`Reputation fetched ${result.reputation.checked_at} UTC`}>
                        {intelAgeLabel(result.reputation.checked_at)}
                      </span>
                    )}
                  </div>
                </section>
              )}

              {loading && (
                <div className="space-y-2">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="skeleton h-12 w-full" />
                  ))}
                </div>
              )}

              {result.samples && result.samples.length > 0 && (
                <section className="rounded-2xl border border-border-subtle bg-bg-surface">
                  <header className="flex items-center gap-2 border-b border-border-subtle px-4 py-2.5">
                    <Icon name="box" size={13} className="text-signal" />
                    <span className="text-xs font-semibold text-text-muted">Uploaded binaries matching this hash</span>
                    <span className="ml-auto rounded border border-border-subtle px-1.5 font-mono text-[10px] text-text-faint">
                      {result.samples.length}
                    </span>
                  </header>
                  <div className="divide-y divide-border-subtle/60">
                    {result.samples.map((s) => (
                      <Link
                        key={s.sample_id}
                        to={`/samples/${s.sample_id}`}
                        className="flex flex-wrap items-center gap-2 px-4 py-2.5 transition-colors hover:bg-bg-elevated/40"
                      >
                        <Icon name={platformIconName(s.detected_platform)} size={13} className="text-text-faint" />
                        <span className="font-mono text-sm text-text-primary">{s.original_name}</span>
                        <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${platformTone(s.detected_platform)}`}>
                          {s.detected_platform}
                        </span>
                        <span className="ml-auto font-mono text-[10px] text-text-faint">{s.sha256.slice(0, 24)}…</span>
                      </Link>
                    ))}
                  </div>
                </section>
              )}

              {result.matches.length === 0 && (result.samples?.length ?? 0) === 0 ? (
                <div className="rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-12 text-center">
                  <Icon name="search" size={26} className="mx-auto text-text-faint" />
                  <p className="mt-3 text-sm text-text-muted">No prior runs contain this value.</p>
                </div>
              ) : (
                result.matches.length > 0 && (
                  <section className="rounded-2xl border border-border-subtle bg-bg-surface">
                    <header className="flex items-center gap-2 border-b border-border-subtle px-4 py-2.5">
                      <Icon name="list" size={13} className="text-signal" />
                      <span className="text-xs font-semibold text-text-muted">Events across runs</span>
                      <span className="ml-auto rounded border border-border-subtle px-1.5 font-mono text-[10px] text-text-faint">
                        {result.matches.length}
                      </span>
                    </header>
                    <div className="divide-y divide-border-subtle/60">
                      {result.matches.map((m, i) => (
                        <Link
                          key={i}
                          to={`/runs/${m.run_id}`}
                          className="group flex flex-wrap items-center gap-3 px-4 py-2.5 transition-colors hover:bg-bg-elevated/40"
                        >
                          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-border-subtle text-signal">
                            <Icon name={EVENT_ICON[m.event_type] ?? "list"} size={13} />
                          </span>
                          <span className="font-mono text-xs text-text-primary group-hover:text-accent">{m.sample_name}</span>
                          <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[9px] uppercase text-text-faint">
                            {m.event_type.replace("_", " ")}
                          </span>
                          <span className="ml-auto font-mono text-[10px] text-text-faint">
                            {(m.timestamp || "").slice(0, 19).replace("T", " ")}
                          </span>
                          <span className="font-mono text-[10px] text-text-faint">{m.run_id.slice(0, 12)}</span>
                        </Link>
                      ))}
                    </div>
                  </section>
                )
              )}
            </div>
          )}
        </>
      ) : (
        <>
          {globalError && (
            <p className="mt-4 inline-flex items-center gap-1.5 text-sm text-risk-malicious">
              <Icon name="alert" size={13} />
              {globalError}
            </p>
          )}

          {globalLoading && (
            <div className="mt-8 space-y-2">
              {Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="skeleton h-12 w-full" />
              ))}
            </div>
          )}

          {globalResult && !globalLoading && (
            <GlobalResults
              data={globalResult}
              onInspectIp={setInspectIp}
              onInspectPid={setInspectPid}
            />
          )}
        </>
      )}

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}
    </div>
  );
}
