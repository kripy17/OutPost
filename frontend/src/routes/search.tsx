import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EVENT_ICON, Icon, platformIconName } from "../components/Icon";
import { PageHeader } from "../components/ui";
import { searchIocs } from "../lib/api";
import type { IocSearchResponse } from "../types";

export default function SearchPage() {
  const [params] = useSearchParams();
  const [value, setValue] = useState(params.get("q") ?? "");
  const [result, setResult] = useState<IocSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Deep-link support (?q=…): static-analysis IOC chips jump here pre-filled
  // and the search runs once on mount — one click from sample → history.
  useEffect(() => {
    const query = (params.get("q") ?? "").trim();
    if (query) void runSearch(query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runSearch(query: string) {
    setValue(query);
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

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const query = value.trim();
    if (!query) return;
    void runSearch(query);
  };

  const sampleTone = (p: string) =>
    p === "windows"
      ? "border-accent/50 text-accent"
      : p === "linux"
        ? "border-risk-clean/50 text-risk-clean"
        : "border-text-faint text-text-muted";

  return (
    <div className="mx-auto max-w-5xl px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Intelligence · search"
        title={
          <>
            IOC search <span className="font-normal text-text-muted">— have I seen this before?</span>
          </>
        }
        lede="Search any IP, process name, file path, or registry key across every run in your history."
      />

      <form onSubmit={onSearch} className="mt-6 flex gap-2">
        <div className="relative w-full max-w-md">
          <Icon name="search" size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="e.g. 185.220.101.34"
            className="w-full rounded-lg border border-border-subtle bg-bg-surface py-2 pl-9 pr-3 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
        >
          <Icon name={loading ? "refresh" : "search"} size={12} className={loading ? "animate-spin" : ""} />
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

      {error && (
        <p className="mt-4 inline-flex items-center gap-1.5 text-sm text-risk-malicious">
          <Icon name="alert" size={13} />
          {error}
        </p>
      )}

      {result && (
        <div className="mt-8 space-y-6">
          <p className="flex items-center gap-2 text-xs text-text-muted">
            <Icon name="zap" size={12} className="text-signal" />
            {result.count} match{result.count === 1 ? "" : "es"} for <span className="font-mono text-text-primary">{result.value}</span>
            {result.returned < result.count && ` — showing first ${result.returned}`}
          </p>

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
                    <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${sampleTone(s.detected_platform)}`}>
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
    </div>
  );
}
