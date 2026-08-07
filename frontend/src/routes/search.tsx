import { useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "../components/ui";
import { searchIocs } from "../lib/api";
import type { IocSearchResponse } from "../types";

export default function SearchPage() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState<IocSearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const query = value.trim();
    if (!query) return;
    setLoading(true);
    setError(null);
    try {
      setResult(await searchIocs(query));
    } catch {
      setError("Search failed — is the OutPost backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
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
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="e.g. 185.220.101.34"
          className="w-full max-w-md rounded border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent-amber/60 focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="press rounded border border-accent-amber/60 px-4 py-2 font-mono text-xs text-accent-amber transition-colors duration-150 hover:bg-accent-amber/10 disabled:opacity-50"
        >
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

      {error && <p className="mt-4 text-sm text-risk-malicious">{error}</p>}

      {result && (
        <div className="mt-8">
          <p className="mb-3 text-xs text-text-muted">
            {result.count} match(es) for <span className="font-mono text-text-primary">{result.value}</span>
            {result.returned < result.count && ` — showing first ${result.returned}`}
          </p>

          {/* Uploaded binaries whose SHA-256 matches (roadmap 1.4) */}
          {result.samples && result.samples.length > 0 && (
            <div className="mb-6 rounded-lg border border-border-subtle bg-bg-surface">
              <div className="border-b border-border-subtle px-4 py-2 font-mono text-[10px] uppercase tracking-widest text-text-faint">
                Uploaded binaries matching this hash
              </div>
              {result.samples.map((s) => (
                <div key={s.sample_id} className="flex flex-wrap items-center gap-2 border-b border-border-subtle/50 px-4 py-2.5 last:border-0">
                  <span className="font-mono text-sm text-text-primary">{s.original_name}</span>
                  <span
                    className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase ${
                      s.detected_platform === "windows"
                        ? "border-accent-amber/50 text-accent-amber"
                        : s.detected_platform === "linux"
                          ? "border-risk-clean/50 text-risk-clean"
                          : "border-text-faint text-text-muted"
                    }`}
                  >
                    {s.detected_platform}
                  </span>
                  <span className="ml-auto font-mono text-[10px] text-text-faint">{s.sha256.slice(0, 24)}…</span>
                </div>
              ))}
            </div>
          )}

          {result.matches.length === 0 && (result.samples?.length ?? 0) === 0 ? (
            <p className="text-sm text-text-muted">No prior runs contain this value.</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border-subtle">
              <table className="w-full text-left">
                <thead className="border-b border-border-subtle">
                  <tr className="text-[10px] uppercase tracking-widest text-text-faint">
                    <th className="px-4 py-2">Run</th>
                    <th className="px-4 py-2">Sample</th>
                    <th className="px-4 py-2">Event</th>
                    <th className="px-4 py-2">When</th>
                  </tr>
                </thead>
                <tbody>
                  {result.matches.map((m, i) => (
                    <tr key={i} className="border-b border-border-subtle/50 transition-colors duration-150 hover:bg-bg-surface">
                      <td className="px-4 py-2">
                        <Link to={`/runs/${m.run_id}`} className="font-mono text-xs text-accent-amber hover:underline">
                          {m.run_id.slice(0, 12)}
                        </Link>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-text-primary">{m.sample_name}</td>
                      <td className="px-4 py-2 font-mono text-xs text-text-muted">{m.event_type}</td>
                      <td className="px-4 py-2 font-mono text-xs text-text-faint">
                        {(m.timestamp || "").slice(0, 19).replace("T", " ")}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
