import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { getVirusTotalIocUrl, iocTotal } from "../../routes/samplesHelpers";
import { watchlistAdd } from "../../lib/api";
import type { SampleStatic } from "../../types";

interface StringsIndicatorsTabProps {
  sampleId: string;
  st?: SampleStatic;
}

export function StringsIndicatorsTab({ sampleId, st }: StringsIndicatorsTabProps) {
  const [subTab, setSubTab] = useState<"strings" | "iocs">("strings");
  const [searchQuery, setSearchQuery] = useState("");
  const [exactMatch, setExactMatch] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [copiedString, setCopiedString] = useState<string | null>(null);
  const [watchlisted, setWatchlisted] = useState<Set<string>>(new Set());
  const [watchlistError, setWatchlistError] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState(100);

  const allStrings = useMemo(() => st?.strings || [], [st?.strings]);

  // Use GNU-concordant detailed strings and backend categories if present
  const detailedList = useMemo(() => {
    if (st?.strings_detailed && st.strings_detailed.length > 0) {
      const cats = st.categorized_strings || {};
      const cmdSet = new Set(cats.commands || []);
      const netSet = new Set(cats.network || []);
      const pathSet = new Set(cats.file_paths || []);
      const regSet = new Set(cats.registry || []);
      const secSet = new Set(cats.security_apis || []);
      const apiSet = new Set(cats.api_names || []);

      return st.strings_detailed.map((sd, idx) => {
        let cat = "General";
        if (cmdSet.has(sd.string)) cat = "Command";
        else if (netSet.has(sd.string)) cat = "Network";
        else if (pathSet.has(sd.string)) cat = "Path";
        else if (regSet.has(sd.string)) cat = "Registry";
        else if (secSet.has(sd.string)) cat = "Security API";
        else if (apiSet.has(sd.string)) cat = "API Name";
        return {
          id: idx,
          value: sd.string,
          length: sd.length,
          encoding: sd.encoding.toUpperCase(),
          offsetHex: sd.offset_hex,
          category: cat,
        };
      });
    }

    return allStrings.map((s, idx) => {
      let cat = "General";
      if (/^https?:\/\//i.test(s)) cat = "Network";
      else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s)) cat = "Network";
      else if (/^(HKEY_|HKLM|HKCU|Software\\|SYSTEM\\)/i.test(s)) cat = "Registry";
      else if (/^(\/bin\/|\/usr\/|\/etc\/|[a-zA-Z]:\\|\/tmp\/|\.exe|\.dll|\.sh)/i.test(s)) cat = "Path";
      else if (/^(sh|bash|powershell|cmd\.exe|curl|wget|chmod|netsh)/i.test(s)) cat = "Command";
      return { id: idx, value: s, length: s.length, encoding: "ASCII", offsetHex: "-", category: cat };
    });
  }, [st?.strings_detailed, st?.categorized_strings, allStrings]);

  const filteredStrings = useMemo(() => {
    return detailedList.filter((item) => {
      if (categoryFilter !== "ALL" && item.category !== categoryFilter) return false;
      if (searchQuery.trim()) {
        if (exactMatch) {
          return item.value === searchQuery;
        }
        return item.value.toLowerCase().includes(searchQuery.toLowerCase());
      }
      return true;
    });
  }, [detailedList, categoryFilter, searchQuery, exactMatch]);

  if (!st || !st.available) {
    return (
      <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs">
        <Icon name="box" size={24} className="mx-auto text-text-faint mb-2" />
        <p className="font-bold text-text-primary">Strings &amp; Indicators Unavailable</p>
        <p className="mt-1 text-text-muted">
          Bytes for this sample are not stored in the vault. Re-upload binary to view extracted strings.
        </p>
      </div>
    );
  }

  const totalIocs = iocTotal(st.iocs);

  const visibleStrings = filteredStrings.slice(0, pageSize);

  const handleCopy = (val: string) => {
    void navigator.clipboard.writeText(val);
    setCopiedString(val);
    setTimeout(() => setCopiedString(null), 1500);
  };

  const handleWatchlist = async (val: string) => {
    try {
      await watchlistAdd(val, `from sample ${sampleId}`);
      setWatchlisted((prev) => new Set(prev).add(val));
      setWatchlistError(null);
    } catch {
      setWatchlistError(`Failed to add ${val} to watchlist`);
    }
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Sub-tab Navigation */}
      <div className="flex items-center gap-2 border-b border-border-subtle pb-2">
        <button
          onClick={() => setSubTab("strings")}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
            subTab === "strings"
              ? "bg-accent text-white font-bold"
              : "bg-bg-surface border border-border-subtle text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="notes" size={12} />
          <span>Extracted Strings ({allStrings.length})</span>
        </button>
        <button
          onClick={() => setSubTab("iocs")}
          className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
            subTab === "iocs"
              ? "bg-accent text-white font-bold"
              : "bg-bg-surface border border-border-subtle text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="shield" size={12} />
          <span>Extracted IOC Indicators ({totalIocs})</span>
        </button>
      </div>

      {watchlistError && <p className="text-[11px] text-risk-malicious">{watchlistError}</p>}

      {/* SUB-VIEW 1: Extracted Strings Table */}
      {subTab === "strings" && (
        <Panel
          kicker="Static Byte Telemetry"
          title={`Extracted ASCII & Wide Strings (${filteredStrings.length} of ${allStrings.length})`}
          right={
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-text-faint">
                Showing {Math.min(pageSize, filteredStrings.length)} rows
              </span>
            </div>
          }
        >
          <div className="space-y-3">
            {st?.strings_truncation?.is_truncated && (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-[11px] text-amber-300">
                Displaying first {st.strings_truncation.strings_stored} of {st.strings_truncation.total_found} strings ({st.strings_truncation.uncategorized_omitted} uncategorized omitted; all categorized strings preserved).
              </div>
            )}

            {/* Filter and Search Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
              {/* Category Pills */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] uppercase text-text-faint">Category:</span>
                {["ALL", "Command", "Network", "Path", "Registry", "Security API", "API Name", "General"].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    className={`rounded px-2 py-0.5 text-[10px] transition ${
                      categoryFilter === cat
                        ? "bg-accent text-white font-bold"
                        : "bg-bg-base border border-border-subtle text-text-muted hover:text-text-primary"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>

              {/* Search & Exact Match */}
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Icon name="search" size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
                  <input
                    type="text"
                    placeholder="Search strings..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-52 rounded border border-border-subtle bg-bg-base py-1 pl-7 pr-2 text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
                  />
                </div>
                <label className="flex items-center gap-1 text-[10px] text-text-muted cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={exactMatch}
                    onChange={(e) => setExactMatch(e.target.checked)}
                    className="rounded border-border-subtle bg-bg-base text-accent"
                  />
                  <span>Exact</span>
                </label>
              </div>
            </div>

            {/* Predictable-Height Strings Table */}
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70 max-h-[440px] overflow-y-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint sticky top-0">
                    <th className="py-2 px-3 w-12 text-center">#</th>
                    <th className="py-2 px-3 w-24">Offset</th>
                    <th className="py-2 px-3 w-20">Encoding</th>
                    <th className="py-2 px-3">Extracted String</th>
                    <th className="py-2 px-3 w-16 text-center">Length</th>
                    <th className="py-2 px-3 w-28">Category</th>
                    <th className="py-2 px-3 text-right w-28">Pivots</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {visibleStrings.map((row) => (
                    <tr key={row.id} className="hover:bg-bg-elevated/40 transition-colors">
                      <td className="py-2 px-3 text-center text-text-faint text-[10px]">{row.id + 1}</td>
                      <td className="py-2 px-3 font-mono text-[10px] text-cyan-400">{row.offsetHex}</td>
                      <td className="py-2 px-3 text-[10px] text-text-faint uppercase">{row.encoding}</td>
                      <td className="py-2 px-3 font-mono text-[11px] text-text-primary select-all break-all">
                        {row.value}
                      </td>
                      <td className="py-2 px-3 text-center text-text-faint text-[10px]">{row.length} B</td>
                      <td className="py-2 px-3">
                        <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${
                          row.category === "Command" ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" :
                          row.category === "Network" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30" :
                          row.category === "Security API" ? "bg-amber-500/20 text-amber-300 border border-amber-500/30" :
                          "bg-bg-elevated text-text-muted"
                        }`}>
                          {row.category}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            onClick={() => handleCopy(row.value)}
                            className="press inline-flex h-5 items-center gap-1 rounded border border-border-subtle bg-bg-surface px-1.5 text-[9px] text-text-muted hover:border-accent hover:text-accent"
                            title="Copy string to clipboard"
                          >
                            <Icon name={copiedString === row.value ? "check" : "copy"} size={9} className={copiedString === row.value ? "text-risk-clean" : ""} />
                            <span>{copiedString === row.value ? "Copied" : "Copy"}</span>
                          </button>
                          <Link
                            to={`/search?q=${encodeURIComponent(row.value)}`}
                            title={`Search OutPost event history for ${row.value}`}
                            className="press inline-flex h-5 w-5 items-center justify-center rounded border border-border-subtle bg-bg-surface text-text-muted hover:border-accent hover:text-accent"
                          >
                            <Icon name="search" size={9} />
                          </Link>
                          <button
                            onClick={() => void handleWatchlist(row.value)}
                            disabled={watchlisted.has(row.value)}
                            title={watchlisted.has(row.value) ? "On watchlist" : "Add to watchlist"}
                            className="press inline-flex h-5 w-5 items-center justify-center rounded border border-border-subtle bg-bg-surface text-text-faint hover:border-accent hover:text-accent disabled:text-risk-clean"
                          >
                            <Icon name={watchlisted.has(row.value) ? "check" : "plus"} size={9} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {filteredStrings.length > pageSize && (
              <div className="flex justify-center pt-2">
                <button
                  onClick={() => setPageSize(pageSize + 100)}
                  className="press rounded-lg border border-border-subtle bg-bg-surface px-4 py-1.5 text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition"
                >
                  Load More (+100 Strings)
                </button>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* SUB-VIEW 2: Dedicated Candidate Indicators Table */}
      {subTab === "iocs" && (
        <Panel
          kicker="Extracted Threat Intelligence"
          title={`Candidate IOCs (${totalIocs})`}
          right={
            <span className="text-[10px] text-text-faint">
              Candidate indicators extracted from binary; presence alone does not establish malice
            </span>
          }
        >
          {totalIocs === 0 ? (
            <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
              <Icon name="shield" size={20} className="mx-auto text-text-faint mb-2" />
              <p className="font-semibold text-text-primary">No Extracted Indicators</p>
              <p className="text-[11px] text-text-muted mt-1">
                Zero candidate IPv4, domain, URL, hash, or email indicators detected in binary bytecode.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                    <th className="py-2 px-3 w-28">Indicator Type</th>
                    <th className="py-2 px-3">Indicator Value</th>
                    <th className="py-2 px-3 w-32">Source Context</th>
                    <th className="py-2 px-3 text-right w-36">Analyst Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {(
                    [
                      { key: "ips" as const, label: "IPv4 Address", icon: "network" as const },
                      { key: "urls" as const, label: "URL Endpoint", icon: "globe" as const },
                      { key: "domains" as const, label: "Domain Name", icon: "globe" as const },
                      { key: "hashes" as const, label: "Payload Hash", icon: "copy" as const },
                      { key: "emails" as const, label: "Email Address", icon: "notes" as const },
                    ] as const
                  ).flatMap((group) =>
                    st.iocs[group.key].map((val, idx) => (
                      <tr key={`${group.key}-${idx}`} className="hover:bg-bg-elevated/40 transition-colors">
                        <td className="py-2 px-3">
                          <span className="flex items-center gap-1.5 font-bold text-text-primary">
                            <Icon name={group.icon} size={11} className="text-accent" />
                            <span>{group.label}</span>
                          </span>
                        </td>
                        <td className="py-2 px-3 font-mono text-[11px] text-text-primary select-all break-all">
                          {val}
                        </td>
                        <td className="py-2 px-3 text-[11px] text-text-muted">
                          Static Binary Extraction
                        </td>
                        <td className="py-2 px-3 text-right">
                          <div className="inline-flex items-center gap-1.5">
                            <Link
                              to={`/search?q=${encodeURIComponent(val)}`}
                              title={`Search OutPost event history for ${val}`}
                              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:border-accent hover:text-accent"
                            >
                              <Icon name="search" size={9} />
                              <span>Search</span>
                            </Link>
                            <a
                              href={getVirusTotalIocUrl(group.key, val)}
                              target="_blank"
                              rel="noopener noreferrer"
                              title={`VirusTotal external threat intelligence lookup for ${val}`}
                              aria-label={`VirusTotal external threat intelligence lookup for ${val}`}
                              className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-accent hover:bg-accent/20"
                            >
                              <span>VT Intel</span>
                              <Icon name="external" size={8} />
                            </a>
                            <button
                              onClick={() => void handleWatchlist(val)}
                              disabled={watchlisted.has(val)}
                              title={watchlisted.has(val) ? "On watchlist" : "Add to watchlist"}
                              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[9px] text-text-faint hover:border-accent hover:text-accent disabled:text-risk-clean"
                            >
                              <Icon name={watchlisted.has(val) ? "check" : "plus"} size={9} />
                              <span>{watchlisted.has(val) ? "Watchlisted" : "Watchlist"}</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
