import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import type { AnalysisObservation } from "../../types";

interface BehavioralEventsTabProps {
  observations: AnalysisObservation[];
  isStatic?: boolean;
}

const EVENT_TYPE_BADGES: Record<string, { label: string; color: string }> = {
  process_create: { label: "PROCESS_SPAWN", color: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400" },
  network_connection: { label: "NET_CONNECT", color: "border-sky-500/30 bg-sky-500/10 text-sky-400" },
  file_write: { label: "FILE_WRITE", color: "border-amber-500/30 bg-amber-500/10 text-amber-400" },
  registry_write: { label: "REG_SET", color: "border-rose-500/30 bg-rose-500/10 text-rose-400" },
};

export function BehavioralEventsTab({ observations, isStatic = false }: BehavioralEventsTabProps) {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  // For static observations
  const [stringSearch, setStringSearch] = useState("");
  const [copiedStrings, setCopiedStrings] = useState(false);

  // Dynamic analysis events stream
  const filteredEvents = useMemo(() => {
    if (isStatic) return [];
    return observations.filter((evt) => {
      if (filterType !== "ALL" && evt.event_type !== filterType) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const procMatch = evt.process_name?.toLowerCase().includes(q) ?? false;
        const cmdMatch = evt.command_line?.toLowerCase().includes(q) ?? false;
        const pathMatch = evt.file_path?.toLowerCase().includes(q) ?? false;
        const ipMatch = evt.dest_ip?.toLowerCase().includes(q) ?? false;
        const regMatch = evt.registry_key?.toLowerCase().includes(q) ?? false;
        const pidMatch = String(evt.pid || "").includes(q);
        if (!procMatch && !cmdMatch && !pathMatch && !ipMatch && !regMatch && !pidMatch) return false;
      }
      return true;
    });
  }, [observations, filterType, search, isStatic]);

  // If static analysis job, render static observation categories
  if (isStatic) {
    const stringObs = observations.find((o) => o.kind === "strings");
    const iocObs = observations.find((o) => o.kind === "iocs");
    const peObs = observations.find((o) => o.kind === "pe" || o.kind === "elf");

    const rawStrings = Array.isArray(stringObs?.data) ? (stringObs.data as string[]) : [];
    const filteredStrings = stringSearch.trim()
      ? rawStrings.filter((s) => s.toLowerCase().includes(stringSearch.toLowerCase()))
      : rawStrings;

    const copyAllStrings = () => {
      void navigator.clipboard.writeText(rawStrings.join("\n"));
      setCopiedStrings(true);
      setTimeout(() => setCopiedStrings(false), 1800);
    };

    const iocsData = (iocObs?.data && typeof iocObs.data === "object" ? iocObs.data : {}) as Record<string, string[]>;
    const peMeta = (peObs?.data && typeof peObs.data === "object" ? peObs.data : {}) as Record<string, unknown>;
    const imports = Array.isArray(peMeta.imports) ? (peMeta.imports as string[]) : [];

    return (
      <div className="space-y-6 font-sans">
        {/* Strings Section */}
        {rawStrings.length > 0 && (
          <Panel
            kicker="Static Byte Inspection"
            title="Extracted &amp; Deobfuscated Strings"
            right={
              <div className="flex items-center gap-2 font-mono text-xs">
                <input
                  type="text"
                  placeholder="Filter strings…"
                  value={stringSearch}
                  onChange={(e) => setStringSearch(e.target.value)}
                  className="w-44 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
                />
                <button
                  onClick={copyAllStrings}
                  className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:text-text-primary transition"
                >
                  {copiedStrings && <Icon name="check" size={10} className="text-signal" />}
                  <span>{copiedStrings ? "Copied" : "Copy All"}</span>
                </button>
              </div>
            }
          >
            <div className="max-h-72 overflow-y-auto font-mono text-[11px] p-2 bg-bg-inset rounded-xl border border-border-subtle divide-y divide-border-subtle/20">
              {filteredStrings.map((str, idx) => (
                <div key={idx} className="py-1 px-2 flex items-start gap-3 hover:bg-bg-elevated/40 transition">
                  <span className="text-text-faint select-none w-8 text-right tabular-nums">{idx + 1}</span>
                  <span className="break-all select-all text-text-primary font-mono">{str}</span>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {/* IOCs Section */}
        {Object.keys(iocsData).length > 0 && (
          <Panel kicker="Threat Indicators" title="Extracted Indicators of Compromise (IOCs)">
            <div className="space-y-4 font-mono text-xs">
              {Object.entries(iocsData).map(([cat, values]) => {
                if (!values || values.length === 0) return null;
                return (
                  <div key={cat} className="space-y-1.5">
                    <span className="text-[10px] uppercase font-bold text-accent tracking-wider">
                      {cat} ({values.length})
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {values.map((v) => (
                        <div
                          key={v}
                          className="inline-flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 font-mono text-[11px] text-text-primary"
                        >
                          <span className="select-all font-semibold">{v}</span>
                          <Link
                            to="/watchlist"
                            className="text-[9px] rounded bg-bg-elevated px-1 py-0.2 text-text-faint hover:text-accent"
                          >
                            Watchlist
                          </Link>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        )}

        {/* PE / ELF Headers Section */}
        {Object.keys(peMeta).length > 0 && (
          <Panel kicker="Executable Structure" title="Binary Headers &amp; Imported Symbols">
            <div className="space-y-4 font-mono text-xs">
              <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(peMeta)
                  .filter(([k]) => k !== "sections" && k !== "imports")
                  .map(([k, v]) => (
                    <div key={k} className="rounded-lg border border-border-subtle bg-bg-base p-2.5">
                      <dt className="text-[10px] uppercase text-text-faint font-semibold">{k}</dt>
                      <dd className="mt-1 truncate font-bold text-text-primary">{String(v ?? "—")}</dd>
                    </div>
                  ))}
              </dl>

              {imports.length > 0 && (
                <div className="border-t border-border-subtle pt-3 space-y-1.5">
                  <span className="text-[10px] uppercase text-text-faint font-semibold">
                    Linked Imports ({imports.length})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {imports.map((imp) => (
                      <span
                        key={imp}
                        className="rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-secondary select-all font-mono"
                      >
                        {imp}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Panel>
        )}
      </div>
    );
  }


  const handleExportJsonl = () => {
    const content = filteredEvents.map((e) => JSON.stringify(e)).join("\n");
    const blob = new Blob([content], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `outpost-events-${Date.now()}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 font-sans">
      <Panel
        kicker="Unified Event Stream"
        title="Chronological Behavioral &amp; Syscall Stream"
        right={
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="Search events, PID, path…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-48 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
            />
            <div className="flex items-center gap-1">
              {["ALL", "process_create", "network_connection", "file_write", "registry_write"].map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`rounded px-2 py-0.5 text-[10px] font-semibold transition ${
                    filterType === t
                      ? "bg-accent text-white"
                      : "border border-border-subtle bg-bg-base text-text-muted hover:text-text-primary"
                  }`}
                >
                  {t === "ALL" ? "ALL" : t.split("_")[0].toUpperCase()}
                </button>
              ))}
            </div>
            <button
              onClick={handleExportJsonl}
              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
              title="Export filtered event stream as JSONL"
            >
              <Icon name="download" size={10} />
              <span>Export JSONL</span>
            </button>
          </div>
        }
      >
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center font-mono text-xs text-text-muted">
            <p className="font-bold text-text-primary">No Matching Events</p>
            <p className="text-text-faint mt-1">Zero events matched your active type and search filters.</p>
          </div>
        ) : (
          <div className="space-y-1.5 font-mono text-xs">
            {filteredEvents.map((evt, idx) => {
              const badge = EVENT_TYPE_BADGES[evt.event_type || ""] || {
                label: (evt.event_type || "EVENT").toUpperCase(),
                color: "border-border-subtle bg-bg-base text-text-muted",
              };
              const isExpanded = expandedRow === idx;

              return (
                <div
                  key={`${evt.id ?? idx}-${idx}`}
                  className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden transition hover:border-accent/30"
                >
                  <div
                    onClick={() => setExpandedRow(isExpanded ? null : idx)}
                    className="flex flex-wrap items-center justify-between gap-2 p-2.5 cursor-pointer bg-bg-surface/80"
                  >
                    <div className="flex flex-wrap items-center gap-2.5 min-w-0">
                      <span className="text-text-faint text-[10px] tabular-nums">
                        {evt.timestamp ? evt.timestamp.slice(11, 23) : "—"}
                      </span>
                      <span className={`rounded border px-1.5 py-0.2 text-[9px] font-bold uppercase ${badge.color}`}>
                        {badge.label}
                      </span>
                      <span className="font-bold text-text-primary">{evt.process_name || "—"}</span>
                      {evt.pid && (
                        <span className="rounded bg-bg-elevated px-1 py-0.2 text-[9px] text-text-faint">
                          PID {evt.pid}
                        </span>
                      )}
                      {evt.dest_ip && (
                        <span className="text-accent text-[11px] font-semibold">
                          → {evt.dest_ip}{evt.dest_port ? `:${evt.dest_port}` : ""}
                        </span>
                      )}
                      {evt.file_path && (
                        <span className="truncate max-w-[280px] text-text-muted" title={evt.file_path}>
                          {evt.file_path}
                        </span>
                      )}
                      {evt.command_line && !evt.file_path && !evt.dest_ip && (
                        <span className="truncate max-w-[320px] text-text-muted text-[10px]" title={evt.command_line}>
                          {evt.command_line}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0 text-[10px] text-text-faint">
                      <span>{isExpanded ? "Collapse ▲" : "Raw JSON ▼"}</span>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-border-subtle bg-bg-inset p-3 text-[10px] text-emerald-400 select-all overflow-x-auto">
                      <pre>{JSON.stringify(evt, null, 2)}</pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Panel>
    </div>
  );
}
