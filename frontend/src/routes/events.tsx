import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { exportEventsCsv, getEvents } from "../lib/api";
import { copyToClipboard } from "../lib/clipboard";
import { playSocAlertSound } from "../lib/sound";
import { useEventStream } from "../lib/useEventStream";
import type { EventFeedEvent, EventType, Severity } from "../types";
import { parsePids, resolveSavedFilters, writeSavedFilters } from "./eventsHelpers";

function eventSeverity(ev: EventFeedEvent): string | null {
  return (ev as { severity?: string }).severity || ev.run_severity || null;
}

export default function EventsPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  // URL search query / pid sync
  const queryParam = searchParams.get("q") || "";
  const pidParam = searchParams.get("pid") || "";
  const typeParam = searchParams.get("type") || "";
  const sevParam = searchParams.get("severity") || "";

  // Restore saved filters on bare /events visit (satisfies eventsPersistence contract)
  const initialSaved = useMemo(() => {
    return resolveSavedFilters(
      (k) => searchParams.get(k),
      () => {
        try {
          return localStorage.getItem("outpost-events-filters");
        } catch {
          return null;
        }
      }
    );
  }, [searchParams]);

  const [searchQuery, setSearchQuery] = useState(
    queryParam || (initialSaved?.q ?? "")
  );
  const [eventTypeFilter, setEventTypeFilter] = useState<string>(
    typeParam || (initialSaved?.category ?? "")
  );
  const [severityFilter, setSeverityFilter] = useState<string>(
    sevParam || (initialSaved?.severity ?? "")
  );

  // Live polling controls
  const [isLive, setIsLive] = useState(true);
  const [bufferedCount, setBufferedCount] = useState(0);
  const [pollInterval, setPollInterval] = useState<number>(2000);

  // Inspector & Export state
  const [inspectEvent, setInspectEvent] = useState<EventFeedEvent | null>(null);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isExportingCsv, setIsExportingCsv] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Sound & Live Stream Notifications
  useEventStream((alert) => {
    if (alert && alert.severity === "malicious") {
      playSocAlertSound("malicious");
    } else if (alert && alert.severity === "suspicious") {
      playSocAlertSound("suspicious");
    }
    if (!isLive) {
      setBufferedCount((c) => c + 1);
    }
  });

  // Query events from API
  const {
    data: eventsData,
    isLoading,
    isFetching,
    refetch,
  } = useQuery({
    queryKey: ["events", "stream", eventTypeFilter, severityFilter, searchQuery, pidParam],
    queryFn: () =>
      getEvents({
        limit: 100,
        event_type: (eventTypeFilter || undefined) as EventType,
        severity: (severityFilter || undefined) as Severity,
        q: searchQuery || undefined,
        pid: pidParam || undefined,
      }),
    refetchInterval: isLive ? pollInterval : false,
  });

  // Persist active filters to localStorage
  useEffect(() => {
    writeSavedFilters(
      {
        severity: severityFilter || undefined,
        category: eventTypeFilter || undefined,
        q: searchQuery || undefined,
        pids: pidParam ? parsePids(pidParam) : undefined,
      },
      (data) => {
        try {
          localStorage.setItem("outpost-events-filters", data);
        } catch {
          // ignore storage errors
        }
      }
    );
  }, [severityFilter, eventTypeFilter, searchQuery, pidParam]);

  // Sync search into URL params
  const handleSearchChange = (val: string) => {
    setSearchQuery(val);
    const next = new URLSearchParams(searchParams);
    if (val.trim()) next.set("q", val.trim());
    else next.delete("q");
    setSearchParams(next, { replace: true });
  };

  const handleTypeChange = (val: string) => {
    setEventTypeFilter(val);
    const next = new URLSearchParams(searchParams);
    if (val) next.set("type", val);
    else next.delete("type");
    setSearchParams(next, { replace: true });
  };

  const handleSeverityChange = (val: string) => {
    setSeverityFilter(val);
    const next = new URLSearchParams(searchParams);
    if (val) next.set("severity", val);
    else next.delete("severity");
    setSearchParams(next, { replace: true });
  };

  const handleExportCsv = async () => {
    try {
      setIsExportingCsv(true);
      const blob = await exportEventsCsv({
        event_type: (eventTypeFilter || undefined) as EventType,
        severity: (severityFilter || undefined) as Severity,
        q: searchQuery || undefined,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `outpost-telemetry-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionMessage("Exported CSV successfully");
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err: any) {
      setActionMessage(`CSV export failed: ${err?.message || "Unknown error"}`);
    } finally {
      setIsExportingCsv(false);
    }
  };

  const events = eventsData?.events || [];
  const totalCount = eventsData?.total ?? events.length;

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 font-sans space-y-6">
      {/* ── Page Header ─────────────────────────────────────────────── */}
      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-text-faint uppercase tracking-wider">
            <span className="flex h-2 w-2 rounded-full bg-signal animate-pulse" />
            <span>Security Operations · Telemetry Lake</span>
          </div>
          <h1 className="mt-1 text-2xl font-bold tracking-tight text-text-primary flex items-center gap-3">
            <span>Security Telemetry Stream</span>
            <span className="rounded-full bg-accent/15 px-2.5 py-0.5 text-xs font-mono font-semibold text-accent border border-accent/40">
              Live Ingest
            </span>
          </h1>
          <p className="mt-1 text-xs text-text-muted max-w-3xl font-sans">
            Real-time sensor event stream across fleet endpoints. Search, filter, and inspect raw process execution, network connections, file modifications, and registry events.
          </p>
        </div>

        {/* Action Controls: Live Polling, Interval, Refresh, Export CSV */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Polling Toggle */}
          <button
            onClick={() => {
              if (!isLive) setBufferedCount(0);
              setIsLive(!isLive);
            }}
            className={`press flex items-center gap-1.5 rounded-xl border px-3 py-1.5 font-mono text-xs font-semibold transition shadow-xs ${
              isLive
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                : "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20"
            }`}
            title={isLive ? "Pause real-time updates" : "Resume live telemetry polling"}
          >
            <span className={`h-2 w-2 rounded-full ${isLive ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
            <span>{isLive ? "Live" : bufferedCount > 0 ? `Paused (${bufferedCount} new)` : "Paused"}</span>
          </button>

          {/* Polling Interval Selector */}
          <select
            value={pollInterval}
            onChange={(e) => setPollInterval(Number(e.target.value))}
            className="rounded-xl border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-hidden focus:border-accent shadow-xs"
            title="Telemetry polling frequency"
          >
            <option value={1000}>1s (Fast)</option>
            <option value={2000}>2s (Balanced)</option>
            <option value={5000}>5s (Relaxed)</option>
          </select>

          {/* Refresh Now Button */}
          <button
            onClick={() => void refetch()}
            disabled={isFetching}
            className="press flex items-center gap-1 rounded-xl border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary transition shadow-xs"
            title="Trigger instant stream refresh"
          >
            <Icon name="refresh" size={13} className={isFetching ? "animate-spin text-accent" : ""} />
            <span className="hidden sm:inline">Refresh</span>
          </button>

          {/* CSV Export Button */}
          <button
            onClick={handleExportCsv}
            disabled={isExportingCsv || events.length === 0}
            className="press flex items-center gap-1.5 rounded-xl border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs font-semibold text-text-secondary hover:text-text-primary hover:border-accent/40 transition disabled:opacity-40 shadow-xs"
            title="Export filtered security telemetry to CSV"
          >
            <Icon name="download" size={13} className={isExportingCsv ? "animate-spin text-accent" : ""} />
            <span>{isExportingCsv ? "Exporting..." : "Export CSV"}</span>
          </button>
        </div>
      </header>

      {/* Action Notice if any */}
      {actionMessage && (
        <div className="rounded-xl border border-signal/50 bg-signal/15 px-4 py-2 text-xs text-signal font-mono flex items-center justify-between">
          <span>✓ {actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* ── Telemetry Query Ribbon & Filters ────────────────────────── */}
      <section className="rounded-xl border border-border-subtle bg-bg-surface p-3 space-y-3 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Universal Search Bar */}
          <div className="relative flex-1 min-w-[260px]">
            <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              type="text"
              placeholder="Search telemetry by command line, binary, host ID, destination IP, file path..."
              value={searchQuery}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="w-full rounded-lg border border-border-subtle bg-bg-base/80 py-1.5 pl-8 pr-8 text-xs text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-hidden"
            />
            {searchQuery && (
              <button
                onClick={() => handleSearchChange("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-faint hover:text-text-primary"
                title="Clear filter"
              >
                ✕
              </button>
            )}
          </div>

          {/* Event Count Badge */}
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] font-semibold text-text-secondary tabular-nums">
              {totalCount.toLocaleString()} Events
            </span>
            {isFetching && <span className="text-[10px] text-accent animate-pulse font-sans">Syncing...</span>}
          </div>
        </div>

        {/* Filter Chips Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1 border-t border-border-subtle/50 text-[11px]">
          {/* Event Type Filter Chips */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-text-faint text-[10px] uppercase font-bold mr-1">Event Type:</span>
            {[
              { id: "", label: "All Types" },
              { id: "process_create", label: "process_create" },
              { id: "network_connection", label: "network" },
              { id: "file_write", label: "file_write" },
              { id: "registry_write", label: "registry" },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => handleTypeChange(t.id)}
                className={`press rounded-lg px-2.5 py-1 transition font-mono text-[10px] ${
                  eventTypeFilter === t.id
                    ? "bg-accent/20 text-accent font-bold border border-accent/40 shadow-xs"
                    : "bg-bg-base/60 text-text-muted hover:text-text-primary border border-border-subtle"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Severity Filter Chips */}
          <div className="flex items-center gap-1.5">
            <span className="text-text-faint text-[10px] uppercase font-bold mr-1">Severity:</span>
            {[
              { id: "", label: "All" },
              { id: "malicious", label: "Critical / Malicious" },
              { id: "suspicious", label: "Suspicious" },
              { id: "info", label: "Informational" },
            ].map((s) => (
              <button
                key={s.id}
                onClick={() => handleSeverityChange(s.id)}
                className={`press rounded-lg px-2.5 py-1 transition text-[10px] ${
                  severityFilter === s.id
                    ? "bg-accent/20 text-accent font-bold border border-accent/40 shadow-xs"
                    : "bg-bg-base/60 text-text-muted hover:text-text-primary border border-border-subtle"
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* ── Telemetry Events Stream Table ───────────────────────────── */}
      <section className="overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-xs font-mono text-xs">
        <div className="overflow-x-auto max-h-[700px] overflow-y-auto">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 z-10 bg-bg-base/95 backdrop-blur-md border-b border-border-subtle text-[10px] text-text-muted uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Host Provenance</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">Process / Actor</th>
                <th className="py-2.5 px-3">Payload / Target</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-text-muted font-sans text-xs">
                    <Icon name="refresh" size={18} className="mx-auto animate-spin text-accent mb-2" />
                    Querying sensor telemetry lake...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-16 text-center text-text-muted font-sans text-xs">
                    <p className="font-semibold text-text-primary">No telemetry events match active filters</p>
                    <p className="text-text-faint text-[11px] mt-1">Adjust search query, severity, or event type parameters above.</p>
                  </td>
                </tr>
              ) : (
                events.map((ev: EventFeedEvent) => {
                  const isMalicious = eventSeverity(ev) === "malicious";
                  const isSuspicious = eventSeverity(ev) === "suspicious";

                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setInspectEvent(ev)}
                      className={`hover:bg-bg-elevated/40 transition cursor-pointer ${
                        inspectEvent?.id === ev.id ? "bg-accent/10" : ""
                      }`}
                    >
                      {/* Timestamp */}
                      <td className="py-2 px-3 text-text-faint whitespace-nowrap tabular-nums text-[11px]">
                        {ev.timestamp ? ev.timestamp.replace("T", " ").replace("Z", "").slice(0, 19) : "—"}
                      </td>

                      {/* Host Provenance (Deep link to host workspace, local stays text) */}
                      <td className="py-2 px-3 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        {ev.host_id ? (
                          <Link
                            to={`/hosts/${encodeURIComponent(ev.host_id)}`}
                            className="font-bold text-accent hover:underline inline-flex items-center gap-1 text-[11px]"
                            title={`Host workspace: ${ev.host_id}`}
                          >
                            <Icon name="box" size={11} className="text-accent/80 shrink-0" />
                            <span className="truncate max-w-[130px]">{ev.host_id}</span>
                          </Link>
                        ) : (
                          <span className="text-text-faint text-[11px]">local</span>
                        )}
                      </td>

                      {/* Severity */}
                      <td className="py-2 px-3 whitespace-nowrap">
                        {isMalicious ? (
                          <span className="inline-flex items-center gap-1 rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.2 text-[10px] font-bold text-red-400">
                            <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                            <span>malicious</span>
                          </span>
                        ) : isSuspicious ? (
                          <span className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.2 text-[10px] font-semibold text-amber-400">
                            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                            <span>suspicious</span>
                          </span>
                        ) : (
                          <span className="rounded border border-border-subtle bg-bg-surface px-1.5 py-0.2 text-[10px] text-text-faint">
                            info
                          </span>
                        )}
                      </td>

                      {/* Event Type */}
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] font-semibold text-text-primary">
                          {ev.event_type}
                        </span>
                      </td>

                      {/* Process / Actor */}
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="font-semibold text-text-primary">{ev.process_name || ev.sample_name || "—"}</span>
                        {ev.pid ? <span className="ml-1 text-[10px] text-text-faint">[{ev.pid}]</span> : null}
                      </td>

                      {/* Telemetry Payload */}
                      <td className="py-2 px-3 text-text-muted truncate max-w-[320px] text-[11px]" title={ev.command_line || ev.dest_ip || ev.file_path || ""}>
                        {ev.command_line || (ev.dest_ip ? `${ev.dest_ip}:${ev.dest_port ?? ""}` : null) || ev.file_path || "—"}
                      </td>

                      {/* Action */}
                      <td className="py-2 px-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setInspectEvent(ev)}
                          className="press rounded-md border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] font-semibold text-text-secondary hover:text-text-primary hover:border-accent/40 shadow-xs"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border-subtle bg-bg-base/70 px-4 py-2 font-sans text-[11px] text-text-muted">
          <span>Showing {events.length} of {totalCount.toLocaleString()} total sensor events</span>
          <span>Click any event row to open telemetry drawer</span>
        </div>
      </section>

      {/* ── Slide-Over Telemetry Inspector Drawer ─────────────────────── */}
      {inspectEvent && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity"
          onClick={() => setInspectEvent(null)}
        >
          <div
            className="h-full w-full max-w-lg bg-[#0B0E14] border-l border-border-subtle p-6 overflow-y-auto space-y-5 font-mono text-xs shadow-2xl animate-in slide-in-from-right duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-start justify-between border-b border-border-subtle pb-4">
              <div>
                <div className="flex items-center gap-2 text-text-faint text-[10px] uppercase">
                  <span>Event #{inspectEvent.id}</span>
                  <span>·</span>
                  <span>{inspectEvent.source || "Sensor Lake"}</span>
                </div>
                <h3 className="mt-1 text-base font-bold text-text-primary flex items-center gap-2">
                  <span>{inspectEvent.event_type}</span>
                  {eventSeverity(inspectEvent) && (
                    <span
                      className={`rounded px-2 py-0.2 text-[10px] font-bold ${
                        eventSeverity(inspectEvent) === "malicious"
                          ? "bg-red-500/15 text-red-400 border border-red-500/30"
                          : eventSeverity(inspectEvent) === "suspicious"
                            ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                            : "bg-slate-500/15 text-text-muted border border-border-subtle"
                      }`}
                    >
                      {eventSeverity(inspectEvent)}
                    </span>
                  )}
                </h3>
              </div>
              <button
                onClick={() => setInspectEvent(null)}
                className="press rounded-lg p-1.5 text-text-faint hover:text-text-primary hover:bg-bg-elevated"
              >
                ✕
              </button>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="rounded-lg border border-border-subtle bg-bg-surface p-2.5">
                <span className="text-[10px] text-text-faint uppercase block">Endpoint Host</span>
                {inspectEvent.host_id ? (
                  <Link
                    to={`/hosts/${encodeURIComponent(inspectEvent.host_id)}`}
                    className="font-bold text-accent hover:underline mt-0.5 block truncate"
                  >
                    {inspectEvent.host_id}
                  </Link>
                ) : (
                  <span className="font-bold text-text-primary mt-0.5 block">local</span>
                )}
              </div>
              <div className="rounded-lg border border-border-subtle bg-bg-surface p-2.5">
                <span className="text-[10px] text-text-faint uppercase block">UTC Timestamp</span>
                <span className="font-bold text-text-primary mt-0.5 block truncate tabular-nums">
                  {inspectEvent.timestamp ? inspectEvent.timestamp.replace("T", " ") : "—"}
                </span>
              </div>
            </div>

            {/* Process Lineage Block */}
            <div className="space-y-1.5 rounded-lg border border-border-subtle bg-bg-surface p-3 text-[11px]">
              <div className="flex items-center justify-between text-text-faint text-[10px] uppercase">
                <span>Process Lineage</span>
                {inspectEvent.host_id && (
                  <Link
                    to={`/hosts/${encodeURIComponent(inspectEvent.host_id)}`}
                    className="text-accent hover:underline font-bold"
                  >
                    Investigate Host →
                  </Link>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 pt-1">
                <div>
                  <span className="text-[10px] text-text-faint">Name:</span>
                  <p className="font-semibold text-text-primary truncate">
                    {inspectEvent.process_name || inspectEvent.sample_name || "—"}
                  </p>
                </div>
                <div>
                  <span className="text-[10px] text-text-faint">PID / PPID:</span>
                  <p className="text-text-primary tabular-nums">
                    {inspectEvent.pid ?? "—"} / {inspectEvent.ppid ?? "—"}
                  </p>
                </div>
              </div>
              {inspectEvent.command_line && (
                <div className="pt-2">
                  <div className="flex items-center justify-between text-[10px] text-text-faint">
                    <span>Command Line</span>
                    <button
                      onClick={() => {
                        void copyToClipboard(inspectEvent.command_line || "");
                        setCopiedPayload(true);
                        setTimeout(() => setCopiedPayload(false), 2000);
                      }}
                      className="text-accent hover:underline text-[10px]"
                    >
                      {copiedPayload ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <pre className="mt-1 rounded border border-border-subtle bg-bg-base p-2 text-[10px] text-text-primary whitespace-pre-wrap break-all select-all">
                    {inspectEvent.command_line}
                  </pre>
                </div>
              )}
            </div>

            {/* Network Socket Target if present */}
            {inspectEvent.dest_ip && (
              <div className="space-y-1 rounded-lg border border-border-subtle bg-bg-surface p-3 text-[11px]">
                <span className="text-[10px] text-text-faint uppercase block">Network Socket Target</span>
                <p className="text-text-primary font-bold">
                  {inspectEvent.dest_ip}:{inspectEvent.dest_port ?? ""}
                </p>
              </div>
            )}

            {/* Raw JSON Dossier */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[10px] text-text-faint uppercase">
                <span>Raw Telemetry Record JSON</span>
                <button
                  onClick={() => {
                    void copyToClipboard(JSON.stringify(inspectEvent, null, 2));
                    setCopiedPayload(true);
                    setTimeout(() => setCopiedPayload(false), 2000);
                  }}
                  className="text-accent hover:underline"
                >
                  {copiedPayload ? "Copied JSON!" : "Copy JSON"}
                </button>
              </div>
              <pre className="max-h-60 overflow-y-auto rounded-lg border border-border-subtle bg-bg-base p-3 text-[10px] text-text-secondary select-all">
                {JSON.stringify(inspectEvent, null, 2)}
              </pre>
            </div>

            {/* Close footer */}
            <div className="border-t border-border-subtle pt-3 flex justify-end">
              <button
                onClick={() => setInspectEvent(null)}
                className="press rounded-lg border border-border-subtle bg-bg-surface px-4 py-1.5 text-xs text-text-primary hover:bg-bg-elevated"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
