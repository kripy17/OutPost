import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { EVENT_ICON, platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import { exportEventsCsv, getBehavioralExplanations, getEventCounts, getEvents, getHostXRaySnapshot, getLocalMonitorStatus, getNetworkMatrix, getProcessTree, saveBlob, startLocalMonitor, stopLocalMonitor } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { parsePids, resolveSavedFilters, type SavedFilters } from "./eventsHelpers";
import { DataProvenanceBadge } from "../components/DataProvenanceBadge";
import { ProcessContextModal } from "../components/ProcessContextModal";
import { NetworkContextModal } from "../components/NetworkContextModal";
import { ProcessTreeGraph } from "../components/ProcessTreeGraph";
import { NetworkMatrixView } from "../components/NetworkMatrixView";
import { BehavioralExplanationsView } from "../components/BehavioralExplanationsView";
import { DifferentialSnapshotView } from "../components/DifferentialSnapshotView";
import { CapsuleDiffModal } from "../components/CapsuleDiffModal";
import { HostForensicsCockpit } from "../components/HostForensicsCockpit";
import AgentsPage from "./agents";
import type { EventFeedEvent, EventSource, EventType, Platform, Severity } from "../types";

const PAGE = 60;

const CATEGORIES: { type: EventType | ""; label: string; icon: "list" | "process" | "network" | "file" | "registry" }[] = [
  { type: "", label: "All events", icon: "list" },
  { type: "process_create", label: "Process activity", icon: "process" },
  { type: "network_connection", label: "Network", icon: "network" },
  { type: "file_write", label: "File activity", icon: "file" },
  { type: "registry_write", label: "Registry", icon: "registry" },
];

// Provenance tabs — the Event Viewer's "source" split. Collectors stamp each
// shipped event with its exact log channel, so the collector stream splits by
// channel (auditd / sysmon) — explicit provenance, not platform inference —
// with a coarse Collectors tab and the webapp/sandbox provenance tabs beside.
const SOURCE_TABS: { v: EventSource | ""; label: string; icon: "terminal" | "linux" | "windows" | "box" | "grid" }[] = [
  { v: "", label: "All sources", icon: "grid" },
  { v: "live", label: "Collectors", icon: "terminal" },
  { v: "auditd", label: "Auditd", icon: "linux" },
  { v: "sysmon", label: "Sysmon", icon: "windows" },
  { v: "webapp", label: "Webapp", icon: "grid" },
  { v: "sandbox", label: "Sandbox", icon: "box" },
];

// One-click focus presets (Sysmon View's "hide the noise" pattern): a
// category shortcut so an analyst can drop to exactly the stream they care
// about — network only, new processes only, etc. — instead of tabbing.
const FOCUS_PRESETS: { label: string; type: EventType | ""; icon: "list" | "network" | "process" | "file" | "registry" }[] = [
  { label: "All activity", type: "", icon: "list" },
  { label: "Network only", type: "network_connection", icon: "network" },
  { label: "New processes", type: "process_create", icon: "process" },
  { label: "File writes", type: "file_write", icon: "file" },
  { label: "Registry", type: "registry_write", icon: "registry" },
];

function sourceLabel(e: EventFeedEvent): string {
  // The stamped channel is authoritative when present.
  if (e.log_source === "auditd") return "auditd";
  if (e.log_source === "sysmon") return "sysmon";
  if (e.source.startsWith("sandbox:")) return "sandbox";
  return "webapp";
}

function levelOf(e: EventFeedEvent): { key: "error" | "warning" | "info"; label: string; badge: string; icon: "alert" | "zap" | "check" } {
  if (e.run_severity === "malicious")
    return { key: "error", label: "Error", badge: "border-risk-malicious/50 bg-risk-malicious/10 text-risk-malicious", icon: "alert" };
  if (e.run_severity === "suspicious")
    return { key: "warning", label: "Warning", badge: "border-risk-suspicious/50 bg-risk-suspicious/10 text-risk-suspicious", icon: "zap" };
  return { key: "info", label: "Info", badge: "border-border-subtle bg-bg-elevated/50 text-text-muted", icon: "check" };
}

function eventDetail(e: EventFeedEvent): string {
  if (e.process_name) return `${e.process_name}${e.command_line ? ` — ${e.command_line}` : ""}`;
  if (e.dest_ip) return `${e.dest_ip}${e.dest_port ? `:${e.dest_port}` : ""}${e.protocol ? ` [${e.protocol}]` : ""}`;
  if (e.file_path) return e.file_path;
  if (e.registry_key) return e.registry_key;
  return "—";
}

function eventMeta(e: EventFeedEvent): string[] {
  const parts: string[] = [];
  if (e.pid) parts.push(`pid ${e.pid}`);
  if (e.dest_ip) parts.push(e.dest_ip);
  if (e.process_name) parts.push(e.process_name);
  return parts.slice(0, 2);
}

/* The full normalized record — every field we carry for an event. Shared by
   the inline expansion (EventRow when active) so the detail view is always
   the same set of fields, in the same order. */
function EventFields({ event }: { event: EventFeedEvent }) {
  return (
    <dl className="space-y-3 border-t border-border-subtle pt-4 font-mono text-xs">
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">Event type</dt>
        <dd className="min-w-0 break-words text-text-primary capitalize">{event.event_type.replace("_", " ")}</dd>
      </div>
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">Timestamp</dt>
        <dd className="min-w-0 break-words text-text-primary">{event.timestamp}</dd>
      </div>
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">Host</dt>
        <dd className="min-w-0 break-words text-text-primary">
          <Link
            to={`/hosts/${encodeURIComponent(event.host_id ?? "local")}`}
            className="text-accent hover:underline inline-flex items-center gap-1"
          >
            {event.host_id ?? "local"}
            <Icon name="external" size={9} className="opacity-60" />
          </Link>
        </dd>
      </div>
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">Sample</dt>
        <dd className="min-w-0 break-words text-text-primary">{event.sample_name}</dd>
      </div>
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">Run</dt>
        <dd className="min-w-0 break-words text-text-primary">
          <Link to={`/runs/${event.run_id}`} className="text-accent hover:underline inline-flex items-center gap-1">
            {event.run_id}
            <Icon name="external" size={9} className="opacity-60" />
          </Link>
        </dd>
      </div>
      <div className="flex gap-3">
        <dt className="w-24 shrink-0 text-text-faint">PID</dt>
        <dd className="min-w-0 break-words text-text-primary">{String(event.pid ?? "—")}</dd>
      </div>
      {event.ppid && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">PPID</dt>
          <dd className="min-w-0 break-words text-text-primary">{String(event.ppid)}</dd>
        </div>
      )}
      {event.process_name && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Process</dt>
          <dd className="min-w-0 break-words text-text-primary">{event.process_name}</dd>
        </div>
      )}
      {event.command_line && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Command line</dt>
          <dd className="min-w-0 break-words text-text-primary">{event.command_line}</dd>
        </div>
      )}
      {event.dest_ip && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Dest IP</dt>
          <dd className="min-w-0 break-words text-text-primary">
            <Link
              to={`/search?q=${encodeURIComponent(event.dest_ip)}`}
              className="text-accent hover:underline inline-flex items-center gap-1 font-semibold"
              title={`Investigate ${event.dest_ip} in IOC search`}
            >
              {event.dest_ip}
              <Icon name="search" size={9} className="opacity-60" />
            </Link>
          </dd>
        </div>
      )}
      {event.dest_port !== null && event.dest_port !== undefined && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Dest port</dt>
          <dd className="min-w-0 break-words text-text-primary">{String(event.dest_port)}</dd>
        </div>
      )}
      {event.protocol && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Protocol</dt>
          <dd className="min-w-0 break-words text-text-primary uppercase">{event.protocol}</dd>
        </div>
      )}
      {event.file_path && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">File path</dt>
          <dd className="min-w-0 break-words text-text-primary">{event.file_path}</dd>
        </div>
      )}
      {event.registry_key && (
        <div className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">Registry key</dt>
          <dd className="min-w-0 break-words text-text-primary">{event.registry_key}</dd>
        </div>
      )}
    </dl>
  );
}

/* A live count badge, shared by the two rails. Each row fixes exactly ONE
   facet — event_type for the category rail, source for the provenance/channel
   source tabs — and shares every other live filter (severity, platform, the
   other facet, search, pid, synthetic). So both rails are noise-meters that
   move as you filter, not static per-bucket totals. React Query dedupes on
   the key, so parallel rows only refetch when a shared filter changes. */
function CountBadge({
  type,
  source,
  severity,
  platform,
  q,
  pids,
  count,
}: {
  type: EventType | "";
  source: EventSource | "";
  severity: Severity | "";
  platform: Platform | "";
  q: string;
  pids: number[];
  count: number | undefined;
}) {
  // Presentational now — every badge reads its bucket from the page's ONE
  // /events/counts query (shared across all five category buttons and the
  // channel tabs), so a filter change costs one count request, not six.
  // The tooltip explains *why* the count is what it is (the active filters).
  const desc = [
    severity ? `level: ${severity}` : null,
    platform ? `platform: ${platform}` : null,
    source ? `source: ${source}` : null,
    type ? `type: ${type}` : null,
    q ? `search: “${q}”` : null,
    pids.length ? `pid: ${pids.join(",")}` : null,
  ]
    .filter(Boolean)
    .join(", ");

  return (
    <span
      className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 py-px font-mono text-[10px] tabular-nums text-text-faint"
      title={desc || "no active filters"}
    >
      {count ?? "…"}
    </span>
  );
}

/* Keyboard hints — a one-line legend for the Event-Viewer navigation. Shows
   until the user actually uses a key (Arrow/Enter/Escape), then disappears
   for good via localStorage — respect the analyst, don't nag. */
function KeyboardHints({ onUsed }: { onUsed: () => void }) {
  const [visible, setVisible] = useState(() => {
    try {
      return localStorage.getItem("outpost-events-hints") !== "1";
    } catch {
      return true;
    }
  });

  useEffect(() => {
    if (!visible) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowUp" || e.key === "ArrowDown" || e.key === "Enter" || e.key === "Escape") {
        setVisible(false);
        onUsed();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visible, onUsed]);

  if (!visible) return null;
  return (
    <div className="mb-5 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2 font-mono text-[10px] text-text-faint transition-opacity duration-300">
      <span className="flex items-center gap-1"><kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px text-text-muted">↑</kbd><kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px text-text-muted">↓</kbd> move</span>
      <span className="flex items-center gap-1"><kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px text-text-muted">Enter</kbd> expand record</span>
      <span className="flex items-center gap-1"><kbd className="rounded border border-border-subtle bg-bg-surface px-1.5 py-px text-text-muted">Esc</kbd> close</span>
      <span className="ml-auto text-[10px] text-text-faint/70">keyboard navigation — press any to dismiss</span>
    </div>
  );
}

/* One feed row — shared by the timeline (minute groups) and the
   process-chain view. The card is a non-interactive container; the select
   button and the run link are SIBLINGS (never nested interactive
   elements). */
function EventRow({
  e,
  active,
  onSelect,
  onFilterPid,
  onInspectProcess,
  onInspectNetwork,
}: {
  e: EventFeedEvent;
  active: boolean;
  onSelect: (e: EventFeedEvent | null) => void;
  onFilterPid?: (pid: number) => void;
  onInspectProcess?: (pid: number) => void;
  onInspectNetwork?: (ip: string) => void;
}) {
  const lvl = levelOf(e);
  const rail = e.run_severity === "malicious" ? "bg-risk-malicious" : e.run_severity === "suspicious" ? "bg-risk-suspicious" : "bg-border-strong";
  return (
    <li className="timeline-item">
      <div
        className={`group relative ml-2 overflow-hidden rounded-xl border bg-bg-surface transition-all duration-150 ${
          active ? "border-accent/50 shadow-[var(--glow-accent)]" : "border-border-subtle hover:border-accent/30 hover:shadow-[var(--shadow-panel)]"
        }`}
      >
        <span className={`absolute left-0 top-0 h-full w-1 ${rail}`} aria-hidden />
        <button
          onClick={() => onSelect(active ? null : e)}
          aria-pressed={active}
          aria-expanded={active}
          className="flex w-full items-start gap-3 py-3 pl-4 pr-3 text-left"
        >
          <span
            className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border ${
              e.run_severity === "malicious"
                ? "border-risk-malicious/30 bg-risk-malicious/10 text-risk-malicious"
                : e.run_severity === "suspicious"
                  ? "border-risk-suspicious/30 bg-risk-suspicious/10 text-risk-suspicious"
                  : "border-border-subtle bg-bg-elevated/60 text-text-muted"
            }`}
          >
            <Icon name={EVENT_ICON[e.event_type]} size={16} />
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <span className="text-[13px] font-semibold capitalize text-text-primary">
                {e.event_type.replace("_", " ")}
              </span>
              <span className={`rounded-full border px-1.5 py-px font-mono text-[9px] uppercase tracking-wide ${lvl.badge}`}>
                {lvl.label}
              </span>
              <DataProvenanceBadge source={e.source} log_source={e.log_source} />
              <span className="ml-auto font-mono text-[10px] tabular-nums text-text-faint">
                {e.timestamp.slice(11, 19)} UTC
              </span>
              <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
                {sourceLabel(e)}
              </span>
            </span>
            <span className="mt-0.5 block truncate font-mono text-[11px] text-text-muted" title={eventDetail(e)}>
              {eventDetail(e)}
            </span>
          </span>
          <Icon name="chevronRight" size={14} className="mt-1 shrink-0 text-text-faint transition-transform duration-150 group-hover:translate-x-0.5" />
        </button>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border-subtle/60 px-4 py-2 text-[10px] text-text-faint">
          {eventMeta(e).map((m) => (
            <span key={m} className="font-mono">{m}</span>
          ))}
          {e.host_id ? (
            <Link
              to={`/hosts/${encodeURIComponent(e.host_id)}`}
              className="press inline-flex items-center gap-1 font-mono text-text-muted hover:text-accent"
              title={`The aggregate timeline — everything OutPost knows about ${e.host_id}`}
            >
              <Icon name="terminal" size={10} className="opacity-60" />
              {e.host_id}
            </Link>
          ) : (
            <span className="inline-flex items-center gap-1 font-mono">
              <Icon name="terminal" size={10} className="opacity-60" />
              local
            </span>
          )}
          <Link
            to={`/runs/${e.run_id}`}
            className="inline-flex items-center gap-1 font-mono font-medium text-accent hover:underline"
          >
            {e.sample_name}
            <Icon name="external" size={10} className="opacity-60" />
          </Link>
        </div>

        {/* Inline expansion — the full raw record, unfolded under the row */}
        {active && (
          <div className="border-t border-border-subtle bg-bg-base/40 px-5 py-4">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${lvl.badge}`}>
                <Icon name={lvl.icon} size={12} />
                {lvl.label}
              </span>
              <DataProvenanceBadge source={e.source} log_source={e.log_source} />
              <span className="inline-flex items-center gap-1.5 rounded-full border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted">
                <Icon name={platformIconName(e.platform)} size={12} />
                {e.platform}
              </span>
            </div>

            <EventFields event={e} />

            {/* Process & Network investigation action pivots */}
            <div className="mt-4 flex flex-wrap gap-2">
              {e.pid && (
                <>
                  <button
                    onClick={() => onInspectProcess?.(e.pid as number)}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent transition-colors hover:bg-accent/20"
                    title={`Inspect full process tree, socket connections, and findings for PID ${e.pid}`}
                  >
                    <Icon name="process" size={12} />
                    Investigate Process Context (PID {e.pid})
                  </button>
                  <button
                    onClick={() => onFilterPid?.(e.pid as number)}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
                    title={`Filter event feed to PID ${e.pid}`}
                  >
                    <Icon name="list" size={12} />
                    Trace PID {e.pid} in Feed
                  </button>
                </>
              )}

              {e.dest_ip && (
                <>
                  <button
                    onClick={() => onInspectNetwork?.(e.dest_ip as string)}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 px-3 py-1.5 font-mono text-xs font-semibold text-sky-400 transition-colors hover:bg-sky-500/20"
                    title={`Inspect communicating hosts, responsible processes, and findings for ${e.dest_ip}`}
                  >
                    <Icon name="network" size={12} />
                    Investigate Network Context ({e.dest_ip})
                  </button>
                  <Link
                    to={`/search?q=${encodeURIComponent(e.dest_ip)}`}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
                    title={`Pivot to IOC Intelligence for ${e.dest_ip}`}
                  >
                    <Icon name="search" size={12} />
                    Search IOC
                  </Link>
                </>
              )}
            </div>

            {/* Raw record */}
            {e.raw_record && (
              <div className="mt-5">
                <p className="kicker mb-2 flex items-center gap-1.5">
                  <Icon name="terminal" size={11} />
                  Raw record
                </p>
                <pre className="overflow-x-auto rounded-lg border border-border-subtle bg-bg-elevated/40 p-3 font-mono text-[10px] leading-relaxed text-text-muted">
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(e.raw_record), null, 2);
                    } catch {
                      return e.raw_record;
                    }
                  })()}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </li>
  );
}

/* ── Page ──────────────────────────────────────────────────────────────── */

export default function EventsPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQ = searchParams.get("q") ?? ""; // deep links: /events?q=<host or ioc>
  // Process-centric deep link: /events?pid=<n[,m,…]> = everything those PIDs
  // did (comma-separated = the recon-sweep jump).
  const initialPids = parsePids(searchParams.get("pid"));
  // Restore the last-used filter set on a bare /events visit (no URL params).
  // URL params always win when present — deep links keep their explicit state.
  // Read into the useState initializers below (NOT a mount effect): the mirror
  // effect would otherwise clobber localStorage with the empty default before
  // the restore could read it back, silently killing persistence.
  const savedFiltersRef = useRef<SavedFilters | null>(null);
  if (savedFiltersRef.current === null) {
    savedFiltersRef.current = resolveSavedFilters(
      (k) => searchParams.get(k),
      () => localStorage.getItem("outpost-events-filters"),
    );
  }
  const saved = savedFiltersRef.current;
  // Filter state lives in the URL (Event-Viewer parity): every view is
  // bookmarkable/shareable — /events?type=network_connection&severity=…&source=…&q=…&pid=…
  const [category, setCategory] = useState<EventType | "">(
    ((searchParams.get("type") as EventType | "") ?? (saved?.category as EventType | "") ?? "") as EventType | "",
  );
  const [severity, setSeverity] = useState<Severity | "">(
    ((searchParams.get("severity") as Severity | "") ?? (saved?.severity as Severity | "") ?? "") as Severity | "",
  );
  const [platform, setPlatform] = useState<Platform | "">(
    ((searchParams.get("platform") as Platform | "") ?? (saved?.platform as Platform | "") ?? "") as Platform | "",
  );
  const [source, setSource] = useState<EventSource | "">(
    ((searchParams.get("source") as EventSource | "") ?? (saved?.source as EventSource | "") ?? "") as EventSource | "",
  );
  const [q, setQ] = useState(initialQ || saved?.q || "");
  const [submittedQ, setSubmittedQ] = useState(initialQ || saved?.q || "");
  const [pidInput, setPidInput] = useState((initialPids.length ? initialPids : (saved?.pids ?? [])).join(","));
  const [submittedPids, setSubmittedPids] = useState<number[]>(initialPids.length ? initialPids : (saved?.pids ?? []));
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<EventFeedEvent | null>(null);
  const [live, setLive] = useState(true);
  const [exportError, setExportError] = useState<string | null>(null);
  const [scopePlatform, setScopePlatform] = useState<"all" | "windows" | "linux">("all");
  // The Event Log displays all active telemetry sources by default with
  // distinct provenance badges (Live Host, Simulation, Sandbox Detonation).
  const [showSynthetic, setShowSynthetic] = useState(() => {
    try {
      return localStorage.getItem("outpost-events-synthetic") !== "0";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("outpost-events-synthetic", showSynthetic ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [showSynthetic]);
  // View mode — flat minute-grouped timeline, or Event-Viewer-style process
  // chains (collapsible per-process nodes, Sysmon View's grouping trick).
  const [view, setView] = useState<"timeline" | "process">("timeline");
  const [collapsedPids, setCollapsedPids] = useState<Set<number>>(new Set());
  // Live auto-scroll: the feed is newest-first (the backend orders by
  // timestamp DESC), so 'latest' is the TOP of the page. While following
  // (pinned to the top), new events scroll into view; scrolling down pauses
  // the jump and accumulates a 'N new events' pill to get back to latest.
  const [atTop, setAtTop] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const lastTotalRef = useRef(0);
  const [mainTab, setMainTab] = useState<"stream" | "fleet" | "forensics">(() => (searchParams.get("tab") as any) || "stream");
  const [forensicsSubView, setForensicsSubView] = useState<"cockpit" | "processes" | "tree" | "network" | "explanations" | "delta">("cockpit");
  const [forensicsFilter, setForensicsFilter] = useState("");
  const [isCapsuleDiffOpen, setIsCapsuleDiffOpen] = useState(false);

  const { data: forensicsSnapshot, isLoading: isForensicsLoading } = useQuery({
    queryKey: ["forensics", "snapshot"],
    queryFn: getHostXRaySnapshot,
    enabled: mainTab === "forensics",
    refetchInterval: live ? 3_000 : false,
  });

  const { data: treeData } = useQuery({
    queryKey: ["forensics", "tree"],
    queryFn: getProcessTree,
    enabled: mainTab === "forensics" && forensicsSubView === "tree",
    refetchInterval: live ? 4_000 : false,
  });

  const { data: networkMatrixData } = useQuery({
    queryKey: ["forensics", "network"],
    queryFn: getNetworkMatrix,
    enabled: mainTab === "forensics" && forensicsSubView === "network",
    refetchInterval: live ? 4_000 : false,
  });

  const { data: explanationsData } = useQuery({
    queryKey: ["forensics", "explanations"],
    queryFn: getBehavioralExplanations,
    enabled: mainTab === "forensics" && forensicsSubView === "explanations",
    refetchInterval: live ? 4_000 : false,
  });

  const { data: monitorStatus, refetch: refetchMonitorStatus } = useQuery({
    queryKey: ["agents", "local", "status"],
    queryFn: getLocalMonitorStatus,
    refetchInterval: 3_000,
  });

  const isLocalStreaming = monitorStatus?.running ?? false;

  const handleToggleLocalStream = async () => {
    try {
      if (isLocalStreaming) {
        await stopLocalMonitor();
      } else {
        await startLocalMonitor({ interval: 2.0 });
        setLive(true);
      }
      await refetchMonitorStatus();
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["forensics"] });
    } catch (err) {
      console.error("Failed to toggle local monitor:", err);
    }
  };

  // Effective synthetic visibility: only show synthetic events when the user explicitly toggles it
  const includeSynthetic = showSynthetic;
  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["events", category, severity, platform, source, submittedQ, submittedPids.join(","), offset, includeSynthetic],
    queryFn: () =>
      getEvents({
        event_type: category,
        severity,
        platform,
        source,
        q: submittedQ,
        pid: submittedPids.length ? submittedPids.join(",") : undefined,
        include_synthetic: includeSynthetic || undefined,
        limit: PAGE,
        offset,
      }),
    refetchInterval: live ? 1_500 : false,
  });

  // The WHOLE rail from ONE /events/counts query — the old pattern fired a
  // filtered COUNT probe per category badge plus a channel-counts call (7
  // requests per filter change); now it's 1 counts request + the feed.
  // The type buckets honor the active source tab but NOT the active category
  // (each badge counts its own type); the channel buckets are the source
  // split and inherit the category so the rail partitions the feed.
  const countsQuery = useQuery({
    queryKey: ["events", "counts", category, severity, platform, source, submittedQ, submittedPids.join(","), includeSynthetic],
    queryFn: () =>
      getEventCounts({
        event_type: category,
        severity,
        platform,
        source: source || undefined,
        q: submittedQ,
        pid: submittedPids.length ? submittedPids.join(",") : undefined,
        include_synthetic: includeSynthetic || undefined,
      }),
    staleTime: live ? 0 : 10_000,
    refetchInterval: live ? 2_500 : false,
  });
  const channelDesc = [
    severity ? `level: ${severity}` : null,
    platform ? `platform: ${platform}` : null,
    category ? `type: ${category}` : null,
    submittedQ ? `search: “${submittedQ}”` : null,
    submittedPids.length ? `pid: ${submittedPids.join(",")}` : null,
  ]
    .filter(Boolean)
    .join(", ");

  const events = useMemo(() => data?.events ?? [], [data]);
  const total = data?.total ?? 0;

  // Live tail: SSE pushes immediately trigger queries refresh
  useEventStream(
    () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    },
    undefined,
    () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] });
    },
    () => {
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  );

  useEffect(() => {
    setOffset(0);
  }, [category, severity, platform, source, submittedQ, submittedPids]);

  // One-click escape hatch for the whole filter set — the over-filtered
  // "no events match" view must offer it (spec), not just per-dimension
  // unpicking.
  const hasFilters = !!(category || severity || platform || source || submittedQ || submittedPids.length);
  const clearAllFilters = () => {
    setCategory("");
    setSeverity("");
    setPlatform("");
    setSource("");
    setQ("");
    setSubmittedQ("");
    setPidInput("");
    setSubmittedPids([]);
    setSelected(null);
  };

  // Mirror the filter state into the URL (replace: true — bookmarkable and
  // shareable, without spamming history on every tab click) AND into
  // localStorage, so a plain /events visit (no URL params) restores the
  // last-used filter set — an open investigation survives a reload or a
  // mid-session trip to another page. URL params always win when present.
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    const set = (k: string, v: string) => {
      if (v) next.set(k, v);
      else next.delete(k);
    };
    set("type", category);
    set("severity", severity);
    set("platform", platform);
    set("source", source);
    set("q", submittedQ);
    set("pid", submittedPids.join(","));
    setSearchParams(next, { replace: true });
    try {
      localStorage.setItem(
        "outpost-events-filters",
        JSON.stringify({ category, severity, platform, source, q: submittedQ, pids: submittedPids }),
      );
    } catch {
      /* storage unavailable — URL state still applies */
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [category, severity, platform, source, submittedQ, submittedPids.join(",")]);

  // Follow-the-top: the window is the scroll container (desk tool, no inner
  // panel scroll), and the feed is newest-first — 'at the top' means within
  // a hair of the newest events.
  useEffect(() => {
    const onScroll = () => {
      setAtTop(window.scrollY < 140);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Live auto-scroll: new events while following (at the top) stay in view;
  // new events while paused accumulate in the jump-back pill.
  useEffect(() => {
    if (!live) return;
    const prev = lastTotalRef.current;
    lastTotalRef.current = total;
    if (prev <= 0 || total <= prev) return;
    const delta = total - prev;
    if (atTop) {
      setNewCount(0);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
      setNewCount((n) => n + delta);
    }
  }, [total, live, atTop]);

  // Event-Viewer keyboard parity: ↑/↓ move the selection through the current
  // page, Enter expands the selected row, Escape collapses. While typing in a
  // filter field the keys do nothing (never fight form input).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
      if (events.length === 0) return;
      const idx = selected ? events.findIndex((x) => x.id === selected.id && x.run_id === selected.run_id) : -1;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const dir = e.key === "ArrowDown" ? 1 : -1;
        const next =
          idx === -1
            ? events[0]
            : events[Math.min(events.length - 1, Math.max(0, idx + dir))];
        setSelected(next);
        // Scroll the freshly selected row into view (it may be off-screen).
        requestAnimationFrame(() => {
          const el = document.querySelector(
            `button[aria-expanded="true"]`,
          )?.closest("li") as HTMLElement | null;
          el?.scrollIntoView({ block: "nearest", behavior: "smooth" });
        });
      } else if (e.key === "Enter" && idx !== -1) {
        e.preventDefault();
        setSelected(events[idx]); // re-select toggles the inline expansion
      } else if (e.key === "Escape") {
        setSelected(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [events, selected]);

  // Process breadcrumb for pid deep-links: per-pid identity (name + run +
  // platform) derived from the feed rows, plus the base (first matching) row
  // for the run/platform/host line. Works for one pid or a recon list.
  const pidInfo = useMemo(() => {
    if (submittedPids.length === 0) return null;
    const perPid = new Map<number, { name: string | null; runId: string; sample: string }>();
    for (const e of events) {
      if (e.pid !== null && submittedPids.includes(e.pid) && !perPid.has(e.pid)) {
        perPid.set(e.pid, { name: e.process_name ?? null, runId: e.run_id, sample: e.sample_name });
      }
    }
    const base = events.find((e) => e.pid !== null && submittedPids.includes(e.pid)) ?? events[0];
    return {
      perPid,
      base: base ? { runId: base.run_id, sample: base.sample_name, platform: base.platform, host: base.host_id ?? null } : null,
    };
  }, [events, submittedPids]);

  // Group by minute — one visual "burst" per moment, like a real viewer.
  const groups = useMemo(() => {
    const g = new Map<string, EventFeedEvent[]>();
    for (const e of events) {
      const key = e.timestamp.slice(0, 16);
      const arr = g.get(key);
      if (arr) arr.push(e);
      else g.set(key, [e]);
    }
    return [...g.entries()];
  }, [events]);

  // Process column (Event-Viewer parity): the distinct processes on this page
  // with their event counts — click one to jump to everything that PID did.
  const processColumn = useMemo(() => {
    const byPid = new Map<number, { name: string | null; count: number }>();
    for (const e of events) {
      if (e.pid === null || e.pid === undefined) continue;
      const cur = byPid.get(e.pid) ?? { name: e.process_name ?? null, count: 0 };
      cur.count += 1;
      if (!cur.name && e.process_name) cur.name = e.process_name;
      byPid.set(e.pid, cur);
    }
    return [...byPid.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8)
      .map(([pid, info]) => ({ pid, ...info }));
  }, [events]);

  // Process-chain grouping (the Sysmon View trick): one collapsible node per
  // PID with its events in chronological order, newest-first nodes. This is
  // the 'what did this one process do' view — everything it did, side by
  // side, instead of a flat interleaved stream.
  const procGroups = useMemo(() => {
    const byPid = new Map<number, { name: string | null; platform: Platform; events: EventFeedEvent[] }>();
    for (const e of events) {
      if (e.pid === null || e.pid === undefined) continue;
      const cur = byPid.get(e.pid) ?? { name: e.process_name ?? null, platform: e.platform, events: [] };
      if (!cur.name && e.process_name) cur.name = e.process_name;
      cur.events.push(e);
      byPid.set(e.pid, cur);
    }
    return [...byPid.entries()]
      .map(([pid, g]) => ({ pid, ...g, events: [...g.events].sort((a, b) => a.timestamp.localeCompare(b.timestamp)) }))
      .sort((a, b) => b.events[b.events.length - 1].timestamp.localeCompare(a.events[a.events.length - 1].timestamp));
  }, [events]);

  return (
    <div className="mx-auto max-w-[1400px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Workspace · host forensics & telemetry"
        title={
          <>
            Host Forensics & Event Manager <span className="font-normal text-text-muted">— live system telemetry & process inspector</span>
          </>
        }
        lede="Authoritative activity stream across hosts, sessions, and log channels (auditd, Sysmon, eBPF) — with real-time deep process causality, hardware sensor access inspection, and live telemetry feeds."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {/* Stream Local Host Telemetry Button */}
            <button
              onClick={handleToggleLocalStream}
              className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 font-mono text-xs transition-colors duration-150 ${
                isLocalStreaming
                  ? "border-signal/60 bg-signal/15 text-signal font-semibold shadow-[var(--glow-signal)]"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/50 hover:text-accent"
              }`}
              title="Start or stop live in-process local host telemetry collector"
            >
              <span className={`h-1.5 w-1.5 rounded-full ${isLocalStreaming ? "animate-outpost-pulse bg-signal" : "bg-text-faint"}`} />
              {isLocalStreaming ? "Streaming Local Host · Active" : "Stream Local Host"}
            </button>

            <button
              onClick={() =>
                void exportEventsCsv({
                  event_type: category,
                  severity,
                  platform,
                  source,
                  q: submittedQ,
                  pid: submittedPids.length ? submittedPids.join(",") : undefined,
                  include_synthetic: includeSynthetic || undefined,
                })
                  .then((blob) => saveBlob(blob, "outpost-events.csv"))
                  .catch(() => setExportError("CSV export failed — is the backend running?"))
              }
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              title="Download the current filter as CSV"
            >
              <Icon name="download" size={12} />
              Export CSV
            </button>
            <button
              onClick={() => setLive((v) => !v)}
              className={`press inline-flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-xs transition-colors duration-150 ${
                live
                  ? "border-signal/60 bg-signal/10 text-signal shadow-[var(--glow-signal)]"
                  : "border-border-subtle text-text-muted hover:text-text-primary"
              }`}
              aria-pressed={live}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${live ? "animate-outpost-pulse bg-signal" : "bg-text-faint"}`} />
              {live ? "Live · 1.5s refresh" : "Follow live"}
            </button>
          </div>
        }
      />

      {/* Main Workspace Tab Switcher */}
      <div className="mb-6 flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-mono text-xs shadow-sm">
        <button
          onClick={() => setMainTab("stream")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            mainTab === "stream"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="list" size={13} />
          <span>Live Telemetry &amp; Event Stream</span>
        </button>
        <button
          onClick={() => setMainTab("fleet")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            mainTab === "fleet"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="terminal" size={13} />
          <span>Sensor Fleet &amp; Agent Roster</span>
        </button>
        <button
          onClick={() => setMainTab("forensics")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            mainTab === "forensics"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="box" size={13} />
          <span>Deep System Forensics</span>
        </button>
      </div>

      {/* Keyboard parity hints — Event-Viewer style: the log is navigable
          without the mouse. Dismissed permanently once the user presses one
          of the keys, so it never nags a returning analyst. */}
      <KeyboardHints onUsed={() => localStorage.setItem("outpost-events-hints", "1")} />

      {/* Process breadcrumb — makes a ?pid= deep link recognizable on return
          (from History, the Overview findings jump, or a run's alert chip):
          per-pid name chips + run + platform, with a one-click clear. A
          comma-separated pid list (the recon-sweep jump) renders each
          enumerating process as its own chip with a drill-down. */}
      {submittedPids.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-accent">
            <Icon name="process" size={12} />
            {submittedPids.length === 1 ? `Process ${submittedPids[0]}` : `Processes (${submittedPids.length})`}
          </span>
          {submittedPids.map((pid) => {
            const info = pidInfo?.perPid.get(pid);
            return (
              <span
                key={pid}
                className="inline-flex items-center gap-1.5 rounded border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 font-mono text-[11px] text-text-primary"
              >
                pid {pid}
                {info?.name && <span className="text-text-muted">{info.name}</span>}
                {submittedPids.length > 1 && (
                  <button
                    onClick={() => setSubmittedPids([pid])}
                    className="press text-text-faint transition-colors hover:text-accent"
                    title="Only this process"
                    aria-label={`Filter to process ${pid} only`}
                  >
                    <Icon name="x" size={9} />
                  </button>
                )}
              </span>
            );
          })}
          {pidInfo?.base && (
            <Link
              to={`/runs/${pidInfo.base.runId}`}
              className="press inline-flex items-center gap-1 font-mono text-[11px] text-text-muted transition-colors hover:text-accent"
              title="Open the run these processes belong to"
            >
              {pidInfo.base.sample}
              <Icon name="external" size={10} className="opacity-60" />
            </Link>
          )}
          {pidInfo?.base && (
            <span className="inline-flex items-center gap-1 rounded-full border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-muted">
              <Icon name={platformIconName(pidInfo.base.platform)} size={10} />
              {pidInfo.base.platform}
            </span>
          )}
          {pidInfo?.base?.host && <span className="font-mono text-[10px] text-text-faint">host {pidInfo.base.host}</span>}
          <span className="ml-auto font-mono text-[10px] text-text-faint">
            {total} event{total === 1 ? "" : "s"} for {submittedPids.length === 1 ? "this process" : "these processes"}
          </span>
          <button
            onClick={() => {
              setSubmittedPids([]);
              setPidInput("");
            }}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors hover:border-accent/50 hover:text-accent"
            aria-label="Clear process filter"
          >
            <Icon name="x" size={10} />
            clear
          </button>
        </div>
      )}

      {mainTab === "fleet" ? (
        /* ── Sensor Fleet & Agent Roster View ─────────────────────────── */
        <AgentsPage />
      ) : mainTab === "forensics" ? (
        /* ── Deep Host Forensics View ──────────────────────────────────── */
        <div className="space-y-6">
          {/* Host Pulse Metrics */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">Host Platform</span>
              <div className="mt-1 flex items-center gap-2 font-mono text-sm font-bold text-text-primary">
                <Icon name={platformIconName(forensicsSnapshot?.metrics?.platform || "linux")} size={16} />
                <span className="capitalize">{forensicsSnapshot?.metrics?.platform || "Linux"} Host</span>
              </div>
            </div>

            <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">CPU Pulse</span>
              <div className="mt-1 flex items-center justify-between font-mono text-sm font-bold text-text-primary">
                <span>{forensicsSnapshot?.metrics?.cpu_percent ?? 0}%</span>
                <span className="text-[10px] text-text-muted">utilization</span>
              </div>
            </div>

            <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">Memory Active</span>
              <div className="mt-1 flex items-center justify-between font-mono text-sm font-bold text-text-primary">
                <span>{forensicsSnapshot?.metrics?.memory_used_mb ?? 0} MB</span>
                <span className="text-[10px] text-text-muted">/ {forensicsSnapshot?.metrics?.memory_total_mb ?? 0} MB</span>
              </div>
            </div>

            <div className="rounded-2xl border border-border-subtle bg-bg-surface/80 p-4 shadow-sm backdrop-blur-sm">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">Active System Footprint</span>
              <div className="mt-1 flex items-center justify-between font-mono text-sm font-bold text-text-primary">
                <span>{forensicsSnapshot?.process_count ?? 0} procs</span>
                <span className="text-[10px] text-text-muted">{forensicsSnapshot?.socket_count ?? 0} sockets</span>
              </div>
            </div>
          </div>

          {/* Forensics Sub-View Navigation Bar */}
          <div className="flex flex-wrap items-center justify-between border-b border-border-subtle bg-bg-surface px-2 gap-2">
            <div className="flex flex-wrap gap-2">
              {[
                { k: "cockpit", label: "Command Cockpit", icon: "box" },
                { k: "processes", label: `Live Processes (${forensicsSnapshot?.processes?.length ?? 0})`, icon: "process" },
                { k: "tree", label: `Causality Tree (${treeData?.length ?? 0} roots)`, icon: "list" },
                { k: "network", label: `Network Threat Matrix (${networkMatrixData?.summary?.total_sockets ?? forensicsSnapshot?.socket_count ?? 0})`, icon: "network" },
                { k: "explanations", label: `Behavioral Insights (${explanationsData?.length ?? 0})`, icon: "alert" },
                { k: "delta", label: "Differential Delta", icon: "zap" },
              ].map((sub) => (
                <button
                  key={sub.k}
                  onClick={() => setForensicsSubView(sub.k as any)}
                  className={`flex items-center gap-2 border-b-2 px-4 py-3 font-mono text-xs font-semibold transition-colors ${
                    forensicsSubView === sub.k
                      ? "border-accent text-accent"
                      : "border-transparent text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name={sub.icon as any} size={14} />
                  {sub.label}
                </button>
              ))}
            </div>
          </div>

          {/* SubView: Command Cockpit */}
          {forensicsSubView === "cockpit" && (
            <HostForensicsCockpit onInspectExternalPid={(pid: number) => setInspectPid(pid)} />
          )}

          {/* SubView: Process Table */}
          {forensicsSubView === "processes" && (
            <div className="space-y-6">
              {/* Universal Search Bar */}
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-4 rounded-xl border border-border-subtle bg-bg-surface p-3 font-mono text-xs">
                  <div className="relative flex-1">
                    <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
                    <input
                      type="text"
                      value={forensicsFilter}
                      onChange={(e) => setForensicsFilter(e.target.value)}
                      placeholder="Universal Target Resolver: filter by :port, pid:123, file:/path, service:name, or keyword..."
                      className="w-full rounded-lg border border-border-subtle bg-bg-base py-2 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                    />
                  </div>
                  <span className="text-text-faint text-[11px] shrink-0">
                    {isForensicsLoading ? "Scanning live system..." : "Live procfs & socket telemetry"}
                  </span>
                </div>

                {/* Quick Syntax Chips */}
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px] text-text-faint px-1">
                  <span>Quick targets:</span>
                  {[
                    { label: ":8000 (Port)", val: ":8000" },
                    { label: "pid:1", val: "pid:1" },
                    { label: "service:systemd", val: "service:systemd" },
                    { label: "file:/tmp", val: "file:/tmp" },
                    { label: "python", val: "python" },
                  ].map((chip) => (
                    <button
                      key={chip.val}
                      onClick={() => setForensicsFilter(chip.val)}
                      className="rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-text-muted hover:border-accent/50 hover:text-accent"
                    >
                      {chip.label}
                    </button>
                  ))}
                  {forensicsFilter && (
                    <button
                      onClick={() => setForensicsFilter("")}
                      className="ml-auto text-[10px] text-text-faint hover:text-accent"
                    >
                      Clear filter
                    </button>
                  )}
                </div>
              </div>

              {/* Active Processes Table */}
              <div className="panel overflow-hidden p-0">
                <div className="border-b border-border-subtle bg-bg-elevated/40 px-5 py-3 flex items-center justify-between font-mono text-xs">
                  <span className="font-bold text-text-primary flex items-center gap-2">
                    <Icon name="process" size={14} className="text-accent" />
                    Live Running Processes ({forensicsSnapshot?.processes?.length ?? 0})
                  </span>
                  <span className="text-[11px] text-text-faint">Click any row to open full Process Inspector</span>
                </div>

                <div className="overflow-x-auto max-h-[500px]">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                      <tr>
                        <th className="p-3">PID</th>
                        <th className="p-3">Process Name</th>
                        <th className="p-3">Security Posture</th>
                        <th className="p-3">Memory RSS</th>
                        <th className="p-3">CPU %</th>
                        <th className="p-3">User</th>
                        <th className="p-3">Command Line</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle">
                      {(forensicsSnapshot?.processes || [])
                        .filter((p) => {
                          if (!forensicsFilter) return true;
                          const q = forensicsFilter.toLowerCase();
                          return (
                            p.name.toLowerCase().includes(q) ||
                            p.cmdline.toLowerCase().includes(q) ||
                            p.user.toLowerCase().includes(q) ||
                            `pid:${p.pid}`.includes(q) ||
                            String(p.pid).includes(q)
                          );
                        })
                        .map((p) => (
                          <tr
                            key={p.pid}
                            onClick={() => setInspectPid(p.pid)}
                            className="cursor-pointer hover:bg-accent/5 transition-colors"
                          >
                            <td className="p-3 font-bold text-accent">{p.pid}</td>
                            <td className="p-3 font-semibold text-text-primary flex items-center gap-2">
                              <Icon name="process" size={12} className="text-text-faint" />
                              {p.name}
                            </td>
                            <td className="p-3">
                              {p.package_label ? (
                                <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${
                                  p.package_status === "managed_package" || p.package_status === "system_binary"
                                    ? "bg-accent/10 text-accent"
                                    : "bg-risk-suspicious/15 text-risk-suspicious"
                                }`}>
                                  {p.package_label}
                                </span>
                              ) : (
                                <span className="text-[10px] text-text-faint font-mono">Standard</span>
                              )}
                            </td>
                            <td className="p-3 text-text-muted">{p.memory_mb} MB</td>
                            <td className="p-3 text-text-muted">{p.cpu_percent}%</td>
                            <td className="p-3 text-text-faint">{p.user}</td>
                            <td className="p-3 max-w-[280px] truncate text-text-faint" title={p.cmdline}>
                              {p.cmdline || "—"}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Active Network Sockets Table */}
              <div className="panel overflow-hidden p-0">
                <div className="border-b border-border-subtle bg-bg-elevated/40 px-5 py-3 flex items-center justify-between font-mono text-xs">
                  <span className="font-bold text-text-primary flex items-center gap-2">
                    <Icon name="network" size={14} className="text-accent" />
                    Live Network Sockets &amp; Ports ({forensicsSnapshot?.sockets?.length ?? 0})
                  </span>
                  <span className="text-[11px] text-text-faint">Listening daemons and active remote connections</span>
                </div>

                <div className="overflow-x-auto max-h-[400px]">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                      <tr>
                        <th className="p-3">Protocol</th>
                        <th className="p-3">Local Address : Port</th>
                        <th className="p-3">Remote Address</th>
                        <th className="p-3">State</th>
                        <th className="p-3">Bound Process</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle">
                      {(forensicsSnapshot?.sockets || [])
                        .filter((s) => {
                          if (!forensicsFilter) return true;
                          const q = forensicsFilter.toLowerCase();
                          return (
                            s.local_ip.toLowerCase().includes(q) ||
                            (s.remote_ip && s.remote_ip.toLowerCase().includes(q)) ||
                            (s.process_name && s.process_name.toLowerCase().includes(q)) ||
                            (s.pid && String(s.pid).includes(q)) ||
                            `:${s.local_port}`.includes(q)
                          );
                        })
                        .map((s, idx) => (
                          <tr key={idx} className="hover:bg-accent/5 transition-colors">
                            <td className="p-3 uppercase text-[10px] font-bold text-accent">{s.protocol}</td>
                            <td className="p-3 font-semibold text-text-primary">
                              {s.local_ip}:{s.local_port}
                            </td>
                            <td className="p-3">
                              {s.remote_ip ? (
                                <button
                                  onClick={() => setInspectIp(s.remote_ip!)}
                                  className="inline-flex items-center gap-1.5 text-accent hover:underline"
                                >
                                  <Icon name="network" size={11} />
                                  {s.remote_ip}:{s.remote_port}
                                </button>
                              ) : (
                                <span className="text-text-faint">*</span>
                              )}
                            </td>
                            <td className="p-3">
                              <span
                                className={`rounded px-1.5 py-0.5 text-[9px] uppercase font-bold ${
                                  s.status === "LISTEN"
                                    ? "bg-accent/10 text-accent border border-accent/30"
                                    : s.status === "ESTABLISHED"
                                      ? "bg-signal/10 text-signal border border-signal/30"
                                      : "bg-bg-elevated text-text-muted"
                                }`}
                              >
                                {s.status}
                              </span>
                            </td>
                            <td className="p-3">
                              {s.pid ? (
                                <button
                                  onClick={() => setInspectPid(s.pid!)}
                                  className="inline-flex items-center gap-1.5 text-accent hover:underline"
                                >
                                  <Icon name="process" size={11} />
                                  {s.process_name || `PID ${s.pid}`}
                                </button>
                              ) : (
                                <span className="text-text-faint">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* SubView: Process Causality Tree */}
          {forensicsSubView === "tree" && (
            <ProcessTreeGraph
              tree={treeData || []}
              onInspect={(pid) => setInspectPid(pid)}
            />
          )}

          {/* SubView: Network Threat Matrix */}
          {forensicsSubView === "network" && (
            <NetworkMatrixView
              matrix={
                networkMatrixData || {
                  public_listeners: [],
                  loopback_listeners: [],
                  outbound_connections: [],
                  multicast_listeners: [],
                  summary: {
                    public_listeners_count: 0,
                    loopback_listeners_count: 0,
                    outbound_count: 0,
                    multicast_count: 0,
                    total_sockets: 0,
                  },
                }
              }
              onInspectPid={(pid) => setInspectPid(pid)}
            />
          )}

          {/* SubView: Behavioral Insights */}
          {forensicsSubView === "explanations" && (
            <BehavioralExplanationsView
              explanations={explanationsData || []}
            />
          )}

          {/* SubView: Differential Delta */}
          {forensicsSubView === "delta" && (
            <DifferentialSnapshotView
              onSelectProcess={(pid) => setInspectPid(pid)}
            />
          )}
        </div>
      ) : (
      <div className="grid gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
        {/* ── Log channels rail ─────────────────────────────────────────── */}
        <aside className="panel h-fit p-2 lg:sticky lg:top-20">
          <p className="kicker px-2 pb-2 pt-1">Log channels</p>
          <ul className="space-y-0.5">
            {CATEGORIES.map((c) => (
              <li key={c.type || "all"}>
                <button
                  onClick={() => {
                    setCategory(c.type);
                    setSelected(null);
                  }}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors duration-150 ${
                    category === c.type
                      ? "bg-accent/10 font-semibold text-accent"
                      : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                  }`}
                >
                  <Icon name={c.icon} size={15} />
                  <span className="flex-1 truncate">{c.label}</span>
                  <CountBadge
                    type={c.type}
                    source={source}
                    severity={severity}
                    platform={platform}
                    q={submittedQ}
                    pids={submittedPids}
                    count={countsQuery.data ? (countsQuery.data.types as Record<string, number>)[c.type === "" ? "all" : c.type] : undefined}
                  />
                </button>
              </li>
            ))}
          </ul>

          {/* Process column — every process on this page with its event count;
              click to jump to everything that PID did (Event-Viewer parity). */}
          {processColumn.length > 0 && (
            <>
              <p className="kicker px-2 pb-2 pt-4">Processes · this page</p>
              <ul className="space-y-0.5">
                {processColumn.map(({ pid, name, count }) => (
                  <li key={pid}>
                    <button
                      onClick={() => {
                        setPidInput(String(pid));
                        setSubmittedPids([pid]);
                        setSelected(null);
                      }}
                      className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left transition-colors duration-150 ${
                        submittedPids.includes(pid)
                          ? "bg-accent/10 text-accent"
                          : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                      }`}
                      title={`Everything process ${pid} did (${count} event${count === 1 ? "" : "s"} on this page)`}
                    >
                      <Icon name="process" size={13} />
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px]">
                        {name ?? `pid ${pid}`}
                      </span>
                      <span className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 py-px font-mono text-[9px] tabular-nums text-text-faint">
                        {count}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </aside>

        {/* ── Timeline ──────────────────────────────────────────────────── */}
        <section className="min-w-0">
          {/* Structured 2-tier filter toolbar */}
          <div className="mb-5 space-y-2.5">
            {/* Tier 1: Provenance & Log Channel Sources */}
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border-subtle bg-bg-surface/60 p-2 backdrop-blur-sm">
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by source">
                <span className="px-2 font-mono text-[10px] uppercase tracking-wider text-text-faint">Source:</span>
                {SOURCE_TABS.map((s) => (
                  <button
                    key={s.v || "all"}
                    onClick={() => setSource(s.v)}
                    className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                      source === s.v
                        ? "bg-accent/15 font-semibold text-accent shadow-[var(--glow-accent)]"
                        : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                    }`}
                    title={
                      s.v === "live"
                        ? "Host collectors (auditd + Sysmon combined) — real telemetry"
                        : s.v === "auditd"
                          ? "The Linux collector's auditd stream"
                          : s.v === "sysmon"
                            ? "The Windows collector's Sysmon stream"
                            : s.v === "sandbox"
                              ? "External-sandbox detonations"
                              : "Everything the webapp produced (synthetic detonations, CLI, seeds)"
                    }
                  >
                    <Icon name={s.icon} size={11} />
                    {s.label}
                    <span
                      className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 py-px font-mono text-[10px] tabular-nums text-text-faint"
                      title={channelDesc || "no active filters"}
                    >
                      {s.v === "" ? (countsQuery.data?.channels.total ?? "…") : (countsQuery.data?.channels[s.v] ?? "…")}
                    </span>
                  </button>
                ))}
              </div>

              {source === "" && (
                <button
                  onClick={() => setShowSynthetic((v) => !v)}
                  aria-pressed={showSynthetic}
                  title={
                    showSynthetic
                      ? "Hide demo/synthetic events again (seeds, webapp detonations, sandbox demo)"
                      : "Include events from seeded demo runs and webapp-synthetic detonations"
                  }
                  className={`press rounded-lg border px-2.5 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                    showSynthetic ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle text-text-faint hover:text-text-primary"
                  }`}
                >
                  {showSynthetic ? "Show synthetic · on" : "Show synthetic"}
                </button>
              )}
            </div>

            {/* Tier 2: Activity Presets, Severity, Platform & Search */}
            <div className="flex flex-wrap items-center gap-2">
              {/* Focus presets */}
              <div className="flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface p-1" role="group" aria-label="Focus preset">
                {FOCUS_PRESETS.map((p) => (
                  <button
                    key={p.label}
                    onClick={() => setCategory(p.type)}
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-1 font-mono text-[10px] transition-colors duration-150 ${
                      category === p.type
                        ? "bg-accent/10 font-medium text-accent"
                        : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                    }`}
                    title={`${p.label} — one-click focus`}
                  >
                    <Icon name={p.icon} size={10} />
                    {p.label}
                  </button>
                ))}
              </div>

              {/* View mode */}
              <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle bg-bg-surface" role="group" aria-label="View mode">
                {(
                  [
                    { v: "timeline", label: "Timeline" },
                    { v: "process", label: "By process" },
                  ] as { v: "timeline" | "process"; label: string }[]
                ).map((m) => (
                  <button
                    key={m.v}
                    onClick={() => setView(m.v)}
                    className={`px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                      view === m.v
                        ? "bg-accent/10 font-medium text-accent"
                        : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                    }`}
                    title={m.v === "process" ? "Group this page's events into one collapsible node per process" : "Flat chronological timeline, grouped by minute"}
                  >
                    {m.label}
                  </button>
                ))}
              </div>

              {/* Severity Level */}
              <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle bg-bg-surface" role="group" aria-label="Filter by level">
                {(
                  [
                    { v: "", label: "All" },
                    { v: "suspicious", label: "Warning" },
                    { v: "malicious", label: "Error" },
                  ] as { v: Severity | ""; label: string }[]
                ).map((lvl) => (
                  <button
                    key={lvl.v || "all"}
                    onClick={() => setSeverity(lvl.v)}
                    className={`px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                      severity === lvl.v
                        ? "bg-accent/10 font-medium text-accent"
                        : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                    }`}
                  >
                    {lvl.label}
                  </button>
                ))}
              </div>

              {/* Platform */}
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value as Platform | "")}
                className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
                aria-label="Filter by platform"
              >
                <option value="">All platforms</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
              </select>

              <form
                className="ml-auto flex items-center gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  setSubmittedQ(q.trim());
                  setSubmittedPids(parsePids(pidInput));
                }}
              >
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search process, path, IP, cmd…"
                  className="w-48 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
                  aria-label="Search events"
                />
                <input
                  value={pidInput}
                  onChange={(e) => setPidInput(e.target.value)}
                  placeholder="pid"
                  inputMode="numeric"
                  className="w-16 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
                  aria-label="Filter by process PID"
                  title="Filter to one process — everything this PID did"
                />
                <button
                  type="submit"
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                >
                  <Icon name="search" size={12} />
                  Search
                </button>
                {hasFilters && (
                  <button
                    type="button"
                    onClick={clearAllFilters}
                    className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-[11px] text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                    title="Clear every filter"
                  >
                    <Icon name="x" size={11} />
                    Clear
                  </button>
                )}
              </form>
            </div>

            {/* Quick query filter pills for rapid forensic scoping */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5 font-mono text-[10px]">
                <button
                  type="button"
                  onClick={() => setScopePlatform("all")}
                  className={`rounded px-1.5 py-0.5 transition ${scopePlatform === "all" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"}`}
                >
                  All Fleet
                </button>
                <button
                  type="button"
                  onClick={() => setScopePlatform("windows")}
                  className={`rounded px-1.5 py-0.5 transition ${scopePlatform === "windows" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"}`}
                >
                  Windows
                </button>
                <button
                  type="button"
                  onClick={() => setScopePlatform("linux")}
                  className={`rounded px-1.5 py-0.5 transition ${scopePlatform === "linux" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"}`}
                >
                  Linux
                </button>
              </div>

              {(scopePlatform === "windows"
                ? [
                    { label: "user:SYSTEM", q: "user:SYSTEM" },
                    { label: "powershell", q: "powershell" },
                    { label: "vssadmin", q: "vssadmin" },
                    { label: "certutil", q: "certutil" },
                    { label: "reg:Run", q: "CurrentVersion\\Run" },
                    { label: "event:sysmon", q: "sysmon" },
                    { label: "lsass", q: "lsass" },
                  ]
                : scopePlatform === "linux"
                ? [
                    { label: "user:root", q: "user:root" },
                    { label: "dev:mic", q: "dev:mic" },
                    { label: "state:deleted", q: "state:deleted" },
                    { label: "memfd", q: "memfd" },
                    { label: "cmd:curl", q: "curl" },
                    { label: "port :443", q: ":443" },
                    { label: "/etc/shadow", q: "/etc/shadow" },
                  ]
                : [
                    { label: "port :443", q: ":443" },
                    { label: "user:root", q: "user:root" },
                    { label: "user:SYSTEM", q: "user:SYSTEM" },
                    { label: "powershell", q: "powershell" },
                    { label: "cmd:curl", q: "curl" },
                    { label: "mimikatz", q: "mimikatz" },
                    { label: "c2-beacon", q: "beacon" },
                  ]
              ).map((pill) => (
                <button
                  key={pill.label}
                  type="button"
                  onClick={() => {
                    setQ(pill.q);
                    setSubmittedQ(pill.q);
                  }}
                  className={`rounded-md border px-2 py-0.5 font-mono text-[10px] transition-colors ${
                    submittedQ === pill.q
                      ? "border-accent bg-accent/15 font-semibold text-accent"
                      : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/50 hover:text-text-primary"
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>
          </div>

          <p className="mb-3 font-mono text-[11px] text-text-faint">
            {isLoading ? "Loading events…" : `${total} event${total === 1 ? "" : "s"} · showing ${offset + 1}–${Math.min(offset + PAGE, total)}`}
            {isFetching && " · refreshing…"}
            {live && " · live"}
            {exportError && <span className="text-risk-malicious"> · {exportError}</span>}
          </p>

          {isError && (
            <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
              Couldn't load events — is the OutPost backend running?
            </p>
          )}

          {!isError && events.length === 0 && !isLoading && (
            <div className="rounded-xl border border-dashed border-border-strong bg-bg-surface/50 p-14 text-center">
              <Icon name="list" size={28} className="mx-auto text-text-faint" />
              <p className="mt-3 text-sm text-text-muted">
                {hasFilters || submittedPids.length > 0
                  ? "No events match these filters."
                  : "No events recorded yet. Connect a collector agent or start a live monitor session to stream system telemetry."}
              </p>
              <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
                {hasFilters && (
                  <button
                    onClick={clearAllFilters}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10"
                  >
                    <Icon name="x" size={11} />
                    Clear all filters
                  </button>
                )}
                {submittedPids.length > 0 && (
                  <button
                    onClick={() => {
                      setSubmittedPids([]);
                      setPidInput("");
                    }}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-accent/50 hover:text-accent"
                  >
                    <Icon name="x" size={11} />
                    Clear pid {submittedPids.join(", ")} filter
                  </button>
                )}
              </div>
            </div>
          )}

          {isLoading && (
            <div className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="skeleton h-14 w-full" />
              ))}
            </div>
          )}

          {events.length > 0 && (
            <div className="space-y-6">
              {view === "timeline" ? (
                <div className="space-y-6">
                  {groups.map(([minute, list]) => (
                    <div key={minute}>
                      <div className="mb-2 flex items-center gap-2">
                        <span className="rounded-md border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] tabular-nums text-text-muted">
                          {minute.slice(5).replace("T", " ")}
                        </span>
                        <span className="h-px flex-1 bg-border-subtle" aria-hidden />
                        <span className="font-mono text-[10px] text-text-faint">{list.length}</span>
                      </div>
                      <ul className="space-y-1.5">
                        {list.map((e) => (
                          <EventRow
                            key={`${e.id}-${e.run_id}-${e.timestamp}`}
                            e={e}
                            active={selected?.id === e.id}
                            onSelect={setSelected}
                            onFilterPid={(pid) => {
                              setPidInput(String(pid));
                              setSubmittedPids([pid]);
                              setSelected(null);
                            }}
                            onInspectProcess={setInspectPid}
                            onInspectNetwork={setInspectIp}
                          />
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="space-y-3">
                  {procGroups.map(({ pid, name, platform: plat, events: evs }) => {
                    const collapsed = collapsedPids.has(pid);
                    const pinned = submittedPids.includes(pid);
                    return (
                      <div
                        key={pid}
                        className={`overflow-hidden rounded-xl border transition-colors duration-150 ${
                          pinned ? "border-accent/50 shadow-[var(--glow-accent)]" : "border-border-subtle"
                        }`}
                      >
                        {/* Node header — a flex row of sibling buttons (never
                            nested interactive elements). */}
                        <div className="flex items-center gap-2 bg-bg-surface px-3 py-2.5">
                          <button
                            onClick={() =>
                              setCollapsedPids((cur) => {
                                const n = new Set(cur);
                                if (n.has(pid)) n.delete(pid);
                                else n.add(pid);
                                return n;
                              })
                            }
                            className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
                            aria-expanded={!collapsed}
                            title={collapsed ? "Expand this process" : "Collapse this process"}
                          >
                            <Icon name={collapsed ? "chevronRight" : "chevronDown"} size={13} className="shrink-0 text-text-faint" />
                            <Icon name="process" size={14} className="shrink-0 text-accent" />
                            <span className="truncate font-mono text-xs font-semibold text-text-primary">
                              {name ?? `pid ${pid}`}
                            </span>
                            <span className="font-mono text-[10px] text-text-faint">pid {pid}</span>
                            <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-border-subtle px-1.5 py-px font-mono text-[9px] text-text-muted">
                              <Icon name={platformIconName(plat)} size={9} />
                              {plat}
                            </span>
                            <span className="ml-auto font-mono text-[10px] tabular-nums text-text-faint">
                              {evs.length} event{evs.length === 1 ? "" : "s"}
                            </span>
                          </button>
                          {pinned ? (
                            <button
                              onClick={() => {
                                setSubmittedPids([]);
                                setPidInput("");
                              }}
                              className="press inline-flex shrink-0 items-center gap-1 rounded border border-accent/50 bg-accent/10 px-2 py-1 font-mono text-[10px] text-accent transition-colors duration-150 hover:bg-accent/15"
                              title="Pinned — everything this process did. Click to unpin."
                            >
                              <Icon name="flag" size={9} />
                              pinned
                            </button>
                          ) : (
                            <button
                              onClick={() => {
                                setPidInput(String(pid));
                                setSubmittedPids([pid]);
                              }}
                              className="press inline-flex shrink-0 items-center gap-1 rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                              title="Pin — jump to everything this process did (survives live refreshes)"
                            >
                              <Icon name="flag" size={9} />
                              pin
                            </button>
                          )}
                        </div>
                        {!collapsed && (
                          <ul className="space-y-1.5 border-t border-border-subtle/60 bg-bg-base/40 px-3 py-3">
                            {evs.map((e) => (
                              <EventRow
                                key={`${e.id}-${e.run_id}-${e.timestamp}`}
                                e={e}
                                active={selected?.id === e.id}
                                onSelect={setSelected}
                                onFilterPid={(pid) => {
                                  setPidInput(String(pid));
                                  setSubmittedPids([pid]);
                                  setSelected(null);
                                }}
                                onInspectProcess={setInspectPid}
                                onInspectNetwork={setInspectIp}
                              />
                            ))}
                          </ul>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Pagination */}
              <div className="flex items-center justify-between border-t border-border-subtle pt-4">
                <span className="font-mono text-[10px] text-text-faint">
                  {platform === "" && category === "" ? "all channels" : platform || category || "filtered"}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setOffset((o) => Math.max(0, o - PAGE))}
                    disabled={offset === 0}
                    className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 enabled:hover:border-accent/60 enabled:hover:text-accent disabled:opacity-40"
                  >
                    <Icon name="chevronRight" size={11} className="rotate-180" />
                    Newer
                  </button>
                  <button
                    onClick={() => setOffset((o) => o + PAGE)}
                    disabled={offset + PAGE >= total}
                    className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 enabled:hover:border-accent/60 enabled:hover:text-accent disabled:opacity-40"
                  >
                    Older
                    <Icon name="chevronRight" size={11} />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Jump-back pill — new events landed while the analyst scrolled up
              (live pause-on-manual-scroll). One click returns to the newest. */}
          {newCount > 0 && live && (
            <button
              onClick={() => {
                setNewCount(0);
                window.scrollTo({ top: 0, behavior: "smooth" });
              }}
              className="press fixed bottom-6 right-6 z-30 inline-flex items-center gap-2 rounded-full border border-accent/60 bg-bg-surface px-4 py-2.5 font-mono text-xs font-medium text-accent shadow-[var(--shadow-raised)] transition-all duration-150 hover:shadow-[var(--glow-accent)] print:hidden"
              title="Jump back to the newest events"
            >
              <Icon name="arrowRight" size={12} className="rotate-90" />
              {newCount} new event{newCount === 1 ? "" : "s"} — jump to latest
            </button>
          )}
        </section>
      </div>
      )}

      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}

      <CapsuleDiffModal
        isOpen={isCapsuleDiffOpen}
        onClose={() => setIsCapsuleDiffOpen(false)}
      />
    </div>
  );
}
