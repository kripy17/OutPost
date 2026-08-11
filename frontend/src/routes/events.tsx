import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { EVENT_ICON, platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import { exportEventsCsv, getEvents, saveBlob } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { resolveSavedFilters, type SavedFilters } from "./eventsHelpers";
import type { EventFeedEvent, EventSource, EventType, Platform, Severity } from "../types";

const PAGE = 60;

/** Parse the `pid` URL/filter value — one integer or a comma-separated list
 *  (the recon-sweep jump: every enumerating PID at once). Invalid tokens are
 *  dropped silently; the backend 422s on genuinely bad input. */
function parsePids(raw: string | null): number[] {
  if (!raw) return [];
  const out: number[] = [];
  for (const token of raw.split(",")) {
    const n = Number(token.trim());
    if (Number.isInteger(n) && n > 0 && !out.includes(n)) out.push(n);
  }
  return out;
}

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
  const rows: [string, string][] = [
    ["Event type", event.event_type.replace("_", " ")],
    ["Timestamp", event.timestamp],
    ["Host", event.host_id ?? "local"],
    ["Sample", event.sample_name],
    ["Run", event.run_id],
    ["PID", String(event.pid ?? "—")],
    ["PPID", String(event.ppid ?? "—")],
    ["Process", event.process_name ?? "—"],
    ["Command line", event.command_line ?? "—"],
    ["Dest IP", event.dest_ip ?? "—"],
    ["Dest port", String(event.dest_port ?? "—")],
    ["Protocol", event.protocol ?? "—"],
    ["File path", event.file_path ?? "—"],
    ["Registry key", event.registry_key ?? "—"],
  ];
  return (
    <dl className="space-y-3 border-t border-border-subtle pt-4 font-mono text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="flex gap-3">
          <dt className="w-24 shrink-0 text-text-faint">{k}</dt>
          <dd className="min-w-0 break-words text-text-primary">{v}</dd>
        </div>
      ))}
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
  live,
  severity,
  platform,
  q,
  pids,
  includeSynthetic,
}: {
  type: EventType | "";
  source: EventSource | "";
  live: boolean;
  severity: Severity | "";
  platform: Platform | "";
  q: string;
  pids: number[];
  includeSynthetic: boolean;
}) {
  const { data } = useQuery({
    queryKey: ["events", "count", type, severity, platform, source, q, pids.join(","), includeSynthetic],
    queryFn: () =>
      getEvents({
        event_type: type || undefined,
        severity,
        platform,
        source: source || undefined,
        q,
        pid: pids.length ? pids.join(",") : undefined,
        include_synthetic: includeSynthetic || undefined,
        limit: 1,
      }),
    staleTime: live ? 0 : 15_000,
    refetchInterval: live ? 5_000 : false,
  });

  // Build a concise summary of active filters — the badge already shows the
  // count, so the tooltip explains *why* the count is what it is.
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
      {data?.total ?? "…"}
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
}: {
  e: EventFeedEvent;
  active: boolean;
  onSelect: (e: EventFeedEvent | null) => void;
  onFilterPid?: (pid: number) => void;
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
          <span className="inline-flex items-center gap-1 font-mono">
            <Icon name="terminal" size={10} className="opacity-60" />
            {e.host_id ?? "local"}
          </span>
          <Link
            to={`/runs/${e.run_id}`}
            className="inline-flex items-center gap-1 font-mono font-medium text-accent hover:underline"
          >
            {e.sample_name}
            <Icon name="external" size={10} className="opacity-60" />
          </Link>
        </div>

        {/* Inline expansion — the full raw record, unfolded under the row
            (Event-Viewer parity: click a row, read everything it carried).
            The summary stays above; this adds the complete field set, the
            process drill-down, and the collector's original payload. */}
        {active && (
          <div className="border-t border-border-subtle bg-bg-base/40 px-5 py-4">
            <div className="mb-4 flex items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${lvl.badge}`}>
                <Icon name={lvl.icon} size={12} />
                {lvl.label}
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted">
                <Icon name={platformIconName(e.platform)} size={12} />
                {e.platform}
              </span>
            </div>

            <EventFields event={e} />

            {/* Process-centric drill-down: jump from one record to everything
                this PID did across the feed. */}
            {e.pid && (
              <button
                onClick={() => onFilterPid?.(e.pid as number)}
                className="press mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              >
                <Icon name="process" size={12} />
                Show everything this process did (pid {e.pid})
              </button>
            )}

            {/* Raw record — the collector's original payload, side by side
                with the normalized row (auditd/Sysmon line parity). */}
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
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<EventFeedEvent | null>(null);
  const [live, setLive] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  // The Event Log reads as real telemetry first (History-archive parity):
  // synthetic provenance (seeds / webapp detonations / the sandbox demo) is
  // hidden by default. The toggle reveals it; explicit source tabs and pid
  // drill-downs are deliberate asks and always show their full content.
  const [showSynthetic, setShowSynthetic] = useState(() => {
    try {
      return localStorage.getItem("outpost-events-synthetic") === "1";
    } catch {
      return false;
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
  // Live auto-scroll: while following (pinned to the bottom), new events
  // scroll into view; scrolling up pauses the jump and accumulates a
  // 'N new events' pill to get back to latest.
  const [atBottom, setAtBottom] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const lastTotalRef = useRef(0);

  // Effective synthetic visibility: the toggle in the "All sources" view, or
  // any explicit provenance tab / pid drill-down (both deliberate asks that
  // always show their full content — a seed run's process jump must not land
  // on an empty feed).
  const includeSynthetic = showSynthetic || source !== "" || submittedPids.length > 0;
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
    refetchInterval: live ? 5_000 : false,
  });

  const events = useMemo(() => data?.events ?? [], [data]);
  const total = data?.total ?? 0;

  // Live tail with pause: while `live` is on, an SSE run-update (a batch
  // landed in any run) refetches the feed the moment it happens — the 5 s
  // poll stays as the fallback. The toggle is the pause.
  useEventStream(
    () => undefined,
    undefined,
    () => {
      if (!live) return;
      void queryClient.invalidateQueries({ queryKey: ["events"] });
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

  // Follow-the-bottom: the window is the scroll container (desk tool, no
  // inner panel scroll), so 'at the bottom' means within a hair of the end.
  useEffect(() => {
    const onScroll = () => {
      const doc = document.documentElement;
      setAtBottom(doc.scrollHeight - window.scrollY - window.innerHeight < 140);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Live auto-scroll: new events while following scroll smoothly into view;
  // new events while paused accumulate in the jump-back pill.
  useEffect(() => {
    if (!live) return;
    const prev = lastTotalRef.current;
    lastTotalRef.current = total;
    if (prev <= 0 || total <= prev) return;
    const delta = total - prev;
    if (atBottom) {
      setNewCount(0);
      window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
    } else {
      setNewCount((n) => n + delta);
    }
  }, [total, live, atBottom]);

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
        kicker="Workspace · event log"
        title={
          <>
            Event Log <span className="font-normal text-text-muted">— system activity viewer</span>
          </>
        }
        lede="Every process, network, file, and registry event across all sessions — grouped by log channel, leveled by severity, live when you want it. Select any entry for the full record."
        actions={
          <div className="flex items-center gap-2">
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
              {live ? "Live · refreshing" : "Follow live"}
            </button>
          </div>
        }
      />

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
                    live={live}
                    severity={severity}
                    platform={platform}
                    q={submittedQ}
                    pids={submittedPids}
                    includeSynthetic={includeSynthetic}
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
          {/* Filter bar */}
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {/* Focus presets — one-click noise-hiding shortcuts (Sysmon View
                pattern): network only, new processes only, files, registry. */}
            <div className="flex items-center gap-1 rounded-lg border border-border-subtle p-1" role="group" aria-label="Focus preset">
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

            {/* View mode — flat timeline or process chains */}
            <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="View mode">
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

            <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="Filter by level">
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

            {/* Source tabs — provenance facet: collectors vs webapp vs sandbox. */}
            <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="Filter by source">
              {SOURCE_TABS.map((s) => (
                <button
                  key={s.v || "all"}
                  onClick={() => setSource(s.v)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                    source === s.v
                      ? "bg-accent/10 font-medium text-accent"
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
                  {/* Live per-channel count — the source rail is a noise-meter
                      too: it shares the active category/severity/platform/
                      search/pid filters, and a specific tab always counts its
                      full content (a deliberate provenance ask, mirroring the
                      feed's include-synthetic rule). */}
                  <CountBadge
                    type={category}
                    source={s.v}
                    live={live}
                    severity={severity}
                    platform={platform}
                    q={submittedQ}
                    pids={submittedPids}
                    includeSynthetic={showSynthetic || s.v !== "" || submittedPids.length > 0}
                  />
                </button>
              ))}
            </div>

            {/* Synthetic-provenance toggle — the Event Log reads as real
                telemetry first (archive parity). Hidden while a source tab is
                active: choosing a tab is a deliberate provenance ask and
                already shows it all. */}
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
                placeholder="Search process, path, IP, command line…"
                className="w-52 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
                aria-label="Search events"
              />
              <input
                value={pidInput}
                onChange={(e) => setPidInput(e.target.value)}
                placeholder="pid"
                inputMode="numeric"
                className="w-20 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
                aria-label="Filter by process PID"
                title="Filter to one process — everything this PID did"
              />
              <button
                type="submit"
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              >
                <Icon name="search" size={12} />
                Search
              </button>
              {hasFilters && (
                <button
                  type="button"
                  onClick={clearAllFilters}
                  className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-1.5 font-mono text-[11px] text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                  title="Clear every filter (type, level, platform, source, search, pid)"
                >
                  <Icon name="x" size={11} />
                  Clear filters
                </button>
              )}
            </form>
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
              <p className="mt-3 text-sm text-text-muted">No events match these filters.</p>
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
                window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "smooth" });
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
    </div>
  );
}
