import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { EVENT_ICON, Icon, platformIconName } from "../components/Icon";
import { PageHeader } from "../components/ui";
import { getEvents } from "../lib/api";
import type { EventFeedEvent, EventType, Platform, Severity } from "../types";

const PAGE = 60;

const CATEGORIES: { type: EventType | ""; label: string; icon: "list" | "process" | "network" | "file" | "registry" }[] = [
  { type: "", label: "All events", icon: "list" },
  { type: "process_create", label: "Process activity", icon: "process" },
  { type: "network_connection", label: "Network", icon: "network" },
  { type: "file_write", label: "File activity", icon: "file" },
  { type: "registry_write", label: "Registry", icon: "registry" },
];

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

function CategoryCount({ type, live }: { type: EventType | ""; live: boolean }) {
  const { data } = useQuery({
    queryKey: ["events", "count", type],
    queryFn: () => getEvents({ event_type: type, limit: 1 }),
    staleTime: live ? 0 : 15_000,
    refetchInterval: live ? 5_000 : false,
  });
  return (
    <span className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 py-px font-mono text-[10px] tabular-nums text-text-faint">
      {data?.total ?? "…"}
    </span>
  );
}

/* ── Record pane — slide-over from the right ───────────────────────────── */

function RecordPane({ event, onClose }: { event: EventFeedEvent; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const lvl = levelOf(event);
  const rows: [string, string][] = [
    ["Event type", event.event_type.replace("_", " ")],
    ["Timestamp", event.timestamp],
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
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/25 backdrop-blur-[2px]" onClick={onClose} aria-hidden />
      <aside className="animate-slide-in absolute inset-y-0 right-0 flex w-full max-w-md flex-col border-l border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]">
        <header className="flex items-center justify-between border-b border-border-subtle px-5 py-4">
          <div>
            <p className="kicker">Event detail</p>
            <h2 className="mt-0.5 text-[15px] font-semibold text-text-primary">{event.event_type.replace("_", " ")}</h2>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border-subtle text-text-muted transition-colors hover:border-accent/50 hover:text-accent"
            aria-label="Close event detail"
          >
            <Icon name="x" size={15} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto p-5">
          <div className="flex items-center gap-2">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${lvl.badge}`}>
              <Icon name={lvl.icon} size={12} />
              {lvl.label}
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted">
              <Icon name={platformIconName(event.platform)} size={12} />
              {event.platform}
            </span>
          </div>

          <dl className="mt-5 space-y-3 border-t border-border-subtle pt-4 font-mono text-xs">
            {rows.map(([k, v]) => (
              <div key={k} className="flex gap-3">
                <dt className="w-24 shrink-0 text-text-faint">{k}</dt>
                <dd className="min-w-0 break-words text-text-primary">{v}</dd>
              </div>
            ))}
          </dl>
        </div>

        <footer className="border-t border-border-subtle p-4">
          <Link
            to={`/runs/${event.run_id}`}
            onClick={onClose}
            className="press inline-flex w-full items-center justify-center gap-2 rounded-lg border border-accent/50 bg-accent/10 px-3 py-2.5 font-mono text-xs font-medium text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)]"
          >
            <Icon name="arrowRight" size={13} />
            Open full run report
          </Link>
        </footer>
      </aside>
    </div>
  );
}

/* ── Page ──────────────────────────────────────────────────────────────── */

export default function EventsPage() {
  const [category, setCategory] = useState<EventType | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [platform, setPlatform] = useState<Platform | "">("");
  const [q, setQ] = useState("");
  const [submittedQ, setSubmittedQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<EventFeedEvent | null>(null);
  const [live, setLive] = useState(false);

  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["events", category, severity, platform, submittedQ, offset],
    queryFn: () => getEvents({ event_type: category, severity, platform, q: submittedQ, limit: PAGE, offset }),
    refetchInterval: live ? 5_000 : false,
  });

  useEffect(() => {
    setOffset(0);
  }, [category, severity, platform, submittedQ]);

  const events = data?.events ?? [];
  const total = data?.total ?? 0;

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
        }
      />

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
                  <CategoryCount type={c.type} live={live} />
                </button>
              </li>
            ))}
          </ul>
        </aside>

        {/* ── Timeline ──────────────────────────────────────────────────── */}
        <section className="min-w-0">
          {/* Filter bar */}
          <div className="mb-4 flex flex-wrap items-center gap-2">
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

            <form
              className="ml-auto flex items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                setSubmittedQ(q.trim());
              }}
            >
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search process, path, IP, command line…"
                className="w-56 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
                aria-label="Search events"
              />
              <button
                type="submit"
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              >
                <Icon name="search" size={12} />
                Search
              </button>
            </form>
          </div>

          <p className="mb-3 font-mono text-[11px] text-text-faint">
            {isLoading ? "Loading events…" : `${total} event${total === 1 ? "" : "s"} · showing ${offset + 1}–${Math.min(offset + PAGE, total)}`}
            {isFetching && " · refreshing…"}
            {live && " · live"}
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
                    {list.map((e) => {
                      const lvl = levelOf(e);
                      const active = selected?.id === e.id;
                      const rail =
                        e.run_severity === "malicious"
                          ? "bg-risk-malicious"
                          : e.run_severity === "suspicious"
                            ? "bg-risk-suspicious"
                            : "bg-border-strong";
                      return (
                        <li key={`${e.id}-${e.run_id}-${e.timestamp}`} className="timeline-item">
                          {/* Card is a non-interactive container; the select button
                              and the run link are SIBLINGS (never nested interactive
                              elements — the old table's tr+td pattern, preserved). */}
                          <div
                            className={`group relative ml-2 overflow-hidden rounded-xl border bg-bg-surface transition-all duration-150 ${
                              active
                                ? "border-accent/50 shadow-[var(--glow-accent)]"
                                : "border-border-subtle hover:border-accent/30 hover:shadow-[var(--shadow-panel)]"
                            }`}
                          >
                            <span className={`absolute left-0 top-0 h-full w-1 ${rail}`} aria-hidden />
                            <button
                              onClick={() => setSelected(active ? null : e)}
                              aria-pressed={active}
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
                                </span>
                                <span className="mt-0.5 block truncate font-mono text-[11px] text-text-muted" title={eventDetail(e)}>
                                  {eventDetail(e)}
                                </span>
                              </span>
                              <Icon name="chevronRight" size={14} className="mt-1 shrink-0 text-text-faint transition-transform duration-150 group-hover:translate-x-0.5" />
                            </button>
                            {/* Meta footer — sibling of the select button */}
                            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border-subtle/60 px-4 py-2 text-[10px] text-text-faint">
                              {eventMeta(e).map((m) => (
                                <span key={m} className="font-mono">{m}</span>
                              ))}
                              <Link
                                to={`/runs/${e.run_id}`}
                                className="inline-flex items-center gap-1 font-mono font-medium text-accent hover:underline"
                              >
                                {e.sample_name}
                                <Icon name="external" size={10} className="opacity-60" />
                              </Link>
                            </div>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}

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
        </section>
      </div>

      {selected && <RecordPane event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
