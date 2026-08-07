import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "../components/ui";
import { getEvents } from "../lib/api";
import { SEVERITY_COLORS } from "../lib/constants";
import type { EventFeedEvent, EventType, Platform, Severity } from "../types";

const PAGE = 100;

const EVENT_TYPES: EventType[] = ["process_create", "network_connection", "file_write", "registry_write"];
const PLATFORMS: Platform[] = ["windows", "linux"];

function eventDetail(e: EventFeedEvent): string {
  if (e.process_name) return `${e.process_name}${e.command_line ? ` — ${e.command_line}` : ""}`;
  if (e.dest_ip) return `${e.dest_ip}${e.dest_port ? `:${e.dest_port}` : ""}${e.protocol ? ` [${e.protocol}]` : ""}`;
  if (e.file_path) return e.file_path;
  if (e.registry_key) return e.registry_key;
  return "—";
}

function PlatformTag({ platform }: { platform: Platform }) {
  return (
    <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-muted">
      {platform === "windows" ? "⊞ win" : "⎈ lnx"}
    </span>
  );
}

function TypeTag({ type }: { type: EventType }) {
  const color =
    type === "network_connection"
      ? "text-accent-amber"
      : type === "registry_write"
        ? "text-risk-suspicious"
        : type === "file_write"
          ? "text-risk-clean"
          : "text-text-primary";
  return <span className={`font-mono text-[11px] ${color}`}>{type}</span>;
}

export default function EventsPage() {
  const [eventType, setEventType] = useState<EventType | "">("");
  const [platform, setPlatform] = useState<Platform | "">("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [q, setQ] = useState("");
  const [submittedQ, setSubmittedQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<EventFeedEvent | null>(null);

  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["events", eventType, platform, severity, submittedQ, offset],
    queryFn: () => getEvents({ event_type: eventType, platform, severity, q: submittedQ, limit: PAGE, offset }),
  });

  // Reset to the first page whenever a filter changes (not on pagination).
  useEffect(() => {
    setOffset(0);
  }, [eventType, platform, severity, submittedQ]);

  const events = data?.events ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Intelligence · event viewer"
        title={
          <>
            Events <span className="font-normal text-text-muted">— across all sessions</span>
          </>
        }
        lede="A global Event Viewer over every run: filter by type, platform, or findings severity, and search any process, path, IP, or command line."
      />

      {/* Filter bar */}
      <div className="mt-6 flex flex-wrap items-center gap-2">
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value as EventType | "")}
          className="press rounded border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors duration-150 hover:border-border-subtle/80 focus:border-accent-amber/60"
          aria-label="Filter by event type"
        >
          <option value="">All types</option>
          {EVENT_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <select
          value={platform}
          onChange={(e) => setPlatform(e.target.value as Platform | "")}
          className="rounded border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent-amber/60"
          aria-label="Filter by platform"
        >
          <option value="">All platforms</option>
          {PLATFORMS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | "")}
          className="rounded border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent-amber/60"
          aria-label="Filter by run severity"
        >
          <option value="">Any severity</option>
          <option value="suspicious">Runs with suspicious findings</option>
          <option value="malicious">Runs with malicious findings</option>
        </select>

        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setSubmittedQ(q.trim());
          }}
        >
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search process, path, IP, command line…"
            className="w-72 rounded border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent-amber/60"
            aria-label="Search events"
          />
          <button
            type="submit"
            className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
          >
            Search
          </button>
        </form>

        {q !== submittedQ && (
          <button
            onClick={() => setQ(submittedQ)}
            className="rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors hover:text-text-primary"
            aria-label="Clear search"
          >
            Clear
          </button>
        )}
      </div>

      {/* Status line */}
      <p className="mt-4 font-mono text-[11px] text-text-faint">
        {isLoading ? "Loading events…" : `${total} event${total === 1 ? "" : "s"} · showing ${offset + 1}–${Math.min(offset + PAGE, total)}`}
        {isFetching && " · refreshing…"}
      </p>

      {isError && (
        <p className="mt-6 rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't load events — is the OutPost backend running?
        </p>
      )}

      {/* Feed */}
      {!isError && events.length === 0 && !isLoading && (
        <p className="mt-6 text-sm text-text-muted">No events match these filters.</p>
      )}

      {events.length > 0 && (
        <div className="mt-3 overflow-hidden rounded-lg border border-border-subtle bg-bg-surface">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border-subtle font-mono text-[10px] uppercase tracking-widest text-text-faint">
                <th className="px-4 py-2.5 font-normal">Time</th>
                <th className="px-4 py-2.5 font-normal">Platform</th>
                <th className="px-4 py-2.5 font-normal">Type</th>
                <th className="px-4 py-2.5 font-normal">Detail</th>
                <th className="px-4 py-2.5 font-normal">Sample</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr
                  key={`${e.id}-${e.run_id}-${e.timestamp}`}
                  onClick={() => setSelected(selected?.id === e.id ? null : e)}
                  className="cursor-pointer border-b border-border-subtle/60 transition-colors duration-150 last:border-0 hover:bg-bg-elevated/60"
                >
                  <td className="whitespace-nowrap px-4 py-2 font-mono tabular-nums text-text-faint">{e.timestamp.slice(11, 19)}</td>
                  <td className="px-4 py-2">
                    <PlatformTag platform={e.platform} />
                  </td>
                  <td className="px-4 py-2">
                    <TypeTag type={e.event_type} />
                  </td>
                  <td className="max-w-md truncate px-4 py-2 font-mono text-text-muted">{eventDetail(e)}</td>
                  <td className="px-4 py-2">
                    <Link
                      to={`/runs/${e.run_id}`}
                      onClick={(ev) => ev.stopPropagation()}
                      className={`font-mono hover:text-accent-amber ${e.run_severity ? SEVERITY_COLORS[e.run_severity] : "text-text-primary"}`}
                    >
                      {e.sample_name}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          <div className="flex items-center justify-between px-4 py-3">
            <button
              onClick={() => setOffset((o) => Math.max(0, o - PAGE))}
              disabled={offset === 0}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 enabled:hover:border-accent-amber/60 enabled:hover:text-accent-amber disabled:opacity-40"
            >
              ← Newer
            </button>
            <button
              onClick={() => setOffset((o) => o + PAGE)}
              disabled={offset + PAGE >= total}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 enabled:hover:border-accent-amber/60 enabled:hover:text-accent-amber disabled:opacity-40"
            >
              Older →
            </button>
          </div>
        </div>
      )}

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/40" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-md overflow-y-auto border-l border-border-subtle bg-bg-surface p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <h2 className="font-mono text-sm font-semibold text-text-primary">Event detail</h2>
              <button
                onClick={() => setSelected(null)}
                className="text-text-faint transition-colors hover:text-text-primary"
                aria-label="Close event detail"
              >
                ×
              </button>
            </div>

            <dl className="mt-5 space-y-3 font-mono text-xs">
              {[
                ["Run", selected.run_id],
                ["Sample", selected.sample_name],
                ["Time", selected.timestamp],
                ["Platform", selected.platform],
                ["Type", selected.event_type],
                ["PID", String(selected.pid ?? "—")],
                ["PPID", String(selected.ppid ?? "—")],
                ["Process", selected.process_name ?? "—"],
                ["Command line", selected.command_line ?? "—"],
                ["Dest IP", selected.dest_ip ?? "—"],
                ["Dest port", String(selected.dest_port ?? "—")],
                ["Protocol", selected.protocol ?? "—"],
                ["File path", selected.file_path ?? "—"],
                ["Registry key", selected.registry_key ?? "—"],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <dt className="w-28 shrink-0 text-text-faint">{k}</dt>
                  <dd className="min-w-0 break-words text-text-primary">{v}</dd>
                </div>
              ))}
            </dl>

            <Link
              to={`/runs/${selected.run_id}`}
              onClick={() => setSelected(null)}
              className="mt-6 inline-block rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-accent-amber/60 hover:text-accent-amber"
            >
              Open full run report →
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
