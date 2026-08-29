// Host investigation — the P1.4 workspace over the P0.6 aggregate timeline.
//
// One route per host (/hosts/:hostId) consuming GET /hosts/{host_id}/timeline
// exactly as the backend defines it — a pure read model, no new endpoints:
// the merged chronological feed of every resource tied to the host (events,
// findings, sessions/jobs, IOCs, investigations), with kind / event_type / q
// filters, honest totals, and per-kind deep-links into the existing
// workspaces. Unknown hosts 404 (the fleet identity union), known-but-quiet
// hosts render an honest empty feed with their platform/heartbeat context.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Icon, type IconName } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import { getHostContainment, getHostTimeline, isolateHost } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { toneFill, toneForReputation, toneForSeverity } from "../lib/fillPatterns";
import type { EventType, HostTimelineEntry, TimelineKind } from "../types";
import { relativeTime } from "./agentsHelpers";
import ProcessContextModal from "../components/ProcessContextModal";
import NetworkContextModal from "../components/NetworkContextModal";

const KIND_TABS: { value: TimelineKind | ""; label: string; icon: IconName }[] = [
  { value: "", label: "All", icon: "grid" },
  { value: "event", label: "Events", icon: "list" },
  { value: "finding", label: "Findings", icon: "alert" },
  { value: "session", label: "Sessions", icon: "clock" },
  { value: "ioc", label: "IOCs", icon: "search" },
  { value: "investigation", label: "Cases", icon: "notes" },
];

const EVENT_TYPES: { value: EventType | ""; label: string }[] = [
  { value: "", label: "All types" },
  { value: "process_create", label: "Process" },
  { value: "network_connection", label: "Network" },
  { value: "file_write", label: "File" },
  { value: "registry_write", label: "Registry" },
];

const KIND_META: Record<TimelineKind, { label: string; icon: IconName; chip: string }> = {
  event: { label: "event", icon: "list", chip: "border-border-subtle text-text-faint" },
  finding: { label: "finding", icon: "alert", chip: "border-risk-suspicious/40 text-risk-suspicious" },
  session: { label: "session", icon: "clock", chip: "border-border-subtle text-text-faint" },
  ioc: { label: "ioc", icon: "search", chip: "border-border-subtle text-text-faint" },
  investigation: { label: "case", icon: "notes", chip: "border-accent/40 text-accent" },
};

/** Deep-link per kind — the same map the global search uses: findings and
 *  events land on the run detail, IOCs on the pre-filled IOC search, sessions
 *  on run detail or the analysis workspace for analysis_job rows,
 *  investigations on the case workspace. */
function entryLink(e: HostTimelineEntry): string {
  switch (e.kind) {
    case "finding":
    case "event":
      return `/runs/${e.payload.run_id}`;
    case "ioc":
      return `/search?q=${encodeURIComponent(String(e.payload.value ?? ""))}`;
    case "session":
      return e.payload.kind === "analysis_job" ? `/analysis/${e.payload.run_id}` : `/runs/${e.payload.run_id}`;
    case "investigation":
      return `/investigations/${e.payload.investigation_id}`;
  }
}

function EntryRow({
  e,
  onInspectIp,
  onInspectPid,
}: {
  e: HostTimelineEntry;
  onInspectIp?: (ip: string) => void;
  onInspectPid?: (pid: number) => void;
}) {
  const meta = KIND_META[e.kind];
  const payload = e.payload as Record<string, string | number | null | undefined>;
  const ts = String(e.timestamp ?? "").slice(0, 19).replace("T", " ");

  const pid = payload.pid ? Number(payload.pid) : undefined;
  const rawIp = String(payload.dest_ip ?? (e.kind === "ioc" && payload.type === "ip" ? payload.value : ""));
  const destIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(rawIp) ? rawIp : undefined;

  return (
    <div className="group flex items-center justify-between gap-3 px-4 py-2.5 transition-colors hover:bg-bg-elevated/40 border-b border-border-subtle/30 last:border-0">
      <Link
        to={entryLink(e)}
        className="flex min-w-0 flex-1 items-center gap-3"
        title={e.subtitle ?? undefined}
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-border-subtle text-signal">
          <Icon name={meta.icon} size={13} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-text-primary group-hover:text-accent">{e.title}</span>
            <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${meta.chip}`}>
              {meta.label}
            </span>
            {e.kind === "finding" && payload.severity && (
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={toneFill(toneForSeverity(payload.severity as "suspicious" | "malicious"))}
                aria-hidden
              />
            )}
            {e.kind === "ioc" && payload.reputation && (
              <span
                className="h-1.5 w-1.5 rounded-full"
                style={toneFill(toneForReputation(payload.reputation as "clean" | "suspicious" | "malicious" | "unknown"))}
                aria-hidden
              />
            )}
          </span>
          <span className="mt-0.5 block truncate font-mono text-[10px] text-text-faint">{e.subtitle ?? e.id}</span>
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
        <span className="font-mono text-[10px] tabular-nums text-text-faint">{ts}</span>
        <Link to={entryLink(e)}>
          <Icon name="chevronRight" size={13} className="text-text-faint transition-colors hover:text-accent" />
        </Link>
      </div>
    </div>
  );
}

export default function HostDetailPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<TimelineKind | "">("");
  const [eventType, setEventType] = useState<EventType | "">("");
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [entries, setEntries] = useState<HostTimelineEntry[]>([]);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const LIMIT = 50;

  // Live-ish: a fleet heartbeat push for this host (or any run update)
  // invalidates the feed — the header/entries refresh without a manual poll;
  // a 30 s poll stays as the fallback.
  useEventStream(
    () => undefined,
    undefined,
    () => void queryClient.invalidateQueries({ queryKey: ["hostTimeline", hostId] }),
    (f) => {
      if (f.host_id === hostId) void queryClient.invalidateQueries({ queryKey: ["hostTimeline", hostId] });
    },
  );

  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["hostTimeline", hostId, kind, eventType, debouncedQ, offset],
    queryFn: () =>
      getHostTimeline(hostId!, {
        kind: kind || undefined,
        eventType: eventType || undefined,
        q: debouncedQ || undefined,
        limit: LIMIT,
        offset,
      }),
    enabled: !!hostId,
    refetchInterval: 30_000,
  });

  // Accumulate pages across Load more; a filter change resets to page 0.
  // (data + offset intentionally exhaustive — setEntries/setOffset are stable.)
  useEffect(() => {
    if (offset === 0) setEntries(data?.timeline ?? []);
    else setEntries((prev) => [...prev, ...(data?.timeline ?? [])]);
  }, [data, offset]);

  const setFilter = (next: { kind?: TimelineKind | ""; eventType?: EventType | ""; q?: string }) => {
    if (next.kind !== undefined && next.kind !== kind) {
      setKind(next.kind);
      if (next.kind !== "event") setEventType("");
    }
    if (next.eventType !== undefined) setEventType(next.eventType);
    if (next.q !== undefined) setQ(next.q);
    setOffset(0);
  };

  const { data: containment } = useQuery({
    queryKey: ["host-containment", hostId],
    queryFn: () => getHostContainment(hostId!),
    enabled: !!hostId,
    retry: false,
  });

  const toggleIsolation = useMutation({
    mutationFn: (isolated: boolean) => isolateHost(hostId!, { isolated, reason: "Toggled from host investigation workspace" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-containment", hostId] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const isIsolated = containment?.isolated ?? false;

  if (isError) {
    return (
      <div className="mx-auto max-w-5xl px-5 py-8 lg:px-8">
        <PageHeader kicker="Host investigation" title="Unknown host" />
        <Panel>
          <p className="py-8 text-center text-sm text-risk-malicious">
            Unknown host{hostId ? ` ${hostId}` : ""} — no event, heartbeat, or snapshot carries this id.
          </p>
          <p className="pb-8 text-center text-xs text-text-faint">
            <Link to="/agents" className="text-accent hover:underline">Back to the fleet</Link>
          </p>
        </Panel>
      </div>
    );
  }

  const shown = entries.length;
  const total = data?.total ?? 0;
  const moreAvailable = shown < total;

  return (
    <div className="mx-auto max-w-5xl px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Host investigation"
        title={hostId ?? ""}
        lede="Everything OutPost knows about this machine in one chronological feed — events, findings, sessions/jobs, IOCs, and the investigations its findings belong to."
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => toggleIsolation.mutate(!isIsolated)}
              disabled={toggleIsolation.isPending}
              className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-[11px] font-semibold transition-colors duration-150 ${
                isIsolated
                  ? "border-signal/60 bg-signal/10 text-signal hover:bg-signal/20"
                  : "border-risk-malicious/60 bg-risk-malicious/10 text-risk-malicious hover:bg-risk-malicious/20"
              }`}
            >
              <Icon name="alert" size={12} />
              {toggleIsolation.isPending ? "Updating…" : isIsolated ? "Lift Quarantine" : "Quarantine Host"}
            </button>
            <Link
              to={`/events?q=${encodeURIComponent(hostId ?? "")}`}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            >
              <Icon name="list" size={12} />
              Event Stream
            </Link>
          </div>
        }
      />

      {isIsolated && (
        <div className="mb-5 flex items-center justify-between rounded-xl border border-risk-malicious/60 bg-risk-malicious/15 p-3.5 text-risk-malicious">
          <div className="flex items-center gap-2">
            <Icon name="alert" size={16} />
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              HOST IS CURRENTLY NETWORK ISOLATED / CONTAINED
            </span>
          </div>
          <span className="font-mono text-[10px] text-text-muted">
            Reason: {containment?.reason || "Operator containment"}
          </span>
        </div>
      )}

      {/* Host context strip — platform + heartbeat from the timeline envelope. */}
      <div className="mb-5 flex flex-wrap items-center gap-3">
        {data?.platform && (
          <span className="rounded-full border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] capitalize text-text-muted">
            {data.platform}
          </span>
        )}
        {data?.last_heartbeat ? (
          <span className="rounded-full border border-signal/40 bg-signal/10 px-2.5 py-1 font-mono text-[11px] text-signal">
            heartbeat {relativeTime(data.last_heartbeat)}
          </span>
        ) : (
          <span
            className="rounded-full border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-faint"
            title="No agent heartbeat — events came from this machine (webapp detonations, sandbox runs)"
          >
            telemetry only
          </span>
        )}
      </div>

      {/* Kind tabs (no per-kind counts — the envelope returns one honest total
          across the searched kinds; the tab applies the kind filter server-side). */}
      <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Filter timeline by resource kind">
        {KIND_TABS.map((t) => (
          <button
            key={t.value || "all"}
            onClick={() => setFilter({ kind: t.value })}
            aria-pressed={kind === t.value}
            className={`press inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] transition-colors duration-150 ${
              kind === t.value
                ? "border-accent/60 bg-accent/10 text-accent"
                : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/40 hover:text-accent"
            }`}
          >
            <Icon name={t.icon} size={11} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Event-type + free-text filters. */}
      <div className="mb-5 flex flex-wrap items-center gap-3">
        {kind === "event" && (
          <div className="flex flex-wrap gap-1.5">
            {EVENT_TYPES.map((t) => (
              <button
                key={t.value || "all"}
                onClick={() => setFilter({ eventType: t.value })}
                aria-pressed={eventType === t.value}
                className={`press rounded-full border px-2.5 py-1 text-[10px] transition-colors ${
                  eventType === t.value
                    ? "border-accent/50 bg-accent/10 text-accent"
                    : "border-border-subtle text-text-muted hover:text-text-primary"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        )}
        <div className="relative ml-auto w-64">
          <Icon name="search" size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            className="w-full rounded-lg border border-border-subtle bg-bg-surface py-1.5 pl-8 pr-3 text-xs outline-none focus:border-accent/50"
            placeholder="Filter process / ip / rule / value…"
            value={q}
            onChange={(e) => {
              setFilter({ q: e.target.value });
              window.setTimeout(() => setDebouncedQ(e.target.value), 250);
            }}
          />
        </div>
      </div>

      {isLoading && offset === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton h-12 w-full" />
          ))}
        </div>
      ) : shown === 0 ? (
        <Panel>
          <p className="py-8 text-center text-sm text-text-muted">
            {eventType === "registry_write" && data?.platform === "linux"
              ? "Registry activity is not collected on Linux (Windows Sysmon only)."
              : total === 0
                ? `No ${kind || "activity"} recorded for this host${debouncedQ ? " matching the filter" : ""}.`
                : `No ${kind || "entries"} match the current filters.`}
          </p>
        </Panel>
      ) : (
        <Panel
          kicker="Aggregate timeline"
          title={`${total} entr${total === 1 ? "y" : "ies"}`}
          right={isFetching ? <span className="font-mono text-[10px] text-text-faint">refreshing…</span> : undefined}
        >
          <div className="divide-y divide-border-subtle/60">
            {entries.map((e) => (
              <EntryRow
                key={`${e.kind}-${e.id}`}
                e={e}
                onInspectIp={setInspectIp}
                onInspectPid={setInspectPid}
              />
            ))}
          </div>
          {moreAvailable && (
            <div className="border-t border-border-subtle p-3 text-center">
              <button className="btn" onClick={() => setOffset((o) => o + LIMIT)}>
                {isFetching ? "Loading…" : `Load more (${shown} of ${total})`}
              </button>
            </div>
          )}
        </Panel>
      )}

      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}
      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
    </div>
  );
}
