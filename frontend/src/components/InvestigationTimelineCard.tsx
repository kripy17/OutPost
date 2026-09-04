import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";
import { Panel } from "./ui";
import { getInvestigationTimeline } from "../lib/api";
import type { InvestigationTimelineEvent } from "../types";

const EVENT_TYPE_META: Record<
  string,
  { label: string; icon: any; iconColor: string; borderColor: string; bgBadge: string }
> = {
  alert: {
    label: "Security Alert",
    icon: "alert",
    iconColor: "text-rose-400",
    borderColor: "border-rose-500/30",
    bgBadge: "bg-rose-500/15 text-rose-300",
  },
  evidence: {
    label: "Evidence Pivot",
    icon: "target",
    iconColor: "text-sky-400",
    borderColor: "border-sky-500/30",
    bgBadge: "bg-sky-500/15 text-sky-300",
  },
  note: {
    label: "Analyst Note",
    icon: "file",
    iconColor: "text-purple-400",
    borderColor: "border-purple-500/30",
    bgBadge: "bg-purple-500/15 text-purple-300",
  },
  task: {
    label: "Incident Action",
    icon: "check",
    iconColor: "text-emerald-400",
    borderColor: "border-emerald-500/30",
    bgBadge: "bg-emerald-500/15 text-emerald-300",
  },
  lifecycle: {
    label: "Case Lifecycle",
    icon: "shield",
    iconColor: "text-accent",
    borderColor: "border-accent/30",
    bgBadge: "bg-accent/15 text-accent",
  },
};

export const InvestigationTimelineCard: React.FC<{ investigationId: string }> = ({ investigationId }) => {
  const [filterType, setFilterType] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["investigation-timeline", investigationId],
    queryFn: () => getInvestigationTimeline(investigationId),
  });

  const rawEvents: InvestigationTimelineEvent[] = Array.isArray(data?.events) ? data.events : [];
  const events = rawEvents.filter(
    (e) => filterType === "all" || (e.event_type && e.event_type.toLowerCase() === filterType.toLowerCase()),
  );

  return (
    <Panel
      kicker="Incident Causality Ledger"
      title={`Chronological Case Timeline (${events.length} Milestones)`}
      right={
        <div className="flex items-center gap-1">
          {["all", "alert", "evidence", "task", "note"].map((ft) => (
            <button
              key={ft}
              type="button"
              onClick={() => setFilterType(ft)}
              className={`rounded-md px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                filterType === ft
                  ? "bg-accent text-bg-base"
                  : "bg-bg-surface text-text-muted hover:bg-bg-elevated hover:text-text-normal"
              }`}
            >
              {ft}
            </button>
          ))}
        </div>
      }
      className="mb-6"
    >
      {isLoading ? (
        <div className="flex items-center justify-center py-8 text-xs text-text-muted">
          <Icon name="refresh" className="mr-2 animate-spin text-accent" size={16} />
          Collation of case chronology in progress...
        </div>
      ) : events.length === 0 ? (
        <p className="py-6 text-center text-xs text-text-muted">No timeline events match the filter.</p>
      ) : (
        <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-border-subtle">
          {events.map((ev, idx) => {
            const meta = EVENT_TYPE_META[ev.event_type] || EVENT_TYPE_META.lifecycle;
            const timeStr = ev.timestamp ? ev.timestamp.slice(0, 19).replace("T", " ") : "—";

            return (
              <div key={idx} className="relative group">
                {/* Node icon dot on the vertical track */}
                <div
                  className={`absolute -left-[27px] top-1 flex h-6 w-6 items-center justify-center rounded-full border border-border-subtle bg-bg-base ${meta.iconColor} group-hover:border-accent transition`}
                >
                  <Icon name={meta.icon} size={11} />
                </div>

                <div className={`rounded-xl border ${meta.borderColor} bg-bg-surface/60 p-3 hover:bg-bg-surface transition-colors`}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className={`rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase ${meta.bgBadge}`}>
                        {meta.label}
                      </span>
                      <span className="text-xs font-semibold text-text-normal">{ev.title}</span>
                    </div>
                    <span className="font-mono text-[10px] text-text-faint">{timeStr}</span>
                  </div>

                  {ev.description && (
                    <p className="mt-1.5 text-xs text-text-muted leading-relaxed whitespace-pre-line">{ev.description}</p>
                  )}

                  <div className="mt-2 flex flex-wrap items-center justify-between gap-2 border-t border-border-subtle/50 pt-1.5 font-mono text-[10px] text-text-faint">
                    <span>
                      Actor / Source: <strong className="text-text-muted">{ev.actor}</strong>
                    </span>

                    {ev.event_type === "evidence" && ev.ref_type && ev.ref_id && (
                      <div className="flex items-center gap-1.5">
                        {ev.ref_type === "run" && (
                          <Link to={`/runs/${ev.ref_id}`} className="text-accent hover:underline flex items-center gap-1">
                            <span>Open Run {ev.ref_id.slice(0, 8)}</span>
                            <Icon name="external" size={9} />
                          </Link>
                        )}
                        {ev.ref_type === "host" && (
                          <Link to={`/hosts/${ev.ref_id}`} className="text-accent hover:underline flex items-center gap-1">
                            <span>Inspect Host</span>
                            <Icon name="external" size={9} />
                          </Link>
                        )}
                        {ev.ref_type === "ioc" && (
                          <Link to={`/events?q=${encodeURIComponent(ev.ref_id)}`} className="text-accent hover:underline flex items-center gap-1">
                            <span>Filter Events</span>
                            <Icon name="external" size={9} />
                          </Link>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
};
