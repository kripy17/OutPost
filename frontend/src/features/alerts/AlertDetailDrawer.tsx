import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  X,
  ShieldCheck,
  Flag,
  FolderPlus,
  Activity,
  Layers,
  Terminal,
} from "lucide-react";
import { AlertItem, NeighborEvent } from "./types";
import { FormattedTime, Entity, SEVERITY, normalizeSeverity } from "../../foundation";

interface AlertDetailDrawerProps {
  alert: AlertItem | null;
  onClose: () => void;
  onAcknowledge: (alert: AlertItem) => void;
  onFalsePositive: (alert: AlertItem) => void;
  onEscalate: (alert: AlertItem) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  onClose,
  onAcknowledge,
  onFalsePositive,
  onEscalate,
}) => {
  if (!alert) {
    return null;
  }

  const sev = normalizeSeverity(alert.severity);
  const sevStyle = SEVERITY[sev];

  // Fetch neighboring correlated events for this run
  const { data: events = [] } = useQuery<NeighborEvent[]>({
    queryKey: ["runs", alert.run_id, "events"],
    queryFn: async () => {
      const res = await fetch(`/runs/${alert.run_id}/events?limit=25`);
      if (!res.ok) return [];
      const json = await res.json();
      return json.events ?? json ?? [];
    },
    enabled: !!alert.run_id,
  });

  return (
    <aside
      className="flex h-full w-[460px] shrink-0 flex-col border-l border-[#26292e] bg-[#141618] text-[#e6edf3]"
      data-testid="alert-detail-drawer"
    >
      {/* Drawer Header */}
      <div className={`flex items-start justify-between border-b border-[#26292e] p-3.5 border-l-4 ${sevStyle.border}`}>
        <div className="min-w-0 pr-2">
          <div className="flex items-center gap-2">
            <span className={`rounded-[3px] px-1.5 py-0.5 text-[10px] font-semibold uppercase ${sevStyle.bg} ${sevStyle.text}`}>
              {sevStyle.label}
            </span>
            <span className="font-mono text-[11px] text-[#7d8590]">#{alert.id}</span>
            <span className="rounded-[2px] bg-[#26292e] px-1.5 py-0.2 text-[10px] uppercase font-mono text-[#8b949e]">
              {alert.status}
            </span>
          </div>
          <h2 className="mt-1.5 text-[14px] font-semibold leading-tight text-[#e6edf3]">
            {alert.rule_name}
          </h2>
          <div className="mt-1 text-[11px] font-mono text-[#7d8590]">
            Triggered <FormattedTime value={alert.triggered_at} />
          </div>
        </div>

        <button
          onClick={onClose}
          className="text-[#8b949e] hover:text-[#e6edf3] p-1"
          title="Close drawer (Esc)"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Action Bar */}
      <div className="flex items-center gap-1.5 border-b border-[#26292e] bg-[#1a1d20]/60 px-3.5 py-2">
        {alert.status === "open" && (
          <button
            onClick={() => onAcknowledge(alert)}
            className="flex items-center gap-1.5 rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-2.5 py-1 text-[11px] font-medium text-[#e6edf3] hover:bg-[#26292e]"
            title="Acknowledge (a)"
          >
            <ShieldCheck className="h-3.5 w-3.5 text-[#3fb950]" />
            <span>Ack (a)</span>
          </button>
        )}
        <button
          onClick={() => onFalsePositive(alert)}
          className="flex items-center gap-1.5 rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-2.5 py-1 text-[11px] font-medium text-[#e6edf3] hover:bg-[#26292e]"
          title="Mark False Positive (f)"
        >
          <Flag className="h-3.5 w-3.5 text-[#db6d28]" />
          <span>False Positive (f)</span>
        </button>
        <button
          onClick={() => onEscalate(alert)}
          className="flex items-center gap-1.5 rounded-[4px] border border-[#26292e] bg-[#2f81f7]/20 px-2.5 py-1 text-[11px] font-medium text-[#58a6ff] hover:bg-[#2f81f7]/30"
          title="Escalate to Case (e)"
        >
          <FolderPlus className="h-3.5 w-3.5" />
          <span>Open Case (e)</span>
        </button>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 space-y-4 overflow-y-auto p-3.5 text-[12px]">
        {/* Detection Logic & Matched Trigger Fields */}
        <section className="rounded-[4px] border border-[#26292e] bg-[#0c0d0e] p-3">
          <div className="flex items-center gap-1.5 font-medium text-[#e6edf3]">
            <Terminal className="h-3.5 w-3.5 text-[#58a6ff]" />
            <span>Detection Evidence & Matched Fields</span>
          </div>
          <p className="mt-2 text-[12px] text-[#8b949e]">
            {alert.details || "Detection rule triggered by monitored host telemetry pattern."}
          </p>

          <div className="mt-3 flex flex-wrap gap-2">
            {alert.related_pid && (
              <Entity type="process" value={`PID ${alert.related_pid}`} />
            )}
            {alert.related_ip && (
              <Entity type="ip" value={alert.related_ip} defang={true} />
            )}
            {alert.host_id && (
              <Entity type="host" value={alert.host_id} />
            )}
          </div>
        </section>

        {/* Process & Execution Context */}
        <section className="rounded-[4px] border border-[#26292e] bg-[#0c0d0e] p-3">
          <div className="flex items-center gap-1.5 font-medium text-[#e6edf3]">
            <Layers className="h-3.5 w-3.5 text-[#58a6ff]" />
            <span>Execution Provenance</span>
          </div>
          <div className="mt-2 space-y-1.5 font-mono text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#7d8590]">Run ID:</span>
              <span className="text-[#e6edf3]">{alert.run_id}</span>
            </div>
            {alert.sample_name && (
              <div className="flex justify-between">
                <span className="text-[#7d8590]">Sample:</span>
                <span className="text-[#e6edf3]">{alert.sample_name}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-[#7d8590]">Rule ID:</span>
              <span className="text-[#e6edf3]">{alert.rule_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7d8590]">Occurrences:</span>
              <span className="tabular-nums text-[#e6edf3]">{alert.occurrence_count}</span>
            </div>
          </div>
        </section>

        {/* Correlated Event Window (+- 5 minutes) */}
        <section className="rounded-[4px] border border-[#26292e] bg-[#0c0d0e] p-3">
          <div className="flex items-center justify-between font-medium text-[#e6edf3]">
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-[#58a6ff]" />
              <span>Neighboring Events Window</span>
            </div>
            <span className="text-[10px] font-mono text-[#7d8590]">{events.length} events</span>
          </div>

          <div className="mt-2.5 max-h-48 space-y-1 overflow-y-auto">
            {events.length === 0 ? (
              <div className="py-2 text-center text-[11px] text-[#7d8590]">
                No neighboring telemetry events found in this window.
              </div>
            ) : (
              events.map((ev) => (
                <div
                  key={ev.id}
                  className="flex items-center justify-between rounded-[2px] border border-[#26292e]/40 bg-[#141618] px-2 py-1 font-mono text-[11px]"
                >
                  <div className="truncate pr-2">
                    <span className="text-[#e6edf3]">{ev.event_type}</span>
                    {ev.process_name && (
                      <span className="ml-1.5 text-[#7d8590]">({ev.process_name})</span>
                    )}
                  </div>
                  <FormattedTime value={ev.timestamp} className="shrink-0 text-[#7d8590]" />
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </aside>
  );
};
