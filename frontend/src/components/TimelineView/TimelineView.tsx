import type { EventOut } from "../../types";

export function eventDetail(ev: EventOut): string {
  switch (ev.event_type) {
    case "process_create":
      return `${ev.process_name ?? "?"} (pid ${ev.pid ?? "?"})${ev.command_line ? ` — ${ev.command_line}` : ""}`;
    case "network_connection":
      return `${ev.dest_ip}:${ev.dest_port ?? "?"} [${ev.protocol ?? "?"}]`;
    case "file_write":
      return ev.file_path ?? "-";
    case "registry_write":
      return ev.registry_key ?? "-";
    default:
      return "-";
  }
}

export const TYPE_STYLE: Record<EventOut["event_type"], string> = {
  process_create: "text-text-primary",
  network_connection: "text-accent",
  file_write: "text-text-muted",
  registry_write: "text-text-muted",
};

export default function TimelineView({ events }: { events: EventOut[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-text-muted">No events recorded for this run.</p>;
  }

  return (
    <ol className="space-y-0.5">
      {events.map((ev, i) => (
        <li key={ev.id ?? `${ev.timestamp}-${i}`} className="flex items-baseline gap-3 rounded px-1 py-0.5 transition-colors duration-150 hover:bg-bg-elevated">
          <span className="w-6 shrink-0 text-right font-mono text-[10px] text-text-faint">
            {String(i + 1).padStart(2, "0")}
          </span>
          <span className="w-16 shrink-0 font-mono text-xs text-text-faint">
            {ev.timestamp.slice(11, 19)}
          </span>
          <span className={`w-36 shrink-0 font-mono text-xs ${TYPE_STYLE[ev.event_type]}`}>{ev.event_type}</span>
          <span className="truncate font-mono text-xs text-text-muted">{eventDetail(ev)}</span>
        </li>
      ))}
    </ol>
  );
}
