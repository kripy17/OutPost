// Timeline row helpers — shared by the run-detail timeline, the Campaigns
// timeline, and the Monitor's live event trickle. Pure, testable, and free of
// React so the component files stay fast-refreshable.

import type { EventOut } from "../../types";

/** One-line human detail for an event — the adaptive "what happened" column. */
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

/** Tailwind text color per event type — mono column stays legible. */
export const TYPE_STYLE: Record<EventOut["event_type"], string> = {
  process_create: "text-text-primary",
  network_connection: "text-accent",
  file_write: "text-text-muted",
  registry_write: "text-text-muted",
};
