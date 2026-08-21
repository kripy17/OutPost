// Recurring fan-out ("plant") detection — pure parse of the fanout-recurring
// alerts into the run-detail plant strip rows. Exported so it's unit-testable
// without rendering the component.

import type { Alert } from "../../types";

export interface PlantInfo {
  ip: string;
  windows: number;
}

// The details string is engine-owned and stable: "… in N distinct 300s windows …".
const WINDOWS_RE = /in (\d+) distinct/;

export function plantIpsFromAlerts(alerts: Alert[]): PlantInfo[] {
  const out: PlantInfo[] = [];
  for (const a of alerts) {
    if (a.rule_id !== "fanout-recurring" || !a.related_ip) continue;
    const m = WINDOWS_RE.exec(a.details ?? "");
    const windows = m ? parseInt(m[1], 10) : 0;
    out.push({ ip: a.related_ip, windows });
  }
  return out.sort((a, b) => b.windows - a.windows);
}
