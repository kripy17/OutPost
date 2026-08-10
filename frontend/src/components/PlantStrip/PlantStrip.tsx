// PlantStrip — every recurring fan-out destination on the run detail page.
//
// fanout-recurring alerts carry the plant story in their details
// ("crossed the fan-out threshold in 3 distinct 300s windows"); this strip
// turns that into a scannable list — one chip per plant IP with its window
// count — and each chip links straight to the network table filtered to that
// destination (onFocus). Pure parse in plantIpsFromAlerts so it's testable.

import { useMemo } from "react";
import { Panel } from "../ui";
import { Icon } from "../Icon";
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

export default function PlantStrip({
  alerts,
  onFocus,
}: {
  alerts: Alert[];
  onFocus: (ip: string) => void;
}) {
  const plants = useMemo(() => plantIpsFromAlerts(alerts), [alerts]);
  if (plants.length === 0) return null;

  return (
    <Panel
      kicker="C2 · recurring"
      title="Coordinated plant"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {plants.length} destination{plants.length === 1 ? "" : "s"} fanning out across multiple windows
        </span>
      }
    >
      <ul className="flex flex-wrap gap-2">
        {plants.map((p) => (
          <li
            key={p.ip}
            className="flex items-center gap-2 rounded-lg border border-risk-suspicious/40 bg-risk-suspicious/10 px-2.5 py-1.5"
          >
            <Icon name="network" size={12} className="text-risk-suspicious" />
            <span className="font-mono text-[11px] text-text-primary">{p.ip}</span>
            <span className="font-mono text-[10px] text-text-faint">×{p.windows} windows</span>
            <button
              onClick={() => onFocus(p.ip)}
              className="press ml-1 inline-flex items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[9px] text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
              title={`Filter the network table to ${p.ip}`}
            >
              <Icon name="arrowRight" size={9} />
              network
            </button>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
