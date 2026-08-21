import { useMemo } from "react";
import { Icon } from "../Icon";
import { Chip, Panel } from "../ui";
import type { Alert, EventOut } from "../../types";
import { persistencePoints } from "./persistence";

/** Persistence-reversal panel — the exact things to remove after a finding. */
export default function PersistencePanel({ alerts, events }: { alerts: Alert[]; events: EventOut[] }) {
  const points = useMemo(() => persistencePoints(alerts, events), [alerts, events]);
  if (points.length === 0) return null;
  return (
    <Panel
      kicker="Reversal"
      title="Persistence points found"
      right={
        <span className="font-mono text-[10px] text-risk-malicious">
          <Icon name="alert" size={10} /> {points.length} to remove
        </span>
      }
    >
      <p className="mb-3 text-xs leading-relaxed text-text-muted">
        Detection flags the persistence write; this panel lists exactly what to delete or revoke to undo it.
      </p>
      <ul className="divide-y divide-border-subtle/60">
        {points.map((p, i) => (
          <li key={i} className="py-2">
            <div className="flex items-center gap-2">
              <Chip tone={p.tone}>{p.label}</Chip>
              <span className="font-mono text-[10px] text-text-faint">{p.rule}</span>
            </div>
            <p className="mt-1.5 break-all font-mono text-[11px] leading-relaxed text-text-primary">{p.target}</p>
            <p className="mt-1 text-[10px] uppercase tracking-wide text-risk-suspicious">{p.action}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
