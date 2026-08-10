import { useMemo } from "react";
import { Icon } from "../Icon";
import { Chip, Panel } from "../ui";
import type { Alert, EventOut } from "../../types";

/** Persistence-family rules mapped to the human action that reverses them. */
const PERSISTENCE_RULES: Record<string, { label: string; action: string; tone: "accent" | "malicious" }> = {
  "registry-persistence": { label: "Registry Run key", action: "Delete the key value", tone: "malicious" },
  "autostart-persistence": { label: "Autostart file", action: "Remove the file / symlink", tone: "accent" },
  "scheduled-task": { label: "Scheduled task", action: "Delete the task", tone: "accent" },
  "ssh-authorized-keys": { label: "SSH authorized_keys", action: "Remove the rogue key · rotate the account", tone: "malicious" },
  "suid-set": { label: "SUID/SGID binary", action: "Clear the SUID/SGID bit", tone: "malicious" },
};

export interface PersistencePoint {
  rule: string;
  label: string;
  action: string;
  target: string;
  tone: "accent" | "malicious";
}

/** Find the concrete artifact (key / path / task) behind each persistence alert. */
export function persistencePoints(alerts: Alert[], events: EventOut[]): PersistencePoint[] {
  const fired = alerts.filter((a) => a.rule_id in PERSISTENCE_RULES);
  if (fired.length === 0) return [];

  const out: PersistencePoint[] = [];
  for (const alert of fired) {
    const meta = PERSISTENCE_RULES[alert.rule_id];
    const pid = alert.related_pid;
    let target: string | null = null;
    if (alert.rule_id === "registry-persistence") {
      const hit = [...events]
        .reverse()
        .find((e) => e.event_type === "registry_write" && e.registry_key && (pid == null || e.pid === pid));
      target = hit?.registry_key ?? null;
    } else if (alert.rule_id === "autostart-persistence") {
      const hit = [...events]
        .reverse()
        .find((e) => e.event_type === "file_write" && e.file_path && (pid == null || e.pid === pid));
      target = hit?.file_path ?? null;
    } else if (alert.rule_id === "scheduled-task") {
      const hit = [...events]
        .reverse()
        .find((e) => e.command_line && /schtasks/i.test(e.command_line) && (pid == null || e.pid === pid));
      target = hit?.command_line?.split(" ").slice(0, 4).join(" ") ?? null;
    } else if (alert.rule_id === "ssh-authorized-keys") {
      const hit = [...events]
        .reverse()
        .find((e) => e.file_path && /authorized_keys/i.test(e.file_path) && (pid == null || e.pid === pid));
      target = hit?.file_path ?? null;
    } else if (alert.rule_id === "suid-set") {
      const hit = [...events]
        .reverse()
        .find((e) => e.command_line && /chmod\s+\+s|chmod\s+[0-7]{3,4}s/i.test(e.command_line) && (pid == null || e.pid === pid));
      target = hit?.command_line?.split(" ").slice(0, 4).join(" ") ?? null;
    }
    const resolved = target ?? alert.details;
    if (out.some((p) => p.rule === alert.rule_id && p.target === resolved)) continue;
    out.push({
      rule: alert.rule_id,
      label: meta.label,
      action: meta.action,
      target: resolved,
      tone: meta.tone,
    });
  }
  return out;
}

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
