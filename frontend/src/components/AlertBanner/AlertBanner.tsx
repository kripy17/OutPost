import { useQuery } from "@tanstack/react-query";
import { SEVERITY_BG } from "../../lib/constants";
import { getRuleMeta } from "../../lib/api";
import type { Alert } from "../../types";

export default function AlertBanner({ alerts }: { alerts: Alert[] }) {
  // ATT&CK map (roadmap 1.3) — one fetch, shared by every alert card.
  // Static metadata — cache forever so monitor polling never refetches it.
  const { data: meta } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: Infinity,
  });
  const byRule = new Map((meta ?? []).map((m) => [m.rule_id, m]));

  if (alerts.length === 0) {
    return (
      <div className="rounded-lg border border-risk-clean/30 bg-bg-surface px-4 py-3">
        <p className="text-sm">
          <span className="font-semibold text-risk-clean">● Clean</span>{" "}
          <span className="text-text-muted">— no detection rules fired in this session.</span>
        </p>
      </div>
    );
  }

  const malicious = alerts.filter((a) => a.severity === "malicious").length;

  return (
    <div className="space-y-2">
      <div className="rounded-t-lg border border-risk-malicious/50 bg-bg-elevated px-4 py-3">
        <p className="text-sm font-semibold text-risk-malicious">
          {alerts.length} alert{alerts.length > 1 ? "s" : ""}
          {malicious > 0 && ` — ${malicious} malicious`}
        </p>
      </div>
      {alerts.map((alert) => {
        const rule = byRule.get(alert.rule_id);
        const accent = alert.severity === "malicious" ? "border-l-risk-malicious" : "border-l-risk-suspicious";
        return (
          <div
            key={alert.id ?? `${alert.rule_id}-${alert.triggered_at}`}
            className={`rounded-lg border border-border-subtle border-l-2 bg-bg-surface p-3 transition-colors duration-150 hover:bg-bg-elevated/40 ${accent}`}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${SEVERITY_BG[alert.severity]}`} />
              <span className="text-sm font-medium text-text-primary">{alert.rule_name}</span>
              <span className="font-mono text-xs text-text-faint">{alert.rule_id}</span>
              {rule && (
                <span
                  className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
                  title={`MITRE ATT&CK ${rule.tactic}`}
                >
                  {rule.technique} · {rule.tactic}
                </span>
              )}
              <span className="ml-auto font-mono text-xs text-text-muted">
                {alert.triggered_at.slice(11, 19)} UTC
              </span>
            </div>
            <p className="mt-1.5 pl-4 font-mono text-xs text-text-muted">{alert.details}</p>
          </div>
        );
      })}
    </div>
  );
}
