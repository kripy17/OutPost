import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";
import { Panel } from "./ui";
import { getRuleMeta } from "../lib/api";
import type { Finding } from "../types";

const ENTERPRISE_TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

interface SampleMitreMatrixProps {
  findings?: Finding[];
  rulesFired?: Array<{
    rule_id?: string;
    rule_name?: string;
    severity?: string;
    details?: string;
    technique?: string;
    tactic?: string;
  }>;
}

export function SampleMitreMatrix({ findings = [], rulesFired = [] }: SampleMitreMatrixProps) {
  const [filterQuery, setFilterQuery] = useState("");
  const { data: allRules = [] } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: 60_000,
  });

  // Build a lookup map of rule_name / rule_id to RuleMeta
  const ruleMap = useMemo(() => {
    const map = new Map<string, any>();
    if (!Array.isArray(allRules)) return map;
    for (const r of allRules) {
      if (r && r.rule_id) map.set(String(r.rule_id).toLowerCase(), r);
      if (r && r.rule_name) map.set(String(r.rule_name).toLowerCase(), r);
    }
    return map;
  }, [allRules]);

  // Merge findings and rulesFired into normalized ATT&CK detections
  const detections = useMemo(() => {
    const list: Array<{
      id: string;
      rule_id: string;
      rule_name: string;
      severity: string;
      details: string;
      technique: string;
      tactic: string;
    }> = [];

    const seen = new Set<string>();

    for (const f of findings) {
      const name = f.rule_name || "";
      const meta = ruleMap.get(name.toLowerCase());
      const technique = meta?.technique || "T1204";
      const tactic = meta?.tactic || "Execution";
      const key = `${technique}-${name}`;
      if (!seen.has(key)) {
        seen.add(key);
        list.push({
          id: String(f.id ?? key),
          rule_id: meta?.rule_id || name.toLowerCase().replace(/\s+/g, "-"),
          rule_name: name,
          severity: f.severity || meta?.severity || "suspicious",
          details: f.details || "",
          technique,
          tactic,
        });
      }
    }

    for (const r of rulesFired) {
      const name = r.rule_name || r.rule_id || "";
      const meta = ruleMap.get(name.toLowerCase()) || (r.rule_id ? ruleMap.get(r.rule_id.toLowerCase()) : undefined);
      const technique = r.technique || meta?.technique || "T1059";
      const tactic = r.tactic || meta?.tactic || "Execution";
      const key = `${technique}-${name}`;
      if (!seen.has(key)) {
        seen.add(key);
        list.push({
          id: key,
          rule_id: r.rule_id || meta?.rule_id || name.toLowerCase().replace(/\s+/g, "-"),
          rule_name: name,
          severity: r.severity || meta?.severity || "suspicious",
          details: r.details || "",
          technique,
          tactic,
        });
      }
    }

    return list;
  }, [findings, rulesFired, ruleMap]);

  // Group detections by Tactic
  const tacticGroups = useMemo(() => {
    const groups: Record<string, typeof detections> = {};
    for (const t of ENTERPRISE_TACTICS) {
      groups[t] = [];
    }

    for (const d of detections) {
      const t = d.tactic || "Execution";
      if (!groups[t]) groups[t] = [];
      groups[t].push(d);
    }
    return groups;
  }, [detections]);

  const totalTechniques = new Set(detections.map((d) => d.technique)).size;
  const activeTactics = ENTERPRISE_TACTICS.filter((t) => (tacticGroups[t]?.length ?? 0) > 0);

  return (
    <Panel
      kicker="Threat Framework Alignment"
      title="MITRE ATT&amp;CK® Behavioral Matrix"
      right={
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-text-faint">
            {totalTechniques} Technique{totalTechniques === 1 ? "" : "s"} across {activeTactics.length} Tactic{activeTactics.length === 1 ? "" : "s"}
          </span>
          <Link
            to="/coverage"
            className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-text-muted hover:border-accent hover:text-accent"
          >
            Open Coverage Matrix →
          </Link>
        </div>
      }
    >
      <div className="space-y-4 font-mono text-xs">
        {detections.length === 0 ? (
          <div className="py-8 text-center text-text-muted">
            <Icon name="grid" size={24} className="mx-auto text-text-faint mb-2" />
            <p className="font-semibold text-text-primary">No ATT&amp;CK Techniques Triggered</p>
            <p className="text-[11px] text-text-muted mt-1">
              When dynamic execution or static heuristics trigger detection rules, they are mapped to MITRE tactics here.
            </p>
          </div>
        ) : (
          <>
            {/* Filter Search */}
            <div className="flex items-center justify-between gap-3 pb-1 border-b border-border-subtle/50">
              <div className="relative w-64">
                <Icon name="search" size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
                <input
                  type="text"
                  placeholder="Filter technique or rule…"
                  value={filterQuery}
                  onChange={(e) => setFilterQuery(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-surface py-1 pl-7 pr-2.5 text-[11px] outline-none focus:border-accent/60"
                />
              </div>
              <span className="text-[10px] text-text-faint">
                Mapped against MITRE ATT&amp;CK v14 Enterprise Matrix
              </span>
            </div>

            {/* Tactics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {activeTactics.map((tactic) => {
                const items = tacticGroups[tactic].filter((d) => {
                  if (!filterQuery.trim()) return true;
                  const q = filterQuery.toLowerCase();
                  return (
                    d.technique.toLowerCase().includes(q) ||
                    d.rule_name.toLowerCase().includes(q) ||
                    d.details.toLowerCase().includes(q)
                  );
                });

                if (items.length === 0) return null;

                return (
                  <div
                    key={tactic}
                    className="rounded-xl border border-border-subtle bg-bg-base/70 p-3 space-y-2 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between border-b border-border-subtle pb-1.5 mb-2">
                        <span className="font-bold text-text-primary text-[11px] uppercase tracking-wider">
                          {tactic}
                        </span>
                        <span className="rounded bg-accent/15 px-1.5 py-0.2 text-[9px] font-bold text-accent">
                          {items.length}
                        </span>
                      </div>

                      <div className="space-y-2">
                        {items.map((item, idx) => (
                          <div
                            key={idx}
                            className={`rounded-lg border p-2 text-[10px] space-y-1 ${
                              item.severity === "malicious"
                                ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                                : "border-amber-500/40 bg-amber-500/10 text-amber-300"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold font-mono text-white">
                                {item.technique}
                              </span>
                              <span className={`rounded px-1.5 py-0.2 text-[8px] uppercase font-bold ${
                                item.severity === "malicious"
                                  ? "bg-rose-500/20 text-rose-400"
                                  : "bg-amber-500/20 text-amber-400"
                              }`}>
                                {item.severity}
                              </span>
                            </div>
                            <p className="font-medium text-text-primary truncate" title={item.rule_name}>
                              {item.rule_name}
                            </p>
                            <p className="text-[9px] text-text-muted font-mono truncate" title={`Rule: ${item.rule_id}`}>
                              Detection: {item.rule_id}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-border-subtle/50 flex justify-end">
                      <Link
                        to={`/coverage?search=${encodeURIComponent(tactic)}`}
                        className="text-[9px] text-text-faint hover:text-accent flex items-center gap-1 transition"
                      >
                        <span>Inspect in Coverage</span>
                        <Icon name="chevronRight" size={9} />
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}
