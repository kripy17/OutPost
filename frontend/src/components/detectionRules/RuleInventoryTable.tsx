import { useMemo, useState } from "react";
import { Icon } from "../Icon";
import { Chip } from "../ui";

export interface UnifiedRuleItem {
  id: string;
  name: string;
  format: "sigma" | "yara" | "enum" | "log" | "core";
  severity: "critical" | "high" | "medium" | "low";
  tactics: string[];
  techniques: string[];
  description: string;
  status: "active" | "custom" | "tuned" | "default";
  rawContent?: string;
  source?: string;
  isCustom?: boolean;
}

interface RuleInventoryTableProps {
  rules: UnifiedRuleItem[];
  isLoading: boolean;
  onSelectRule: (rule: UnifiedRuleItem) => void;
  onBacktestRule: (rule: { id?: string; name: string; customYaml?: string }) => void;
  onTestRule: (rule: { id?: string; name: string; customYaml?: string }) => void;
}

export function RuleInventoryTable({
  rules,
  isLoading,
  onSelectRule,
  onBacktestRule,
  onTestRule,
}: RuleInventoryTableProps) {
  const [search, setSearch] = useState("");
  const [formatFilter, setFormatFilter] = useState<string>("all");
  const [tacticFilter, setTacticFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sortField, setSortField] = useState<"name" | "format" | "severity">("name");
  const [sortAsc, setSortAsc] = useState(true);

  // Extract unique tactics for filter dropdown
  const uniqueTactics = useMemo(() => {
    const set = new Set<string>();
    rules.forEach((r) => r.tactics.forEach((t) => set.add(t.toLowerCase())));
    return Array.from(set).sort();
  }, [rules]);

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (formatFilter !== "all" && r.format !== formatFilter) return false;
      if (severityFilter !== "all" && r.severity !== severityFilter) return false;
      if (tacticFilter !== "all" && !r.tactics.some((t) => t.toLowerCase() === tacticFilter)) return false;

      if (search.trim()) {
        const q = search.toLowerCase();
        const nameMatch = r.name.toLowerCase().includes(q);
        const idMatch = r.id.toLowerCase().includes(q);
        const descMatch = r.description.toLowerCase().includes(q);
        const techMatch = r.techniques.some((t) => t.toLowerCase().includes(q));
        if (!nameMatch && !idMatch && !descMatch && !techMatch) return false;
      }

      return true;
    }).sort((a, b) => {
      const valA: string = a[sortField];
      const valB: string = b[sortField];
      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [rules, formatFilter, severityFilter, tacticFilter, search, sortField, sortAsc]);

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const getFormatBadge = (fmt: UnifiedRuleItem["format"]) => {
    switch (fmt) {
      case "sigma":
        return <span className="rounded border border-accent/40 bg-accent/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-accent uppercase">Sigma AST</span>;
      case "yara":
        return <span className="rounded border border-emerald-500/40 bg-emerald-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400 uppercase">YARA</span>;
      case "enum":
        return <span className="rounded border border-cyan-500/40 bg-cyan-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cyan-400 uppercase">Enum Recon</span>;
      case "log":
        return <span className="rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400 uppercase">Log Audit</span>;
      case "core":
        return <span className="rounded border border-purple-500/40 bg-purple-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-400 uppercase">OutPost Core</span>;
    }
  };

  return (
    <div className="space-y-4 font-sans">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[280px]">
          <div className="relative min-w-64 flex-1">
            <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              type="text"
              placeholder="Search by rule name, ATT&CK technique, ID, description…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-xl border border-border-subtle bg-bg-surface py-2 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
            />
          </div>

          <select
            value={formatFilter}
            onChange={(e) => setFormatFilter(e.target.value)}
            className="rounded-xl border border-border-subtle bg-bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          >
            <option value="all">All Formats</option>
            <option value="sigma">Sigma AST</option>
            <option value="yara">YARA Signatures</option>
            <option value="enum">Enum Recon</option>
            <option value="log">Log Tamper</option>
            <option value="core">OutPost Core</option>
          </select>

          <select
            value={tacticFilter}
            onChange={(e) => setTacticFilter(e.target.value)}
            className="rounded-xl border border-border-subtle bg-bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          >
            <option value="all">All Tactics</option>
            {uniqueTactics.map((t) => (
              <option key={t} value={t}>
                {t.toUpperCase()}
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-xl border border-border-subtle bg-bg-surface px-3 py-2 text-xs outline-none focus:border-accent"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <span className="text-[11px] text-text-faint tabular-nums">
          Showing <strong>{filteredRules.length}</strong> of {rules.length} signatures
        </span>
      </div>

      {/* Rules Table */}
      {isLoading ? (
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-12 text-center font-mono text-xs text-text-muted">
          <Icon name="refresh" size={16} className="mx-auto mb-2 animate-spin text-accent" />
          <p>Querying detection signatures across rule engines…</p>
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-12 text-center font-mono text-xs text-text-muted">
          <Icon name="shield" size={24} className="mx-auto mb-2 text-text-faint" />
          <p className="font-bold text-text-primary">No Detection Signatures Found</p>
          <p className="text-text-faint mt-1">Adjust search terms or format filters to inspect signatures.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-surface shadow-xs">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold tracking-wider">
                <th className="py-2.5 px-3">Format</th>
                <th
                  className="py-2.5 px-3 cursor-pointer hover:text-text-primary"
                  onClick={() => toggleSort("name")}
                >
                  <div className="flex items-center gap-1">
                    <span>Signature Name</span>
                    {sortField === "name" && (
                      <Icon
                        name="chevronDown"
                        size={10}
                        className={`text-accent transition-transform ${sortAsc ? "rotate-180" : ""}`}
                      />
                    )}
                  </div>
                </th>
                <th className="py-2.5 px-3">MITRE ATT&amp;CK Alignment</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Engine Status</th>
                <th className="py-2.5 px-3 text-right">Engineering Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/40 text-[11px]">
              {filteredRules.map((rule) => {
                return (
                  <tr
                    key={rule.id}
                    className="hover:bg-bg-elevated/40 transition cursor-pointer"
                    onClick={() => onSelectRule(rule)}
                  >
                    {/* Format Badge */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {getFormatBadge(rule.format)}
                    </td>

                    {/* Signature Name & ID */}
                    <td className="py-2.5 px-3 max-w-[320px]">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-text-primary hover:text-accent transition" title={rule.name}>
                            {rule.name}
                          </span>
                          {rule.isCustom && (
                            <span className="rounded bg-accent/20 px-1 py-0.2 font-mono text-[9px] text-accent font-bold uppercase">
                              Custom
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-text-muted truncate" title={rule.description}>
                          {rule.description}
                        </p>
                      </div>
                    </td>

                    {/* MITRE ATT&CK */}
                    <td className="py-2.5 px-3 max-w-[200px]">
                      <div className="flex flex-wrap items-center gap-1">
                        {rule.tactics.slice(0, 2).map((tac) => (
                          <span
                            key={tac}
                            className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.2 text-[9px] font-semibold text-text-secondary uppercase"
                          >
                            {tac}
                          </span>
                        ))}
                        {rule.techniques.slice(0, 1).map((tech) => (
                          <span
                            key={tech}
                            className="rounded border border-accent/30 bg-accent/10 px-1.5 py-0.2 text-[9px] font-bold text-accent font-mono"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <Chip
                        tone={
                          rule.severity === "critical" || rule.severity === "high"
                            ? "malicious"
                            : rule.severity === "medium"
                              ? "suspicious"
                              : "clean"
                        }
                      >
                        {rule.severity}
                      </Chip>
                    </td>

                    {/* Status */}
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="text-[10px] uppercase font-semibold text-text-faint">
                        {rule.status}
                      </span>
                    </td>

                    {/* Actions */}
                    <td className="py-2.5 px-3 whitespace-nowrap text-right">
                      <div
                        className="flex items-center justify-end gap-1.5"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() => onTestRule({ id: rule.id, name: rule.name, customYaml: rule.rawContent })}
                          className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] font-semibold text-text-muted hover:border-accent hover:text-accent transition shadow-xs"
                          title="Simulate rule against synthetic telemetry"
                        >
                          Simulate
                        </button>
                        <button
                          onClick={() => onBacktestRule({ id: rule.id, name: rule.name, customYaml: rule.rawContent })}
                          className="press rounded border border-accent/40 bg-accent/10 px-2 py-1 text-[10px] font-semibold text-accent hover:bg-accent/20 transition shadow-xs"
                          title="Run historical backtest against vault runs"
                        >
                          Backtest
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
