import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";

export interface MitreTechniqueItem {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  rulesCount: number;
  simulated: boolean;
  status: "covered" | "tested" | "gap";
}

const DEFAULT_TACTICS = [
  { id: "TA0001", name: "Initial Access", key: "initial-access" },
  { id: "TA0002", name: "Execution", key: "execution" },
  { id: "TA0003", name: "Persistence", key: "persistence" },
  { id: "TA0004", name: "Priv Escalation", key: "privilege-escalation" },
  { id: "TA0005", name: "Defense Evasion", key: "defense-evasion" },
  { id: "TA0006", name: "Cred Access", key: "credential-access" },
  { id: "TA0007", name: "Discovery", key: "discovery" },
  { id: "TA0008", name: "Lateral Move", key: "lateral-movement" },
  { id: "TA0009", name: "Collection", key: "collection" },
  { id: "TA0011", name: "Command & Control", key: "command-and-control" },
  { id: "TA0010", name: "Exfiltration", key: "exfiltration" },
  { id: "TA0040", name: "Impact", key: "impact" },
];

const STANDARD_TECHNIQUES: MitreTechniqueItem[] = [
  { id: "T1190", name: "Exploit Public App", tactic: "Initial Access", tacticId: "TA0001", rulesCount: 3, simulated: true, status: "covered" },
  { id: "T1566", name: "Phishing Attachment", tactic: "Initial Access", tacticId: "TA0001", rulesCount: 2, simulated: false, status: "covered" },
  { id: "T1059", name: "Command & Scripting", tactic: "Execution", tacticId: "TA0002", rulesCount: 8, simulated: true, status: "tested" },
  { id: "T1204", name: "User Execution", tactic: "Execution", tacticId: "TA0002", rulesCount: 4, simulated: true, status: "covered" },
  { id: "T1053", name: "Scheduled Task/Cron", tactic: "Persistence", tacticId: "TA0003", rulesCount: 5, simulated: true, status: "tested" },
  { id: "T1543", name: "Create System Service", tactic: "Persistence", tacticId: "TA0003", rulesCount: 3, simulated: false, status: "covered" },
  { id: "T1078", name: "Valid Accounts", tactic: "Persistence", tacticId: "TA0003", rulesCount: 1, simulated: false, status: "gap" },
  { id: "T1548", name: "Abuse Elevation (sudo)", tactic: "Priv Escalation", tacticId: "TA0004", rulesCount: 6, simulated: true, status: "tested" },
  { id: "T1055", name: "Process Injection", tactic: "Priv Escalation", tacticId: "TA0004", rulesCount: 7, simulated: true, status: "tested" },
  { id: "T1070", name: "Indicator Removal / Log Clear", tactic: "Defense Evasion", tacticId: "TA0005", rulesCount: 9, simulated: true, status: "tested" },
  { id: "T1036", name: "Masquerading Binary", tactic: "Defense Evasion", tacticId: "TA0005", rulesCount: 4, simulated: true, status: "covered" },
  { id: "T1562", name: "Impair Defenses (Disable AV)", tactic: "Defense Evasion", tacticId: "TA0005", rulesCount: 5, simulated: false, status: "covered" },
  { id: "T1003", name: "OS Credential Dumping (LSASS)", tactic: "Cred Access", tacticId: "TA0006", rulesCount: 7, simulated: true, status: "tested" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "Cred Access", tacticId: "TA0006", rulesCount: 2, simulated: false, status: "gap" },
  { id: "T1082", name: "System Info Discovery", tactic: "Discovery", tacticId: "TA0007", rulesCount: 6, simulated: true, status: "tested" },
  { id: "T1057", name: "Process Discovery", tactic: "Discovery", tacticId: "TA0007", rulesCount: 4, simulated: true, status: "covered" },
  { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", tacticId: "TA0007", rulesCount: 2, simulated: false, status: "gap" },
  { id: "T1021", name: "Remote Services (SSH/RDP)", tactic: "Lateral Move", tacticId: "TA0008", rulesCount: 4, simulated: true, status: "covered" },
  { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Move", tacticId: "TA0008", rulesCount: 3, simulated: false, status: "covered" },
  { id: "T1005", name: "Data from Local System", tactic: "Collection", tacticId: "TA0009", rulesCount: 3, simulated: false, status: "covered" },
  { id: "T1560", name: "Archive Collected Data (zip/tar)", tactic: "Collection", tacticId: "TA0009", rulesCount: 4, simulated: true, status: "covered" },
  { id: "T1071", name: "Application Layer Protocol (C2)", tactic: "Command & Control", tacticId: "TA0011", rulesCount: 11, simulated: true, status: "tested" },
  { id: "T1573", name: "Encrypted Channel (TLS C2)", tactic: "Command & Control", tacticId: "TA0011", rulesCount: 5, simulated: true, status: "tested" },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", tacticId: "TA0010", rulesCount: 6, simulated: true, status: "tested" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", tacticId: "TA0010", rulesCount: 2, simulated: false, status: "gap" },
  { id: "T1486", name: "Data Encrypted for Impact (Ransom)", tactic: "Impact", tacticId: "TA0040", rulesCount: 8, simulated: true, status: "tested" },
  { id: "T1490", name: "Inhibit System Recovery (vssadmin)", tactic: "Impact", tacticId: "TA0040", rulesCount: 5, simulated: true, status: "tested" },
];

interface MitreAttackMatrixGridProps {
  ruleMetaList?: any[];
  onSelectTechnique?: (tech: MitreTechniqueItem) => void;
  className?: string;
}

export default function MitreAttackMatrixGrid({
  ruleMetaList = [],
  onSelectTechnique,
  className = "",
}: MitreAttackMatrixGridProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTech, setSelectedTech] = useState<MitreTechniqueItem | null>(null);
  const [filterStatus, setFilterStatus] = useState<"all" | "tested" | "covered" | "gap">("all");

  // Merge ruleMetaList dynamically into technique items
  const techniquesByTactic = useMemo(() => {
    const map = new Map<string, MitreTechniqueItem[]>();
    DEFAULT_TACTICS.forEach((t) => map.set(t.id, []));

    const ruleCountsByTechnique = new Map<string, number>();
    ruleMetaList.forEach((r) => {
      const tech = (r.technique || "").toUpperCase();
      if (tech) {
        ruleCountsByTechnique.set(tech, (ruleCountsByTechnique.get(tech) || 0) + 1);
      }
    });

    const q = searchQuery.toLowerCase().trim();

    STANDARD_TECHNIQUES.forEach((tech) => {
      // Check query match
      if (q && !tech.id.toLowerCase().includes(q) && !tech.name.toLowerCase().includes(q)) {
        return;
      }

      // Check status filter
      if (filterStatus !== "all" && tech.status !== filterStatus) {
        return;
      }

      const dynamicCount = ruleCountsByTechnique.get(tech.id.toUpperCase()) ?? tech.rulesCount;
      const enrichedTech = { ...tech, rulesCount: dynamicCount };

      const list = map.get(tech.tacticId) || [];
      list.push(enrichedTech);
      map.set(tech.tacticId, list);
    });

    return map;
  }, [searchQuery, filterStatus, ruleMetaList]);

  const totalTechniques = STANDARD_TECHNIQUES.length;
  const testedCount = STANDARD_TECHNIQUES.filter((t) => t.status === "tested").length;
  const coveredCount = STANDARD_TECHNIQUES.filter((t) => t.status === "covered" || t.status === "tested").length;
  const gapCount = STANDARD_TECHNIQUES.filter((t) => t.status === "gap").length;

  return (
    <div className={`space-y-4 font-sans ${className}`}>
      {/* Top Filter and KPI Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-950 p-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="relative min-w-56">
            <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search MITRE ID or Technique..."
              className="w-full rounded-lg border border-zinc-800 bg-zinc-900 py-1.5 pl-8 pr-3 text-xs text-zinc-100 placeholder:text-zinc-500 focus:border-blue-500 outline-none"
            />
          </div>

          <div className="flex items-center rounded-lg border border-zinc-800 bg-zinc-900 p-0.5 text-xs">
            <button
              onClick={() => setFilterStatus("all")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                filterStatus === "all" ? "bg-zinc-800 text-white" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              All ({totalTechniques})
            </button>
            <button
              onClick={() => setFilterStatus("tested")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                filterStatus === "tested" ? "bg-emerald-600 text-white" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Simulated &amp; Verified ({testedCount})
            </button>
            <button
              onClick={() => setFilterStatus("gap")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                filterStatus === "gap" ? "bg-rose-600 text-white" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Coverage Gaps ({gapCount})
            </button>
          </div>
        </div>

        {/* Coverage Percentage Gauge */}
        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-[10px] text-zinc-500 uppercase font-bold block">Enterprise ATT&amp;CK Coverage</span>
            <span className="text-sm font-bold text-zinc-100">
              {Math.round((coveredCount / totalTechniques) * 100)}% Matrix Depth
            </span>
          </div>
          <div className="h-2 w-28 overflow-hidden rounded-full bg-zinc-800">
            <div
              className="h-full rounded-full bg-blue-500 transition-all duration-300"
              style={{ width: `${Math.round((coveredCount / totalTechniques) * 100)}%` }}
            />
          </div>
        </div>
      </div>

      {/* MITRE Enterprise 12-Column Grid */}
      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950 p-4 shadow-sm">
        <div className="grid grid-cols-12 gap-2.5 min-w-[1280px]">
          {DEFAULT_TACTICS.map((tactic) => {
            const techs = techniquesByTactic.get(tactic.id) || [];

            return (
              <div key={tactic.id} className="flex flex-col space-y-2">
                {/* Tactic Column Header */}
                <div className="rounded-lg border border-zinc-800/80 bg-zinc-900/60 p-2 text-center shadow-xs">
                  <span className="text-[9px] font-mono font-bold text-zinc-500 block">{tactic.id}</span>
                  <span className="text-xs font-bold text-zinc-200 block truncate" title={tactic.name}>
                    {tactic.name}
                  </span>
                  <span className="text-[10px] text-zinc-400 block mt-0.5">
                    {techs.length} techniques
                  </span>
                </div>

                {/* Technique Tiles in Column */}
                <div className="space-y-1.5 flex-1">
                  {techs.length === 0 ? (
                    <div className="rounded border border-dashed border-zinc-800/60 p-3 text-center text-[10px] text-zinc-600">
                      No matches
                    </div>
                  ) : (
                    techs.map((tech) => {
                      const isTested = tech.status === "tested";
                      const isGap = tech.status === "gap";

                      return (
                        <div
                          key={tech.id}
                          onClick={() => {
                            setSelectedTech(tech);
                            onSelectTechnique?.(tech);
                          }}
                          className={`cursor-pointer rounded-lg border p-2 text-left transition-all duration-150 hover:scale-[1.02] shadow-xs ${
                            isTested
                              ? "border-emerald-500/40 bg-emerald-950/20 hover:border-emerald-500/60"
                              : isGap
                              ? "border-rose-500/30 bg-rose-950/20 hover:border-rose-500/50"
                              : "border-zinc-800 bg-zinc-900/70 hover:border-zinc-700 hover:bg-zinc-900"
                          }`}
                        >
                          <div className="flex items-center justify-between gap-1">
                            <span className="font-mono text-[9px] font-bold text-zinc-400">{tech.id}</span>
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                isTested ? "bg-emerald-400 shadow-xs shadow-emerald-400/50" : isGap ? "bg-rose-400" : "bg-blue-400"
                              }`}
                            />
                          </div>

                          <p className="mt-1 font-semibold text-[11px] text-zinc-100 leading-tight line-clamp-2" title={tech.name}>
                            {tech.name}
                          </p>

                          <div className="mt-2 flex items-center justify-between text-[9px] text-zinc-400 font-mono">
                            <span>{tech.rulesCount} rules</span>
                            {isTested && <span className="text-emerald-400 font-bold">VERIFIED</span>}
                            {isGap && <span className="text-rose-400 font-bold">GAP</span>}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Technique Drill-Down Modal / Side Drawer */}
      {selectedTech && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-fade-in font-sans"
          onClick={() => setSelectedTech(null)}
        >
          <div
            className="w-full max-w-lg rounded-2xl border border-zinc-700 bg-zinc-950 p-6 shadow-2xl space-y-4 animate-scale-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
              <div>
                <span className="font-mono text-xs font-bold text-blue-400">{selectedTech.id} · {selectedTech.tactic}</span>
                <h3 className="text-lg font-bold text-white mt-0.5">{selectedTech.name}</h3>
              </div>
              <button
                onClick={() => setSelectedTech(null)}
                className="text-zinc-400 hover:text-white p-1 rounded hover:bg-zinc-800"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs text-zinc-300">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-3 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase font-bold block">COVERAGE POSTURE</span>
                <p className="text-zinc-200 leading-relaxed">
                  This technique is mapped to <strong>{selectedTech.rulesCount} active Sigma &amp; heuristic detection rules</strong> in the OutPost engine.
                  {selectedTech.simulated
                    ? " Continuous BAS atomic simulation tests have verified kernel telemetry ingestion and detection firing."
                    : " No atomic simulation test has been executed recently for this technique."}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2.5">
                  <span className="text-[9px] text-zinc-500 font-sans block">TACTIC IDENTIFIER</span>
                  <span className="text-zinc-200 font-bold">{selectedTech.tacticId} ({selectedTech.tactic})</span>
                </div>
                <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2.5">
                  <span className="text-[9px] text-zinc-500 font-sans block">TEST STATUS</span>
                  <span className={selectedTech.status === "tested" ? "text-emerald-400 font-bold" : selectedTech.status === "gap" ? "text-rose-400 font-bold" : "text-blue-400 font-bold"}>
                    {selectedTech.status.toUpperCase()}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-zinc-800 pt-3">
              <Link
                to={`/monitor?technique=${encodeURIComponent(selectedTech.id)}`}
                className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-semibold text-zinc-200 hover:bg-zinc-700 transition"
              >
                <Icon name="play" size={11} />
                <span>Simulate in Lab</span>
              </Link>
              <Link
                to={`/rules?tab=sigma&mode=builder&technique=${encodeURIComponent(selectedTech.id)}`}
                className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/50 bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-500 transition shadow-sm"
              >
                <Icon name="zap" size={11} />
                <span>Open in Rule Builder</span>
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
