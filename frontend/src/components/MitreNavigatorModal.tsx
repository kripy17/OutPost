import { useEffect, useMemo, useState } from "react";
import { Icon } from "./Icon";

export interface MitreTechniqueEvaluation {
  id: string;
  name?: string;
  tactic?: string;
  detected: boolean;
  severity?: string;
  command?: string;
  rule_id?: string;
}

interface MitreNavigatorModalProps {
  scenarioName: string;
  techniques: MitreTechniqueEvaluation[];
  onClose: () => void;
}

const ATTACK_TACTICS = [
  { id: "Initial Access", label: "Initial Access" },
  { id: "Execution", label: "Execution" },
  { id: "Persistence", label: "Persistence" },
  { id: "Privilege Escalation", label: "Priv Escalation" },
  { id: "Defense Evasion", label: "Defense Evasion" },
  { id: "Credential Access", label: "Credential Access" },
  { id: "Discovery", label: "Discovery" },
  { id: "Lateral Movement", label: "Lateral Movement" },
  { id: "Collection", label: "Collection" },
  { id: "Command and Control", label: "Command & Control" },
  { id: "Exfiltration", label: "Exfiltration" },
  { id: "Impact", label: "Impact" },
];

export function MitreNavigatorModal({
  scenarioName,
  techniques,
  onClose,
}: MitreNavigatorModalProps) {
  const [selectedTech, setSelectedTech] = useState<MitreTechniqueEvaluation | null>(
    techniques[0] || null
  );

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const detectedCount = techniques.filter((t) => t.detected).length;
  const efficacyPct = techniques.length > 0 ? Math.round((detectedCount / techniques.length) * 100) : 100;

  // Group techniques by tactic
  const tacticGroups = useMemo(() => {
    const map = new Map<string, MitreTechniqueEvaluation[]>();
    ATTACK_TACTICS.forEach((t) => map.set(t.id, []));

    techniques.forEach((tech) => {
      // Guess tactic or match known
      const tacticKey = tech.tactic || "Execution";
      const existing = map.get(tacticKey) || [];
      existing.push(tech);
      map.set(tacticKey, existing);
    });

    return map;
  }, [techniques]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="MITRE ATT&CK Technique Matrix"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity font-mono"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-5xl flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
              <Icon name="shield" size={18} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-400 uppercase">
                  ATT&amp;CK TECHNIQUE MATRIX
                </span>
                <h2 className="text-sm font-bold text-text-primary">
                  {scenarioName}
                </h2>
              </div>
              <p className="text-[11px] text-text-muted">
                Enterprise Coverage Grid · <span className="text-emerald-400 font-bold">{detectedCount} of {techniques.length} Detected</span> ({efficacyPct}% Efficacy)
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            aria-label="Close modal"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Matrix Grid Columns */}
        <div className="flex-1 overflow-x-auto overflow-y-auto p-6 space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3 min-w-[700px]">
            {ATTACK_TACTICS.map((tactic) => {
              const items = tacticGroups.get(tactic.id) || [];
              const hasHit = items.some((i) => i.detected);

              return (
                <div
                  key={tactic.id}
                  className={`rounded-xl border p-3 space-y-2 flex flex-col ${
                    items.length > 0
                      ? hasHit
                        ? "border-emerald-500/40 bg-emerald-500/5"
                        : "border-amber-500/40 bg-amber-500/5"
                      : "border-border-subtle/50 bg-bg-base/40 opacity-70"
                  }`}
                >
                  <div className="border-b border-white/5 pb-1.5 flex items-center justify-between text-[10px]">
                    <span className="font-bold uppercase tracking-wider text-text-primary">
                      {tactic.label}
                    </span>
                    <span className="text-[9px] text-text-faint">{items.length}</span>
                  </div>

                  <div className="space-y-1.5 flex-1">
                    {items.length === 0 ? (
                      <span className="text-[9px] text-text-faint block py-4 text-center">—</span>
                    ) : (
                      items.map((tech) => (
                        <button
                          key={tech.id}
                          onClick={() => setSelectedTech(tech)}
                          className={`w-full text-left rounded-lg p-2 transition text-[10px] space-y-1 border ${
                            selectedTech?.id === tech.id
                              ? "border-accent ring-1 ring-accent bg-accent/15"
                              : tech.detected
                                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20"
                                : "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20"
                          }`}
                        >
                          <div className="flex items-center justify-between font-bold">
                            <span>{tech.id}</span>
                            <span className="text-[8px] uppercase">{tech.detected ? "✓ DETECT" : "● OBS"}</span>
                          </div>
                          <div className="truncate text-text-muted text-[9px]">{tech.name || tech.id}</div>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Technique Inspector Deck */}
          {selectedTech && (
            <div className="rounded-xl border border-border-subtle bg-bg-base/80 p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-accent/20 px-2 py-0.5 font-bold text-accent">
                    {selectedTech.id}
                  </span>
                  <span className="font-bold text-text-primary text-sm">{selectedTech.name || selectedTech.id}</span>
                </div>
                <span
                  className={`rounded px-2.5 py-0.5 text-[10px] font-bold uppercase ${
                    selectedTech.detected
                      ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                      : "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                  }`}
                >
                  {selectedTech.detected ? "Detection Validated: PASS" : "Observed Behavior: EVADED"}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <span className="text-text-faint text-[10px] uppercase font-bold block">Tactic Classification</span>
                  <p className="text-text-primary">{selectedTech.tactic || "Adversary Technique"}</p>
                </div>
                <div className="space-y-1">
                  <span className="text-text-faint text-[10px] uppercase font-bold block">Evaluation Severity</span>
                  <p className="text-accent uppercase">{selectedTech.severity || "Suspicious"}</p>
                </div>
              </div>

              {selectedTech.command && (
                <div className="space-y-1">
                  <span className="text-text-faint text-[10px] uppercase font-bold block">Attack Emulation Command:</span>
                  <pre className="rounded-lg border border-white/10 bg-[#06080d] p-3 text-[11px] text-[#c9d1d9] whitespace-pre-wrap break-all">
                    {selectedTech.command}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-3 bg-bg-base/50 text-[11px] text-text-faint">
          <span>Aligned with MITRE ATT&amp;CK Enterprise Knowledge Base</span>
          <button
            onClick={onClose}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-4 py-1.5 text-text-primary hover:border-accent"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
