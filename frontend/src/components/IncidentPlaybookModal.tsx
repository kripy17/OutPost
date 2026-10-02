import React, { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Icon } from "./Icon";
import { listIncidentPlaybooks, applyIncidentPlaybook, executeIncidentPlaybook } from "../lib/api";
import type { IncidentPlaybookItem } from "../types";

interface IncidentPlaybookModalProps {
  investigationId: string;
  onClose: () => void;
}

export const IncidentPlaybookModal: React.FC<IncidentPlaybookModalProps> = ({
  investigationId,
  onClose,
}) => {
  const queryClient = useQueryClient();
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>("ransomware_containment");
  const [assignee, setAssignee] = useState("");
  const [mode, setMode] = useState<"tasks" | "soar">("soar");
  const [autoContain, setAutoContain] = useState(false);
  const [runProbes, setRunProbes] = useState(true);
  const [targetHost, setTargetHost] = useState("local");
  const [executionResult, setExecutionResult] = useState<any | null>(null);

  const { data: playbooks = [], isLoading } = useQuery<IncidentPlaybookItem[]>({
    queryKey: ["incident-playbooks"],
    queryFn: listIncidentPlaybooks,
  });

  const applyMutation = useMutation({
    mutationFn: async () => {
      return applyIncidentPlaybook(investigationId, {
        playbook_id: selectedPlaybookId,
        assignee: assignee.trim() || undefined,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["investigation", investigationId] });
      void queryClient.invalidateQueries({ queryKey: ["investigation-tasks", investigationId] });
      void queryClient.invalidateQueries({ queryKey: ["investigation-timeline", investigationId] });
      onClose();
    },
  });

  const executeMutation = useMutation({
    mutationFn: async () => {
      return executeIncidentPlaybook(investigationId, selectedPlaybookId, {
        auto_contain: autoContain,
        run_probes: runProbes,
        target_host: targetHost.trim() || "local",
      });
    },
    onSuccess: (data) => {
      setExecutionResult(data);
      void queryClient.invalidateQueries({ queryKey: ["investigation", investigationId] });
      void queryClient.invalidateQueries({ queryKey: ["investigation-tasks", investigationId] });
      void queryClient.invalidateQueries({ queryKey: ["investigation-timeline", investigationId] });
    },
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const selectedPlaybook = playbooks.find((p) => p.id === selectedPlaybookId) || playbooks[0];

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-3xl flex-col overflow-hidden border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent">
              <Icon name="shield" size={18} />
            </span>
            <div>
              <h2 className="text-base font-bold text-text-primary">Apply Incident Response Playbook</h2>
              <p className="text-xs text-text-muted">
                Instantiate phase-structured containment and remediation procedures into this case dossier
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="grid flex-1 grid-cols-1 overflow-hidden md:grid-cols-3">
          {/* Left Column: Playbook List */}
          <div className="border-r border-border-subtle p-4 space-y-2 overflow-y-auto max-h-[60vh]">
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">
              Standardized Playbooks ({playbooks.length})
            </span>
            {isLoading ? (
              <div className="py-8 text-center text-xs text-text-muted">Loading playbooks...</div>
            ) : (
              playbooks.map((pb) => {
                const isSelected = pb.id === selectedPlaybookId;
                return (
                  <button
                    key={pb.id}
                    type="button"
                    onClick={() => setSelectedPlaybookId(pb.id)}
                    className={`w-full text-left p-3 rounded-xl border transition ${
                      isSelected
                        ? "border-accent/60 bg-accent/10 shadow-sm"
                        : "border-border-subtle bg-bg-elevated/40 hover:border-accent/40"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-mono text-[10px] font-bold uppercase ${
                        pb.severity === "critical"
                          ? "text-rose-400"
                          : pb.severity === "high"
                            ? "text-amber-400"
                            : "text-accent"
                      }`}>
                        {pb.severity}
                      </span>
                      <span className="font-mono text-[9px] text-text-faint">{pb.tactic}</span>
                    </div>
                    <div className="mt-1 font-semibold text-xs text-text-primary">{pb.name}</div>
                    <div className="mt-1 text-[11px] text-text-muted line-clamp-2">{pb.description}</div>
                  </button>
                );
              })
            )}
          </div>

          {/* Right Column: Playbook Preview & Configuration */}
          <div className="col-span-2 p-6 overflow-y-auto max-h-[60vh] space-y-5">
            {selectedPlaybook && (
              <>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-bold text-text-primary">{selectedPlaybook.name}</h3>
                    <span className="rounded bg-accent/20 px-2 py-0.5 font-mono text-xs font-bold text-accent">
                      {selectedPlaybook.tactic}
                    </span>
                  </div>
                  <p className="text-xs text-text-muted leading-relaxed">{selectedPlaybook.description}</p>
                </div>

                {/* MITRE ATT&CK & Probes */}
                <div className="grid grid-cols-2 gap-3 rounded-xl border border-border-subtle bg-bg-base/60 p-3 font-mono text-xs">
                  <div>
                    <span className="text-[10px] uppercase text-text-faint">MITRE ATT&CK Mapping</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {selectedPlaybook.mitre_attack.map((m) => (
                        <span key={m} className="rounded bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-accent">
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-text-faint">Recommended Endpoint Hunts</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {selectedPlaybook.recommended_probes.map((p) => (
                        <span key={p} className="rounded bg-bg-elevated px-1.5 py-0.5 text-[10px] text-text-muted">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Structured Tasks Breakdown */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
                      Phase-Structured Response Tasks ({selectedPlaybook.tasks.length})
                    </span>
                    <span className="text-[11px] text-text-muted">Auto-instantiated upon application</span>
                  </div>
                  <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                    {selectedPlaybook.tasks.map((t, idx) => (
                      <div
                        key={idx}
                        className="flex items-start justify-between gap-3 rounded-lg border border-border-subtle bg-bg-elevated/30 p-2.5 text-xs"
                      >
                        <div className="space-y-1">
                          <div className="font-semibold text-text-primary">{t.title}</div>
                          {t.description && (
                            <p className="text-[11px] text-text-muted">{t.description}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="rounded bg-bg-base px-1.5 py-0.5 font-mono text-[9px] uppercase text-text-faint">
                            {t.category}
                          </span>
                          <span className={`rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase ${
                            t.priority === "critical"
                              ? "bg-rose-500/20 text-rose-400"
                              : t.priority === "high"
                                ? "bg-amber-500/20 text-amber-400"
                                : "bg-bg-base text-text-muted"
                          }`}>
                            {t.priority}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Mode Selector */}
                <div className="flex items-center gap-2 border-t border-border-subtle pt-4">
                  <button
                    type="button"
                    onClick={() => setMode("soar")}
                    className={`flex-1 py-1.5 px-3 rounded-lg font-mono text-xs font-bold transition flex items-center justify-center gap-2 ${
                      mode === "soar"
                        ? "bg-accent text-bg-base shadow-sm"
                        : "bg-bg-elevated text-text-muted hover:text-text-primary"
                    }`}
                  >
                    <Icon name="play" size={12} />
                    <span>Automated SOAR Orchestrator</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setMode("tasks")}
                    className={`flex-1 py-1.5 px-3 rounded-lg font-mono text-xs font-bold transition flex items-center justify-center gap-2 ${
                      mode === "tasks"
                        ? "bg-accent text-bg-base shadow-sm"
                        : "bg-bg-elevated text-text-muted hover:text-text-primary"
                    }`}
                  >
                    <Icon name="check" size={12} />
                    <span>Task Checklist Only</span>
                  </button>
                </div>

                {executionResult ? (
                  /* Execution Results Card */
                  <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 space-y-3">
                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
                      <Icon name="check" size={16} />
                      <span>Automated SOAR Execution Successful</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
                      <div className="rounded-lg bg-bg-base p-2 border border-border-subtle">
                        <span className="text-text-muted block text-[10px]">Tasks Created</span>
                        <span className="font-bold text-text-primary">{executionResult.tasks_instantiated}</span>
                      </div>
                      <div className="rounded-lg bg-bg-base p-2 border border-border-subtle">
                        <span className="text-text-muted block text-[10px]">Probes Run</span>
                        <span className="font-bold text-text-primary">{executionResult.probes_executed_count}</span>
                      </div>
                      <div className="rounded-lg bg-bg-base p-2 border border-border-subtle">
                        <span className="text-text-muted block text-[10px]">Anomalies</span>
                        <span className={`font-bold ${executionResult.total_anomalies_detected > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                          {executionResult.total_anomalies_detected}
                        </span>
                      </div>
                    </div>
                    {executionResult.contained && (
                      <div className="flex items-center gap-2 rounded-lg bg-rose-500/20 border border-rose-500/40 px-3 py-1.5 text-xs text-rose-300 font-bold">
                        <Icon name="shield" size={14} />
                        <span>Host '{executionResult.target_host}' is now Network Isolated (Quarantined)</span>
                      </div>
                    )}
                    <div className="space-y-1">
                      <span className="font-mono text-[10px] uppercase text-text-faint">Audited SOAR Actions:</span>
                      <ul className="text-xs text-text-muted space-y-0.5 list-disc list-inside">
                        {(executionResult.actions_taken || []).map((act: string, idx: number) => (
                          <li key={idx} className="font-mono text-[11px]">{act}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ) : mode === "soar" ? (
                  /* SOAR Configuration */
                  <div className="rounded-xl border border-accent/20 bg-accent/5 p-4 space-y-3">
                    <span className="font-mono text-xs font-bold text-text-primary block">
                      SOAR Execution Parameters
                    </span>
                    <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer">
                      <input
                        type="checkbox"
                        checked={runProbes}
                        onChange={(e) => setRunProbes(e.target.checked)}
                        className="rounded border-border-subtle bg-bg-base text-accent focus:ring-0"
                      />
                      <span>Automatically execute recommended forensic hunt probes ({selectedPlaybook?.recommended_probes?.length || 0})</span>
                    </label>
                    <label className="flex items-center gap-2 text-xs text-rose-400 font-semibold cursor-pointer">
                      <input
                        type="checkbox"
                        checked={autoContain}
                        onChange={(e) => setAutoContain(e.target.checked)}
                        className="rounded border-rose-500/50 bg-bg-base text-rose-500 focus:ring-0"
                      />
                      <span>Quarantine Endpoint Immediately (Apply Host Network Isolation)</span>
                    </label>
                    <div className="space-y-1 pt-1">
                      <label className="font-mono text-[11px] text-text-muted">Target Host ID:</label>
                      <input
                        type="text"
                        value={targetHost}
                        onChange={(e) => setTargetHost(e.target.value)}
                        placeholder="local"
                        className="w-full rounded-xl border border-border-subtle bg-bg-base px-3 py-1.5 text-xs text-text-primary focus:border-accent focus:outline-none"
                      />
                    </div>
                  </div>
                ) : (
                  /* Task Checklist Configuration */
                  <div className="space-y-1.5 border-t border-border-subtle pt-2">
                    <label className="font-mono text-xs font-semibold text-text-primary">
                      Assign Response Lead (Optional)
                    </label>
                    <input
                      type="text"
                      value={assignee}
                      onChange={(e) => setAssignee(e.target.value)}
                      placeholder="e.g. secops_lead, analyst_carter"
                      className="w-full rounded-xl border border-border-subtle bg-bg-base px-3 py-2 text-xs text-text-primary focus:border-accent focus:outline-none"
                    />
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-4">
          <span className="font-mono text-xs text-text-muted">
            {executionResult
              ? "All actions logged to case audit timeline"
              : mode === "soar"
              ? "Automated triage findings and probes will be attached to case dossier"
              : `${selectedPlaybook?.tasks.length ?? 0} tasks will be created and added to the case timeline`}
          </span>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs font-semibold text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            >
              {executionResult ? "Close & View Case" : "Cancel"}
            </button>
            {!executionResult && (
              mode === "soar" ? (
                <button
                  type="button"
                  onClick={() => executeMutation.mutate()}
                  disabled={executeMutation.isPending || !selectedPlaybook}
                  className="press inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 font-mono text-xs font-bold text-bg-base hover:bg-accent/90 disabled:opacity-50 shadow-md shadow-accent/20"
                >
                  <Icon
                    name={executeMutation.isPending ? "refresh" : "play"}
                    size={14}
                    className={executeMutation.isPending ? "animate-spin" : ""}
                  />
                  <span>{executeMutation.isPending ? "Executing SOAR..." : "⚡ Execute SOAR Playbook"}</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => applyMutation.mutate()}
                  disabled={applyMutation.isPending || !selectedPlaybook}
                  className="press inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 font-mono text-xs font-bold text-bg-base hover:bg-accent/90 disabled:opacity-50"
                >
                  <Icon
                    name={applyMutation.isPending ? "refresh" : "check"}
                    size={14}
                    className={applyMutation.isPending ? "animate-spin" : ""}
                  />
                  <span>{applyMutation.isPending ? "Applying Tasks..." : "Apply Tasks to Case"}</span>
                </button>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
