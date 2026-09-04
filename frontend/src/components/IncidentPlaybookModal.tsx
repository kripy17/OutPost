import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Icon } from "./Icon";
import { listIncidentPlaybooks, applyIncidentPlaybook } from "../lib/api";
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

  const selectedPlaybook = playbooks.find((p) => p.id === selectedPlaybookId) || playbooks[0];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl">
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

                {/* Assignee Config */}
                <div className="space-y-1.5 border-t border-border-subtle pt-4">
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
              </>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-4">
          <span className="font-mono text-xs text-text-muted">
            {selectedPlaybook?.tasks.length ?? 0} tasks will be created and added to the case timeline
          </span>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs font-semibold text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => applyMutation.mutate()}
              disabled={applyMutation.isPending || !selectedPlaybook}
              className="press inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 font-mono text-xs font-bold text-bg-base hover:bg-accent/90 disabled:opacity-50"
            >
              <Icon name={applyMutation.isPending ? "refresh" : "check"} size={14} className={applyMutation.isPending ? "animate-spin" : ""} />
              <span>{applyMutation.isPending ? "Applying Playbook..." : "Apply Playbook to Case"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
