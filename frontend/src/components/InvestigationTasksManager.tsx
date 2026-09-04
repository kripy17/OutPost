import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Icon } from "./Icon";
import { Panel } from "./ui";
import {
  createInvestigationTask,
  deleteInvestigationTask,
  generateRecommendedTasks,
  listInvestigationTasks,
  patchInvestigationTask,
} from "../lib/api";
import type { InvestigationTask, TaskCategory, TaskPriority, TaskStatus } from "../types";

const CATEGORY_COLORS: Record<TaskCategory, { text: string; bg: string; border: string }> = {
  containment: { text: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/30" },
  eradication: { text: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30" },
  evidence_collection: { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/30" },
  remediation: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  triage: { text: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30" },
};

const PRIORITY_BADGES: Record<TaskPriority, { label: string; text: string }> = {
  critical: { label: "P0 Critical", text: "text-rose-400 font-bold" },
  high: { label: "P1 High", text: "text-amber-400 font-semibold" },
  medium: { label: "P2 Medium", text: "text-text-muted" },
  low: { label: "P3 Low", text: "text-text-faint" },
};

export const InvestigationTasksManager: React.FC<{ investigationId: string }> = ({ investigationId }) => {
  const queryClient = useQueryClient();
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [showAddForm, setShowAddForm] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newCategory, setNewCategory] = useState<TaskCategory>("containment");
  const [newPriority, setNewPriority] = useState<TaskPriority>("high");
  const [newAssignee, setNewAssignee] = useState("");

  const { data: rawTasks, isLoading } = useQuery<InvestigationTask[]>({
    queryKey: ["investigation-tasks", investigationId],
    queryFn: () => listInvestigationTasks(investigationId),
  });
  const tasks = Array.isArray(rawTasks) ? rawTasks : [];

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["investigation-tasks", investigationId] });
    void queryClient.invalidateQueries({ queryKey: ["investigation", investigationId] });
    void queryClient.invalidateQueries({ queryKey: ["investigation-timeline", investigationId] });
  };

  const toggleTask = useMutation({
    mutationFn: async ({ taskId, currentStatus }: { taskId: number; currentStatus: TaskStatus }) => {
      const nextStatus: TaskStatus = currentStatus === "completed" ? "todo" : "completed";
      return patchInvestigationTask(investigationId, taskId, { status: nextStatus });
    },
    onSuccess: invalidate,
  });

  const addTask = useMutation({
    mutationFn: async () => {
      if (!newTitle.trim()) return;
      return createInvestigationTask(investigationId, {
        title: newTitle.trim(),
        category: newCategory,
        priority: newPriority,
        assignee: newAssignee.trim() || undefined,
      });
    },
    onSuccess: () => {
      setNewTitle("");
      setShowAddForm(false);
      invalidate();
    },
  });

  const generateAutoTasks = useMutation({
    mutationFn: async () => generateRecommendedTasks(investigationId),
    onSuccess: invalidate,
  });

  const removeTask = useMutation({
    mutationFn: async (taskId: number) => deleteInvestigationTask(investigationId, taskId),
    onSuccess: invalidate,
  });

  const completedCount = tasks.filter((t) => t.status === "completed").length;
  const progressPct = tasks.length > 0 ? Math.round((completedCount / tasks.length) * 100) : 0;

  const filteredTasks = tasks.filter(
    (t) => selectedCategory === "all" || t.category.toLowerCase() === selectedCategory.toLowerCase(),
  );

  return (
    <Panel
      kicker="Incident Response Checklist"
      title={`Containment & Remediation Tasks (${completedCount}/${tasks.length})`}
      right={
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="press inline-flex items-center gap-1 rounded-lg border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs font-semibold text-accent hover:bg-accent/20"
            onClick={() => generateAutoTasks.mutate()}
            disabled={generateAutoTasks.isPending}
            title="Analyze findings & IOCs to auto-generate response tasks"
          >
            <Icon name="terminal" size={11} className={generateAutoTasks.isPending ? "animate-spin" : ""} />
            <span>{generateAutoTasks.isPending ? "Analyzing…" : "Auto-Generate Checklist"}</span>
          </button>
          <button
            type="button"
            className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs font-semibold text-text hover:bg-bg-elevated"
            onClick={() => setShowAddForm((v) => !v)}
          >
            <Icon name="plus" size={11} />
            <span>Add Task</span>
          </button>
        </div>
      }
      className="mb-6"
    >
      <div className="space-y-4">
        {/* Progress Bar */}
        {tasks.length > 0 && (
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-text-muted mb-1.5">
              <span>Containment Progress</span>
              <span className="font-bold text-accent">{progressPct}% completed</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg-elevated">
              <div
                className="h-full rounded-full bg-accent transition-all duration-300"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>
        )}

        {/* Category Filters */}
        <div className="flex flex-wrap items-center gap-1.5 border-b border-border-subtle pb-2">
          {["all", "containment", "eradication", "evidence_collection", "remediation", "triage"].map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setSelectedCategory(cat)}
              className={`rounded-md px-2 py-1 text-[11px] font-semibold uppercase tracking-wider ${
                selectedCategory === cat
                  ? "bg-accent text-bg-base"
                  : "bg-bg-surface text-text-muted hover:bg-bg-elevated hover:text-text-normal"
              }`}
            >
              {cat.replace("_", " ")}
            </button>
          ))}
        </div>

        {/* Add Task Inline Form */}
        {showAddForm && (
          <div className="rounded-xl border border-accent/40 bg-bg-elevated/40 p-3 space-y-3">
            <span className="font-mono text-xs font-bold text-accent block">New Incident Response Action Item</span>
            <input
              type="text"
              placeholder="e.g. Isolate compromised workstation from subnet..."
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-normal outline-none focus:border-accent"
              autoFocus
            />
            <div className="flex flex-wrap items-center gap-3">
              <select
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value as TaskCategory)}
                className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-normal outline-none"
              >
                <option value="containment">Containment</option>
                <option value="eradication">Eradication</option>
                <option value="evidence_collection">Evidence Collection</option>
                <option value="remediation">Remediation</option>
                <option value="triage">Triage</option>
              </select>

              <select
                value={newPriority}
                onChange={(e) => setNewPriority(e.target.value as TaskPriority)}
                className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-normal outline-none"
              >
                <option value="critical">Critical (P0)</option>
                <option value="high">High (P1)</option>
                <option value="medium">Medium (P2)</option>
                <option value="low">Low (P3)</option>
              </select>

              <input
                type="text"
                placeholder="Assignee (e.g. secops-team)"
                value={newAssignee}
                onChange={(e) => setNewAssignee(e.target.value)}
                className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-normal outline-none"
              />

              <button
                type="button"
                onClick={() => addTask.mutate()}
                disabled={!newTitle.trim() || addTask.isPending}
                className="press rounded-lg bg-accent px-3 py-1 text-xs font-semibold text-bg-base hover:opacity-90 disabled:opacity-50"
              >
                Save Action
              </button>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="text-xs text-text-muted hover:text-text-normal"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Tasks List */}
        {isLoading ? (
          <p className="py-4 text-center text-xs text-text-muted">Loading investigation checklist...</p>
        ) : filteredTasks.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border-subtle py-8 text-center text-xs text-text-muted">
            <Icon name="check" size={20} className="mx-auto mb-2 text-text-faint" />
            <p>No checklist items recorded yet.</p>
            <p className="mt-1 text-text-faint">
              Click <strong>"Auto-Generate Checklist"</strong> to synthesize tasks from case evidence.
            </p>
          </div>
        ) : (
          <ul className="space-y-2">
            {filteredTasks.map((t) => {
              const catMeta = CATEGORY_COLORS[t.category] || CATEGORY_COLORS.triage;
              const priMeta = PRIORITY_BADGES[t.priority] || PRIORITY_BADGES.medium;
              const isCompleted = t.status === "completed";

              return (
                <li
                  key={t.id}
                  className={`flex items-start justify-between gap-3 rounded-xl border px-3 py-2.5 transition-colors ${
                    isCompleted
                      ? "border-border-subtle/40 bg-bg-surface/40 opacity-70"
                      : "border-border-subtle bg-bg-surface hover:border-accent/40"
                  }`}
                >
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <button
                      type="button"
                      onClick={() => toggleTask.mutate({ taskId: t.id, currentStatus: t.status })}
                      className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                        isCompleted
                          ? "border-emerald-500 bg-emerald-500 text-bg-base"
                          : "border-border-strong hover:border-accent bg-bg-base"
                      }`}
                      title={isCompleted ? "Mark incomplete" : "Mark completed"}
                    >
                      {isCompleted && <Icon name="check" size={10} />}
                    </button>

                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`text-xs font-medium ${
                            isCompleted ? "line-through text-text-muted" : "text-text-normal"
                          }`}
                        >
                          {t.title}
                        </span>
                        <span
                          className={`rounded border px-1.5 py-0.2 text-[9px] font-bold uppercase tracking-wider ${catMeta.text} ${catMeta.bg} ${catMeta.border}`}
                        >
                          {t.category.replace("_", " ")}
                        </span>
                        <span className={`font-mono text-[10px] ${priMeta.text}`}>{priMeta.label}</span>
                      </div>

                      <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[10px] text-text-faint">
                        {t.assignee && (
                          <span>
                            Owner: <strong className="text-text-muted">{t.assignee}</strong>
                          </span>
                        )}
                        {t.completed_at ? (
                          <span className="text-emerald-400">Completed {t.completed_at.slice(0, 19).replace("T", " ")}</span>
                        ) : (
                          <span>Created {t.created_at.slice(0, 19).replace("T", " ")}</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => removeTask.mutate(t.id)}
                    className="text-text-faint hover:text-rose-400 transition"
                    title="Delete task"
                  >
                    <Icon name="x" size={12} />
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
};
