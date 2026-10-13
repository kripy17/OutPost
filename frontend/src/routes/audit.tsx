// Analyst audit trail — who did what, when. Every triage transition, login,
// password rotation, allowlist/suppression edit, retention prune, and backup
// lands here with the acting identity. Cryptographically hash-chained and tamper-evident.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import { BASE_URL, createAuditCheckpoint, getAudit, verifyAuditChain } from "../lib/api";
import type { AuditEntry } from "../types";
import { actionMeta, auditActionKinds } from "./auditHelpers";

function ActionChip({ action }: { action: string }) {
  const meta = actionMeta(action);
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wide ${meta.cls}`}>
      {meta.label}
    </span>
  );
}

function EntryRow({ entry }: { entry: AuditEntry }) {
  const target =
    entry.target_type === "alert" && entry.target_id
      ? {
          label: `alert #${entry.target_id}`,
          to: null as string | null,
        }
      : { label: entry.target_type ?? "", to: null as string | null };

  const isFailure = entry.outcome === "failure";

  return (
    <li className="flex flex-wrap items-start gap-x-4 gap-y-1 px-4 py-2.5">
      <span className="w-16 shrink-0 pt-0.5 font-mono text-[10px] tabular-nums text-text-faint">
        {entry.ts.slice(11, 19)} <span className="text-[9px]">{entry.ts.slice(5, 10)}</span>
      </span>
      <span className="w-28 shrink-0 font-mono text-[11px] font-medium text-text-primary flex items-center gap-1.5">
        <span
          className={`inline-block h-1.5 w-1.5 rounded-full ${isFailure ? "bg-risk-malicious" : "bg-risk-clean"}`}
          title={isFailure ? "Operation Failed" : "Operation Succeeded"}
        />
        {entry.actor}
      </span>
      <span className="w-28 shrink-0">
        <ActionChip action={entry.action} />
      </span>
      <span className="w-24 shrink-0 font-mono text-[10px] text-text-faint">{target.label}</span>
      <span className="min-w-0 flex-1 break-words font-mono text-[11px] text-text-muted">{entry.detail ?? "—"}</span>
      {entry.entry_hash && (
        <span
          className="shrink-0 font-mono text-[9px] text-text-faint/70 bg-bg-elevated/40 px-1.5 py-0.5 rounded border border-border-subtle/50"
          title={`Entry SHA-256 Digest: ${entry.entry_hash}\nPrev Digest: ${entry.prev_hash ?? "genesis"}`}
        >
          #{entry.entry_hash.slice(0, 8)}
        </span>
      )}
    </li>
  );
}

export default function AuditPage() {
  const queryClient = useQueryClient();
  const [action, setAction] = useState("");
  const [checkpointStatus, setCheckpointStatus] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit", action],
    queryFn: () => getAudit({ limit: 200, action: action || undefined }),
    refetchInterval: 10_000,
  });

  const {
    data: verification,
    isLoading: isVerifying,
    refetch: refetchVerification,
  } = useQuery({
    queryKey: ["audit-verify"],
    queryFn: () => verifyAuditChain(),
    refetchInterval: 30_000,
  });

  const signCheckpointMutation = useMutation({
    mutationFn: () => createAuditCheckpoint(),
    onSuccess: (res) => {
      setCheckpointStatus(
        `Checkpoint #${res.checkpoint.checkpoint_seq} signed through audit #${res.checkpoint.last_audit_id}`
      );
      queryClient.invalidateQueries({ queryKey: ["audit-verify"] });
      setTimeout(() => setCheckpointStatus(null), 6000);
    },
    onError: (err: any) => {
      setCheckpointStatus(`Failed to sign checkpoint: ${err.message}`);
      setTimeout(() => setCheckpointStatus(null), 6000);
    },
  });

  const events = data?.events ?? [];
  const actions = auditActionKinds();

  const exportAuditCsv = () => {
    if (events.length === 0) return;
    const headers = ["Timestamp", "Actor", "Action", "Target Type", "Target ID", "Outcome", "Detail", "Entry Hash", "Prev Hash"];
    const rows = events.map((e) => [
      `"${e.ts}"`,
      `"${e.actor.replace(/"/g, '""')}"`,
      `"${e.action}"`,
      `"${e.target_type ?? ""}"`,
      `"${e.target_id ?? ""}"`,
      `"${e.outcome ?? "success"}"`,
      `"${(e.detail ?? "").replace(/"/g, '""')}"`,
      `"${e.entry_hash ?? ""}"`,
      `"${e.prev_hash ?? ""}"`,
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `outpost-audit-trail-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCheckpoint = () => {
    window.open(`${BASE_URL}/audit/checkpoint/export`, "_blank");
  };

  return (
    <div className="mx-auto max-w-[1100px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · audit"
        title={
          <>
            Audit Log <span className="font-normal text-text-muted">— who did what, when</span>
          </>
        }
        lede="Every analyst action lands here with the acting identity: triage transitions, process controls, isolation, allowlist/suppression edits, detonations, retention prunes, and backups. Cryptographically chained and protected by database-level triggers."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={exportAuditCsv}
              disabled={events.length === 0}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-[11px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
              title="Export audit log trail to CSV"
            >
              <Icon name="download" size={11} />
              Export CSV
            </button>
            <div className="flex items-center gap-0.5 overflow-hidden rounded-lg border border-border-subtle font-mono text-[10px]">
              {actions.map((a) => (
                <button
                  key={a || "all"}
                  onClick={() => setAction(a)}
                  className={`px-2.5 py-1.5 transition-colors ${
                    action === a ? "bg-accent/15 font-semibold text-accent" : "text-text-faint hover:text-text-muted"
                  }`}
                >
                  {a === "" ? "all" : a.split(".").pop()}
                </button>
              ))}
            </div>
          </div>
        }
      />

      {/* Cryptographic Chain Verification Status Line */}
      {verification && (
        <div
          className={`mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 text-xs transition-colors ${
            verification.intact
              ? "border-risk-clean/30 bg-risk-clean/5 text-text-primary"
              : "border-risk-malicious/50 bg-risk-malicious/10 text-risk-malicious"
          }`}
        >
          <div className="flex items-center gap-2.5">
            <span
              className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full ${
                verification.intact ? "bg-risk-clean/20 text-risk-clean" : "bg-risk-malicious/20 text-risk-malicious"
              }`}
            >
              <Icon name={verification.intact ? "shield" : "alert"} size={13} />
            </span>
            <div>
              <span className="font-semibold">Audit Integrity: </span>
              {verification.intact ? (
                <span className="font-mono text-risk-clean">
                  chain intact through entry {verification.verified_through}, verified at{" "}
                  {verification.verified_at ? new Date(verification.verified_at).toLocaleTimeString() : "—"}
                </span>
              ) : (
                <span className="font-mono text-risk-malicious font-medium">
                  TAMPER DETECTED at entry #{verification.first_break?.id} (row {verification.first_break?.index}):{" "}
                  {verification.first_break?.reason}
                </span>
              )}
              <span className="ml-2 text-text-faint text-[11px]">
                ({verification.total_entries} total records verified)
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => refetchVerification()}
              disabled={isVerifying}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
              title="Recompute cryptographic hash chain"
            >
              <Icon name="refresh" size={11} className={isVerifying ? "animate-spin" : ""} />
              {isVerifying ? "Verifying..." : "Verify Chain"}
            </button>
            <button
              onClick={() => signCheckpointMutation.mutate()}
              disabled={signCheckpointMutation.isPending}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
              title="Sign periodic checkpoint with local key"
            >
              <Icon name="check" size={11} />
              {signCheckpointMutation.isPending ? "Signing..." : "Sign Checkpoint"}
            </button>
            <button
              onClick={handleExportCheckpoint}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted hover:border-accent/50 hover:text-accent"
              title="Export signed checkpoint bundle for out-of-band cold storage"
            >
              <Icon name="download" size={11} />
              Export Checkpoint
            </button>
          </div>
        </div>
      )}

      {checkpointStatus && (
        <div className="mb-4 rounded-lg border border-accent/40 bg-accent/10 px-4 py-2 font-mono text-xs text-accent">
          {checkpointStatus}
        </div>
      )}

      {isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="skeleton h-11 w-full" />
          ))}
        </div>
      )}

      {isError && (
        <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't load the audit trail — is the backend running?
        </p>
      )}

      {!isLoading && !isError && (
        <Panel
          kicker="Trail"
          title={action === "" ? "All actions" : `Action · ${action}`}
          right={<span className="font-mono text-[10px] text-text-faint">{events.length} entries · newest first</span>}
        >
          {events.length === 0 ? (
            <p className="py-8 text-center text-sm text-text-muted">
              No audit entries yet — triage an alert or log in to start the trail.
            </p>
          ) : (
            <ol className="divide-y divide-border-subtle/60">
              {events.map((e) => (
                <EntryRow key={e.id} entry={e} />
              ))}
            </ol>
          )}
        </Panel>
      )}

      <p className="mt-4 text-center text-[11px] text-text-faint">
        Want the raw feed?{" "}
        <Link to="/events" className="text-accent hover:underline">
          Event Manager
        </Link>{" "}
        is the machine-level stream — this is the human-level one.
      </p>
    </div>
  );
}
