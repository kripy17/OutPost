// Analyst audit trail — who did what, when. Every triage transition, login,
// password rotation, allowlist/suppression edit, retention prune, and backup
// lands here with the acting identity. Filterable by action kind.

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader, Panel } from "../components/ui";
import { getAudit } from "../lib/api";
import type { AuditEntry } from "../types";

const ACTION_META: Record<string, { label: string; cls: string }> = {
  "alert.status": { label: "triage", cls: "border-accent/50 text-accent bg-accent/10" },
  "alert.false-positive": { label: "false positive", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "auth.login": { label: "login", cls: "border-risk-clean/50 text-risk-clean bg-risk-clean/10" },
  "auth.login.failed": { label: "login failed", cls: "border-risk-malicious/50 text-risk-malicious bg-risk-malicious/10" },
  "auth.password": { label: "password", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "allowlist.add": { label: "allowlist", cls: "border-accent/50 text-accent bg-accent/10" },
  "allowlist.remove": { label: "allowlist", cls: "border-border-subtle text-text-muted bg-bg-elevated/60" },
  "suppression.add": { label: "suppress", cls: "border-accent/50 text-accent bg-accent/10" },
  "suppression.remove": { label: "suppress", cls: "border-border-subtle text-text-muted bg-bg-elevated/60" },
  "retention.prune": { label: "retention", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "backup.create": { label: "backup", cls: "border-risk-clean/50 text-risk-clean bg-risk-clean/10" },
  "restore.apply": { label: "restore", cls: "border-risk-malicious/50 text-risk-malicious bg-risk-malicious/10" },
};

function ActionChip({ action }: { action: string }) {
  const meta = ACTION_META[action] ?? { label: action, cls: "border-border-subtle text-text-muted bg-bg-elevated/60" };
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
          // Alerts are referenced by numeric id; the detail carries the rule.
          to: null as string | null,
        }
      : { label: entry.target_type ?? "", to: null as string | null };
  return (
    <li className="flex flex-wrap items-start gap-x-4 gap-y-1 px-4 py-2.5">
      <span className="w-16 shrink-0 pt-0.5 font-mono text-[10px] tabular-nums text-text-faint">
        {entry.ts.slice(11, 19)} <span className="text-[9px]">{entry.ts.slice(5, 10)}</span>
      </span>
      <span className="w-28 shrink-0 font-mono text-[11px] font-medium text-text-primary">{entry.actor}</span>
      <span className="w-28 shrink-0">
        <ActionChip action={entry.action} />
      </span>
      <span className="w-24 shrink-0 font-mono text-[10px] text-text-faint">{target.label}</span>
      <span className="min-w-0 flex-1 break-words font-mono text-[11px] text-text-muted">{entry.detail ?? "—"}</span>
    </li>
  );
}

export default function AuditPage() {
  const [action, setAction] = useState("");
  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit", action],
    queryFn: () => getAudit({ limit: 200, action: action || undefined }),
    refetchInterval: 10_000,
  });

  const events = data?.events ?? [];
  const actions = ["", "alert.status", "alert.false-positive", "auth.login", "auth.login.failed", "auth.password", "allowlist.add", "suppression.add", "retention.prune", "backup.create"];

  return (
    <div className="mx-auto max-w-[1100px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · audit"
        title={
          <>
            Audit Log <span className="font-normal text-text-muted">— who did what, when</span>
          </>
        }
        lede="Every analyst action lands here with the acting identity: triage transitions, false-positive marks, logins, password rotations, allowlist and suppression edits, retention prunes, and backups. Read-only trail — nothing here is editable."
        actions={
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
        }
      />

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
          Event Log
        </Link>{" "}
        is the machine-level stream — this is the human-level one.
      </p>
    </div>
  );
}
