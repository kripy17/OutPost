// Alert-triage panels (analyst workflow) for the run-detail page:
//  - AllowlistPanel — per-run IOC allowlist: suppress matching alerts going
//    forward, and auto-ack already-open matching alerts (the backend counts
//    them in `acked`).
//  - SuppressionPanel — per-rule suppression scoped to THIS run: stop a noisy
//    rule from firing again on this run's future batches.
// Both call the same API the CLI could mirror; edits apply to the next
// ingested batch with no backend restart.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Icon } from "../Icon";
import { Chip, Panel } from "../ui";
import {
  addRunAllowlist,
  addSuppression,
  getRunAllowlist,
  getSuppressions,
  removeRunAllowlist,
  removeSuppression,
} from "../../lib/api";
import type { Alert, AllowlistKind } from "../../types";

const KINDS: AllowlistKind[] = ["ip", "file", "registry", "process", "hash"];

/* ── QuickAllowlist — two-click allowlisting from the network table and the
   process tree, so an analyst can whitelist a destination mid-triage without
   opening the panel: click 1 arms the button ("confirm?"), click 2 adds the
   entry for this run (auto-acks already-open matching alerts via the API's
   `acked` count). Already-allowlisted values render as a quiet check. Shares
   the ["allowlist", runId] query cache with AllowlistPanel, so the panel and
   the inline affordance always agree. */
export function QuickAllowlist({
  runId,
  kind,
  value,
  note,
}: {
  runId: string;
  kind: AllowlistKind;
  value: string;
  note?: string;
}) {
  const queryClient = useQueryClient();
  const { data: entries = [] } = useQuery({
    queryKey: ["allowlist", runId],
    queryFn: () => getRunAllowlist(runId),
    staleTime: 30_000,
  });
  const [armed, setArmed] = useState(false);

  const exists = entries.some((e) => e.kind === kind && e.value.toLowerCase() === value.toLowerCase());

  const add = useMutation({
    mutationFn: () => addRunAllowlist(runId, kind, value, note ?? `quick-add from ${kind === "ip" ? "network table" : "process tree"}`),
    onSuccess: () => {
      setArmed(false);
      // The allowlist refetch below flips this button into the "allowed"
      // check chip — that IS the feedback, no extra flash needed.
      void queryClient.invalidateQueries({ queryKey: ["allowlist", runId] });
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    },
  });

  if (exists) {
    return (
      <span
        className="inline-flex items-center gap-1 font-mono text-[9px] text-risk-clean"
        title={`Allowlisted for this run — matching alerts suppressed (${kind}: ${value})`}
      >
        <Icon name="check" size={9} />
        allowed
      </span>
    );
  }

  return (
    <button
      onClick={(e) => {
        e.stopPropagation(); // never trigger row select / node expand
        if (armed) add.mutate();
        else setArmed(true);
      }}
      onBlur={() => setArmed(false)}
      disabled={add.isPending}
      className={`press inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[9px] transition-colors duration-150 disabled:opacity-50 ${
        armed
          ? "border-risk-suspicious/60 bg-risk-suspicious/10 text-risk-suspicious"
          : "border-border-subtle text-text-faint hover:border-accent/60 hover:text-accent"
      }`}
      title={armed ? "Click again to allowlist for this run" : `Allowlist ${value} for this run`}
      aria-label={`Allowlist ${value} for this run`}
    >
      <Icon name={add.isPending ? "refresh" : armed ? "alert" : "shield"} size={9} className={add.isPending ? "animate-spin" : ""} />
      {add.isPending ? "adding…" : armed ? "confirm?" : "allowlist"}
    </button>
  );
}

export function AllowlistPanel({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<AllowlistKind>("ip");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [flash, setFlash] = useState<string | null>(null);
  const flashTimer = useRef<number | null>(null);
  useEffect(() => () => {
    if (flashTimer.current !== null) window.clearTimeout(flashTimer.current);
  }, []);

  const { data: entries = [] } = useQuery({
    queryKey: ["allowlist", runId],
    queryFn: () => getRunAllowlist(runId),
  });

  const add = useMutation({
    mutationFn: () => addRunAllowlist(runId, kind, value.trim(), note.trim()),
    onSuccess: (entry) => {
      setValue("");
      setNote("");
      setFlash(entry.acked > 0 ? `${entry.acked} matching alert${entry.acked === 1 ? "" : "s"} auto-acknowledged` : "Allowlisted — matching alerts will be suppressed");
      if (flashTimer.current !== null) window.clearTimeout(flashTimer.current);
      flashTimer.current = window.setTimeout(() => setFlash(null), 3500);
      void queryClient.invalidateQueries({ queryKey: ["allowlist", runId] });
      void queryClient.invalidateQueries({ queryKey: ["run", runId] });
    },
  });

  const remove = useMutation({
    mutationFn: (id: number) => removeRunAllowlist(runId, id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["allowlist", runId] }),
  });

  return (
    <Panel
      kicker="Triage"
      title="IOC allowlist"
      right={
        <span className="font-mono text-[10px] text-text-faint">{entries.length} entr{entries.length === 1 ? "y" : "ies"}</span>
      }
    >
      <p className="mb-3 text-xs leading-relaxed text-text-muted">
        Allowlisted IOCs stop matching alerts from firing on this run&apos;s future batches, and auto-acknowledge any
        already-open matches (e.g. your own scanner or a known dev box).
      </p>
      {flash && (
        <p className="mb-3 rounded border border-risk-clean/40 bg-risk-clean/10 px-2 py-1.5 font-mono text-[10px] text-risk-clean">
          {flash}
        </p>
      )}
      <div className="mb-3 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as AllowlistKind)}
            className="rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && value.trim()) add.mutate();
            }}
            placeholder="e.g. 203.0.113.88 or .bashrc"
            className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="reason (optional)"
            className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
          <button
            onClick={() => {
              if (value.trim()) add.mutate();
            }}
            disabled={!value.trim() || add.isPending}
            className="press rounded border border-accent/50 px-2.5 py-1 font-mono text-[11px] text-accent transition-colors hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {add.isPending ? "Adding…" : "Allowlist"}
          </button>
        </div>
      </div>
      {entries.length > 0 && (
        <ul className="divide-y divide-border-subtle/60">
          {entries.map((e) => (
            <li key={e.id} className="flex items-center gap-2 py-1.5">
              <Chip tone="accent">{e.kind}</Chip>
              <span className="min-w-0 truncate font-mono text-xs text-text-primary">{e.value}</span>
              {e.note && <span className="truncate text-[10px] text-text-faint">{e.note}</span>}
              <button
                onClick={() => remove.mutate(e.id)}
                className="ml-auto text-text-faint transition-colors hover:text-risk-malicious"
                aria-label={`Remove ${e.value} from the allowlist`}
              >
                <Icon name="x" size={12} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function SuppressionPanel({ runId, alerts }: { runId: string; alerts: Alert[] }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");

  const { data: all = [] } = useQuery({
    queryKey: ["suppressions"],
    queryFn: getSuppressions,
  });
  const active = all.filter((s) => s.run_id === runId);
  const activeRules = new Set(active.map((s) => s.rule_id));

  // The rules that fired in this run — the ones worth suppressing here.
  const fired = new Map<string, string>();
  for (const a of alerts) if (a.rule_id) fired.set(a.rule_id, a.rule_name);

  const add = useMutation({
    mutationFn: (ruleId: string) => addSuppression(ruleId, reason.trim(), runId),
    onSuccess: () => {
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => removeSuppression(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["suppressions"] }),
  });

  return (
    <Panel
      kicker="Triage"
      title="Rule suppressions"
      right={
        <span className="font-mono text-[10px] text-text-faint">{active.length} for this run</span>
      }
    >
      <p className="mb-3 text-xs leading-relaxed text-text-muted">
        Suppressing a rule stops it from firing on this run&apos;s future batches — for noisy rules that already tripped
        here. Global suppression (all runs) lives on the Rules page.
      </p>
      {fired.size === 0 ? (
        <p className="text-xs text-text-muted">No rules fired in this run yet.</p>
      ) : (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {[...fired.entries()].map(([ruleId, name]) =>
            activeRules.has(ruleId) ? (
              <span
                key={ruleId}
                className="inline-flex items-center gap-1 rounded border border-risk-clean/40 bg-risk-clean/10 px-2 py-0.5 font-mono text-[10px] text-risk-clean"
                title={`${name} — suppressed for this run`}
              >
                {ruleId} ✓
              </span>
            ) : (
              <button
                key={ruleId}
                onClick={() => add.mutate(ruleId)}
                title={`Suppress ${name} for this run`}
                className="press rounded border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-muted transition-colors hover:border-risk-malicious/50 hover:text-risk-malicious"
              >
                {ruleId}
              </button>
            ),
          )}
        </div>
      )}
      {active.length > 0 && (
        <ul className="divide-y divide-border-subtle/60">
          {active.map((s) => (
            <li key={s.id} className="flex items-center gap-2 py-1.5">
              <Chip tone="clean">suppressed</Chip>
              <span className="font-mono text-xs text-text-primary">{s.rule_id}</span>
              {s.reason && <span className="truncate text-[10px] text-text-faint">{s.reason}</span>}
              <button
                onClick={() => remove.mutate(s.id)}
                className="ml-auto font-mono text-[10px] text-text-faint transition-colors hover:text-risk-clean"
              >
                restore
              </button>
            </li>
          ))}
        </ul>
      )}
      {fired.size > 0 && (
        <div className="mt-3 flex items-center gap-2">
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="suppression reason (optional)"
            className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
      )}
    </Panel>
  );
}
