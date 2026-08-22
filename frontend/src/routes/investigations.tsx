import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { createInvestigation, listInvestigations } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { InvestigationStatus } from "../types";

const STATUS_TABS: { value: InvestigationStatus | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "created", label: "Created" },
  { value: "triage", label: "Triage" },
  { value: "active", label: "Active" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

function InvestigationRow({ inv }: { inv: { id: string; title: string; status: InvestigationStatus; severity: "suspicious" | "malicious" | null; finding_count: number; ref_count: number; tags: string[]; updated_at: string | null; closed_at: string | null } }) {
  const sev = inv.severity;
  return (
    <li className="group flex items-start gap-3 rounded-xl border border-border-subtle bg-bg-surface px-4 py-3 transition-colors duration-150 hover:border-accent/30">
      {sev ? (
        <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={toneFill(toneForSeverity(sev))} aria-hidden />
      ) : (
        <span className="mt-1 h-2 w-2 shrink-0 rounded-full border border-border-subtle" aria-hidden />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <Link to={`/investigations/${inv.id}`} className="press truncate text-[13px] font-semibold text-text-primary hover:text-accent">
            {inv.title}
          </Link>
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {inv.status}
          </span>
          <span className="ml-auto inline-flex items-center gap-2 font-mono text-[10px] tabular-nums text-text-faint">
            <span title="Attached findings">
              <Icon name="alert" size={9} className="opacity-60" /> {inv.finding_count}
            </span>
            <span title="Evidence refs">
              <Icon name="external" size={9} className="opacity-60" /> {inv.ref_count}
            </span>
          </span>
        </div>
        {inv.tags.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {inv.tags.map((t) => (
              <Chip key={t} tone="accent">
                {t}
              </Chip>
            ))}
          </div>
        )}
        <p className="mt-1 font-mono text-[10px] text-text-faint">
          {inv.closed_at ? `closed ${inv.closed_at}` : `updated ${inv.updated_at ?? inv.closed_at ?? ""}`}
        </p>
      </div>
    </li>
  );
}

export default function InvestigationsPage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<InvestigationStatus | "">("");
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState("");
  const [tags, setTags] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["investigations", status, debouncedQ],
    queryFn: () => listInvestigations({ status: status || undefined, q: debouncedQ || undefined, limit: 100 }),
  });

  // P1.5 realtime: an investigation frame (created / closed / reopened / a
  // finding attached) refreshes the list immediately — a case opened from
  // the CLI or another surface shows up without waiting for the next poll.
  // The persisted row stays the source of truth on reconnect.
  useEventStream(
    () => undefined,
    undefined,
    (r) => {
      if (r.investigation_id !== undefined) {
        void queryClient.invalidateQueries({ queryKey: ["investigations"] });
      }
    },
  );

  const create = useMutation({
    mutationFn: () =>
      createInvestigation({
        title: title.trim(),
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: () => {
      setCreating(false);
      setTitle("");
      setTags("");
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
    },
  });

  const tabs = useMemo(
    () =>
      STATUS_TABS.map((t) => ({
        ...t,
        count: t.value === "" ? data?.total ?? 0 : undefined,
      })),
    [data],
  );

  return (
    <div className="mx-auto max-w-[1200px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Case management"
        title="Investigations"
        lede="Optional cross-workflow case anchors. An investigation connects findings, artifacts, hosts, runs, IOCs, and campaigns into one timeline — created by an analyst, never required by a workflow."
        actions={
          <button className="btn btn-primary" onClick={() => setCreating((v) => !v)}>
            <Icon name="plus" size={14} /> New investigation
          </button>
        }
      />

      {creating && (
        <Panel title="New investigation" kicker="POST /investigations" className="mb-6">
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">Title</label>
              <input
                className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                placeholder="e.g. C2 beaconing across agent fleet"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                autoFocus
              />
            </div>
            <div>
              <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">
                Tags <span className="normal-case text-text-faint">(comma-separated)</span>
              </label>
              <input
                className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                placeholder="c2, beaconing"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <button className="btn btn-primary" disabled={!title.trim() || create.isPending} onClick={() => create.mutate()}>
                {create.isPending ? "Creating…" : "Create"}
              </button>
              <button className="btn" onClick={() => setCreating(false)}>
                Cancel
              </button>
              {create.isError && <span className="text-xs text-[#C4453B]">Creation failed</span>}
            </div>
          </div>
        </Panel>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1">
          {tabs.map((t) => (
            <button
              key={t.value}
              onClick={() => setStatus(t.value)}
              className={`rounded-full border px-3 py-1 text-[11px] font-medium transition-colors ${
                status === t.value
                  ? "border-accent/50 bg-accent/10 text-accent"
                  : "border-border-subtle text-text-muted hover:border-accent/30"
              }`}
            >
              {t.label}
              {t.count !== undefined && <span className="ml-1 font-mono tabular-nums text-text-faint">{t.count}</span>}
            </button>
          ))}
        </div>
        <div className="relative ml-auto w-64">
          <Icon name="search" size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            className="w-full rounded-lg border border-border-subtle bg-bg-surface py-1.5 pl-8 pr-3 text-xs outline-none focus:border-accent/50"
            placeholder="Search title / tags / notes…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              window.setTimeout(() => setDebouncedQ(e.target.value), 250);
            }}
          />
        </div>
      </div>

      {isLoading ? (
        <Panel><p className="py-6 text-center text-sm text-text-muted">Loading investigations…</p></Panel>
      ) : isError ? (
        <Panel><p className="py-6 text-center text-sm text-[#C4453B]">Failed to load investigations</p></Panel>
      ) : (data?.investigations.length ?? 0) === 0 ? (
        <Panel>
          <div className="py-8 text-center">
            <p className="text-sm text-text-muted">
              {q || status ? "No investigations match your active filter." : "No investigations match. Investigations are optional — create one when a finding deserves a case."}
            </p>
            {(q || status) && (
              <button
                onClick={() => {
                  setQ("");
                  setDebouncedQ("");
                  setStatus("");
                }}
                className="press mt-3 inline-flex items-center gap-1.5 rounded-lg border border-accent/50 px-3 py-1 font-mono text-xs text-accent hover:bg-accent/10"
              >
                <Icon name="x" size={11} />
                Clear filters
              </button>
            )}
          </div>
        </Panel>
      ) : (
        <ul className="space-y-2">
          {data!.investigations.map((inv) => (
            <InvestigationRow key={inv.id} inv={inv} />
          ))}
        </ul>
      )}
    </div>
  );
}
