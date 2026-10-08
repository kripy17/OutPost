// Enterprise Incident Case Management & Triage Workstation (Tier-1 SOC Benchmark: Elastic Cases / TheHive 5)
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { addInvestigationRef, createInvestigation, listInvestigations } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { InvestigationStatus } from "../types";

const STATUS_TABS: { value: InvestigationStatus | ""; label: string }[] = [
  { value: "", label: "All Cases" },
  { value: "active", label: "Active" },
  { value: "triage", label: "Triage" },
  { value: "created", label: "Created" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

function statusBadge(status: InvestigationStatus) {
  switch (status) {
    case "active":
      return "border-rose-500/40 bg-rose-500/10 text-rose-400 font-bold";
    case "contained":
      return "border-amber-500/40 bg-amber-500/10 text-amber-400";
    case "resolved":
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
    case "triage":
      return "border-sky-500/40 bg-sky-500/10 text-sky-400";
    case "created":
      return "border-purple-500/40 bg-purple-500/10 text-purple-300";
    case "closed":
    default:
      return "border-border-subtle bg-bg-elevated/40 text-text-muted";
  }
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function NewCaseDrawer({
  isOpen,
  onClose,
  initialTitle = "",
  initialTags = "",
  runId,
  hostId,
}: {
  isOpen: boolean;
  onClose: () => void;
  initialTitle?: string;
  initialTags?: string;
  runId?: string | null;
  hostId?: string | null;
}) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [title, setTitle] = useState(initialTitle);
  const [tags, setTags] = useState(initialTags);
  const [severity, setSeverity] = useState<"malicious" | "suspicious" | "">("suspicious");

  useEffect(() => {
    setTitle(initialTitle);
    setTags(initialTags);
  }, [initialTitle, initialTags]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  const create = useMutation({
    mutationFn: () =>
      createInvestigation({
        title: title.trim(),
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: async (inv) => {
      onClose();
      if (runId) {
        try {
          await addInvestigationRef(inv.id, { ref_type: "run", ref_id: runId });
        } catch {
          // ignore
        }
      }
      if (hostId) {
        try {
          await addInvestigationRef(inv.id, { ref_type: "host", ref_id: hostId });
        } catch {
          // ignore
        }
      }
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
      navigate(`/investigations/${inv.id}`);
    },
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-lg flex-col overflow-hidden border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="flex items-center justify-between border-b border-border-subtle bg-bg-elevated/40 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-accent/40 bg-accent/15 text-accent">
              <Icon name="plus" size={16} />
            </span>
            <div>
              <h3 className="font-mono text-sm font-bold text-text-primary">Open Incident Case</h3>
              <p className="font-mono text-[10px] text-text-muted">Create an investigation dossier to correlate evidence</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Quick Scenario Templates */}
          <div>
            <label className="mb-2 block font-mono text-[10px] font-bold uppercase tracking-wider text-text-muted">
              Quick Case Templates
            </label>
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                onClick={() => {
                  setTitle("C2 Beaconing & Lateral Traversal");
                  setTags("c2, lateral-movement, network");
                  setSeverity("malicious");
                }}
                className="press rounded-md border border-border-subtle bg-bg-elevated/60 px-2 py-1 font-mono text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
              >
                + C2 Beaconing
              </button>
              <button
                type="button"
                onClick={() => {
                  setTitle("Ransomware Pre-Cursor & Shadow Copy Tampering");
                  setTags("ransomware, defense-evasion, vss");
                  setSeverity("malicious");
                }}
                className="press rounded-md border border-border-subtle bg-bg-elevated/60 px-2 py-1 font-mono text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
              >
                + Ransomware Drill
              </button>
              <button
                type="button"
                onClick={() => {
                  setTitle("Credential Dumping via LSASS Process Access");
                  setTags("credential-access, lsass, mimikatz");
                  setSeverity("malicious");
                }}
                className="press rounded-md border border-border-subtle bg-bg-elevated/60 px-2 py-1 font-mono text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
              >
                + Credential Access
              </button>
            </div>
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-[11px] font-semibold text-text-primary">
              Incident Case Title <span className="text-risk-malicious">*</span>
            </label>
            <input
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-sans text-sm text-text-primary outline-none focus:border-accent/60"
              placeholder="e.g. C2 beaconing across agent fleet"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              autoFocus
            />
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-[11px] font-semibold text-text-primary">
              Initial Severity Assessment
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setSeverity("malicious")}
                className={`flex items-center justify-center gap-1.5 rounded-lg border py-2 font-mono text-xs font-semibold ${
                  severity === "malicious"
                    ? "border-rose-500/60 bg-rose-500/15 text-rose-400"
                    : "border-border-subtle bg-bg-elevated/30 text-text-muted hover:border-border-strong"
                }`}
              >
                <span className="h-2 w-2 rounded-full bg-rose-500" />
                Malicious
              </button>
              <button
                type="button"
                onClick={() => setSeverity("suspicious")}
                className={`flex items-center justify-center gap-1.5 rounded-lg border py-2 font-mono text-xs font-semibold ${
                  severity === "suspicious"
                    ? "border-amber-500/60 bg-amber-500/15 text-amber-400"
                    : "border-border-subtle bg-bg-elevated/30 text-text-muted hover:border-border-strong"
                }`}
              >
                <span className="h-2 w-2 rounded-full bg-amber-500" />
                Suspicious
              </button>
              <button
                type="button"
                onClick={() => setSeverity("")}
                className={`flex items-center justify-center gap-1.5 rounded-lg border py-2 font-mono text-xs font-semibold ${
                  severity === ""
                    ? "border-sky-500/60 bg-sky-500/15 text-sky-400"
                    : "border-border-subtle bg-bg-elevated/30 text-text-muted hover:border-border-strong"
                }`}
              >
                <span className="h-2 w-2 rounded-full bg-sky-500" />
                Unassigned
              </button>
            </div>
          </div>

          <div>
            <label className="mb-1.5 block font-mono text-[11px] font-semibold text-text-primary">
              Classification Tags <span className="font-mono text-[10px] text-text-faint">(comma-separated)</span>
            </label>
            <input
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary outline-none focus:border-accent/60"
              placeholder="c2, beaconing, apt29, windows"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
          </div>

          {(runId || hostId) && (
            <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-3.5 space-y-1.5">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">
                Correlated Context Anchors
              </span>
              <div className="flex flex-wrap gap-2 font-mono text-xs">
                {runId && (
                  <span className="inline-flex items-center gap-1 rounded bg-accent/10 px-2 py-0.5 text-accent">
                    <Icon name="clock" size={10} /> Run: {runId}
                  </span>
                )}
                {hostId && (
                  <span className="inline-flex items-center gap-1 rounded bg-sky-500/10 px-2 py-0.5 text-sky-400">
                    <Icon name="box" size={10} /> Host: {hostId}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2.5 border-t border-border-subtle bg-bg-elevated/40 px-6 py-4">
          <button
            type="button"
            onClick={onClose}
            className="press rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted hover:bg-bg-elevated hover:text-text-primary"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!title.trim() || create.isPending}
            onClick={() => create.mutate()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent px-4 py-2 font-mono text-xs font-semibold text-black hover:bg-accent/90 disabled:opacity-50"
          >
            {create.isPending ? (
              <>
                <Icon name="refresh" size={12} className="animate-spin" />
                Creating…
              </>
            ) : (
              <>
                <Icon name="check" size={12} />
                Open Investigation
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function InvestigationsPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [status, setStatus] = useState<InvestigationStatus | "">("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [q, setQ] = useState("");
  const [debouncedQ, setDebouncedQ] = useState("");
  const [isDrawerOpen, setIsDrawerOpen] = useState(() => searchParams.get("create") === "1");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["investigations", status, debouncedQ],
    queryFn: () => listInvestigations({ status: status || undefined, q: debouncedQ || undefined, limit: 100 }),
  });

  useEventStream(
    () => undefined,
    undefined,
    (r) => {
      if (r.investigation_id !== undefined) {
        void queryClient.invalidateQueries({ queryKey: ["investigations"] });
      }
    },
  );

  const allInvestigations = data?.investigations ?? [];

  // Filter by severity if specified
  const filteredInvestigations = useMemo(() => {
    return allInvestigations.filter((inv) => {
      if (severityFilter === "all") return true;
      if (severityFilter === "malicious") return inv.severity === "malicious";
      if (severityFilter === "suspicious") return inv.severity === "suspicious";
      if (severityFilter === "unassigned") return !inv.severity;
      return true;
    });
  }, [allInvestigations, severityFilter]);

  // Executive SLA metrics
  const metrics = useMemo(() => {
    const total = allInvestigations.length;
    const active = allInvestigations.filter((i) => i.status === "active" || i.status === "triage" || i.status === "created").length;
    const critical = allInvestigations.filter((i) => i.severity === "malicious" && i.status !== "closed").length;
    const contained = allInvestigations.filter((i) => i.status === "contained").length;
    const resolved = allInvestigations.filter((i) => i.status === "resolved" || i.status === "closed").length;
    return { total, active, critical, contained, resolved };
  }, [allInvestigations]);

  return (
    <div className="mx-auto max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8 space-y-6">
      {/* Page Header */}
      <PageHeader
        kicker="Incident Response & Case Management"
        title="Investigations"
        lede="Enterprise cross-workflow incident dossiers. Connect alerts, endpoint processes, network C2 beacons, IOC evidence, and response playbooks into defensible investigation records."
        actions={
          <button
            onClick={() => setIsDrawerOpen(true)}
            className="press inline-flex items-center gap-2 rounded-lg border border-accent bg-accent px-3.5 py-2 font-sans text-xs font-semibold text-white shadow-xs hover:brightness-110"
          >
            <Icon name="plus" size={14} />
            Open New Incident Case
          </button>
        }
      />

      {/* Executive Case Posture Strip */}
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-5 font-sans" aria-label="Incident Posture Metrics">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-text-muted">
            <span className="text-[10px] uppercase tracking-wider font-semibold text-text-faint">Total Cases</span>
            <Icon name="notes" size={14} className="text-text-faint" />
          </div>
          <div className="mt-1 font-mono text-2xl font-bold tabular-nums text-text-primary">
            {metrics.total}
          </div>
          <p className="mt-0.5 text-[11px] text-text-muted">Logged incident anchors</p>
        </div>

        <div className="rounded-xl border border-rose-500/25 bg-rose-500/5 p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-rose-400">
            <span className="text-[10px] uppercase tracking-wider font-semibold">Critical Threat</span>
            <span className="h-2 w-2 rounded-full bg-rose-500" />
          </div>
          <div className="mt-1 font-mono text-2xl font-bold tabular-nums text-rose-400">
            {metrics.critical}
          </div>
          <p className="mt-0.5 text-[11px] text-rose-400/80">Malicious active SLA</p>
        </div>

        <div className="rounded-xl border border-accent/25 bg-accent/5 p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-accent">
            <span className="text-[10px] uppercase tracking-wider font-semibold">Active Triage</span>
            <Icon name="activity" size={14} />
          </div>
          <div className="mt-1 font-mono text-2xl font-bold tabular-nums text-accent">
            {metrics.active}
          </div>
          <p className="mt-0.5 text-[11px] text-accent/80">In flight operations</p>
        </div>

        <div className="rounded-xl border border-amber-500/25 bg-amber-500/5 p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-amber-400">
            <span className="text-[10px] uppercase tracking-wider font-semibold">Contained</span>
            <Icon name="shield" size={14} />
          </div>
          <div className="mt-1 font-mono text-2xl font-bold tabular-nums text-amber-400">
            {metrics.contained}
          </div>
          <p className="mt-0.5 text-[11px] text-amber-400/80">Network isolated / neutralized</p>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 shadow-xs">
          <div className="flex items-center justify-between text-text-muted">
            <span className="text-[10px] uppercase tracking-wider font-semibold text-text-faint">Resolved / Closed</span>
            <Icon name="check" size={14} className="text-emerald-400" />
          </div>
          <div className="mt-1 font-mono text-2xl font-bold tabular-nums text-emerald-400">
            {metrics.resolved}
          </div>
          <p className="mt-0.5 text-[11px] text-text-muted">Completed investigations</p>
        </div>
      </section>

      {/* Filter and Command Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-4 font-sans text-xs">
        {/* Status Tabs */}
        <div className="flex flex-wrap gap-1">
          {STATUS_TABS.map((t) => (
            <button
              key={t.value}
              onClick={() => setStatus(t.value)}
              className={`rounded-lg border px-3 py-1.5 font-sans text-xs font-medium transition-colors ${
                status === t.value
                  ? "border-accent/60 bg-accent/15 text-accent shadow-xs font-semibold"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:border-border-strong hover:text-text-primary"
              }`}
            >
              {t.label}
              {t.value === "" && data?.total !== undefined && (
                <span className="ml-1.5 rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-faint">
                  {data.total}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Search & Severity Filters */}
        <div className="flex items-center gap-2.5">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted outline-none focus:border-accent/50"
          >
            <option value="all">Severity: All</option>
            <option value="malicious">Critical / Malicious</option>
            <option value="suspicious">High / Suspicious</option>
            <option value="unassigned">Unassigned</option>
          </select>

          <div className="relative w-72">
            <Icon name="search" size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              className="w-full rounded-lg border border-border-subtle bg-bg-surface py-1.5 pl-8 pr-3 font-mono text-xs text-text-primary outline-none focus:border-accent/50"
              placeholder="Search case ID, title, tags…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                window.setTimeout(() => setDebouncedQ(e.target.value), 250);
              }}
            />
          </div>
        </div>
      </div>

      {/* Main Table / State View */}
      {isLoading ? (
        <Panel>
          <div className="flex items-center justify-center py-16 text-text-muted">
            <Icon name="refresh" size={20} className="mr-2 animate-spin text-accent" />
            <span className="font-mono text-xs">Loading incident case dossiers…</span>
          </div>
        </Panel>
      ) : isError ? (
        <Panel>
          <p className="py-8 text-center font-mono text-xs text-risk-malicious">
            Failed to query case management index. Verify backend connectivity.
          </p>
        </Panel>
      ) : filteredInvestigations.length === 0 ? (
        <Panel>
          <div className="py-14 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-border-subtle bg-bg-elevated/40 text-accent">
              <Icon name="notes" size={22} />
            </div>
            <p className="mt-3 font-sans text-sm font-semibold text-text-primary">
              {q || status || severityFilter !== "all" ? "No matching investigations" : "No open investigation cases"}
            </p>
            <p className="mx-auto mt-1 max-w-md font-sans text-xs text-text-muted">
              {q || status || severityFilter !== "all"
                ? "No cases matched your search query or active filter combination."
                : "Open an investigation case to correlate multiple findings, host processes, network destinations, and analyst timeline notes into a defensible incident dossier."}
            </p>
            {q || status || severityFilter !== "all" ? (
              <button
                onClick={() => {
                  setQ("");
                  setDebouncedQ("");
                  setStatus("");
                  setSeverityFilter("all");
                }}
                className="press mt-4 inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3 py-1.5 font-sans text-xs font-semibold text-accent hover:bg-accent/20"
              >
                <Icon name="x" size={11} />
                Clear active filters
              </button>
            ) : (
              <button
                onClick={() => setIsDrawerOpen(true)}
                className="press mt-4 inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-4 py-2 font-sans text-xs font-semibold text-white shadow-xs hover:brightness-110"
              >
                <Icon name="plus" size={12} />
                Open First Incident Case
              </button>
            )}
          </div>
        </Panel>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-elevated/40 font-mono text-[10px] uppercase tracking-wider text-text-muted">
                  <th className="py-3 pl-4 pr-2 w-10 text-center">Sev</th>
                  <th className="py-3 px-3">Case ID & Title</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3 text-center">Findings</th>
                  <th className="py-3 px-3 text-center">Observables</th>
                  <th className="py-3 px-3">Assignee</th>
                  <th className="py-3 px-3">Updated</th>
                  <th className="py-3 pr-4 pl-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/50 text-xs">
                {filteredInvestigations.map((inv) => {
                  const sev = inv.severity;
                  return (
                    <tr
                      key={inv.id}
                      className="group transition-colors duration-100 hover:bg-bg-elevated/40"
                    >
                      {/* Severity Dot */}
                      <td className="py-3.5 pl-4 pr-2 text-center">
                        {sev ? (
                          <span
                            className="inline-block h-2.5 w-2.5 rounded-full"
                            style={toneFill(toneForSeverity(sev))}
                            title={`Severity: ${sev}`}
                            aria-hidden
                          />
                        ) : (
                          <span
                            className="inline-block h-2 w-2 rounded-full border border-border-subtle"
                            title="Unassigned severity"
                            aria-hidden
                          />
                        )}
                      </td>

                      {/* Case ID & Title */}
                      <td className="py-3.5 px-3 min-w-[280px]">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] font-semibold text-accent">
                              {inv.id}
                            </span>
                            <Link
                              to={`/investigations/${inv.id}`}
                              className="font-medium text-text-primary hover:text-accent font-sans text-xs transition-colors"
                            >
                              {inv.title}
                            </Link>
                          </div>
                          {inv.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {inv.tags.map((t) => (
                                <Chip key={t} tone="accent">
                                  {t}
                                </Chip>
                              ))}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-3">
                        <span
                          className={`inline-block rounded-md border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${statusBadge(
                            inv.status,
                          )}`}
                        >
                          {inv.status}
                        </span>
                      </td>

                      {/* Findings count */}
                      <td className="py-3.5 px-3 text-center">
                        <span
                          className={`inline-flex items-center gap-1 font-mono text-xs tabular-nums ${
                            inv.finding_count > 0 ? "font-bold text-rose-400" : "text-text-faint"
                          }`}
                          title={`${inv.finding_count} Correlated Findings`}
                        >
                          <Icon name="alert" size={11} className="opacity-70" />
                          {inv.finding_count}
                        </span>
                      </td>

                      {/* Observables count */}
                      <td className="py-3.5 px-3 text-center">
                        <span
                          className="inline-flex items-center gap-1 font-mono text-xs tabular-nums text-text-muted"
                          title={`${inv.ref_count} Evidence Observables (Hosts, Runs, IOCs)`}
                        >
                          <Icon name="external" size={11} className="opacity-60" />
                          {inv.ref_count}
                        </span>
                      </td>

                      {/* Assignee */}
                      <td className="py-3.5 px-3 font-mono text-[11px] text-text-muted">
                        <span className="inline-flex items-center gap-1">
                          <span className="text-text-faint font-semibold">@</span>
                          {inv.created_by || "analyst"}
                        </span>
                      </td>

                      {/* Updated */}
                      <td className="py-3.5 px-3 font-mono text-[11px] text-text-faint whitespace-nowrap">
                        {inv.closed_at ? `Closed ${timeAgo(inv.closed_at)}` : timeAgo(inv.updated_at || inv.created_at)}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 pr-4 pl-2 text-right">
                        <Link
                          to={`/investigations/${inv.id}`}
                          className="press inline-flex items-center gap-1 rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/40 hover:text-accent"
                        >
                          Dossier
                          <Icon name="chevronRight" size={10} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Slide-Over New Case Drawer */}
      <NewCaseDrawer
        isOpen={isDrawerOpen}
        onClose={() => {
          setIsDrawerOpen(false);
          if (searchParams.get("create") === "1") {
            const next = new URLSearchParams(searchParams);
            next.delete("create");
            setSearchParams(next);
          }
        }}
        initialTitle={searchParams.get("title") || ""}
        initialTags={searchParams.get("tags") || ""}
        runId={searchParams.get("run_id")}
        hostId={searchParams.get("host_id")}
      />
    </div>
  );
}
