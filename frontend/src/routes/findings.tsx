import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { DataProvenanceBadge } from "../components/DataProvenanceBadge";
import { PageHeader, Panel } from "../components/ui";
import { copyToClipboard } from "../lib/clipboard";
import {
  addInvestigationRef,
  addSuppression,
  bulkUpdateAlertStatus,
  createInvestigation,
  getAlertQueue,
  getRuleMeta,
  getRunDetail,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { SEVERITY_COLORS, SEVERITY_LABEL } from "../lib/constants";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { AlertStatus, ProcessNode, QueueAlert, RuleMeta, Severity } from "../types";
import ProcessContextModal from "../components/ProcessContextModal";
import NetworkContextModal from "../components/NetworkContextModal";
import InvestigationsPage from "./investigations";
import {
  ageLabel,
  PAGE,
  provenanceChips,
  provenanceLabel,
  readSavedProvenance,
  STATUS_TABS,
  statusTabCount,
  writeSavedProvenance,
} from "./findingsHelpers";

const RULE_RATIONALE: Record<string, string> = {
  masquerading: "Process naming itself after a legitimate system executable running from an unexpected directory path.",
  "suspicious-parent-child": "Office applications, documents, or scripting engines spawning unexpected command shells or interpreters.",
  "lolbin-abuse": "Living-Off-the-Land Binaries (PowerShell, CertUtil, Mshta, etc.) invoked with evasive command-line flags or remote downloads.",
  beaconing: "Repetitive outbound network telemetry to a fixed destination with low interval variance characteristic of C2 beaconing.",
  "registry-persistence": "Modifications to Windows Run, RunOnce, or startup registry keys to establish persistence across reboots.",
  "autostart-persistence": "Creation or manipulation of startup scripts, systemd services, or autostart entries.",
  "ssh-authorized-keys": "Modifications to ~/.ssh/authorized_keys indicating unauthorized persistent SSH access configuration.",
  "scheduled-task": "Creation or modification of scheduled tasks or cron entries to execute payloads at timed intervals.",
  "suid-set": "Modifications adding SUID or SGID permission bits to Linux binaries to facilitate privilege escalation.",
  "credential-dump": "Access to or dumping of sensitive authentication stores (LSASS memory, /etc/shadow, SAM).",
  "enumeration-burst": "Rapid burst of host, domain, or user discovery commands indicative of post-exploitation discovery.",
  "data-staging": "Rapid archive creation (tar, zip) or staging in temporary directories prior to exfiltration.",
  "rename-burst": "Rapid batch renaming or file extension modification across user directories indicative of ransomware encryption.",
  "first-seen-process": "Execution of an unrecognized process or binary hash absent from historical baseline.",
  "network-scan": "Sequential or rapid port probing across multiple network targets or destination ports.",
  "lateral-rdp-smb": "Lateral authentication or administrative sessions initiated across internal network hosts.",
  "log-service-stop": "Termination or suspension of audit and event logging services to conceal attacker actions.",
  "log-clearing": "Clearing or truncation of security and audit event logs to destroy forensic telemetry.",
  "dns-tunneling": "High-volume or encoded DNS queries used to establish covert data transfer channels.",
  "dns-long-label": "Abnormally long subdomain labels in DNS queries characteristic of base32/base64 tunneling.",
  "shadow-copy-deletion": "Volume Shadow Copy deletion commands executed to prevent system rollback during attacks.",
  "remote-thread-injection": "Thread injection into external target processes to execute malicious code within trusted address spaces.",
};

function findProcessLineage(nodes: ProcessNode[] | undefined, targetPid: number, path: ProcessNode[] = []): ProcessNode[] | null {
  if (!nodes || nodes.length === 0) return null;
  for (const node of nodes) {
    const currentPath = [...path, node];
    if (node.pid === targetPid) {
      return currentPath;
    }
    if (node.children && node.children.length > 0) {
      const found = findProcessLineage(node.children, targetPid, currentPath);
      if (found) return found;
    }
  }
  return null;
}

function AlertDetailDrawer({
  alert,
  onClose,
  ruleMeta,
  onStatusChange,
  onSuppress,
  onEscalate,
}: {
  alert: QueueAlert;
  onClose: () => void;
  ruleMeta?: RuleMeta;
  onStatusChange: (id: number, status: AlertStatus) => void;
  onSuppress: (alert: QueueAlert) => void;
  onEscalate: (alert: QueueAlert) => void;
}) {
  const [copied, setCopied] = useState(false);
  const sev = alert.severity as Severity;

  const { data: runDetail, isLoading: isLoadingRun } = useQuery({
    queryKey: ["run", alert.run_id],
    queryFn: () => getRunDetail(alert.run_id),
    enabled: Boolean(alert.run_id),
  });

  const tree = runDetail?.process_tree;
  const lineagePath = alert.related_pid && tree ? findProcessLineage(tree, alert.related_pid) : null;

  const timeline = runDetail?.timeline;
  const relatedEvents = timeline
    ? (alert.evidence_event_ids && alert.evidence_event_ids.length > 0
        ? timeline.filter((e) => e.id != null && alert.evidence_event_ids!.includes(e.id))
        : timeline.filter((e) =>
            (alert.related_pid && e.pid === alert.related_pid) ||
            (alert.related_ip && e.dest_ip === alert.related_ip)
          ))
    : [];

  const rationaleText = RULE_RATIONALE[alert.rule_id] || (
    ruleMeta?.technique
      ? `Detection hypothesis aligned with MITRE ATT&CK ${ruleMeta.technique} (${ruleMeta.tactic}) with rule weight ${ruleMeta.weight}/100.`
      : null
  );

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity"
      onClick={onClose}
    >
      <div
        className="h-full w-full max-w-lg bg-bg-surface border-l border-border-subtle p-6 overflow-y-auto space-y-5 font-sans text-xs shadow-2xl animate-in slide-in-from-right duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between border-b border-border-subtle pb-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-text-faint text-[10px] uppercase">
              <span>Alert #{alert.id}</span>
              <span>·</span>
              <span>{ageLabel(alert.triggered_at)} ago</span>
              <span>·</span>
              <DataProvenanceBadge source={alert.run_source || alert.source || "live"} />
              {alert.confidence && (
                <span
                  className={`rounded border px-1.5 py-px font-mono text-[9px] font-bold ${
                    alert.confidence === "high"
                      ? "border-risk-malicious/50 bg-risk-malicious/15 text-risk-malicious"
                      : alert.confidence === "medium"
                      ? "border-accent/50 bg-accent/15 text-accent"
                      : "border-border-subtle bg-bg-elevated text-text-muted"
                  }`}
                >
                  {alert.confidence} confidence
                </span>
              )}
              {ruleMeta?.weight && (
                <span className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-px font-mono text-[9px] text-text-muted">
                  weight {ruleMeta.weight}/100
                </span>
              )}
              {alert.occurrence_count && alert.occurrence_count > 1 && (
                <span className="rounded border border-accent/40 bg-accent/15 px-1.5 py-px font-mono text-[9px] font-bold text-accent">
                  deduped ({alert.occurrence_count} occurrences)
                </span>
              )}
            </div>
            <h3 className="text-base font-bold text-text-primary flex items-center gap-2">
              <span className={SEVERITY_COLORS[sev]}>{alert.rule_name}</span>
            </h3>
            <p className="text-[11px] text-text-muted">{alert.rule_id}</p>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1.5 text-text-faint hover:text-text-primary hover:bg-bg-elevated"
            aria-label="Close alert drawer"
          >
            <Icon name="x" size={14} />
          </button>
        </div>

        {/* 1-Click Triage Actions */}
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border-subtle bg-bg-surface p-3">
          {alert.status === "open" && (
            <button
              onClick={() => onStatusChange(alert.id, "acknowledged")}
              className="press flex-1 rounded-lg border border-accent/40 bg-accent/15 py-1.5 text-center font-bold text-accent hover:bg-accent/25 transition"
            >
              Acknowledge Alert
            </button>
          )}
          {alert.status !== "resolved" && (
            <button
              onClick={() => onStatusChange(alert.id, "resolved")}
              className="press flex-1 rounded-lg border border-risk-clean/40 bg-risk-clean/15 py-1.5 text-center font-bold text-risk-clean hover:bg-risk-clean/25 transition"
            >
              Resolve Alert
            </button>
          )}
          <button
            onClick={() => onEscalate(alert)}
            className="press rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-center font-semibold text-text-secondary hover:text-text-primary hover:border-accent/40 transition"
          >
            Escalate to Case
          </button>
          {(alert.sample_name || alert.related_ip) && (
            <button
              onClick={() => onSuppress(alert)}
              className="press rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-center font-semibold text-text-muted hover:text-risk-malicious hover:border-risk-malicious/40 transition"
              title="Suppress this rule scope"
            >
              Suppress Scope
            </button>
          )}
        </div>

        {/* Rule Rationale & Hypothesis */}
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-2.5">
          <div className="flex items-center justify-between text-[10px] text-text-faint uppercase font-bold">
            <span>Rule Rationale &amp; Hypothesis</span>
            {ruleMeta && <span className="font-mono text-accent">{ruleMeta.tactic}</span>}
          </div>
          {alert.rule_condition && (
            <div className="rounded border border-accent/30 bg-accent/10 p-2 font-mono text-[11px] text-accent space-y-0.5">
              <span className="text-[9px] uppercase font-bold text-text-faint block tracking-wide">Trigger Condition:</span>
              <span className="select-all">{alert.rule_condition}</span>
            </div>
          )}
          {rationaleText ? (
            <p className="text-[11px] text-text-secondary leading-relaxed">
              {rationaleText}
            </p>
          ) : (
            <div className="rounded border border-dashed border-border-subtle bg-bg-base/40 p-2.5 text-[10px] text-text-faint italic">
              Missing evidence: No analytical detection rationale documented for rule {alert.rule_id}.
            </div>
          )}
        </div>

        {/* Process Lineage & Ancestry */}
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-2.5">
          <div className="flex items-center justify-between text-[10px] text-text-faint uppercase font-bold">
            <span>Process Lineage &amp; Ancestry</span>
            {alert.related_pid && <span className="font-mono text-accent">PID {alert.related_pid}</span>}
          </div>
          {!alert.related_pid ? (
            <div className="rounded border border-dashed border-border-subtle bg-bg-base/40 p-2.5 text-[11px] text-text-faint">
              Missing evidence: No associated process PID was captured for this finding.
            </div>
          ) : isLoadingRun ? (
            <div className="skeleton h-10 w-full" />
          ) : lineagePath && lineagePath.length > 0 ? (
            <div className="space-y-1.5 font-mono text-[11px]">
              {lineagePath.map((node, idx) => (
                <div key={node.pid} className="flex items-start gap-1.5" style={{ paddingLeft: `${idx * 14}px` }}>
                  <span className="text-text-faint">{idx === 0 ? "●" : "↳"}</span>
                  <span className={idx === lineagePath.length - 1 ? "font-bold text-accent" : "text-text-muted"}>
                    {node.process_name}
                  </span>
                  <span className="text-text-faint text-[10px]">({node.pid})</span>
                  {node.command_line && (
                    <span className="truncate text-text-faint text-[10px] max-w-[200px]" title={node.command_line}>
                      {node.command_line}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded border border-dashed border-border-subtle bg-bg-base/40 p-2.5 text-[11px] text-text-faint">
              Process lineage unavailable: PID {alert.related_pid} not found in process tree (process may have terminated before tree snapshot).
            </div>
          )}
        </div>

        {/* Raw Event Evidence */}
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-2.5">
          <div className="flex items-center justify-between text-[10px] text-text-faint uppercase font-bold">
            <span>Raw Event Evidence</span>
            <span className="font-mono text-text-faint">
              {relatedEvents.length} event(s) {alert.evidence_event_ids?.length ? "directly linked" : "matched"}
            </span>
          </div>
          {isLoadingRun ? (
            <div className="skeleton h-12 w-full" />
          ) : relatedEvents.length > 0 ? (
            <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
              {relatedEvents.map((ev, i) => (
                <div key={ev.id ?? i} className="rounded-lg border border-border-subtle bg-bg-base p-2.5 font-mono text-[10px] space-y-1">
                  <div className="flex items-center justify-between text-text-faint">
                    <span className="text-accent font-semibold">{ev.event_type}</span>
                    <span>{ev.timestamp}</span>
                  </div>
                  {ev.process_name && (
                    <div className="text-text-secondary truncate">
                      proc: {ev.process_name} (pid {ev.pid})
                    </div>
                  )}
                  {ev.command_line && (
                    <div className="text-text-muted truncate select-all" title={ev.command_line}>
                      cmd: {ev.command_line}
                    </div>
                  )}
                  {ev.dest_ip && (
                    <div className="text-text-secondary">
                      dest: {ev.dest_ip}{ev.dest_port ? `:${ev.dest_port}` : ""} ({ev.protocol || "tcp"})
                    </div>
                  )}
                  {ev.file_path && (
                    <div className="text-text-muted truncate" title={ev.file_path}>
                      file: {ev.file_path}
                    </div>
                  )}
                  {ev.raw_record && (
                    <pre className="mt-1 p-1.5 rounded bg-bg-surface text-[9px] text-text-faint overflow-x-auto whitespace-pre-wrap">
                      {ev.raw_record}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded border border-dashed border-border-subtle bg-bg-base/40 p-2.5 text-[11px] text-text-faint">
              Missing evidence: No matching raw telemetry events captured in this run timeline.
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Matrix Mapping */}
        {ruleMeta && (
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-2">
            <div className="flex items-center justify-between text-[10px] text-text-faint uppercase font-bold">
              <span>MITRE ATT&CK Alignment</span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-text-primary font-mono">{ruleMeta.technique}</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-[10px] text-text-faint block">Tactic</span>
                <span className="text-text-primary font-semibold capitalize">{ruleMeta.tactic}</span>
              </div>
              <div>
                <span className="text-[10px] text-text-faint block">Rule Weight</span>
                <span className="text-text-primary font-semibold">{ruleMeta.weight} / 100</span>
              </div>
            </div>
          </div>
        )}

        {/* Forensic Entities & Context */}
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-3">
          <span className="text-[10px] text-text-faint uppercase font-bold block">Correlated Entities</span>
          <div className="space-y-2 text-[11px]">
            {/* Host */}
            {alert.host_ids.filter(Boolean).length > 0 && (
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Target Host:</span>
                <div className="flex items-center gap-1">
                  {alert.host_ids.filter(Boolean).map((h) => (
                    <Link
                      key={h}
                      to={`/hosts/${encodeURIComponent(h)}`}
                      className="font-bold text-accent hover:underline flex items-center gap-1"
                      title={`The aggregate timeline — everything OutPost knows about ${h}`}
                    >
                      <Icon name="box" size={11} />
                      <span>{h}</span>
                    </Link>
                  ))}
                </div>
              </div>
            )}
            {/* Run */}
            {alert.run_id && (
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Sample Run:</span>
                <Link to={`/runs/${alert.run_id}`} className="font-bold text-accent hover:underline flex items-center gap-1">
                  <span>{alert.sample_name || alert.run_id}</span>
                  <Icon name="external" size={10} />
                </Link>
              </div>
            )}
            {/* Network IP */}
            {alert.related_ip && (
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Network Indicator:</span>
                <Link to={`/search?q=${encodeURIComponent(alert.related_ip)}`} className="font-bold text-accent hover:underline">
                  {alert.related_ip}
                </Link>
              </div>
            )}
            {/* Process PID */}
            {alert.related_pids && alert.related_pids.length > 0 && (
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Process PID:</span>
                <Link to={`/events?pid=${alert.related_pids.join(",")}`} className="font-bold text-accent hover:underline">
                  PID {alert.related_pids.join(", ")}
                </Link>
              </div>
            )}
            {/* Case Link */}
            {alert.investigation_id && (
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Active Case:</span>
                <Link to={`/investigations/${encodeURIComponent(alert.investigation_id)}`} className="font-bold text-accent hover:underline">
                  case {alert.investigation_id}
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Remediation Playbook Guidance */}
        {ruleMeta?.remediation && ruleMeta.remediation.length > 0 && (
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-2">
            <span className="text-[10px] text-text-faint uppercase font-bold block">SOC Remediation Playbook</span>
            <ul className="space-y-1.5 text-[11px] text-text-secondary list-disc pl-4">
              {ruleMeta.remediation.map((step, idx) => (
                <li key={idx} className="leading-relaxed">{step}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Alert Details Message */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[10px] text-text-faint uppercase">
            <span>Detection Details</span>
            <button
              onClick={() => {
                void copyToClipboard(alert.details);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="text-accent hover:underline"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <pre className="rounded-xl border border-border-subtle bg-bg-base p-3 text-[11px] text-text-primary whitespace-pre-wrap break-all select-all">
            {alert.details}
          </pre>
        </div>

        {/* Footer */}
        <div className="border-t border-border-subtle pt-3 flex justify-end">
          <button
            onClick={onClose}
            className="press rounded-lg border border-border-subtle bg-bg-surface px-4 py-1.5 text-xs text-text-primary hover:bg-bg-elevated"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}

function FindingRow({
  a,
  selected,
  isCursorActive,
  innerRef,
  onToggle,
  ruleNames,
  ruleMap,
  onSuppress,
  suppressing,
  onStatusChange,
  onInspectIp,
  onInspectPid,
  onInspect,
}: {
  a: QueueAlert;
  selected: boolean;
  isCursorActive?: boolean;
  innerRef?: (el: HTMLLIElement | null) => void;
  onToggle: (id: number) => void;
  ruleNames: Map<string, string>;
  ruleMap?: Map<string, { tactic: string; technique: string }>;
  onSuppress: (a: QueueAlert) => void;
  suppressing: boolean;
  onStatusChange?: (id: number, status: AlertStatus) => void;
  onInspectIp?: (ip: string) => void;
  onInspectPid?: (pid: number) => void;
  onInspect?: (a: QueueAlert) => void;
}) {
  const sev = a.severity as Severity;
  const mitre = ruleMap?.get(a.rule_id);

  return (
    <li
      ref={innerRef}
      tabIndex={0}
      aria-selected={isCursorActive}
      data-finding-id={a.id}
      data-cursor-active={isCursorActive ? "true" : undefined}
      className={`group flex items-start gap-3 rounded-xl border px-4 py-3 transition-all duration-150 ${
        isCursorActive
          ? "border-accent ring-2 ring-accent/60 bg-accent/10 shadow-sm"
          : selected
          ? "border-accent/50 bg-accent/5"
          : "border-border-subtle bg-bg-surface hover:border-accent/30"
      }`}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(a.id)}
        aria-label={`Select ${a.rule_name} finding`}
        className="mt-1 h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
      />
      {/* Pattern-encoded severity dot (deck-wide fill language). */}
      <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={toneFill(toneForSeverity(sev))} title={SEVERITY_LABEL[sev]} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className={`text-[13px] font-semibold ${SEVERITY_COLORS[sev]}`}>
            {ruleNames.get(a.rule_id) ?? a.rule_name}
          </span>
          {isCursorActive && (
            <span className="rounded bg-accent/20 px-1 py-px font-mono text-[9px] font-bold text-accent uppercase">
              active
            </span>
          )}
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {a.rule_id}
          </span>
          {mitre && (
            <span
              className="rounded border border-border-subtle bg-bg-elevated/60 px-1.5 py-px font-mono text-[9px] text-text-faint"
              title={`MITRE ATT&CK ${mitre.tactic}`}
            >
              {mitre.technique} · {mitre.tactic}
            </span>
          )}
          {a.confidence && (
            <span
              className={`rounded border px-1.5 py-px font-mono text-[9px] font-bold uppercase ${
                a.confidence === "high"
                  ? "border-risk-malicious/40 bg-risk-malicious/10 text-risk-malicious"
                  : a.confidence === "medium"
                  ? "border-accent/40 bg-accent/10 text-accent"
                  : "border-border-subtle bg-bg-elevated/40 text-text-muted"
              }`}
              title={`Detection confidence: ${a.confidence}`}
            >
              {a.confidence}
            </span>
          )}
          {a.occurrence_count && a.occurrence_count > 1 && (
            <span
              className="rounded border border-accent/40 bg-accent/15 px-1.5 py-px font-mono text-[9px] font-bold text-accent"
              title={`Deduplicated ${a.occurrence_count} occurrences into this finding`}
            >
              ×{a.occurrence_count}
            </span>
          )}
          <DataProvenanceBadge source={a.run_source || a.source || "live"} />
          <span
            className="ml-auto rounded-full border border-border-subtle px-1.5 py-px font-mono text-[10px] tabular-nums text-text-faint"
            title={`Triggered ${a.triggered_at}`}
          >
            {ageLabel(a.triggered_at)} ago
          </span>
        </div>
        <p className="mt-0.5 truncate font-sans text-xs text-text-muted leading-relaxed" title={a.details}>
          {a.details}
        </p>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-text-faint">
          <Link to={`/runs/${a.run_id}`} className="press inline-flex items-center gap-1 font-mono font-medium text-accent hover:underline">
            {a.sample_name}
            <Icon name="external" size={9} className="opacity-60" />
          </Link>
          {a.host_ids.filter(Boolean).map((h) => (
            <Link
              key={h}
              to={`/hosts/${encodeURIComponent(h)}`}
              className="press inline-flex items-center gap-1 font-mono text-text-muted hover:text-accent"
              title={`The aggregate timeline — everything OutPost knows about ${h}`}
            >
              <Icon name="terminal" size={9} className="opacity-60" />
              {h}
            </Link>
          ))}
          {a.related_ip && (
            <span className="inline-flex items-center gap-1">
              <Link to={`/search?q=${encodeURIComponent(a.related_ip)}`} className="press font-mono text-accent hover:underline">
                {a.related_ip}
              </Link>
              {onInspectIp && (
                <button
                  onClick={() => onInspectIp(a.related_ip as string)}
                  className="press inline-flex items-center gap-0.5 rounded border border-accent/40 bg-accent/10 px-1 py-px font-mono text-[9px] text-accent hover:bg-accent/20"
                  title={`Inspect network context for ${a.related_ip}`}
                >
                  <Icon name="activity" size={9} />
                  Context
                </button>
              )}
            </span>
          )}
          {a.related_pids.filter(Boolean).length > 0 && (
            <span className="inline-flex items-center gap-1">
              <Link to={`/events?pid=${a.related_pids.join(",")}`} className="press font-mono hover:text-accent">
                pid {a.related_pids.join(",")}
              </Link>
              {onInspectPid && a.related_pids[0] && (
                <button
                  onClick={() => onInspectPid(a.related_pids[0])}
                  className="press inline-flex items-center gap-0.5 rounded border border-border-subtle bg-bg-elevated/60 px-1 py-px font-mono text-[9px] text-text-muted hover:border-accent/40 hover:text-accent"
                  title={`Inspect process context for PID ${a.related_pids[0]}`}
                >
                  <Icon name="terminal" size={9} />
                  PID
                </button>
              )}
            </span>
          )}
          {a.investigation_id && (
            <Link
              to={`/investigations/${encodeURIComponent(a.investigation_id)}`}
              className="press inline-flex items-center gap-1 font-mono text-text-muted hover:text-accent"
              title={`Attached to the investigation ${a.investigation_id}`}
            >
              <Icon name="notes" size={9} className="opacity-60" />
              case {a.investigation_id.slice(0, 12)}
            </Link>
          )}
          {a.assignee && <span className="font-mono">→ {a.assignee}</span>}
          {a.status !== "open" && (
            <span className="font-mono uppercase tracking-wide">
              {a.status}
              {a.status_comment ? ` — ${a.status_comment}` : ""}
            </span>
          )}

          {/* Quick inline triage actions */}
          <div className="ml-auto flex items-center gap-1.5 font-mono text-[10px]">
            {onInspect && (
              <button
                onClick={() => onInspect(a)}
                className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-muted hover:border-accent/50 hover:text-accent transition"
                title="Inspect finding in detail drawer"
              >
                <Icon name="eye" size={9} />
                <span>inspect</span>
              </button>
            )}
            {a.status === "open" && onStatusChange && (
              <button
                onClick={() => onStatusChange(a.id, "acknowledged")}
                className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-muted hover:border-signal/50 hover:text-signal transition"
                title="Acknowledge alert"
              >
                <Icon name="check" size={9} />
                <span>ack</span>
              </button>
            )}
            {a.status !== "resolved" && onStatusChange && (
              <button
                onClick={() => onStatusChange(a.id, "resolved")}
                className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-muted hover:border-risk-clean/50 hover:text-risk-clean transition"
                title="Resolve alert"
              >
                <Icon name="check" size={9} />
                <span>resolve</span>
              </button>
            )}
            <Link
              to={`/investigations?create=1&alert_id=${a.id}&title=${encodeURIComponent(a.rule_name + " Incident")}`}
              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-muted hover:border-accent/50 hover:text-accent transition"
              title="Create case from finding"
            >
              <Icon name="notes" size={9} />
              <span>case</span>
            </Link>
            {(a.sample_name || a.related_ip) && (
              <button
                onClick={() => onSuppress(a)}
                disabled={suppressing}
                className="press font-mono text-[9px] uppercase tracking-wide text-text-faint transition-colors hover:text-risk-malicious disabled:opacity-40"
                title={`Suppress ${a.rule_id} for ${a.sample_name || a.related_ip} — future runs of this sample/C2 stop firing it`}
              >
                {suppressing ? "…" : "suppress"}
              </button>
            )}
          </div>
        </div>
      </div>
    </li>
  );
}

export default function FindingsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const status = (searchParams.get("status") as "open" | "acknowledged" | "resolved" | "all") ?? "open";
  const sort = (searchParams.get("sort") as "aging" | "newest") ?? "aging";
  const sev = (searchParams.get("severity") as Severity | "") ?? "";
  // Provenance split (real hosts vs synthetic/demo) — mirrors the History
  // archive's default hide-synthetic behavior, so demo noise can be hidden
  // or selected for a bulk ack without hand-picking sample names. An explicit
  // ?provenance= wins; otherwise each status tab's saved preference applies
  // ("real hosts first" survives navigation like the search draft).
  const provParam = searchParams.get("provenance");
  const provenance: "" | "real" | "synthetic" =
    provParam === "real" || provParam === "synthetic" ? provParam : readSavedProvenance(status);
  const q = searchParams.get("q") ?? "";
  const [activeTab, setActiveTab] = useState<"findings" | "investigations">(() => (searchParams.get("tab") as any) || "findings");
  const [submittedQ, setSubmittedQ] = useState(q);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [cursorIndex, setCursorIndex] = useState(0);
  const [busy, setBusy] = useState(false);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [inspectFinding, setInspectFinding] = useState<QueueAlert | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const rowRefs = useRef<Map<number, HTMLLIElement>>(new Map());

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(searchParams);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  // Changing provenance updates the URL AND remembers it for the active tab.
  const setProvenance = (v: string) => {
    writeSavedProvenance(status, (v === "real" || v === "synthetic" ? v : "") as "" | "real" | "synthetic");
    setParam("provenance", v);
  };

  // Switching tabs applies THAT tab's saved preference (each status keeps its
  // own split), folding it into one navigation so nothing gets lost.
  const switchStatus = (v: string) => {
    const saved = readSavedProvenance(v);
    const next = new URLSearchParams(searchParams);
    if (saved) next.set("provenance", saved);
    else next.delete("provenance");
    next.set("status", v === "open" ? "" : v);
    next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  const { data, isLoading, isError } = useQuery({
    queryKey: ["alerts", "queue", status, sort, sev, provenance, submittedQ, offset],
    queryFn: () =>
      getAlertQueue({
        status,
        severity: sev || undefined,
        provenance: provenance || undefined,
        q: submittedQ || undefined,
        sort,
        limit: PAGE,
        offset,
      }),
  });

  // P1.5 realtime: the queue is a live surface — a fired alert (new
  // detection) or a run-update naming a finding (attach/detach moved its
  // investigation link) refreshes the sweep immediately. The DB row stays
  // the source of truth on reconnect; the queue's own mutations invalidate
  // as before (push is an enhancement over the default refetch, never a
  // dependency).
  useEventStream(
    () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    },
    undefined,
    (r) => {
      if (r.finding_id !== undefined) {
        void queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      }
    },
  );
  const { data: ruleMeta } = useQuery({ queryKey: ["rules", "meta"], queryFn: getRuleMeta });
  const ruleNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of ruleMeta ?? []) m.set(r.rule_id, r.rule_name);
    return m;
  }, [ruleMeta]);

  const ruleMap = useMemo(() => {
    const m = new Map<string, { tactic: string; technique: string }>();
    for (const r of ruleMeta ?? []) m.set(r.rule_id, { tactic: r.tactic, technique: r.technique });
    return m;
  }, [ruleMeta]);

  const ruleMetaMap = useMemo(() => {
    const m = new Map<string, RuleMeta>();
    for (const r of ruleMeta ?? []) m.set(r.rule_id, r);
    return m;
  }, [ruleMeta]);

  const handleSingleStatus = useCallback(
    async (id: number, nextStatus: AlertStatus) => {
      if (busy) return;
      setBusy(true);
      setMsg(null);
      try {
        await bulkUpdateAlertStatus([id], nextStatus);
        setMsg({ ok: true, text: `Finding #${id} marked ${nextStatus}.` });
        await queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
        await queryClient.invalidateQueries({ queryKey: ["statusbar"] });
        if (inspectFinding && inspectFinding.id === id) {
          setInspectFinding({ ...inspectFinding, status: nextStatus });
        }
      } catch (err) {
        console.error("Failed to update status:", err);
        setMsg({ ok: false, text: `Failed to update status for finding #${id}.` });
      } finally {
        setBusy(false);
      }
    },
    [busy, inspectFinding, queryClient]
  );

  const handleAcknowledgeAlert = useCallback(
    async (target: QueueAlert) => {
      await handleSingleStatus(target.id, "acknowledged");
    },
    [handleSingleStatus]
  );

  const handleEscalateSingle = useCallback(
    async (target: QueueAlert) => {
      if (busy) return;
      setBusy(true);
      setMsg(null);
      try {
        const title = `Incident Case: ${target.rule_name}${target.sample_name ? ` (${target.sample_name})` : ""} [Alert #${target.id}]`;
        const inv = await createInvestigation({
          title,
          tags: ["escalated-finding", target.rule_id],
        });
        if (target.run_id) {
          try {
            await addInvestigationRef(inv.id, { ref_type: "run", ref_id: target.run_id });
          } catch {
            // best-effort
          }
        }
        setMsg({ ok: true, text: `Created investigation case for finding #${target.id}.` });
        navigate(`/investigations/${inv.id}`);
      } catch {
        setMsg({ ok: false, text: `Failed to create investigation case for finding #${target.id}.` });
      } finally {
        setBusy(false);
      }
    },
    [busy, navigate]
  );

  const alerts = useMemo(() => data?.alerts ?? [], [data?.alerts]);
  const onPage = alerts.map((a) => a.id);

  // Preserve cursor within valid range when alerts array updates
  useEffect(() => {
    if (alerts.length === 0) {
      setCursorIndex(0);
    } else {
      setCursorIndex((cur) => Math.min(Math.max(0, cur), alerts.length - 1));
    }
  }, [alerts]);

  // Scroll active cursor row into view
  useEffect(() => {
    if (alerts.length > 0 && alerts[cursorIndex]) {
      const el = rowRefs.current.get(alerts[cursorIndex].id);
      if (typeof el?.scrollIntoView === "function") {
        el.scrollIntoView({ block: "nearest", behavior: "smooth" });
      }
    }
  }, [cursorIndex, alerts]);

  // Keyboard navigation & triage shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isEditing = target && (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable
      );

      // Esc dismisses transient UI, drawer, or blurs input
      if (e.key === "Escape") {
        if (inspectFinding) {
          e.preventDefault();
          setInspectFinding(null);
          return;
        }
        if (inspectIp) {
          e.preventDefault();
          setInspectIp(null);
          return;
        }
        if (inspectPid) {
          e.preventDefault();
          setInspectPid(null);
          return;
        }
        if (isEditing) {
          e.preventDefault();
          target?.blur();
          return;
        }
        if (selected.size > 0) {
          e.preventDefault();
          setSelected(new Set());
          return;
        }
        return;
      }

      // Ignore all other shortcuts while editing or inside another modal
      if (isEditing) return;
      if (inspectIp !== null || inspectPid !== null) return;

      // Focus search input
      if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }

      const currentAlert = inspectFinding || alerts[cursorIndex] || null;

      // Navigate list: j (next), k (prev)
      if (e.key === "j" || e.key === "J") {
        if (inspectFinding) return;
        e.preventDefault();
        setCursorIndex((prev) => Math.min(prev + 1, Math.max(0, alerts.length - 1)));
        return;
      }
      if (e.key === "k" || e.key === "K") {
        if (inspectFinding) return;
        e.preventDefault();
        setCursorIndex((prev) => Math.max(prev - 1, 0));
        return;
      }

      // Acknowledge selected finding: x
      if (e.key === "x" || e.key === "X") {
        if (!currentAlert || busy) return;
        e.preventDefault();
        void handleAcknowledgeAlert(currentAlert);
        return;
      }

      // Escalate selected finding: e
      if (e.key === "e" || e.key === "E") {
        if (!currentAlert || busy) return;
        e.preventDefault();
        void handleEscalateSingle(currentAlert);
        return;
      }

      // Open evidence drawer: Enter or Space
      if (e.key === "Enter" || e.key === " ") {
        if (!inspectFinding && currentAlert) {
          e.preventDefault();
          setInspectFinding(currentAlert);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    alerts,
    cursorIndex,
    inspectFinding,
    inspectIp,
    inspectPid,
    busy,
    selected,
    handleAcknowledgeAlert,
    handleEscalateSingle,
  ]);

  const toggle = (id: number) =>
    setSelected((cur) => {
      const n = new Set(cur);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  // Select EVERY alert matching the active filters (across pages) — the
  // bulk-ack lever for a provenance-filtered demo sweep: filter to synthetic,
  // "Select all N matching", Ack. The queue API caps at 200/page, so this
  // walks offsets until it has collected the whole filtered set.
  const selectAllMatching = async () => {
    setBusy(true);
    try {
      const ids = new Set<number>();
      const limit = 200;
      let offset = 0;
      let total = Infinity;
      while (offset < total) {
        const page = await getAlertQueue({
          status,
          severity: sev || undefined,
          provenance: provenance || undefined,
          q: submittedQ || undefined,
          sort,
          limit,
          offset,
        });
        total = page.total;
        for (const a of page.alerts) ids.add(a.id);
        if (page.alerts.length === 0) break;
        offset += limit;
      }
      setSelected(ids);
      setMsg({ ok: true, text: `Selected all ${ids.size} matching finding(s).` });
    } catch {
      setMsg({ ok: false, text: "Couldn't select all matching — is the backend running?" });
    } finally {
      setBusy(false);
    }
  };

  // The value scope a suppression targets from the sweep: the run's sample
  // name (detonate-demo.sh etc.) when present, else the alert's related IP
  // (the C2). This is what makes the suppression future-proof — it applies
  // to every subsequent run of that sample / touch of that IP, not just the
  // alerts on screen.
  const suppressScope = (a: QueueAlert): string | null => {
    const sample = (a.sample_name || "").trim();
    if (sample) return sample;
    const ip = (a.related_ip || "").trim();
    return ip || null;
  };

  const [suppressingId, setSuppressingId] = useState<number | null>(null);

  const suppress = async (targets: QueueAlert[]) => {
    const seen = new Set<string>();
    const plans: { ruleId: string; scope: string }[] = [];
    for (const a of targets) {
      const scope = suppressScope(a);
      if (!scope) continue;
      const key = `${a.rule_id}\u0000${scope}`;
      if (seen.has(key)) continue;
      seen.add(key);
      plans.push({ ruleId: a.rule_id, scope });
    }
    if (plans.length === 0) {
      setMsg({ ok: false, text: "None of the selected findings have a sample name or IP to scope a suppression to." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      for (const p of plans) {
        await addSuppression(p.ruleId, "suppressed from queue sweep", undefined, p.scope);
      }
      setMsg({
        ok: true,
        text: `Suppressed ${plans.length} rule scope(s) — future matching runs stop firing (${plans.map((p) => p.ruleId).join(", ")}).`,
      });
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      await queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    } catch {
      setMsg({ ok: false, text: "Suppression failed — is the backend running?" });
    } finally {
      setBusy(false);
      setSuppressingId(null);
    }
  };

  const bulk = async (nextStatus: AlertStatus) => {
    const ids = [...selected];
    if (ids.length === 0) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await bulkUpdateAlertStatus(ids, nextStatus);
      setMsg({ ok: true, text: `${res.updated} finding(s) marked ${nextStatus}.` });
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      await queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    } catch {
      setMsg({ ok: false, text: "Bulk update failed — is the backend running?" });
    } finally {
      setBusy(false);
    }
  };

  const handleEscalateToCase = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    const selectedAlerts = alerts.filter((a) => selected.has(a.id));
    const firstRule = selectedAlerts[0]?.rule_name || "Findings Escalation";
    const sample = selectedAlerts[0]?.sample_name || "";
    setBusy(true);
    setMsg(null);
    try {
      const title = `Incident Case: ${firstRule}${sample ? ` (${sample})` : ""} [${ids.length} Alerts]`;
      const inv = await createInvestigation({
        title,
        tags: ["escalated-finding", ...selectedAlerts.map((a) => a.rule_id).slice(0, 3)],
      });
      // Attach run, host, and ioc evidence references to the new case
      const seenRuns = new Set<string>();
      for (const a of selectedAlerts) {
        if (a.run_id && !seenRuns.has(a.run_id)) {
          seenRuns.add(a.run_id);
          try {
            await addInvestigationRef(inv.id, { ref_type: "run", ref_id: a.run_id });
          } catch {
            // continue
          }
        }
      }
      setMsg({ ok: true, text: `Created investigation case: ${title}` });
      setSelected(new Set());
      navigate(`/investigations/${inv.id}`);
    } catch {
      setMsg({ ok: false, text: "Failed to create investigation case." });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1200px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · findings & investigations"
        title={
          <>
            Incident Findings &amp; Cases <span className="font-normal text-text-muted">— alert triage &amp; incident management</span>
          </>
        }
        lede="Actionable detection alerts and case investigations across runs and hosts. Acknowledge and isolate threats during triage, or escalate to an incident case dossier."
      />

      {/* Main Tab Switcher */}
      <div className="mb-6 flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-sans text-xs shadow-sm">
        <button
          onClick={() => setActiveTab("findings")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            activeTab === "findings"
              ? "bg-accent/15 font-semibold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="alert" size={13} />
          <span>Findings &amp; Alert Queue</span>
        </button>
        <button
          onClick={() => setActiveTab("investigations")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            activeTab === "investigations"
              ? "bg-accent/15 font-semibold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="notes" size={13} />
          <span>Case Files &amp; Investigations</span>
        </button>
      </div>

      {activeTab === "investigations" ? (
        <InvestigationsPage />
      ) : (
        <>
      {/* ── Triage KPI Ribbon ─────────────────────────────── */}
      <section className="mb-4 grid grid-cols-2 sm:grid-cols-4 gap-3 font-sans text-xs">
        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3 shadow-xs">
          <div className="flex items-center justify-between text-text-faint text-[10px] uppercase tracking-wider font-medium">
            <span>Open Findings</span>
            <span className="h-2 w-2 rounded-full bg-red-400" />
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-text-primary tabular-nums">{data?.open ?? 0}</span>
            <span className="text-[11px] text-text-muted">active in triage</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3 shadow-xs">
          <div className="flex items-center justify-between text-text-faint text-[10px] uppercase tracking-wider font-medium">
            <span>Acknowledged</span>
            <span className="h-2 w-2 rounded-full bg-amber-400" />
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-amber-400 tabular-nums">{data?.acknowledged ?? 0}</span>
            <span className="text-[11px] text-text-muted">in progress</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3 shadow-xs">
          <div className="flex items-center justify-between text-text-faint text-[10px] uppercase tracking-wider font-medium">
            <span>Resolved</span>
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-emerald-400 tabular-nums">{data?.resolved ?? 0}</span>
            <span className="text-[11px] text-text-muted">closed</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface/80 p-3 shadow-xs">
          <div className="flex items-center justify-between text-text-faint text-[10px] uppercase tracking-wider font-medium">
            <span>Queue Total</span>
            <Icon name="activity" size={12} className="text-accent" />
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-xl font-bold font-mono text-accent tabular-nums">{data?.total ?? 0}</span>
            <span className="text-[11px] text-text-muted">scope findings</span>
          </div>
        </div>
      </section>

      {/* Status tabs with live counts */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {STATUS_TABS.map((t) => {
          // Badges are live totals across the active non-status filters; the
          // "All" badge sums the three status buckets (data.total is scoped
          // to the active view for pagination).
          const count = statusTabCount(t.v, data);
          return (
            <button
              key={t.v}
              onClick={() => switchStatus(t.v)}
              aria-pressed={status === t.v}
              className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-sans text-xs transition-colors duration-150 ${
                status === t.v ? "border-accent/50 bg-accent/10 font-semibold text-accent" : "border-border-subtle text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              {t.label}
              <span className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 font-mono text-[10px] tabular-nums text-text-faint">
                {count ?? "…"}
              </span>
            </button>
          );
        })}

        <div className="ml-auto flex items-center gap-2 font-sans text-xs">
          <select
            value={provenance}
            onChange={(e) => setProvenance(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-sans text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
            aria-label="Filter by provenance"
            title="Real = host/sandbox telemetry · Synthetic = seed/webapp-demo runs — demo noise can be hidden or acked in bulk"
          >
            <option value="">All provenance</option>
            <option value="real">Real hosts</option>
            <option value="synthetic">Synthetic / demo</option>
          </select>
          <select
            value={sev}
            onChange={(e) => setParam("severity", e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-sans text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
            aria-label="Filter by severity"
          >
            <option value="">All severities</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
          <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="Sort findings">
            <button
              onClick={() => setParam("sort", sort === "aging" ? "newest" : "aging")}
              aria-pressed={sort === "aging"}
              className={`px-3 py-1.5 font-sans text-xs transition-colors duration-150 ${
                sort === "aging" ? "bg-accent/10 font-semibold text-accent" : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
              title={sort === "aging" ? "Oldest first — findings that have waited longest surface first" : "Newest first"}
            >
              {sort === "aging" ? "Oldest first" : "Newest first"}
            </button>
          </div>
          <form
            className="flex items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              setSubmittedQ(q.trim());
              setOffset(0);
            }}
          >
            <input
              ref={searchInputRef}
              value={q}
              onChange={(e) => setParam("q", e.target.value)}
              placeholder="sample, rule, detail… (/ to search)"
              className="w-44 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-sans text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
              aria-label="Search findings"
            />
            <button type="submit" className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-1.5 font-sans text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent">
              <Icon name="search" size={12} />
            </button>
          </form>
        </div>
      </div>

      {/* Keyboard Shortcut Hints Bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface/60 px-3 py-1.5 font-mono text-[11px] text-text-muted">
        <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Shortcuts:</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">j</kbd>
          <span>/</span>
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">k</kbd>
          <span>nav</span>
        </span>
        <span className="text-border-subtle">·</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">x</kbd>
          <span>ack</span>
        </span>
        <span className="text-border-subtle">·</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">e</kbd>
          <span>escalate</span>
        </span>
        <span className="text-border-subtle">·</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">↵</kbd>
          <span>/</span>
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">space</kbd>
          <span>inspect</span>
        </span>
        <span className="text-border-subtle">·</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">/</kbd>
          <span>search</span>
        </span>
        <span className="text-border-subtle">·</span>
        <span className="inline-flex items-center gap-1">
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-primary">esc</kbd>
          <span>dismiss</span>
        </span>
      </div>

      {/* Saved-split chips — the same per-tab vocabulary as Settings, so an
          analyst sees what each tab will show (and what the active tab IS
          showing) without leaving the sweep. Hidden when nothing is saved
          and the active tab has no explicit override. */}
      {provenanceChips(status, provenance).some((c) => c.value) && (
        <div className="mb-4 flex flex-wrap items-center gap-1.5" aria-label="Saved provenance split per status tab">
          <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">Saved splits:</span>
          {provenanceChips(status, provenance).map((c) => (
            <span
              key={c.tab}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] ${
                c.active
                  ? "border-accent/60 bg-accent/10 text-accent"
                  : "border-border-subtle bg-bg-elevated/40 text-text-muted"
              }`}
              title={`${c.label} tab: ${provenanceLabel(c.value)}${c.active ? " (active view)" : " (saved)"}`}
            >
              <span className="uppercase tracking-wide">{c.label}</span>
              <span>{provenanceLabel(c.value)}</span>
            </span>
          ))}
        </div>
      )}

      {/* Bulk action bar */}
      {(selected.size > 0 || msg) && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="font-mono text-xs font-semibold text-accent">{selected.size} selected</span>
          <button
            onClick={() => void bulk("acknowledged")}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-primary transition-colors hover:border-accent/60 disabled:opacity-40"
          >
            Ack {selected.size > 0 ? `(${selected.size})` : ""}
          </button>
          <button
            onClick={() => void bulk("resolved")}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-risk-clean/40 bg-risk-clean/10 px-2.5 py-1 font-mono text-[11px] text-risk-clean transition-colors hover:border-risk-clean/70 disabled:opacity-40"
          >
            Resolve
          </button>
          <button
            onClick={() => void suppress(alerts.filter((a) => selected.has(a.id)))}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-risk-malicious/60 hover:text-risk-malicious disabled:opacity-40"
            title="Suppress each selected rule for its sample or C2 — future matching runs stop firing it"
          >
            Suppress
          </button>
          <button
            onClick={handleEscalateToCase}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-accent/40 bg-accent/15 px-2.5 py-1 font-mono text-[11px] font-semibold text-accent transition-colors hover:bg-accent/25 disabled:opacity-40"
            title="Create a new incident investigation case from selected findings"
          >
            Escalate to Case
          </button>
          {selected.size > 0 && (
            <button onClick={() => setSelected(new Set())} className="press ml-auto font-mono text-[10px] text-text-faint hover:text-text-primary" title="Clear selection">
              clear
            </button>
          )}
          {msg && <span className={`font-mono text-[11px] ${msg.ok ? "text-risk-clean" : "text-risk-malicious"}`}>{msg.text}</span>}
        </div>
      )}

      <Panel
        title={status === "open" ? "Open findings" : `${status[0].toUpperCase()}${status.slice(1)} findings`}
        right={
          alerts.length > 0 ? (
            <span className="font-mono text-[10px] text-text-faint">
              {offset + 1}–{Math.min(offset + PAGE, data?.total ?? 0)} of {data?.total ?? 0}
            </span>
          ) : undefined
        }
      >
        {isLoading && (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton h-14 w-full" />
            ))}
          </div>
        )}
        {isError && <p className="p-6 text-sm text-risk-malicious">Couldn't load findings — is the OutPost backend running?</p>}
        {!isLoading && !isError && alerts.length === 0 && (
          <div className="p-10 text-center">
            <Icon name="check" size={26} className="mx-auto text-risk-clean" />
            <p className="mt-3 text-sm text-text-muted">
              {status === "open" ? "No open findings — the queue is clear." : "Nothing matches these filters."}
            </p>
            {(sev || submittedQ) && (
              <button
                onClick={() => {
                  setParam("severity", "");
                  setParam("q", "");
                  setSubmittedQ("");
                }}
                className="press mt-4 inline-flex items-center gap-1.5 rounded-lg border border-accent/50 px-3 py-1.5 font-mono text-xs text-accent transition-colors hover:bg-accent/10"
              >
                <Icon name="x" size={11} />
                Clear filters
              </button>
            )}
          </div>
        )}
        {!isLoading && !isError && alerts.length > 0 && (
          <div className="p-3">
            <div className="mb-2 flex items-center justify-between px-1">
              <button
                onClick={() => {
                  const all = onPage.length === 0 ? [] : onPage.every((id) => selected.has(id)) ? [] : onPage;
                  setSelected(new Set(all));
                }}
                className="press font-mono text-[10px] text-text-faint hover:text-text-primary"
              >
                {onPage.length > 0 && onPage.every((id) => selected.has(id)) ? "Clear page selection" : "Select this page"}
              </button>
              {(data?.total ?? 0) > onPage.length && selected.size < (data?.total ?? 0) && (
                <button
                  onClick={() => void selectAllMatching()}
                  disabled={busy}
                  className="press font-mono text-[10px] text-text-faint transition-colors hover:text-accent disabled:opacity-40"
                  title="Select every alert matching the active filters (across all pages) — one step before a bulk ack"
                >
                  Select all {data?.total ?? 0} matching
                </button>
              )}
              {selected.size > onPage.length && (
                <span className="font-mono text-[10px] text-text-faint">+{selected.size - onPage.length} from other pages</span>
              )}
            </div>
            <ul className="space-y-2">
              {alerts.map((a, index) => (
                <FindingRow
                  key={a.id}
                  a={a}
                  selected={selected.has(a.id)}
                  isCursorActive={index === cursorIndex}
                  innerRef={(el) => {
                    if (el) rowRefs.current.set(a.id, el);
                    else rowRefs.current.delete(a.id);
                  }}
                  onToggle={toggle}
                  ruleNames={ruleNames}
                  ruleMap={ruleMap}
                  onStatusChange={handleSingleStatus}
                  onSuppress={(target) => {
                    setSuppressingId(target.id);
                    void suppress([target]);
                  }}
                  suppressing={suppressingId === a.id}
                  onInspectIp={setInspectIp}
                  onInspectPid={setInspectPid}
                  onInspect={setInspectFinding}
                />
              ))}
            </ul>
            {(data?.total ?? 0) > PAGE && (
              <div className="mt-4 flex items-center justify-between border-t border-border-subtle pt-3">
                <button
                  onClick={() => setOffset(Math.max(0, offset - PAGE))}
                  disabled={offset === 0}
                  className="press inline-flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/60 disabled:opacity-40"
                >
                  <Icon name="chevronLeft" size={11} /> Prev
                </button>
                <span className="font-mono text-[10px] text-text-faint">
                  page {Math.floor(offset / PAGE) + 1} / {Math.max(1, Math.ceil((data?.total ?? 0) / PAGE))}
                </span>
                <button
                  onClick={() => setOffset(offset + PAGE)}
                  disabled={offset + PAGE >= (data?.total ?? 0)}
                  className="press inline-flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/60 disabled:opacity-40"
                >
                  Next <Icon name="chevronRight" size={11} />
                </button>
              </div>
            )}
          </div>
        )}
      </Panel>
        </>
      )}

      {inspectFinding && (
        <AlertDetailDrawer
          alert={inspectFinding}
          onClose={() => setInspectFinding(null)}
          ruleMeta={ruleMetaMap.get(inspectFinding.rule_id)}
          onStatusChange={handleSingleStatus}
          onSuppress={(target) => {
            setSuppressingId(target.id);
            void suppress([target]);
          }}
          onEscalate={(target) => {
            void handleEscalateSingle(target);
          }}
        />
      )}

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}
    </div>
  );
}
