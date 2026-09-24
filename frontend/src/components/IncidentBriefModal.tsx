import { useState } from "react";
import { Icon } from "./Icon";
import type { DroppedArtifactItem } from "../types";

export interface IncidentBriefData {
  runId: string;
  title: string;
  platform: string;
  threatVerdict: string;
  threatScore: number;
  threatFamily: string;
  detectionEfficacyPct: number;
  isolationDriver: string;
  eventsCount: number;
  alerts: Array<{ id?: number | string; rule_id: string; rule_name: string; severity: string; details?: string }>;
  actionableIocs: {
    ips: string[];
    domains: string[];
    firewall_rules: string[];
    dropped_count: number;
    threat_family?: string;
  };
  artifacts: DroppedArtifactItem[];
  mitreMatrix: Array<{ id: string; name?: string; detected: boolean; severity?: string }>;
  syscalls: Array<{ pid?: number; syscall: string; arguments: string; result: string; category: string }>;
}

interface IncidentBriefModalProps {
  data: IncidentBriefData;
  onClose: () => void;
}

export function IncidentBriefModal({ data, onClose }: IncidentBriefModalProps) {
  const [copiedMd, setCopiedMd] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  const generateMarkdown = (): string => {
    const timestamp = new Date().toISOString();
    return `# [OutPost Incident Brief] ${data.title}
**Run ID:** \`${data.runId}\`  
**Generated At:** ${timestamp}  
**Classification:** **${data.threatVerdict}** (Threat Score: ${data.threatScore}/100)  
**Threat Family:** ${data.threatFamily}  
**Detection Efficacy:** ${data.detectionEfficacyPct}%  
**Isolation Driver:** \`${data.isolationDriver}\`  
**Host Platform:** \`${data.platform}\`  

---

## 1. Executive Incident Summary
During automated behavioral execution within OutPost's isolated sandbox cage, sample/scenario \`${data.title}\` exhibited behavior characteristic of **${data.threatFamily}**. The detection engine evaluated **${data.eventsCount} telemetry events**, triggering **${data.alerts.length} detection rules** with an efficacy rating of **${data.detectionEfficacyPct}%**.

---

## 2. Immediate Host & Network Containment Playbook
Run the following containment commands on affected endpoints or perimeter egress firewalls:

\`\`\`bash
# OutPost Instant Firewall Egress Isolation
${data.actionableIocs.firewall_rules.length > 0 ? data.actionableIocs.firewall_rules.join("\n") : "# No outbound socket egress observed requiring firewall drop rules."}
\`\`\`

**Adversary C2 IP Addresses:**
${data.actionableIocs.ips.length > 0 ? data.actionableIocs.ips.map((ip) => `- \`${ip}\``).join("\n") : "- None detected"}

**Adversary DNS Domains:**
${data.actionableIocs.domains.length > 0 ? data.actionableIocs.domains.map((d) => `- \`${d}\``).join("\n") : "- None detected"}

---

## 3. MITRE ATT&CK Technique Alignment & Detection Status
| Technique ID | Technique Name | Status | Severity |
| :--- | :--- | :--- | :--- |
${data.mitreMatrix.length > 0 ? data.mitreMatrix.map((m) => `| \`${m.id}\` | ${m.name || m.id} | ${m.detected ? "**DETECTED**" : "OBSERVED"} | ${m.severity || "suspicious"} |`).join("\n") : "| — | No technique mapping recorded | — | — |"}

---

## 4. Triggered Detection Alerts
${data.alerts.length > 0 ? data.alerts.map((a, idx) => `${idx + 1}. **${a.rule_name}** [\`${a.severity.toUpperCase()}\`]\n   - Rule ID: \`${a.rule_id}\`\n   - Details: ${a.details || "Observed matching event"}`).join("\n\n") : "- Zero detection rules fired."}

---

## 5. Dropped Ephemeral Artifacts & Forensic Hashes
| Artifact Filename | Size (Bytes) | Shannon Entropy | SHA-256 Hash |
| :--- | :--- | :--- | :--- |
${data.artifacts.length > 0 ? data.artifacts.map((art) => `| \`${art.filename || art.name}\` | ${art.size_bytes} | ${art.entropy}/8.0 | \`${art.sha256}\` |`).join("\n") : "| — | Zero artifacts dropped | — | — |"}

---

## 6. Kernel Syscall Audit Trail (First 10 Invocations)
\`\`\`
${data.syscalls.length > 0 ? data.syscalls.slice(0, 10).map((s) => `[PID ${s.pid || "-"}] ${s.syscall}(${s.arguments}) -> ${s.result}`).join("\n") : "No low-level system call traces captured."}
\`\`\`

---
*Report synthesized autonomously by OutPost Threat Forensics & Adversary Simulation Engine.*
`;
  };

  const handleCopyMarkdown = () => {
    const md = generateMarkdown();
    void navigator.clipboard.writeText(md);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  const handleDownloadJson = () => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `outpost_incident_brief_${data.runId || "session"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="SOC Incident Brief & Forensic Dossier"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-fade-in font-mono"
      onClick={onClose}
    >
      <div
        className="flex max-h-[90vh] w-full max-w-5xl flex-col rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
          <div className="flex items-center gap-3">
            <span
              className={`flex h-10 w-10 items-center justify-center rounded-xl border text-base font-bold ${
                data.threatVerdict === "MALICIOUS"
                  ? "border-risk-malicious/50 bg-risk-malicious/15 text-risk-malicious"
                  : "border-risk-suspicious/50 bg-risk-suspicious/15 text-risk-suspicious"
              }`}
            >
              <Icon name="shield" size={20} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-accent/20 px-2 py-0.5 text-[10px] font-bold text-accent uppercase">
                  INCIDENT BRIEF
                </span>
                <h2 className="text-sm font-bold text-text-primary">
                  {data.title}
                </h2>
                <span className="text-[11px] text-text-faint">({data.threatFamily})</span>
              </div>
              <p className="text-[11px] text-text-muted">
                Run ID: <span className="text-accent">{data.runId}</span> · Generated for Tier-3 SOC Incident Escalation &amp; Case Attachment
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyMarkdown}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 text-xs font-bold text-accent transition hover:bg-accent/25"
              title="Copy formatted Markdown report to clipboard"
            >
              <Icon name={copiedMd ? "check" : "copy"} size={13} />
              <span>{copiedMd ? "Copied Markdown!" : "Copy Markdown Brief"}</span>
            </button>

            <button
              onClick={handleDownloadJson}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-muted transition hover:border-accent/40 hover:text-text-primary"
              title="Download JSON dossier file"
            >
              <Icon name={copiedJson ? "check" : "download"} size={13} />
              <span>{copiedJson ? "Downloaded!" : "JSON Dossier"}</span>
            </button>

            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              aria-label="Close modal"
            >
              <Icon name="x" size={16} />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs leading-relaxed">
          {/* Top Key Metrics Banner */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold block mb-1">Threat Verdict</span>
              <span className={`text-base font-bold ${data.threatVerdict === "MALICIOUS" ? "text-risk-malicious" : "text-risk-suspicious"}`}>
                {data.threatVerdict}
              </span>
            </div>
            <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold block mb-1">Threat Risk Score</span>
              <span className="text-base font-bold text-text-primary">
                {data.threatScore} <span className="text-xs text-text-faint">/ 100</span>
              </span>
            </div>
            <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold block mb-1">Detection Efficacy</span>
              <span className="text-base font-bold text-emerald-400">
                {data.detectionEfficacyPct}% <span className="text-xs text-text-faint">caught</span>
              </span>
            </div>
            <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3">
              <span className="text-text-faint text-[10px] uppercase font-bold block mb-1">Alerts Fired</span>
              <span className={`text-base font-bold ${data.alerts.length > 0 ? "text-risk-malicious" : "text-text-primary"}`}>
                {data.alerts.length} <span className="text-xs text-text-faint">rules</span>
              </span>
            </div>
          </div>

          {/* Actionable Containment Playbook */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2">
              <span className="font-bold text-text-primary flex items-center gap-2">
                <Icon name="sliders" size={14} className="text-accent" />
                Immediate Containment Playbook (Perimeter &amp; Host Isolation)
              </span>
              <span className="text-[10px] text-text-faint">Copyable Shell Commands</span>
            </div>

            <div className="space-y-2">
              <div className="bg-[#070a10] p-3 rounded-lg border border-white/10 text-[11px] font-mono">
                <div className="text-text-faint uppercase text-[9px] font-bold mb-1">Host Firewall Rule:</div>
                <pre className="text-accent whitespace-pre-wrap break-all select-all">
                  {data.actionableIocs.firewall_rules.length > 0
                    ? data.actionableIocs.firewall_rules.join("\n")
                    : "# No egress connections observed"}
                </pre>
              </div>

              {data.actionableIocs.ips.length > 0 && (
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="text-text-muted">Target C2 IPs:</span>
                  {data.actionableIocs.ips.map((ip) => (
                    <span key={ip} className="rounded bg-accent/15 border border-accent/40 px-2 py-0.5 text-accent font-bold">
                      {ip}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2">
              <span className="font-bold text-text-primary flex items-center gap-2">
                <Icon name="shield" size={14} className="text-emerald-400" />
                Evaluated ATT&amp;CK Techniques &amp; Efficacy
              </span>
              <span className="text-[10px] text-text-faint">{data.mitreMatrix.length} Techniques Mapped</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {data.mitreMatrix.map((m) => (
                <div
                  key={m.id}
                  className={`rounded-lg border p-2.5 space-y-1 ${
                    m.detected
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                      : "border-amber-500/40 bg-amber-500/10 text-amber-400"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold">{m.id}</span>
                    <span className="text-[9px] font-bold uppercase">{m.detected ? "✓ DETECTED" : "● OBSERVED"}</span>
                  </div>
                  <p className="text-[10px] text-text-muted truncate">{m.name || "Technique Vector"}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Dropped Artifacts Hash Ledger */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2">
              <span className="font-bold text-text-primary flex items-center gap-2">
                <Icon name="file" size={14} className="text-accent" />
                Dropped Artifacts &amp; Cryptographic Hashes ({data.artifacts.length})
              </span>
              <span className="text-[10px] text-text-faint">Forensic File Integrity</span>
            </div>

            {data.artifacts.length === 0 ? (
              <p className="text-text-muted py-2 text-[11px]">No persistent disk files or dropped binaries detected.</p>
            ) : (
              <div className="space-y-2">
                {data.artifacts.map((art, aidx) => (
                  <div key={aidx} className="rounded-lg border border-border-subtle bg-bg-surface p-2.5 text-[11px] space-y-1">
                    <div className="flex items-center justify-between font-bold">
                      <span className="text-text-primary">{art.filename || art.name}</span>
                      <span className="text-text-faint">{art.size_bytes} B · Entropy: {art.entropy}/8.0</span>
                    </div>
                    <div className="text-text-muted text-[10px] truncate">
                      <span className="text-text-faint">SHA256:</span> {art.sha256}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-3 bg-bg-base/50 text-[11px] text-text-faint">
          <span>OutPost Enterprise Incident Response &amp; Forensics Suite</span>
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
