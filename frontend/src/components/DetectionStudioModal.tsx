import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getRunDetectionSuite } from "../lib/api";
import { Icon } from "./Icon";
import { copyToClipboard } from "../lib/clipboard";
import type { DetectionSuite } from "../types";

interface DetectionStudioModalProps {
  runId: string;
  isOpen: boolean;
  onClose: () => void;
}

export function DetectionStudioModal({ runId, isOpen, onClose }: DetectionStudioModalProps) {
  const [activeTab, setActiveTab] = useState<"sigma" | "suricata" | "yara" | "all">("sigma");
  const [copied, setCopied] = useState(false);

  const { data: suite, isLoading } = useQuery<DetectionSuite>({
    queryKey: ["detection-suite", runId],
    queryFn: () => getRunDetectionSuite(runId),
    enabled: isOpen && !!runId,
  });

  if (!isOpen) return null;

  const getCodeContent = () => {
    if (!suite) return "";
    if (activeTab === "sigma") {
      return suite.sigma.length > 0
        ? suite.sigma.join("\n\n---\n\n")
        : "# No Sigma log detection rules generated for this run.";
    }
    if (activeTab === "suricata") {
      return suite.suricata.length > 0
        ? suite.suricata.join("\n")
        : "# No Suricata network IDS rules generated for this run (no malicious IPs observed).";
    }
    if (activeTab === "yara") {
      return suite.yara.length > 0
        ? suite.yara.join("\n\n")
        : "# No YARA signatures generated for this run.";
    }
    const sigmaPart = suite.sigma.join("\n\n") || "# No Sigma rules";
    const suricataPart = suite.suricata.join("\n") || "# No Suricata rules";
    const yaraPart = suite.yara.join("\n\n") || "# No YARA rules";
    return `# ═══════════════════════════════════════════════════════\n# OUTPOST AUTOMATED DETECTION SUITE — RUN ${runId.slice(0, 12)}\n# ═══════════════════════════════════════════════════════\n\n# ─── SIGMA (LOG-BASED RULES) ───\n\n${sigmaPart}\n\n# ─── SURICATA (NETWORK IDS) ───\n\n${suricataPart}\n\n# ─── YARA (MEMORY / FILE SIGNATURES) ───\n\n${yaraPart}`;
  };

  const handleCopy = async () => {
    const text = getCodeContent();
    await copyToClipboard(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const text = getCodeContent();
    const ext =
      activeTab === "sigma"
        ? "yml"
        : activeTab === "suricata"
          ? "rules"
          : activeTab === "yara"
            ? "yar"
            : "txt";
    const filename = `outpost-${activeTab}-${runId.slice(0, 10)}.${ext}`;
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-md">
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-border-strong bg-bg-surface shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent shadow-[var(--glow-accent)]">
              <Icon name="shield" size={18} />
            </span>
            <div>
              <h2 className="font-sans text-base font-semibold tracking-tight text-text-primary">
                Detection Rule Synthesis Studio
              </h2>
              <p className="font-mono text-[11px] text-text-muted">
                Run <span className="text-text-primary">{runId.slice(0, 12)}</span> · Automated Sigma, Suricata &amp; YARA generation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-text-faint hover:bg-bg-elevated hover:text-text-primary"
            title="Close"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Toolbar Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-elevated/40 px-6 py-2.5">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab("sigma")}
              className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs transition-all ${
                activeTab === "sigma"
                  ? "border border-accent/50 bg-accent/20 font-semibold text-accent shadow-[var(--glow-accent)]"
                  : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              <Icon name="file" size={13} />
              Sigma YAML ({suite?.counts.sigma ?? 0})
            </button>
            <button
              onClick={() => setActiveTab("suricata")}
              className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs transition-all ${
                activeTab === "suricata"
                  ? "border border-signal/50 bg-signal/20 font-semibold text-signal shadow-[var(--glow-signal)]"
                  : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              <Icon name="activity" size={13} />
              Suricata IDS ({suite?.counts.suricata ?? 0})
            </button>
            <button
              onClick={() => setActiveTab("yara")}
              className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs transition-all ${
                activeTab === "yara"
                  ? "border border-risk-clean/50 bg-risk-clean/20 font-semibold text-risk-clean shadow-[var(--glow-clean)]"
                  : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              <Icon name="box" size={13} />
              YARA ({suite?.counts.yara ?? 0})
            </button>
            <button
              onClick={() => setActiveTab("all")}
              className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs transition-all ${
                activeTab === "all"
                  ? "border border-border-strong bg-bg-elevated font-semibold text-text-primary"
                  : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              Full Suite ({suite?.counts.total ?? 0})
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
            >
              <Icon name={copied ? "check" : "copy"} size={13} />
              {copied ? "Copied to clipboard" : "Copy"}
            </button>
            <button
              onClick={handleDownload}
              className="press inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 font-mono text-xs font-semibold text-bg-base transition-all hover:bg-accent-soft shadow-[var(--glow-accent)]"
            >
              <Icon name="download" size={13} />
              Export
            </button>
          </div>
        </div>

        {/* Code Content View */}
        <div className="relative min-h-[350px] flex-1 overflow-auto bg-bg-inset p-6 font-mono text-xs leading-relaxed text-text-primary">
          {isLoading ? (
            <div className="flex h-full min-h-[250px] items-center justify-center text-text-muted">
              <span className="inline-flex items-center gap-2">
                <Icon name="refresh" size={16} className="animate-spin text-accent" />
                Synthesizing detection rules from telemetry...
              </span>
            </div>
          ) : (
            <pre className="overflow-x-auto whitespace-pre font-mono text-[11px] text-text-primary selection:bg-accent/30">
              {getCodeContent()}
            </pre>
          )}
        </div>

        {/* Footer info */}
        <div className="flex items-center justify-between border-t border-border-subtle bg-bg-surface px-6 py-3 font-mono text-[11px] text-text-muted">
          <span className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-risk-clean" />
            Verified deterministic templates · Ready for SIEM / IDS deployment
          </span>
          <button onClick={onClose} className="hover:text-text-primary">
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
