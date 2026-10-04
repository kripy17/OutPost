import React, { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Icon } from "./Icon";
import { acquireHostTriagePack } from "../lib/api";

interface LiveTriageModalProps {
  onClose: () => void;
  hostId?: string;
}

export const LiveTriageModal: React.FC<LiveTriageModalProps> = ({ onClose, hostId = "local" }) => {
  const [includeYara, setIncludeYara] = useState(true);
  const [triageData, setTriageData] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const triageMutation = useMutation({
    mutationFn: async () => {
      return acquireHostTriagePack(includeYara);
    },
    onSuccess: (data) => {
      setTriageData(data);
    },
  });

  const handleCopyJson = () => {
    if (!triageData) return;
    navigator.clipboard.writeText(JSON.stringify(triageData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (triageData) {
      const blob = new Blob([JSON.stringify(triageData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${triageData.triage_id || "triage_pack"}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } else {
      window.open(`/system/forensics/triage/export?include_yara=${includeYara ? "true" : "false"}`, "_blank");
    }
  };

  const summary = triageData?.summary || {};
  const sev = summary.severity || "clean";

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity" onClick={onClose}>
      <div
        className="flex h-full w-full max-w-3xl flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-elevated/40">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-500/15 text-cyan-400">
              <Icon name="zap" size={18} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-text-primary">Live Endpoint Forensic Triage Pack</h2>
                <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-cyan-400 border border-cyan-500/30">
                  Endpoint Acquisition Engine
                </span>
              </div>
              <p className="text-xs text-text-muted">
                Captures holistic volatile memory, process causality, listening sockets, and forensic hunt anomalies from endpoint '{hostId}'
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
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {!triageData && !triageMutation.isPending && (
            <div className="space-y-4">
              <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-5 space-y-3">
                <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary block">
                  Triage Acquisition Scope
                </span>
                <p className="text-xs text-text-muted leading-relaxed">
                  Executing a triage pack performs a non-destructive, rapid forensic snapshot of the target endpoint.
                  The resulting bundle includes process ancestry, sockets, crontabs, authorized SSH keys, deleted RAM-resident binaries, and SUID GTFOBin escalations.
                </p>
                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>Crontab & Scheduled Job Persistence</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>SSH Authorized Keys Backdoor Audit</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>Memory-Resident Deleted Inodes (Fileless)</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>Suspicious Listening Sockets & Ports</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>SUID GTFOBins Escalation Audit</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-text-muted">
                    <span className="text-accent font-bold">✓</span>
                    <span>Kernel & Hardware Utilization Metrics</span>
                  </div>
                </div>

                <div className="border-t border-border-subtle pt-4 mt-2">
                  <label className="flex items-center gap-2 text-xs text-text-primary cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeYara}
                      onChange={(e) => setIncludeYara(e.target.checked)}
                      className="rounded border-border-subtle bg-bg-base text-accent focus:ring-0"
                    />
                    <span className="font-semibold">Include Volatile Process Memory YARA Signature Sweep</span>
                  </label>
                  <span className="text-[11px] text-text-muted block pl-6">
                    Scans executable memory mappings of top active processes against the OutPost signature catalog.
                  </span>
                </div>
              </div>
            </div>
          )}

          {triageMutation.isPending && (
            <div className="py-16 text-center space-y-4">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 animate-pulse">
                <Icon name="refresh" size={24} className="animate-spin" />
              </div>
              <div className="space-y-1">
                <h3 className="font-bold text-sm text-text-primary">Acquiring Live Host Forensic Triage Pack...</h3>
                <p className="text-xs text-text-muted font-mono">Executing probes, scanning processes, and compiling evidence bundle</p>
              </div>
            </div>
          )}

          {triageData && (
            <div className="space-y-5">
              {/* Rollup Banner */}
              <div className={`rounded-xl border p-4 ${
                sev === "critical"
                  ? "border-rose-500/50 bg-rose-500/10"
                  : sev === "suspicious"
                  ? "border-amber-500/50 bg-amber-500/10"
                  : "border-emerald-500/50 bg-emerald-500/10"
              }`}>
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-xs font-bold uppercase ${
                        sev === "critical" ? "text-rose-400" : sev === "suspicious" ? "text-amber-400" : "text-emerald-400"
                      }`}>
                        Triage Verdict: {sev.toUpperCase()}
                      </span>
                      <span className="font-mono text-[10px] text-text-faint">ID: {triageData.triage_id}</span>
                    </div>
                    <p className="text-xs text-text-muted">
                      Captured at {new Date(triageData.collected_at).toUTCString()} on host '{triageData.hostname}' ({triageData.platform})
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleCopyJson}
                      className="rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs font-semibold text-text-muted hover:text-text-primary"
                    >
                      {copied ? "Copied!" : "Copy JSON"}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownload}
                      className="press inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 font-mono text-xs font-bold text-bg-base hover:bg-accent/90 shadow-sm"
                    >
                      <Icon name="download" size={13} />
                      <span>Download JSON Bundle</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* KPI Grid */}
              <div className="grid grid-cols-4 gap-3 font-mono text-xs">
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
                  <span className="text-text-muted block text-[10px] uppercase">Active Processes</span>
                  <span className="text-base font-bold text-text-primary">{summary.total_processes || 0}</span>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
                  <span className="text-text-muted block text-[10px] uppercase">Open Sockets</span>
                  <span className="text-base font-bold text-text-primary">{summary.total_sockets || 0}</span>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
                  <span className="text-text-muted block text-[10px] uppercase">Probe Anomalies</span>
                  <span className={`text-base font-bold ${(summary.probe_anomalies_count || 0) > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                    {summary.probe_anomalies_count || 0}
                  </span>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3">
                  <span className="text-text-muted block text-[10px] uppercase">YARA Memory Hits</span>
                  <span className={`text-base font-bold ${(summary.yara_threats_count || 0) > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                    {summary.yara_threats_count || 0}
                  </span>
                </div>
              </div>

              {/* Probe Breakdown Table */}
              <div className="rounded-xl border border-border-subtle bg-bg-elevated/20 overflow-hidden">
                <div className="border-b border-border-subtle px-4 py-2 font-mono text-[11px] font-bold uppercase tracking-wider text-text-muted">
                  Forensic Hunt Probes Breakdown
                </div>
                <div className="divide-y divide-border-subtle">
                  {Object.entries(triageData.probe_results || {}).map(([pId, pData]: [string, any]) => {
                    const anoms = pData.anomalies_count || 0;
                    return (
                      <div key={pId} className="flex items-center justify-between p-3.5 text-xs hover:bg-bg-elevated/30">
                        <div className="space-y-0.5">
                          <span className="font-bold text-text-primary block">{pData.name || pId}</span>
                          <span className="font-mono text-[10px] text-text-muted">{pData.tactic} · {pData.technique}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-[11px] text-text-muted">{pData.total_items || 0} scanned</span>
                          <span className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-bold ${
                            anoms > 0 ? "bg-rose-500/20 text-rose-400 border border-rose-500/40" : "bg-emerald-500/10 text-emerald-400"
                          }`}>
                            {anoms > 0 ? `${anoms} Anomalies` : "Clean"}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-4 bg-bg-elevated/40">
          <span className="font-mono text-xs text-text-muted">
            {triageData
              ? "Forensic bundle ready for export or offline analysis"
              : "Acquiring triage pack executes probes in real time on the live system"}
          </span>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs font-semibold text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            >
              {triageData ? "Close" : "Cancel"}
            </button>
            {!triageData && (
              <button
                type="button"
                onClick={() => triageMutation.mutate()}
                disabled={triageMutation.isPending}
                className="press inline-flex items-center gap-2 rounded-xl bg-cyan-500 px-5 py-2 font-mono text-xs font-bold text-black hover:bg-cyan-400 disabled:opacity-50 shadow-md shadow-cyan-500/20"
              >
                <Icon name={triageMutation.isPending ? "refresh" : "play"} size={14} className={triageMutation.isPending ? "animate-spin" : ""} />
                <span>{triageMutation.isPending ? "Acquiring Pack..." : "⚡ Acquire Live Triage Pack"}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
