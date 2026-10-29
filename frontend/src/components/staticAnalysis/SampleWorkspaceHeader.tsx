import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../Icon";
import { platformIconName } from "../iconMeta";
import { deleteSample, detonateDynamic, downloadSample } from "../../lib/api";
import { getVirusTotalFileUrl } from "../../routes/samplesHelpers";
import type { SampleRow, SampleStatic } from "../../types";

interface SampleWorkspaceHeaderProps {
  sample: SampleRow;
  st?: SampleStatic;
  isAnalyzing?: boolean;
  onRunStatic?: () => void;
  onSwitchToDynamic?: () => void;
}

export function SampleWorkspaceHeader({
  sample,
  st,
  isAnalyzing = false,
  onRunStatic,
  onSwitchToDynamic,
}: SampleWorkspaceHeaderProps) {
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const [detonating, setDetonating] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleDetonateDynamic = async () => {
    setErrorMsg(null);
    setDetonating(true);
    try {
      const res = await detonateDynamic({ sample_id: sample.sample_id });
      navigate(`/runs/${res.run_id}`);
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Detonation failed");
      setDetonating(false);
    }
  };

  const handleExportStix = () => {
    const bundle = {
      type: "bundle",
      id: `bundle--${sample.sample_id}`,
      objects: [
        {
          type: "file",
          spec_version: "2.1",
          id: `file--${sample.sample_id}`,
          hashes: {
            "SHA-256": sample.sha256,
          },
          name: sample.original_name,
          size: sample.size,
        },
      ],
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `outpost-stix-${sample.original_name || sample.sample_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setMenuOpen(false);
  };

  const handleDelete = async () => {
    if (!window.confirm(`Delete sample "${sample.original_name}" from vault?`)) return;
    try {
      await deleteSample(sample.sample_id);
      navigate("/samples");
    } catch {
      setErrorMsg("Failed to delete sample");
    }
  };

  const platIcon =
    sample.detected_platform === "macos" || sample.detected_platform === "windows" || sample.detected_platform === "linux"
      ? platformIconName(sample.detected_platform)
      : "terminal";

  // Derive explicit verdict with honest provenance label
  let verdictLabel: string | null = null;
  let verdictBadgeClass = "";
  if (st && st.available) {
    const score = st.static_risk_score ?? 0;
    const isPacked = Boolean(st.is_packed || (st.entropy ?? 0) > 7.1);
    const hasYara = sample.yara_rules && sample.yara_rules.length > 0;
    
    if (st.static_severity === "malicious" || score >= 70 || hasYara) {
      verdictLabel = hasYara ? "Signature Match: Malicious" : "Heuristic Assessment: Malicious";
      verdictBadgeClass = "border-rose-500/50 bg-rose-500/15 text-rose-400";
    } else if (st.static_severity === "suspicious" || score >= 35 || isPacked) {
      verdictLabel = "Heuristic Assessment: Suspicious";
      verdictBadgeClass = "border-amber-500/50 bg-amber-500/15 text-amber-400";
    } else {
      verdictLabel = "Heuristic Assessment: Clean";
      verdictBadgeClass = "border-emerald-500/50 bg-emerald-500/15 text-emerald-400";
    }
  }

  // Format machine tag
  const formatTag = st?.pe
    ? `PE32${st.pe.bits === 64 ? "+" : ""} (${st.pe.machine})`
    : st?.elf
      ? `ELF${st.elf.class} (${st.elf.machine})`
      : (sample.detected_platform || "UNKNOWN").toUpperCase();

  return (
    <div className="border-b border-border-subtle bg-bg-surface/50 pb-4 mb-4">
      {/* Aligned Breadcrumbs */}
      <nav aria-label="Breadcrumb" className="mb-2.5 flex items-center gap-1.5 font-mono text-[11px] text-text-faint">
        <Link to="/samples" className="text-text-muted hover:text-accent transition-colors">
          Malware Analysis
        </Link>
        <span className="text-text-faint">/</span>
        <Link to="/samples" className="text-text-muted hover:text-accent transition-colors">
          Samples
        </Link>
        <span className="text-text-faint">/</span>
        <span className="truncate max-w-[280px] font-semibold text-text-primary" title={sample.original_name}>
          {sample.original_name}
        </span>
      </nav>

      {/* Main Identity Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5 min-w-0">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-border-subtle bg-bg-base text-accent">
            <Icon name={platIcon} size={16} />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="truncate font-mono text-base font-bold text-text-primary" title={sample.original_name}>
                {sample.original_name}
              </h1>
              <span className="rounded border border-border-subtle bg-bg-base/80 px-1.5 py-0.5 font-mono text-[10px] text-text-muted" title="Detected binary format">
                {formatTag}
              </span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-faint" title="Sample identifier">
                {sample.sample_id}
              </span>
            </div>
          </div>

          {/* Analysis State Label */}
          {isAnalyzing ? (
            <span className="inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent">
              <Icon name="refresh" size={10} className="animate-spin" />
              <span>Analyzing...</span>
            </span>
          ) : st?.available === false ? (
            <span className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] text-amber-400">
              Bytes Not Stored
            </span>
          ) : (
            <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-400">
              Analyzed (Static)
            </span>
          )}

          {/* Verdict with Provenance */}
          {verdictLabel && (
            <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wide ${verdictBadgeClass}`}>
              {verdictLabel}
            </span>
          )}
        </div>

        {/* Action Toolbar */}
        <div className="flex items-center gap-2">
          {errorMsg && (
            <span className="font-mono text-[11px] text-risk-malicious">{errorMsg}</span>
          )}

          {/* Primary Action: Run Static Analysis */}
          <button
            onClick={onRunStatic}
            disabled={isAnalyzing}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs font-semibold text-text-primary hover:border-accent hover:text-accent disabled:opacity-50 transition"
            title="Re-run static analysis on binary bytes"
          >
            <Icon name="refresh" size={12} className={isAnalyzing ? "animate-spin" : ""} />
            <span>{isAnalyzing ? "Analyzing..." : "Re-analyze Static"}</span>
          </button>

          {/* Secondary Action: Run Dynamic Analysis */}
          <button
            onClick={onSwitchToDynamic || handleDetonateDynamic}
            disabled={detonating}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-3 py-1.5 font-mono text-xs font-semibold text-white shadow-xs hover:brightness-110 disabled:opacity-50 transition"
            title="Detonate sample safely in local isolated dynamic sandbox"
          >
            <Icon name="play" size={12} />
            <span>{detonating ? "Detonating..." : "Run Dynamic Analysis"}</span>
          </button>

          {/* Overflow Menu */}
          <div className="relative">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="press inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border-subtle bg-bg-surface text-text-muted hover:border-accent hover:text-accent transition"
              title="More actions"
              aria-label="More actions"
            >
              <Icon name="menu" size={14} />
            </button>

            {menuOpen && (
              <div
                className="absolute right-0 top-9 z-30 w-52 rounded-xl border border-border-subtle bg-bg-surface/95 p-1 font-mono text-xs shadow-xl backdrop-blur animate-in fade-in zoom-in-95"
                onMouseLeave={() => setMenuOpen(false)}
              >
                <a
                  href={getVirusTotalFileUrl(sample.sha256)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-text-muted hover:bg-bg-elevated hover:text-accent transition"
                >
                  <Icon name="external" size={12} />
                  <span>VirusTotal Report</span>
                </a>
                <Link
                  to={`/footprint?sample=${sample.sample_id}`}
                  className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-text-muted hover:bg-bg-elevated hover:text-accent transition"
                >
                  <Icon name="activity" size={12} />
                  <span>Digital Footprint</span>
                </Link>
                <button
                  onClick={handleExportStix}
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-text-muted hover:bg-bg-elevated hover:text-accent transition"
                >
                  <Icon name="shield" size={12} />
                  <span>Export STIX 2.1 Bundle</span>
                </button>
                <button
                  onClick={() => {
                    void downloadSample(sample.sample_id, sample.original_name).catch(() =>
                      setErrorMsg("Download failed — bytes not stored?"),
                    );
                    setMenuOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-text-muted hover:bg-bg-elevated hover:text-accent transition"
                >
                  <Icon name="download" size={12} />
                  <span>Download Binary</span>
                </button>
                <div className="my-1 border-t border-border-subtle/50" />
                <button
                  onClick={handleDelete}
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-rose-400 hover:bg-rose-500/10 transition"
                >
                  <Icon name="x" size={12} />
                  <span>Delete Sample</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
