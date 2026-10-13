import { useState } from "react";
import { Icon } from "../Icon";
import { formatBytes } from "../../routes/samplesHelpers";
import type { SampleRow, SampleStatic } from "../../types";

interface SampleIdentificationStripProps {
  sample: SampleRow;
  st?: SampleStatic;
}

export function SampleIdentificationStrip({ sample, st }: SampleIdentificationStripProps) {
  const [copiedSha256, setCopiedSha256] = useState(false);
  const [showFullHash, setShowFullHash] = useState(false);

  const sha256 = st?.sha256 || sample.sha256;
  const isAvailable = st ? st.available : true;
  const yaraCount = sample.yara_rules ? sample.yara_rules.length : 0;
  const sizeFormatted = formatBytes(sample.size);

  const handleCopySha256 = () => {
    void navigator.clipboard.writeText(sha256);
    setCopiedSha256(true);
    setTimeout(() => setCopiedSha256(false), 1500);
  };

  const uploadTime = sample.created_at
    ? `${sample.created_at.slice(0, 19).replace("T", " ")} UTC`
    : "Unknown";

  return (
    <div className="mb-6 rounded-xl border border-border-subtle bg-bg-surface/40 p-3 font-mono text-xs">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Strip Item 1: SHA-256 with Copy & Expand */}
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[10px] uppercase text-text-faint">
            <span>SHA-256 Fingerprint</span>
            <button
              onClick={handleCopySha256}
              className="press inline-flex items-center gap-1 text-[10px] text-accent hover:underline"
              title="Copy full SHA-256 to clipboard"
            >
              <Icon name={copiedSha256 ? "check" : "copy"} size={10} className={copiedSha256 ? "text-risk-clean" : ""} />
              <span>{copiedSha256 ? "Copied" : "Copy"}</span>
            </button>
          </div>
          <div className="flex items-center gap-1.5">
            <code
              onClick={() => setShowFullHash(!showFullHash)}
              className="cursor-pointer truncate rounded bg-bg-base/80 px-2 py-0.5 text-[11px] text-text-primary select-all hover:text-accent transition-colors"
              title={`Click to ${showFullHash ? "collapse" : "expand"}: ${sha256}`}
            >
              {showFullHash ? sha256 : `${sha256.slice(0, 16)}…${sha256.slice(-10)}`}
            </code>
          </div>
          {showFullHash && (
            <div className="break-all rounded border border-border-subtle bg-bg-base p-1.5 text-[10px] text-text-muted">
              {sha256}
            </div>
          )}
        </div>

        {/* Strip Item 2: File Size & Format/Platform */}
        <div className="space-y-1">
          <div className="text-[10px] uppercase text-text-faint">Size &amp; Platform</div>
          <div className="flex items-center gap-2">
            <span className="font-semibold text-text-primary">{sizeFormatted}</span>
            <span className="text-[10px] text-text-faint">({sample.size.toLocaleString()} bytes)</span>
          </div>
          <div className="text-[10px] text-text-muted flex items-center gap-1" title="Platform inferred strictly from magic bytes header, not verified certificate">
            <span>Platform: <strong className="capitalize text-text-primary">{sample.detected_platform}</strong></span>
            <span className="text-[9px] text-text-faint">(inferred from magic bytes)</span>
          </div>
        </div>

        {/* Strip Item 3: Timestamps & Most Recent Analysis */}
        <div className="space-y-1">
          <div className="text-[10px] uppercase text-text-faint">Submission &amp; Analysis</div>
          <div className="text-[11px] text-text-primary truncate" title={uploadTime}>
            Submitted: {uploadTime}
          </div>
          <div className="text-[10px] text-text-muted flex items-center gap-1.5">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
            <span>Static analyzer: {isAvailable ? "Complete" : "Pending bytes"}</span>
          </div>
        </div>

        {/* Strip Item 4: Signatures & Vault Availability */}
        <div className="space-y-1">
          <div className="text-[10px] uppercase text-text-faint">Signatures &amp; Retention</div>
          <div className="flex items-center gap-2">
            <span className={`font-semibold ${yaraCount > 0 ? "text-amber-400" : "text-text-muted"}`}>
              {yaraCount} YARA match{yaraCount === 1 ? "" : "es"}
            </span>
          </div>
          <div className="text-[10px] text-text-muted">
            {isAvailable ? (
              <span className="text-emerald-400">● Stored in vault (bytes retained)</span>
            ) : (
              <span className="text-amber-400">○ Bytes not stored (re-upload needed)</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
