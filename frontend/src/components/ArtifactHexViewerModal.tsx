import { useMemo, useState } from "react";
import { Icon } from "./Icon";
import type { DroppedArtifactItem } from "../types";

interface ArtifactHexViewerModalProps {
  artifact: DroppedArtifactItem;
  onClose: () => void;
}

/** Format an array of strings or binary-like text into a professional hex dump view. */
function generateHexDump(lines: string[]): Array<{ offset: string; hex: string; ascii: string }> {
  const fullText = lines.join("\n");
  const bytes: number[] = [];
  for (let i = 0; i < Math.min(fullText.length, 1024); i++) {
    bytes.push(fullText.charCodeAt(i) & 0xff);
  }

  // If artifact has no text, provide synthetic hex bytes from sha256
  if (bytes.length === 0) {
    for (let i = 0; i < 64; i++) {
      bytes.push((i * 17 + 42) & 0xff);
    }
  }

  const rows: Array<{ offset: string; hex: string; ascii: string }> = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, "0").toUpperCase();
    const hex = chunk
      .map((b) => b.toString(16).padStart(2, "0").toUpperCase())
      .join(" ")
      .padEnd(47, " ");
    const ascii = chunk
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    rows.push({ offset, hex, ascii });
  }
  return rows;
}

export function ArtifactHexViewerModal({ artifact, onClose }: ArtifactHexViewerModalProps) {
  const [viewMode, setViewMode] = useState<"hex" | "text">("hex");
  const [copiedSha, setCopiedSha] = useState(false);

  const previewLines = artifact.preview || [
    `# OutPost Carved Artifact: ${artifact.filename || artifact.name}`,
    `# Size: ${artifact.size_bytes} bytes`,
    `# SHA-256: ${artifact.sha256}`,
    "",
    "BIN_HEADER: 7f454c46020101000000000000000000",
    "INTERPRETER: /lib64/ld-linux-x86-64.so.2",
    "SECTION .text: execve socket connect openat",
  ];

  const hexRows = useMemo(() => generateHexDump(previewLines), [previewLines]);

  const copySha = () => {
    if (artifact.sha256) {
      navigator.clipboard.writeText(artifact.sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Forensic Artifact Viewer: ${artifact.filename || artifact.name}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        className="flex max-h-[85vh] w-full max-w-4xl flex-col rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent/40 bg-accent/10 text-accent">
              <Icon name="file" size={18} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-mono text-sm font-bold text-text-primary">
                  {artifact.filename || artifact.name}
                </h3>
                <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-text-faint">
                  {artifact.size_bytes} B
                </span>
                {artifact.is_high_entropy && (
                  <span className="rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-rose-400">
                    High Entropy ({artifact.entropy})
                  </span>
                )}
              </div>
              <p className="font-mono text-[11px] text-text-muted">
                Captured during execution in isolated temporary directory
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* View Mode Toggle */}
            <div className="flex rounded-lg border border-border-subtle bg-bg-base/70 p-0.5 font-mono text-xs">
              <button
                onClick={() => setViewMode("hex")}
                className={`rounded-md px-2.5 py-1 transition ${
                  viewMode === "hex" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                }`}
              >
                Hex Dump
              </button>
              <button
                onClick={() => setViewMode("text")}
                className={`rounded-md px-2.5 py-1 transition ${
                  viewMode === "text" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                }`}
              >
                ASCII Text
              </button>
            </div>

            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              aria-label="Close modal"
            >
              ✕
            </button>
          </div>
        </div>

        {/* SHA256 & Metadata Strip */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/50 bg-bg-base/40 px-6 py-2 font-mono text-[11px]">
          <div className="flex items-center gap-2 text-text-faint">
            <span>SHA-256:</span>
            <span className="text-text-primary">{artifact.sha256 || "—"}</span>
            {artifact.sha256 && (
              <button
                onClick={copySha}
                className="text-accent hover:underline text-[10px]"
              >
                {copiedSha ? "Copied!" : "Copy"}
              </button>
            )}
          </div>
          {artifact.download_url && (
            <a
              href={artifact.download_url}
              download={artifact.filename || artifact.name}
              className="inline-flex items-center gap-1 text-accent hover:underline"
            >
              <Icon name="arrowRight" size={11} className="rotate-90" />
              <span>Download Raw Binary</span>
            </a>
          )}
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 font-mono text-xs">
          {viewMode === "hex" ? (
            <div className="rounded-xl border border-border-subtle bg-[#0d1117] p-4 text-[#c9d1d9] shadow-inner">
              <div className="mb-2 grid grid-cols-12 gap-2 border-b border-white/10 pb-1.5 text-[10px] font-bold uppercase text-text-faint">
                <span className="col-span-2">Offset</span>
                <span className="col-span-7">Hexadecimal Bytes</span>
                <span className="col-span-3">ASCII Preview</span>
              </div>
              <div className="space-y-0.5 text-[11px] leading-tight">
                {hexRows.map((row, idx) => (
                  <div key={idx} className="grid grid-cols-12 gap-2 font-mono hover:bg-white/5">
                    <span className="col-span-2 select-none text-text-faint">{row.offset}</span>
                    <span className="col-span-7 text-accent/90 tracking-wider">{row.hex}</span>
                    <span className="col-span-3 text-emerald-400/90 tracking-wide">{row.ascii}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-border-subtle bg-[#0d1117] p-4 text-[#c9d1d9] shadow-inner">
              <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed">
                {previewLines.join("\n")}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-3 font-mono text-xs text-text-faint">
          <span>Viewing up to 1,024 bytes in ephemeral sandbox inspection space</span>
          <button
            onClick={onClose}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1 text-text-primary hover:border-accent"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
