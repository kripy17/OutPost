import { useState, type ChangeEvent } from "react";
import { compareForensicCapsules } from "../lib/api";

interface CapsuleDiffModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CapsuleDiffModal({ isOpen, onClose }: CapsuleDiffModalProps) {
  const [capsuleAJson, setCapsuleAJson] = useState<string>("");
  const [capsuleBJson, setCapsuleBJson] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [diffResult, setDiffResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>, target: "A" | "B") => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (target === "A") setCapsuleAJson(content);
      else setCapsuleBJson(content);
    };
    reader.readAsText(file);
  };

  const handleCompare = async () => {
    try {
      setLoading(true);
      setError(null);
      let parsedA: any = null;
      let parsedB: any = null;

      try {
        parsedA = JSON.parse(capsuleAJson);
      } catch {
        throw new Error("Capsule A contains invalid JSON.");
      }

      try {
        parsedB = JSON.parse(capsuleBJson);
      } catch {
        throw new Error("Capsule B contains invalid JSON.");
      }

      const res = await compareForensicCapsules(parsedA, parsedB);
      setDiffResult(res);
    } catch (err: any) {
      setError(err?.message || "Failed to compare capsules.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4">
      <div className="bg-panel-bg border border-panel-border rounded-xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-panel-border">
          <div className="flex items-center gap-2">
            <span className="text-base font-bold text-text-primary">Forensic Capsule Differential Comparison</span>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-accent/15 text-accent border border-accent/30">
              .xray.json Diff
            </span>
          </div>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary text-xl font-mono leading-none cursor-pointer"
          >
            ×
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-3 rounded text-xs">
              {error}
            </div>
          )}

          {/* Capsule Inputs */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Capsule A */}
            <div className="bg-panel-border/20 border border-panel-border rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text-primary">Capsule A (Baseline / Prior)</span>
                <label className="text-[11px] text-accent hover:underline cursor-pointer">
                  Upload .json
                  <input
                    type="file"
                    accept=".json"
                    className="hidden"
                    onChange={(e) => handleFileUpload(e, "A")}
                  />
                </label>
              </div>
              <textarea
                value={capsuleAJson}
                onChange={(e) => setCapsuleAJson(e.target.value)}
                placeholder="Paste Capsule A JSON or upload .xray.json file..."
                rows={5}
                className="w-full bg-background border border-panel-border rounded p-2 text-xs font-mono text-text-primary resize-none"
              />
            </div>

            {/* Capsule B */}
            <div className="bg-panel-border/20 border border-panel-border rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-text-primary">Capsule B (Infected / Delta)</span>
                <label className="text-[11px] text-accent hover:underline cursor-pointer">
                  Upload .json
                  <input
                    type="file"
                    accept=".json"
                    className="hidden"
                    onChange={(e) => handleFileUpload(e, "B")}
                  />
                </label>
              </div>
              <textarea
                value={capsuleBJson}
                onChange={(e) => setCapsuleBJson(e.target.value)}
                placeholder="Paste Capsule B JSON or upload .xray.json file..."
                rows={5}
                className="w-full bg-background border border-panel-border rounded p-2 text-xs font-mono text-text-primary resize-none"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleCompare}
              disabled={loading || !capsuleAJson.trim() || !capsuleBJson.trim()}
              className="px-4 py-2 rounded text-xs font-semibold bg-accent text-white hover:bg-accent/80 transition cursor-pointer disabled:opacity-50"
            >
              {loading ? "Comparing..." : "🔍 Run Side-by-Side Comparison"}
            </button>
          </div>

          {/* Diff Results Output */}
          {diffResult && (
            <div className="space-y-4 pt-4 border-t border-panel-border">
              {/* Summary Cards */}
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-xs space-y-1">
                  <div className="font-semibold text-text-primary">
                    Capsule A: {diffResult.capsule_a?.name || "Unknown"} (PID {diffResult.capsule_a?.pid})
                  </div>
                  <div className="text-text-muted font-mono truncate">{diffResult.capsule_a?.executable_path}</div>
                  <div className="text-text-muted">
                    Capabilities: <span className="font-mono text-text-primary">{diffResult.capsule_a?.capabilities_count}</span> · Libraries: <span className="font-mono text-text-primary">{diffResult.capsule_a?.libraries_count}</span>
                  </div>
                </div>

                <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-xs space-y-1">
                  <div className="font-semibold text-text-primary">
                    Capsule B: {diffResult.capsule_b?.name || "Unknown"} (PID {diffResult.capsule_b?.pid})
                  </div>
                  <div className="text-text-muted font-mono truncate">{diffResult.capsule_b?.executable_path}</div>
                  <div className="text-text-muted">
                    Capabilities: <span className="font-mono text-text-primary">{diffResult.capsule_b?.capabilities_count}</span> · Libraries: <span className="font-mono text-text-primary">{diffResult.capsule_b?.libraries_count}</span>
                  </div>
                </div>
              </div>

              {/* Capabilities Diff */}
              <div className="bg-panel-bg border border-panel-border rounded-lg p-3 space-y-2">
                <div className="text-xs font-semibold text-text-primary">Capabilities Differential</div>
                <div className="flex flex-wrap gap-2">
                  {(diffResult.capabilities_diff?.only_in_b || []).map((cap: string) => (
                    <span
                      key={cap}
                      className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/30"
                    >
                      + {cap} (Added in B)
                    </span>
                  ))}
                  {(diffResult.capabilities_diff?.only_in_a || []).map((cap: string) => (
                    <span
                      key={cap}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-panel-border/60 text-text-muted"
                    >
                      - {cap} (Only in A)
                    </span>
                  ))}
                  {(diffResult.capabilities_diff?.only_in_b || []).length === 0 && (diffResult.capabilities_diff?.only_in_a || []).length === 0 && (
                    <span className="text-xs text-text-muted">Identical capabilities between capsules.</span>
                  )}
                </div>
              </div>

              {/* Mapped Libraries Diff */}
              <div className="bg-panel-bg border border-panel-border rounded-lg p-3 space-y-2">
                <div className="text-xs font-semibold text-text-primary">
                  Shared Libraries (.so) Differential ({diffResult.libraries_diff?.common_count || 0} common)
                </div>
                <div className="flex flex-wrap gap-2">
                  {(diffResult.libraries_diff?.only_in_b || []).map((lib: string) => (
                    <span
                      key={lib}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30"
                    >
                      + {lib}
                    </span>
                  ))}
                  {(diffResult.libraries_diff?.only_in_b || []).length === 0 && (
                    <span className="text-xs text-text-muted">No newly mapped libraries detected in Capsule B.</span>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
