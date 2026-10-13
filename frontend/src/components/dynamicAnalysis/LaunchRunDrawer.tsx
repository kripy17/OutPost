import { useState } from "react";
import { Icon } from "../Icon";
import type { AnalysisBackend, Platform, SampleRow } from "../../types";

interface LaunchRunDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunch: (params: {
    backend: AnalysisBackend;
    sample_id?: string;
    sample_name?: string;
    platform?: Platform;
    timeout_seconds?: number;
    isolation_driver?: string;
  }) => void;
  isLaunching: boolean;
  samples: SampleRow[];
  drivers?: Array<{ id: string; name: string; available: boolean; description: string; type: string }>;
  error: string | null;
}

const BACKENDS: Array<{
  value: AnalysisBackend;
  label: string;
  hint: string;
  tag: string;
}> = [
  {
    value: "static",
    label: "Static Triage (Zero Execution Risk)",
    hint: "Synchronous deep triage over stored bytes — Shannon entropy, PE/ELF structures, strings, and YARA signatures",
    tag: "Safe · Instant",
  },
  {
    value: "isolated-outpost",
    label: "Native Isolated Dynamic Sandbox",
    hint: "Bounded execution under Linux Bubblewrap/tempdir boundary with real-time process tree & telemetry flight recorder",
    tag: "Hardware Isolated",
  },
];

const TIMEOUT_PRESETS = [15, 30, 60, 120, 300];

export function LaunchRunDrawer({
  isOpen,
  onClose,
  onLaunch,
  isLaunching,
  samples,
  drivers = [],
  error,
}: LaunchRunDrawerProps) {
  const [backend, setBackend] = useState<AnalysisBackend>("static");
  const [sampleId, setSampleId] = useState("");
  const [manualName, setManualName] = useState(false);
  const [sampleName, setSampleName] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);
  const [networkIsolation, setNetworkIsolation] = useState<"airgap" | "sinkhole" | "loopback">("airgap");
  const [selectedDriver, setSelectedDriver] = useState<string>("auto");

  if (!isOpen) return null;

  const selectedSample = samples.find((s) => s.sample_id === sampleId);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!sampleId && !(manualName && sampleName.trim())) return;

    onLaunch({
      backend,
      sample_id: sampleId || undefined,
      sample_name: manualName || !sampleId ? sampleName.trim() || undefined : undefined,
      platform: backend === "static" ? undefined : (selectedSample?.detected_platform as Platform | undefined),
      timeout_seconds: backend === "static" ? undefined : timeoutSeconds,
      isolation_driver: backend === "static" ? undefined : selectedDriver,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-fade-in font-sans">
      <div className="w-full max-w-2xl rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl overflow-hidden animate-scale-in">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-border-subtle bg-bg-base/80 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-accent/40 bg-accent/15 text-accent">
              <Icon name="zap" size={15} />
            </div>
            <div>
              <h2 className="text-sm font-bold text-text-primary">Detonate Artifact · New Analysis Run</h2>
              <p className="text-[11px] font-mono text-text-muted">POST /analysis · Orchestrated Execution Sandbox</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1 text-text-muted hover:bg-bg-elevated hover:text-text-primary transition"
            aria-label="Close modal"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5 font-mono text-xs max-h-[80vh] overflow-y-auto">
          {/* Section 1: Backend Selection */}
          <div>
            <label className="mb-1.5 block text-[11px] font-bold uppercase tracking-wider text-text-muted">
              Backend
            </label>
            <div className="grid gap-2 sm:grid-cols-2">
              {BACKENDS.map((b) => (
                <button
                  type="button"
                  key={b.value}
                  onClick={() => setBackend(b.value)}
                  className={`flex flex-col items-start gap-1 rounded-xl border p-3 text-left transition ${
                    backend === b.value
                      ? "border-accent bg-accent/10 shadow-xs"
                      : "border-border-subtle bg-bg-base/40 hover:border-border-subtle/80 hover:bg-bg-elevated/40"
                  }`}
                >
                  <div className="flex w-full items-center justify-between">
                    <span className="font-bold text-text-primary text-[11px]">{b.label}</span>
                    <span className={`rounded px-1.5 py-0.2 text-[9px] font-semibold uppercase ${
                      b.value === "static" ? "bg-emerald-500/20 text-emerald-400" : "bg-accent/20 text-accent"
                    }`}>
                      {b.tag}
                    </span>
                  </div>
                  <p className="text-[10px] text-text-muted leading-relaxed font-sans mt-0.5">{b.hint}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Section 2: Vault Artifact Selection */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
                Artifact &amp; Target Payload
              </label>
              <label className="flex items-center gap-1.5 text-[11px] text-text-muted font-sans cursor-pointer">
                <input
                  type="checkbox"
                  checked={manualName}
                  onChange={(e) => setManualName(e.target.checked)}
                  className="rounded border-border-subtle accent-accent"
                />
                <span>Manual Sample Name</span>
              </label>
            </div>

            {!manualName ? (
              <div>
                <select
                  className="w-full rounded-lg border border-border-subtle bg-bg-base px-3 py-2 text-xs text-text-primary outline-none focus:border-accent"
                  value={sampleId}
                  onChange={(e) => setSampleId(e.target.value)}
                >
                  <option value="">— select from the sample library —</option>
                  {samples.map((s) => (
                    <option key={s.sample_id} value={s.sample_id}>
                      {s.original_name} · {s.detected_platform} · {s.sha256.slice(0, 12)}…
                    </option>
                  ))}
                </select>
                {selectedSample && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface/50 p-2 text-[10px]">
                    <span className="text-text-faint">Platform:</span>
                    <span className="rounded bg-bg-elevated px-1.5 py-0.2 font-bold text-accent uppercase">
                      {selectedSample.detected_platform}
                    </span>
                    <span className="text-text-faint">SHA-256:</span>
                    <span className="truncate max-w-[200px] text-text-secondary select-all">
                      {selectedSample.sha256}
                    </span>
                    <span className="ml-auto text-text-faint">{selectedSample.size} bytes</span>
                  </div>
                )}
              </div>
            ) : (
              <input
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-3 py-2 text-xs text-text-primary outline-none focus:border-accent font-mono"
                placeholder="e.g. payload_dropper.bin"
                value={sampleName}
                onChange={(e) => setSampleName(e.target.value)}
              />
            )}
          </div>

          {/* Section 3: Dynamic Sandbox Configuration (Only if dynamic execution selected) */}
          {backend !== "static" && (
            <div className="space-y-4 rounded-xl border border-border-subtle bg-bg-base/40 p-4">
              <div className="flex items-center gap-1.5 text-accent font-bold text-[11px]">
                <Icon name="sliders" size={13} />
                <span>Execution Boundary &amp; Containment Controls</span>
              </div>

              {/* Isolation Driver Selector */}
              <div>
                <label className="mb-1 block text-[10px] uppercase text-text-faint">
                  Isolation Driver (Fail-Closed Sandbox)
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setSelectedDriver("auto")}
                    className={`rounded-lg border p-2 text-left transition ${
                      selectedDriver === "auto" ? "border-accent bg-accent/10" : "border-border-subtle bg-bg-surface"
                    }`}
                  >
                    <span className="font-bold text-text-primary block text-[10px]">Auto Detect</span>
                    <span className="text-[9px] text-text-faint">Prefer Bubblewrap namespace</span>
                  </button>
                  {drivers.map((drv) => (
                    <button
                      type="button"
                      key={drv.id}
                      onClick={() => drv.available && setSelectedDriver(drv.id)}
                      disabled={!drv.available}
                      className={`rounded-lg border p-2 text-left transition ${
                        selectedDriver === drv.id
                          ? "border-accent bg-accent/10"
                          : !drv.available
                            ? "border-border-subtle/50 opacity-40 cursor-not-allowed"
                            : "border-border-subtle bg-bg-surface hover:border-accent/40"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-text-primary block text-[10px]">{drv.name}</span>
                        <span className={`h-1.5 w-1.5 rounded-full ${drv.available ? "bg-emerald-400" : "bg-text-faint"}`} />
                      </div>
                      <span className="text-[9px] text-text-faint">{drv.available ? "Ready" : "Unavailable"}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Network Isolation Controls */}
              <div>
                <label className="mb-1 block text-[10px] uppercase text-text-faint">
                  Network Containment Mode
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { id: "airgap", label: "Air-Gapped", hint: "--unshare-net (Zero egress)" },
                    { id: "sinkhole", label: "Simulated Sinkhole", hint: "Fake DNS + dummy responder" },
                    { id: "loopback", label: "Local Loopback", hint: "127.0.0.1 bound only" },
                  ].map((mode) => (
                    <button
                      type="button"
                      key={mode.id}
                      onClick={() => setNetworkIsolation(mode.id as any)}
                      className={`rounded-lg border p-2 text-left transition ${
                        networkIsolation === mode.id
                          ? "border-accent bg-accent/10"
                          : "border-border-subtle bg-bg-surface hover:border-accent/40"
                      }`}
                    >
                      <span className="font-bold text-text-primary block text-[10px]">{mode.label}</span>
                      <span className="text-[9px] text-text-faint">{mode.hint}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Execution Timeout */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[10px] uppercase text-text-faint">
                    Execution Timeout
                  </label>
                  <span className="font-bold text-accent tabular-nums">{timeoutSeconds} seconds</span>
                </div>
                <div className="flex items-center gap-1.5">
                  {TIMEOUT_PRESETS.map((t) => (
                    <button
                      type="button"
                      key={t}
                      onClick={() => setTimeoutSeconds(t)}
                      className={`press rounded-lg border px-2.5 py-1 text-[10px] font-semibold transition ${
                        timeoutSeconds === t
                          ? "border-accent bg-accent text-white"
                          : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
                      }`}
                    >
                      {t}s
                    </button>
                  ))}
                  <input
                    type="number"
                    min={5}
                    max={600}
                    value={timeoutSeconds}
                    onChange={(e) => setTimeoutSeconds(Number(e.target.value) || 15)}
                    className="w-16 rounded-lg border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-center outline-none focus:border-accent"
                  />
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-400">
              <Icon name="alert" size={14} className="shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Form Actions */}
          <div className="flex items-center justify-end gap-3 pt-2 border-t border-border-subtle">
            <button
              type="button"
              onClick={onClose}
              className="press rounded-lg border border-border-subtle bg-bg-surface px-4 py-2 font-mono text-xs font-semibold text-text-muted hover:text-text-primary transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLaunching || (!sampleId && !(manualName && sampleName.trim()))}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-5 py-2 font-mono text-xs font-bold text-white hover:bg-accent/90 disabled:opacity-50 transition shadow-xs"
            >
              <Icon name={isLaunching ? "refresh" : "zap"} size={13} className={isLaunching ? "animate-spin" : ""} />
              <span>{isLaunching ? "Launching…" : "Launch analysis"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
