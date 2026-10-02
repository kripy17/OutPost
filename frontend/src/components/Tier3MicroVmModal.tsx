import { useEffect, useState } from "react";
import { Icon } from "./Icon";

export function Tier3MicroVmModal({ onClose }: { onClose: () => void }) {
  const [copiedCode, setCopiedCode] = useState(false);
  const setupCmd = "bash scripts/setup_qemu_sandbox.sh";

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Tier 3 MicroVM & Guest Agent Configuration"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-lg flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Icon name="terminal" size={18} />
            </div>
            <div>
              <h3 className="font-bold text-text-primary text-sm">Tier 3: Isolated MicroVM &amp; Guest Agent</h3>
              <p className="text-[11px] text-text-faint">Disposable Windows 10/11 QEMU / KVM Detonation Pipeline</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-base transition"
            title="Close modal"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs text-text-muted leading-relaxed">
          <p>
            OutPost's <strong>Tier 2 (Wine64)</strong> provides instant user-mode emulation for standard PEs and scripts. However, modern Windows threats—such as kernel drivers, anti-emulation hooks, and direct ETW evasion—require a genuine Windows kernel.
          </p>
          <p>
            OutPost's <strong>Tier 3 Architecture</strong> dispatches detonation to a disposable QEMU / KVM Windows MicroVM running <code className="text-accent bg-bg-base px-1 py-0.5 rounded border border-border-subtle">outpost-guest-agent</code>. The agent monitors native <strong>Microsoft-Windows-Sysmon</strong> Event Logs, socket tables, and memory dumps under strict snapshot isolation.
          </p>

          <div className="rounded-xl border border-border-subtle bg-bg-base p-3.5 space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between text-[11px] text-text-faint">
              <span className="font-sans font-semibold text-text-primary">Launch Disposable MicroVM:</span>
              <button
                onClick={() => {
                  void navigator.clipboard.writeText(setupCmd);
                  setCopiedCode(true);
                  setTimeout(() => setCopiedCode(false), 2000);
                }}
                className="text-accent hover:underline flex items-center gap-1 text-[10px] font-sans font-bold"
              >
                <Icon name="copy" size={11} />
                <span>{copiedCode ? "Copied!" : "Copy command"}</span>
              </button>
            </div>
            <div className="text-accent select-all bg-[#0a0c10] p-2.5 rounded-lg border border-white/5 overflow-x-auto">
              $ {setupCmd}
            </div>
            <div className="text-[10px] text-text-faint pt-1 leading-normal font-sans">
              Agent listens on guest port 8009 with host forward: <code className="text-accent font-mono">OUTPOST_GUEST_VM_URL="http://127.0.0.1:8009"</code>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-4 bg-bg-base/70 text-[11px] text-text-faint">
          <span>Snapshot Isolation: All disk mutations are discarded upon exit</span>
          <button
            onClick={onClose}
            className="press rounded-lg bg-bg-elevated border border-border-subtle px-4 py-1.5 text-xs font-semibold text-text-primary hover:bg-bg-base transition"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
