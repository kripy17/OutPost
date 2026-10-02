import { useState } from "react";
import { Icon } from "./Icon";

export function Tier3MicroVmModal({ onClose }: { onClose: () => void }) {
  const [copiedCode, setCopiedCode] = useState(false);
  const setupCmd = "bash scripts/setup_qemu_sandbox.sh";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-xl rounded-2xl border border-border-subtle bg-bg-surface p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-start justify-between">
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

        <div className="text-xs text-text-muted space-y-2.5 leading-relaxed">
          <p>
            OutPost's <strong>Tier 2 (Wine64)</strong> provides instant user-mode emulation for standard PEs and scripts. However, modern Windows threats—such as kernel drivers, anti-emulation hooks, and direct ETW evasion—require a genuine Windows kernel.
          </p>
          <p>
            OutPost's <strong>Tier 3 Architecture</strong> dispatches detonation to a disposable QEMU / KVM Windows MicroVM running <code className="text-accent bg-bg-base px-1 py-0.5 rounded border border-border-subtle">outpost-guest-agent</code>. The agent monitors native <strong>Microsoft-Windows-Sysmon</strong> Event Logs, socket tables, and memory dumps under strict snapshot isolation.
          </p>
        </div>

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

        <div className="flex items-center justify-between pt-2 border-t border-border-subtle/50 text-[11px] text-text-faint">
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
