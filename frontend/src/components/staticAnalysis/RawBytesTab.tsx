import { useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import type { SampleStatic } from "../../types";

interface RawBytesTabProps {
  st?: SampleStatic;
  sampleName: string;
}

export function RawBytesTab({ st, sampleName }: RawBytesTabProps) {
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);
  const [activeOffset, setActiveOffset] = useState<string | null>(null);

  if (!st || !st.available) {
    return (
      <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs">
        <Icon name="box" size={24} className="mx-auto text-text-faint mb-2" />
        <p className="font-bold text-text-primary">Byte Inspection Unavailable</p>
        <p className="mt-1 text-text-muted max-w-md mx-auto">
          Raw bytes are not retained in vault storage for sample <span className="font-semibold text-text-primary">{sampleName}</span>. Byte inspection requires persistent disk payload. Re-upload binary to enable hex inspection.
        </p>
      </div>
    );
  }

  const preview = st.hex_preview;
  if (!preview || preview.length === 0) {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface/60 p-8 text-center text-text-muted font-mono text-xs">
        <Icon name="terminal" size={24} className="mx-auto text-amber-400 mb-2" />
        <p className="font-bold text-text-primary">No Hex Byte Stream Available</p>
        <p className="mt-1 text-text-muted">
          The static analysis engine did not produce a hex preview for this file format.
        </p>
      </div>
    );
  }

  const filtered = filter.trim()
    ? preview.filter(
        (r) =>
          r.offset.toLowerCase().includes(filter.toLowerCase()) ||
          r.hex.toLowerCase().includes(filter.toLowerCase()) ||
          r.ascii.toLowerCase().includes(filter.toLowerCase()),
      )
    : preview;

  const handleCopyRaw = () => {
    const text = preview.map((r) => `${r.offset}  ${r.hex.padEnd(48, " ")}  |${r.ascii}|`).join("\n");
    void navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const jumpToOffset = (offsetHex: string) => {
    setActiveOffset(offsetHex);
    const el = document.getElementById(`hex-row-${offsetHex}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  const entryPointRva = st.pe?.entry_point_rva;
  const elfEntryPoint = st.elf?.entry_point;

  return (
    <Panel
      kicker="Binary Inspection"
      title="Raw Byte & Hex Header Inspector"
      right={
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-text-faint">{preview.length * 16} bytes mapped</span>
          <button
            onClick={handleCopyRaw}
            className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-text-muted transition hover:border-accent hover:text-accent"
          >
            {copied ? "Copied Hex Dump" : "Copy Hex Dump"}
          </button>
        </div>
      }
    >
      <div className="space-y-3 font-mono text-xs">
        {/* Controls & Quick Jump Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs border-b border-border-subtle pb-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase text-text-faint">Jump to Offset:</span>
            <button
              onClick={() => jumpToOffset("00000000")}
              className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] text-text-primary hover:border-accent"
            >
              0x0000 (File Header)
            </button>
            {entryPointRva != null && (
              <button
                onClick={() => jumpToOffset(Number(entryPointRva).toString(16).padStart(8, "0"))}
                className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                title={`Jump to PE Entry Point RVA 0x${Number(entryPointRva).toString(16)}`}
              >
                Entry Point (0x{Number(entryPointRva).toString(16)})
              </button>
            )}
            {elfEntryPoint != null && (
              <button
                onClick={() => {
                  const hex = String(elfEntryPoint).replace(/^0x/i, "");
                  jumpToOffset(hex.padStart(8, "0"));
                }}
                className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                title={`Jump to ELF Entry Point ${String(elfEntryPoint)}`}
              >
                Entry Point ({String(elfEntryPoint).startsWith("0x") ? String(elfEntryPoint) : `0x${Number(elfEntryPoint).toString(16)}`})
              </button>
            )}
          </div>

          <div className="relative">
            <Icon name="search" size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter offset / hex / ascii..."
              className="w-56 rounded border border-border-subtle bg-bg-base py-1 pl-7 pr-2 text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
            />
          </div>
        </div>

        {/* Monospaced Hex Dump Grid */}
        <div className="max-h-96 overflow-x-auto overflow-y-auto rounded-xl border border-border-subtle bg-bg-inset p-3 text-[11px] leading-relaxed shadow-inner">
          <table className="w-full text-left font-mono">
            <thead>
              <tr className="border-b border-border-subtle text-[10px] uppercase text-text-faint">
                <th className="pb-1.5 pr-4 font-normal w-24">Offset</th>
                <th className="pb-1.5 pr-4 font-normal">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</th>
                <th className="pb-1.5 font-normal w-40">Decoded Text</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => {
                const isActive = activeOffset === row.offset;
                return (
                  <tr
                    key={row.offset}
                    id={`hex-row-${row.offset}`}
                    className={`transition-colors hover:bg-bg-elevated/40 ${
                      isActive ? "bg-accent/20 ring-1 ring-accent" : ""
                    }`}
                  >
                    <td className="pr-4 select-all font-bold text-accent whitespace-nowrap">
                      {row.offset}
                    </td>
                    <td className="pr-4 select-all tracking-wider text-text-primary whitespace-nowrap">
                      {row.hex.slice(0, 23)} <span className="text-text-faint">|</span> {row.hex.slice(24)}
                    </td>
                    <td className="select-all font-medium text-emerald-400 whitespace-nowrap">
                      {row.ascii}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  );
}
