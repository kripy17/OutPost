import { useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import type { SampleStatic } from "../../types";

interface FileStructureTabProps {
  st?: SampleStatic;
  sampleName: string;
}

export function FileStructureTab({ st, sampleName }: FileStructureTabProps) {
  const [sectionFilter, setSectionFilter] = useState("");

  if (!st || !st.available) {
    return (
      <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs">
        <Icon name="box" size={24} className="mx-auto text-text-faint mb-2" />
        <p className="font-bold text-text-primary">File Structure Unavailable</p>
        <p className="mt-1 text-text-muted">
          Bytes for this sample are not stored in the vault. Re-upload binary to enable structural inspection.
        </p>
      </div>
    );
  }

  const pe = st.pe;
  const elf = st.elf;

  if (!pe && !elf) {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface/60 p-8 text-center text-text-muted font-mono text-xs space-y-2">
        <Icon name="terminal" size={24} className="mx-auto text-amber-400 mb-2" />
        <p className="font-bold text-text-primary">Unsupported Executable Format</p>
        <p className="max-w-md mx-auto text-text-muted">
          Sample <span className="text-text-primary font-semibold">{sampleName}</span> is not a PE or ELF binary (e.g. script payload, document, or raw bytecode). Executable structure inspection is not applicable.
        </p>
        <div className="pt-2 text-[11px] text-text-faint">
          Raw size: {st.size.toLocaleString()} bytes · Strings and hex preview are still available in adjacent tabs.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* PE Executable Inspection View */}
      {pe && (
        <div className="space-y-6">
          {/* Header Metadata Grid */}
          <Panel kicker="PE Header Inspector" title="DOS / PE / Optional Headers">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Machine Architecture</span>
                <span className="font-bold text-text-primary text-[11px]">{pe.machine}</span>
                <span className="text-[9px] text-text-muted block">{pe.bits}-bit architecture</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Subsystem</span>
                <span className="font-bold text-text-primary text-[11px]">{pe.subsystem || "Native / Console"}</span>
                <span className="text-[9px] text-text-muted block">Target runtime</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Image Base</span>
                <span className="font-bold text-accent text-[11px]">{pe.image_base || "0x00400000"}</span>
                <span className="text-[9px] text-text-muted block">Preferred load VA</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Entry Point RVA</span>
                <span className="font-bold text-accent text-[11px]">
                  {pe.entry_point_rva !== null ? `0x${pe.entry_point_rva.toString(16).toUpperCase()}` : "0x0"}
                </span>
                <span className="text-[9px] text-text-muted block">Code entry offset</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Import Hash (Imphash)</span>
                <span className="font-bold text-text-primary text-[11px] truncate block" title={pe.imphash || "None"}>
                  {pe.imphash ? `${pe.imphash.slice(0, 10)}…` : "None"}
                </span>
                <span className="text-[9px] text-text-muted block">{pe.imports.length} linked DLLs</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Rich Header</span>
                <span className="font-bold text-text-primary text-[11px]">
                  {pe.rich_header?.present ? "Present" : "None"}
                </span>
                <span className="text-[9px] text-text-muted block">
                  {pe.rich_header?.present ? `${pe.rich_header.records_count} records` : "No MSVC records"}
                </span>
              </div>
            </div>

            {/* Rich Header Details (if present) */}
            {pe.rich_header?.present && (
              <div className="mt-3 rounded-lg border border-purple-500/30 bg-purple-500/5 p-2.5 text-[11px] flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-purple-500/20 px-1.5 py-0.5 text-[9px] font-bold text-purple-300 uppercase">
                    Rich Header Hash
                  </span>
                  <code className="text-purple-300 font-mono text-[10px]">{pe.rich_header.hash}</code>
                </div>
                <div className="text-[10px] text-text-muted">
                  XOR Key: <strong className="text-text-primary">{pe.rich_header.xor_key}</strong> · {pe.rich_header.records_count} tool/compiler entries
                </div>
              </div>
            )}
          </Panel>

          {/* Exploit Mitigations & Authenticode */}
          <Panel kicker="Binary Hardening" title="Exploit Mitigations &amp; Signature Integrity">
            {(() => {
              const mitigations = pe.mitigations || [];
              const checks = [
                {
                  name: "Data Execution Prevention (DEP / NX)",
                  desc: "Prevents execution of code in non-executable memory segments (stack/heap)",
                  active: mitigations.some((m) => m.toLowerCase().includes("dep") || m.toLowerCase().includes("nx")),
                },
                {
                  name: "Address Space Layout Randomization (ASLR)",
                  desc: "Randomizes module base addresses in memory to obstruct ROP payload exploits",
                  active: mitigations.some((m) => m.toLowerCase().includes("aslr")),
                },
                {
                  name: "High Entropy Virtual Addresses",
                  desc: "64-bit high-entropy address space layout support",
                  active: mitigations.some((m) => m.toLowerCase().includes("high entropy") || m.toLowerCase().includes("64-bit")),
                },
                {
                  name: "Control Flow Guard (CFG)",
                  desc: "Validates indirect call targets against ROP/JOP call hijacking primitives",
                  active: mitigations.some((m) => m.toLowerCase().includes("cfg") || m.toLowerCase().includes("control flow")),
                },
                {
                  name: "SafeSEH / Structured Exception Handling",
                  desc: "Validates exception handler records before dispatching CPU traps",
                  active: mitigations.some((m) => m.toLowerCase().includes("seh")),
                },
                {
                  name: "Authenticode Signature",
                  desc: "Cryptographically signed with a digital certificate catalog entry",
                  active: Boolean(pe.authenticode?.signed),
                },
              ];

              return (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-[10px] uppercase text-text-faint">
                    <span>Active Mitigations:</span>
                    <span>
                      {checks.filter((c) => c.active).length} / {checks.length} Enforced
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {checks.map((chk) => (
                      <div
                        key={chk.name}
                        className={`flex items-start gap-2.5 rounded-lg border p-2.5 text-[11px] ${
                          chk.active
                            ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"
                            : "border-border-subtle bg-bg-base/40 text-text-muted"
                        }`}
                      >
                        <span className={`mt-0.5 shrink-0 ${chk.active ? "text-emerald-400" : "text-text-faint"}`}>
                          <Icon name={chk.active ? "check" : "x"} size={12} />
                        </span>
                        <div className="space-y-0.5 min-w-0">
                          <span className={`block font-bold truncate ${chk.active ? "text-emerald-300" : "text-text-muted"}`}>
                            {chk.name}
                          </span>
                          <span className="block text-[9px] text-text-faint leading-tight line-clamp-2">
                            {chk.desc}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </Panel>

          {/* PE Sections Table */}
          <Panel
            kicker="Structural Layout"
            title={`PE Sections Table (${pe.sections.length})`}
            right={
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Filter sections..."
                  value={sectionFilter}
                  onChange={(e) => setSectionFilter(e.target.value)}
                  className="h-6 w-36 rounded border border-border-subtle bg-bg-base px-2 text-[10px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
                />
              </div>
            }
          >
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
              <table className="w-full min-w-[620px] text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                    <th className="py-2 px-3">Name</th>
                    <th className="py-2 px-3 text-right">Virtual Size</th>
                    <th className="py-2 px-3 text-right">Raw Disk Size</th>
                    <th className="py-2 px-3 text-center">Expansion Δ</th>
                    <th className="py-2 px-3">Entropy</th>
                    <th className="py-2 px-3">Permissions</th>
                    <th className="py-2 px-3">Characteristics / Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {pe.sections
                    .filter((s) => !sectionFilter || s.name.toLowerCase().includes(sectionFilter.toLowerCase()))
                    .map((s) => {
                      const delta = s.raw_size > 0 ? Math.round(((s.virtual_size - s.raw_size) / s.raw_size) * 100) : 0;
                      const isPackedDelta = delta > 40;
                      const entropyVal = s.entropy ?? 0;
                      const isHighEntropy = entropyVal > 7.0;
                      const isRwX = Boolean(s.is_rwx || s.permissions?.includes("RWX"));

                      return (
                        <tr key={s.name} className="hover:bg-bg-elevated/40 transition-colors">
                          <td className="py-2 px-3 font-bold text-text-primary font-mono">{s.name || "(anon)"}</td>
                          <td className="py-2 px-3 text-right text-text-muted font-mono">
                            0x{s.virtual_size.toString(16).toUpperCase()} ({s.virtual_size.toLocaleString()} B)
                          </td>
                          <td className="py-2 px-3 text-right text-text-muted font-mono">
                            0x{s.raw_size.toString(16).toUpperCase()} ({s.raw_size.toLocaleString()} B)
                          </td>
                          <td className="py-2 px-3 text-center">
                            {isPackedDelta ? (
                              <span
                                className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[9px] font-bold text-amber-400"
                                title="Virtual memory exceeds raw disk size — unpacked expansion characteristic of runtime unpackers"
                              >
                                +{delta}%
                              </span>
                            ) : (
                              <span className="text-[10px] text-text-faint">{delta >= 0 ? `+${delta}%` : `${delta}%`}</span>
                            )}
                          </td>
                          <td className="py-2 px-3">
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`text-[10px] font-bold ${
                                  isHighEntropy ? "text-rose-400" : entropyVal > 6.0 ? "text-amber-400" : "text-emerald-400"
                                }`}
                              >
                                {entropyVal.toFixed(2)}
                              </span>
                              <div className="h-1.5 w-14 overflow-hidden rounded-full bg-bg-elevated">
                                <div
                                  className={`h-full rounded-full ${
                                    isHighEntropy ? "bg-rose-500" : entropyVal > 6.0 ? "bg-amber-400" : "bg-emerald-400"
                                  }`}
                                  style={{ width: `${Math.min(100, (entropyVal / 8.0) * 100)}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-2 px-3">
                            {isRwX ? (
                              <span
                                className="inline-flex items-center gap-1 rounded border border-rose-500/50 bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-400"
                                title="Read, Write, and Execute permissions — self-modifying code or shellcode injection danger"
                              >
                                <span>RWX</span>
                                <Icon name="alert" size={10} />
                              </span>
                            ) : s.permissions ? (
                              <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[10px] font-bold text-text-muted">
                                {s.permissions}
                              </span>
                            ) : (
                              <span className="text-[10px] text-text-faint">—</span>
                            )}
                          </td>
                          <td className="py-2 px-3">
                            <span className="block max-w-[180px] truncate text-[10px] text-text-faint" title={s.flags?.join(" · ")}>
                              {s.flags?.join(" · ") || "—"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}

      {/* ELF Executable Inspection View */}
      {elf && (
        <div className="space-y-6">
          <Panel kicker="ELF Header Inspector" title="ELF Headers &amp; Architecture">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">ELF Class</span>
                <span className="font-bold text-text-primary text-[11px]">{elf.class}-bit</span>
                <span className="text-[9px] text-text-muted block">Architecture size</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Machine</span>
                <span className="font-bold text-text-primary text-[11px]">{elf.machine}</span>
                <span className="text-[9px] text-text-muted block">Instruction set</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Type</span>
                <span className="font-bold text-text-primary text-[11px]">{elf.type}</span>
                <span className="text-[9px] text-text-muted block">Executable / Shared / Relocatable</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Endianness</span>
                <span className="font-bold text-text-primary text-[11px]">{elf.endian}-endian</span>
                <span className="text-[9px] text-text-muted block">Byte order</span>
              </div>

              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                <span className="text-[9px] uppercase text-text-faint block">Entry Point</span>
                <span className="font-bold text-accent text-[11px]">0x{elf.entry_point.toString(16).toUpperCase()}</span>
                <span className="text-[9px] text-text-muted block">Virtual address</span>
              </div>
            </div>
          </Panel>

          {/* ELF Sections */}
          <Panel kicker="Structural Layout" title={`ELF Sections (${elf.sections.length})`}>
            {elf.sections.length === 0 ? (
              <p className="text-xs text-text-muted py-4">No ELF section headers mapped.</p>
            ) : (
              <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                      <th className="py-2 px-3">Name</th>
                      <th className="py-2 px-3">Type ID</th>
                      <th className="py-2 px-3 text-right">Size (Bytes)</th>
                      <th className="py-2 px-3">Entropy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/50">
                    {elf.sections.map((sec, sidx) => (
                      <tr key={sidx} className="hover:bg-bg-elevated/40">
                        <td className="py-2 px-3 font-bold text-text-primary font-mono">{sec.name || "(anon)"}</td>
                        <td className="py-2 px-3 text-text-muted font-mono">{sec.type}</td>
                        <td className="py-2 px-3 text-right text-text-primary font-mono">{sec.size.toLocaleString()} B</td>
                        <td className="py-2 px-3">
                          {sec.entropy !== undefined ? (
                            <span className="font-bold text-text-muted">{sec.entropy.toFixed(2)}</span>
                          ) : (
                            <span className="text-text-faint">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
