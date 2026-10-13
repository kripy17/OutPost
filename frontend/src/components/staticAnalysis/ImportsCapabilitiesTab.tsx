import { useMemo, useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import type { SampleStatic } from "../../types";

interface ImportsCapabilitiesTabProps {
  st?: SampleStatic;
}

// Well-known security-sensitive Windows and POSIX APIs with MITRE context
const SENSITIVE_API_MAP: Record<string, { category: string; technique: string; desc: string }> = {
  // Process Injection & Memory
  VirtualAlloc: { category: "Memory Allocation", technique: "T1055", desc: "Allocates memory pages in address space" },
  VirtualAllocEx: { category: "Process Injection", technique: "T1055", desc: "Allocates memory in target remote process" },
  VirtualProtect: { category: "Memory Permissions", technique: "T1055", desc: "Changes protection of memory region (e.g. RW to RWX)" },
  VirtualProtectEx: { category: "Memory Permissions", technique: "T1055", desc: "Modifies memory page permissions in remote process" },
  WriteProcessMemory: { category: "Process Injection", technique: "T1055", desc: "Writes payload or shellcode directly to remote process memory" },
  CreateRemoteThread: { category: "Process Injection", technique: "T1055.002", desc: "Creates thread to execute shellcode in target process" },
  QueueUserAPC: { category: "Process Injection", technique: "T1055.004", desc: "Enqueues asynchronous procedure call to execute payload on thread wake" },
  NtMapViewOfSection: { category: "Process Hollowing", technique: "T1055.012", desc: "Maps shared memory section into target process space" },
  SetThreadContext: { category: "Thread Hijacking", technique: "T1055.003", desc: "Hijacks thread instruction pointer (EIP/RIP) to divert control flow" },
  
  // Anti-Analysis & Debugging
  IsDebuggerPresent: { category: "Anti-Debugging", technique: "T1622", desc: "Checks PEB BeingDebugged flag to detect debugger attachment" },
  CheckRemoteDebuggerPresent: { category: "Anti-Debugging", technique: "T1622", desc: "Queries kernel port to identify active debugger session" },
  NtQueryInformationProcess: { category: "Anti-Debugging", technique: "T1622", desc: "Inspects process debug port or debug object handle" },
  OutputDebugStringA: { category: "Anti-Debugging", technique: "T1622", desc: "Sends string to debugger or tests SEH unhandled exception filter" },
  
  // Persistence & Registry
  RegSetValueExA: { category: "Persistence", technique: "T1547.001", desc: "Modifies registry Run/RunOnce keys for auto-start execution" },
  RegSetValueExW: { category: "Persistence", technique: "T1547.001", desc: "Modifies registry Run/RunOnce keys for auto-start execution" },
  CreateServiceA: { category: "Persistence", technique: "T1543.003", desc: "Registers Windows NT service for persistence" },
  CreateServiceW: { category: "Persistence", technique: "T1543.003", desc: "Registers Windows NT service for persistence" },

  // Execution & Subprocesses
  CreateProcessA: { category: "Execution", technique: "T1059", desc: "Spawns new executable child process" },
  CreateProcessW: { category: "Execution", technique: "T1059", desc: "Spawns new executable child process" },
  ShellExecuteA: { category: "Execution", technique: "T1059", desc: "Executes command line or document through Windows shell" },
  ShellExecuteW: { category: "Execution", technique: "T1059", desc: "Executes command line or document through Windows shell" },
  WinExec: { category: "Execution", technique: "T1059", desc: "Runs command line program" },
  execve: { category: "Execution", technique: "T1059.004", desc: "Replaces current process image with new program" },
  system: { category: "Execution", technique: "T1059.004", desc: "Executes shell command string via sh" },

  // Network & C2
  connect: { category: "Network Sockets", technique: "T1071", desc: "Initiates outbound TCP socket connection" },
  socket: { category: "Network Sockets", technique: "T1071", desc: "Creates network communication endpoint" },
  InternetOpenA: { category: "HTTP Network", technique: "T1071.001", desc: "Initializes WinINet HTTP/FTP session" },
  InternetOpenUrlA: { category: "HTTP Network", technique: "T1071.001", desc: "Requests remote HTTP resource / payload drop" },
  URLDownloadToFileA: { category: "Ingress Transfer", technique: "T1105", desc: "Downloads remote file from Internet and writes to disk" },
  WSAStartup: { category: "Network Sockets", technique: "T1071", desc: "Initializes Winsock network subsystem" },

  // Credential Access
  OpenProcess: { category: "Credential Access / Privileges", technique: "T1003", desc: "Opens handle to foreign process (e.g. lsass.exe)" },
  AdjustTokenPrivileges: { category: "Privilege Escalation", technique: "T1134", desc: "Enables SeDebugPrivilege or security privileges" },
  CryptDecrypt: { category: "Cryptography", technique: "T1027", desc: "Decrypts in-memory encrypted configuration or payload" },
};

export function ImportsCapabilitiesTab({ st }: ImportsCapabilitiesTabProps) {
  const [selectedLibrary, setSelectedLibrary] = useState<string>("ALL");
  const [importSearch, setImportSearch] = useState("");

  const pe = st?.pe;
  const capabilities = st?.capabilities || [];

  // Parse imports and separate library name from imported functions if structured
  // In SampleStatic: pe.imports is string[] (e.g. ["KERNEL32.dll", "ADVAPI32.dll"] or ["KERNEL32.dll!VirtualAlloc"])
  const libraries = useMemo(() => {
    if (!st || !st.available || !pe || !pe.imports) return [];
    return Array.from(
      new Set(
        pe.imports.map((imp) => {
          if (imp.includes("!")) return imp.split("!")[0].toUpperCase();
          if (imp.includes(":")) return imp.split(":")[0].toUpperCase();
          return imp.toUpperCase();
        }),
      ),
    );
  }, [st, pe]);

  // Normalize symbols list
  const parsedSymbols = useMemo(() => {
    if (!st || !st.available || !pe || !pe.imports) return [];
    
    // Check if imports contain library!function notation or are standalone libraries
    const result: Array<{ library: string; symbol: string; sensitiveInfo?: typeof SENSITIVE_API_MAP[string] }> = [];
    
    // Also inspect categorized_strings?.security_apis or strings for known APIs
    const knownApisInStrings = new Set<string>();
    const searchPool = [...(st.categorized_strings?.security_apis || []), ...(st.strings || [])];
    searchPool.forEach((s) => {
      if (SENSITIVE_API_MAP[s]) knownApisInStrings.add(s);
    });

    pe.imports.forEach((item) => {
      if (item.includes("!")) {
        const [lib, fn] = item.split("!");
        result.push({
          library: lib.toUpperCase(),
          symbol: fn,
          sensitiveInfo: SENSITIVE_API_MAP[fn],
        });
      } else if (item.includes(":")) {
        const [lib, fn] = item.split(":");
        result.push({
          library: lib.toUpperCase(),
          symbol: fn,
          sensitiveInfo: SENSITIVE_API_MAP[fn],
        });
      } else {
        // Just the library name; check if any known APIs from this library match
        result.push({
          library: item.toUpperCase(),
          symbol: "(Import Descriptor)",
        });
      }
    });

    // Add any confirmed sensitive symbols detected in binary imports/strings
    knownApisInStrings.forEach((sym) => {
      if (!result.some((r) => r.symbol === sym)) {
        result.push({
          library: "EXTRACTED_SYMBOLS",
          symbol: sym,
          sensitiveInfo: SENSITIVE_API_MAP[sym],
        });
      }
    });

    return result;
  }, [pe, st]);

  const filteredSymbols = useMemo(() => {
    return parsedSymbols.filter((item) => {
      if (selectedLibrary !== "ALL" && item.library !== selectedLibrary) return false;
      if (importSearch.trim()) {
        const q = importSearch.toLowerCase();
        return item.library.toLowerCase().includes(q) || item.symbol.toLowerCase().includes(q) || (item.sensitiveInfo?.desc.toLowerCase().includes(q) ?? false);
      }
      return true;
    });
  }, [parsedSymbols, selectedLibrary, importSearch]);

  if (!st || !st.available) {
    return (
      <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs">
        <Icon name="box" size={24} className="mx-auto text-text-faint mb-2" />
        <p className="font-bold text-text-primary">Imports &amp; Capabilities Unavailable</p>
        <p className="mt-1 text-text-muted">
          Bytes for this sample are not stored in the vault. Re-upload binary to enable import table analysis.
        </p>
      </div>
    );
  }

  const sensitiveHits = parsedSymbols.filter((p) => p.sensitiveInfo);

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* SECTION 1: Analyst-Focused Capability Matrix */}
      <Panel
        kicker="Behavioral Inference"
        title={`Detected Capabilities (${capabilities.length})`}
        right={
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-text-faint">
              Categorized MITRE capability patterns
            </span>
          </div>
        }
      >
        {capabilities.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
            <Icon name="check" size={20} className="mx-auto text-emerald-400 mb-2" />
            <p className="font-semibold text-text-primary">No Suspicious Capabilities Detected</p>
            <p className="text-[11px] text-text-muted mt-1">
              No standard evasion, persistence, process injection, or C2 capability heuristics triggered.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {capabilities.map((cap, cidx) => {
              const isHigh = cap.confidence === "high";
              return (
                <div
                  key={cidx}
                  className={`rounded-xl border p-3 space-y-2 ${
                    isHigh
                      ? "border-amber-500/40 bg-amber-500/5"
                      : "border-border-subtle bg-bg-base/60"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-text-primary text-[11px]">{cap.category}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                        isHigh ? "bg-amber-500/20 text-amber-400" : "bg-bg-elevated text-text-muted"
                      }`}
                    >
                      {cap.confidence} Confidence
                    </span>
                  </div>

                  <p className="text-[10px] text-text-muted">
                    Source: <strong className="text-text-primary">{cap.source || "Static Heuristic Rules"}</strong>
                  </p>

                  <div className="space-y-1 pt-1 border-t border-border-subtle/50">
                    <span className="text-[9px] uppercase text-text-faint block">Evidence (Matched Indicators):</span>
                    <div className="flex flex-wrap gap-1">
                      {cap.matched.map((m, midx) => (
                        <span
                          key={midx}
                          className="rounded bg-bg-elevated px-1.5 py-0.5 text-[10px] text-accent font-semibold"
                        >
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      {/* SECTION 2: Structured Imports Table & Sensitive APIs */}
      <Panel
        kicker="API Telemetry"
        title="Import Table &amp; Sensitive Security APIs"
        right={
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-text-faint">
              {sensitiveHits.length} sensitive API{sensitiveHits.length === 1 ? "" : "s"} highlighted
            </span>
          </div>
        }
      >
        <div className="space-y-3">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] uppercase text-text-faint">Library:</span>
              <button
                onClick={() => setSelectedLibrary("ALL")}
                className={`rounded px-2 py-0.5 text-[10px] transition ${
                  selectedLibrary === "ALL"
                    ? "bg-accent text-white font-bold"
                    : "bg-bg-base border border-border-subtle text-text-muted hover:text-text-primary"
                }`}
              >
                All ({libraries.length})
              </button>
              {libraries.map((lib) => (
                <button
                  key={lib}
                  onClick={() => setSelectedLibrary(lib)}
                  className={`rounded px-2 py-0.5 text-[10px] transition ${
                    selectedLibrary === lib
                      ? "bg-accent text-white font-bold"
                      : "bg-bg-base border border-border-subtle text-text-muted hover:text-text-primary"
                  }`}
                >
                  {lib}
                </button>
              ))}
            </div>

            <div className="relative">
              <Icon name="search" size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
              <input
                type="text"
                placeholder="Search symbol / API / description..."
                value={importSearch}
                onChange={(e) => setImportSearch(e.target.value)}
                className="w-56 rounded border border-border-subtle bg-bg-base py-1 pl-7 pr-2 text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
              />
            </div>
          </div>

          {/* Table */}
          {filteredSymbols.length === 0 ? (
            <p className="text-xs text-text-muted py-6 text-center">No symbols matched the current filter.</p>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70 max-h-96 overflow-y-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint sticky top-0">
                    <th className="py-2 px-3 w-40">Library (DLL)</th>
                    <th className="py-2 px-3 w-48">Imported Function</th>
                    <th className="py-2 px-3 w-32">Security Category</th>
                    <th className="py-2 px-3">Behavioral Purpose / Context</th>
                    <th className="py-2 px-3 text-right w-24">MITRE Tag</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {filteredSymbols.map((item, idx) => {
                    const isSensitive = Boolean(item.sensitiveInfo);
                    return (
                      <tr
                        key={idx}
                        className={`transition-colors hover:bg-bg-elevated/40 ${
                          isSensitive ? "bg-amber-500/5" : ""
                        }`}
                      >
                        <td className="py-2 px-3 font-semibold text-text-primary">{item.library}</td>
                        <td className="py-2 px-3 font-mono">
                          {isSensitive ? (
                            <span className="font-bold text-amber-400">{item.symbol}</span>
                          ) : (
                            <span className="text-text-muted">{item.symbol}</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          {item.sensitiveInfo ? (
                            <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-bold text-amber-400">
                              {item.sensitiveInfo.category}
                            </span>
                          ) : (
                            <span className="text-[10px] text-text-faint">Standard API</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-[11px] text-text-muted font-sans leading-tight">
                          {item.sensitiveInfo ? item.sensitiveInfo.desc : "Standard system library export"}
                        </td>
                        <td className="py-2 px-3 text-right font-mono text-[10px]">
                          {item.sensitiveInfo ? (
                            <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-text-primary font-bold">
                              {item.sensitiveInfo.technique}
                            </span>
                          ) : (
                            <span className="text-text-faint">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
