import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, Panel } from "../components/ui";
import { detonateSample, getDetonateSampleStreamUrl, getRuns, getSample, getSampleForecast, getSampleStatic, getSandboxArtifactUrl, getSandboxProviders, getSandboxTask, getSimilarSamples, sandboxDetonate, watchlistAdd } from "../lib/api";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import { NetworkProtocolInspector } from "../components/NetworkProtocolInspector";
import { ArtifactHexViewerModal } from "../components/ArtifactHexViewerModal";
import { IncidentBriefModal } from "../components/IncidentBriefModal";
import { Tier3MicroVmModal } from "../components/Tier3MicroVmModal";
import { SampleMitreMatrix } from "../components/SampleMitreMatrix";
import type { BehavioralForecast, DroppedArtifactItem, ForecastReconciliation, PeMetadata, Platform, RunSummary, SampleDetonationResult, SampleStatic, SandboxTask } from "../types";
import { getVirusTotalFileUrl } from "./samplesHelpers";
import { SampleWorkspaceHeader } from "../components/staticAnalysis/SampleWorkspaceHeader";
import { SampleIdentificationStrip } from "../components/staticAnalysis/SampleIdentificationStrip";
import { StaticOverviewTab } from "../components/staticAnalysis/StaticOverviewTab";
import { FileStructureTab } from "../components/staticAnalysis/FileStructureTab";
import { ImportsCapabilitiesTab } from "../components/staticAnalysis/ImportsCapabilitiesTab";
import { StringsIndicatorsTab } from "../components/staticAnalysis/StringsIndicatorsTab";
import { RawBytesTab } from "../components/staticAnalysis/RawBytesTab";
import { AnalysisHistoryTab } from "../components/staticAnalysis/AnalysisHistoryTab";

/* ── Cryptographic Hashes & Forensic Identity Components ─────────────────── */

function CopyHashRow({ label, value, badge }: { label: string; value?: string | null; badge?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;

  const handleCopy = () => {
    void navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border-subtle bg-bg-base/70 px-3 py-2 font-mono text-xs transition hover:border-accent/40">
      <div className="flex items-center gap-2 min-w-0">
        <span className="w-16 shrink-0 font-bold text-text-faint uppercase text-[10px]">{label}</span>
        <code className="truncate text-text-primary text-[11px] select-all">{value}</code>
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        {badge && (
          <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] text-text-faint">{badge}</span>
        )}
        <button
          onClick={handleCopy}
          className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted transition hover:border-accent hover:text-accent"
          title={`Copy ${label}`}
        >
          <Icon name={copied ? "check" : "copy"} size={10} className={copied ? "text-risk-clean" : ""} />
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
    </div>
  );
}

export function CryptographicHashesCard({ sample, st }: { sample: { sample_id: string; sha256: string }; st?: SampleStatic }) {
  const sha256 = st?.sha256 || sample.sha256;
  const sha1 = st?.sha1;
  const md5 = st?.md5;
  const imphash = st?.imphash || st?.pe?.imphash;
  const ssdeep = st?.fuzzy_hash;

  return (
    <Panel kicker="Forensic Identity" title="Cryptographic Hashes &amp; Signatures">
      <div className="space-y-2 font-mono">
        <CopyHashRow label="SHA-256" value={sha256} badge="Primary Fingerprint" />
        {sha1 && <CopyHashRow label="SHA-1" value={sha1} badge="Legacy Digest" />}
        {md5 && <CopyHashRow label="MD5" value={md5} badge="Legacy Digest" />}
        {imphash && <CopyHashRow label="ImpHash" value={imphash} badge="PE Import Digest" />}
        {ssdeep && <CopyHashRow label="SSDEEP" value={ssdeep} badge="CTPH Fuzzy Similarity" />}
      </div>
    </Panel>
  );
}

export function HexPreviewViewer({ preview }: { preview?: Array<{ offset: string; hex: string; ascii: string }> }) {
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);

  if (!preview || preview.length === 0) return null;

  const filtered = filter
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

  return (
    <Panel
      kicker="Binary Inspection"
      title="Raw Byte &amp; Hex Header Inspector"
      right={
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="text-text-faint">{preview.length * 16} bytes mapped</span>
          <button
            onClick={handleCopyRaw}
            className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-text-muted transition hover:border-accent hover:text-accent"
          >
            {copied ? "Copied Hex" : "Copy Hex Dump"}
          </button>
        </div>
      }
    >
      <div className="space-y-3 font-mono">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="relative">
            <Icon name="search" size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter offset / hex / ascii..."
              className="w-56 rounded border border-border-subtle bg-bg-base py-1 pl-7 pr-2 text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
            />
          </div>
          <span className="text-[10px] text-text-faint">
            Initial 512 bytes (PE / ELF Executable Header &amp; Entry Section)
          </span>
        </div>

        <div className="max-h-72 overflow-x-auto overflow-y-auto rounded-xl border border-border-subtle bg-bg-inset p-3 text-[11px] leading-relaxed shadow-inner">
          <table className="w-full text-left font-mono">
            <thead>
              <tr className="border-b border-border-subtle/40 text-[10px] uppercase text-text-faint">
                <th className="pb-1.5 pr-4 font-normal">Offset</th>
                <th className="pb-1.5 pr-4 font-normal">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</th>
                <th className="pb-1.5 font-normal">Decoded Text</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.offset} className="transition-colors hover:bg-white/5">
                  <td className="pr-4 select-all font-bold text-accent/80">{row.offset}</td>
                  <td className="pr-4 select-all tracking-wider text-text-primary whitespace-nowrap">
                    {row.hex.slice(0, 23)} <span className="text-white/20">|</span> {row.hex.slice(24)}
                  </td>
                  <td className="select-all font-medium text-emerald-400 whitespace-nowrap">
                    {row.ascii}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  );
}

/* ── Static Threat Triage & DFIR Posture Card ────────────────────────── */

export function StaticThreatTriageCard({
  sample,
  st,
}: {
  sample: { sample_id: string; sha256: string; original_name?: string; detected_platform?: string };
  st?: SampleStatic;
}) {
  if (!st || !st.available) return null;

  // Determine threat classification verdict
  const capCats = new Set((st.capabilities || []).map((c) => c.category));
  const riskScore = st.static_risk_score ?? 0;
  const entropy = st.entropy ?? 0;
  const isPacked = Boolean(st.is_packed || entropy > 7.1);

  let verdict = "No Suspicious Indicators Detected";
  let verdictColor = "text-emerald-400 border-emerald-500/40 bg-emerald-500/10";
  let verdictBadge = "No Indicators";

  if (capCats.has("Cryptographic & Ransomware") || (st.risk_factors || []).some((rf) => rf.toLowerCase().includes("ransom"))) {
    verdict = "Ransomware / Cryptographic Extortion Payload";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (capCats.has("Process Injection") && isPacked) {
    verdict = "Packed Dropper / In-Memory Payload Injector";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (capCats.has("Process Injection")) {
    verdict = "Trojan / Process Hollowing Primitive";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (capCats.has("Credential Access")) {
    verdict = "Credential Harvester / LSASS Stealer";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (capCats.has("Persistence & Autostart") && capCats.has("Network Communications & C2")) {
    verdict = "Backdoor / Remote Access Trojan (RAT)";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (riskScore >= 70) {
    verdict = "High-Risk Malicious Artifact";
    verdictColor = "text-rose-400 border-rose-500/50 bg-rose-500/15";
    verdictBadge = "Malicious";
  } else if (riskScore >= 35 || isPacked) {
    verdict = "Suspicious Binary / Obfuscated Code";
    verdictColor = "text-amber-400 border-amber-500/50 bg-amber-500/15";
    verdictBadge = "Suspicious";
  }

  // Format machine architecture
  const formatStr = st.pe
    ? `PE (${st.pe.machine}, ${st.pe.bits}-bit, ${st.pe.subsystem || "Native"})`
    : st.elf
      ? `ELF (${st.elf.machine}, ${st.elf.class}-bit, ${st.elf.type})`
      : "Raw Binary Stream";

  return (
    <Panel kicker="Static Threat Triage" title="Static Threat Verdict & Binary Posture">
      <div className="space-y-4 font-mono">
        {/* Main Verdict & Gauge Bar */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 rounded-xl border border-border-subtle bg-bg-base/70 p-4">
          <div className="md:col-span-2 space-y-2">
            <div className="flex items-center gap-2">
              <span className={`rounded border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${verdictColor}`}>
                {verdictBadge}
              </span>
              <span className="text-[11px] text-text-faint">Heuristic Static Classifier</span>
            </div>
            <h3 className="text-base font-bold text-text-primary">{verdict}</h3>
            <p className="text-xs text-text-muted leading-relaxed">
              Analyzed {sample.original_name ? <span className="font-semibold text-text-primary">{sample.original_name}</span> : "binary payload"} against Shannon entropy distributions, static IOCs, import table hashes, and MITRE capability patterns without execution risk.
            </p>
          </div>

          <div className="flex flex-col justify-center items-start md:items-end rounded-lg bg-bg-surface/60 p-3 border border-border-subtle/60">
            <span className="text-[10px] uppercase tracking-wider text-text-faint">Static Threat Score</span>
            <div className="flex items-baseline gap-1 mt-0.5">
              <span className={`text-2xl font-black ${riskScore >= 70 ? "text-rose-400" : riskScore >= 35 ? "text-amber-400" : "text-emerald-400"}`}>
                {riskScore}
              </span>
              <span className="text-xs text-text-faint">/ 100</span>
            </div>
            <div className="w-full mt-2 h-2 rounded-full bg-bg-elevated overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  riskScore >= 70 ? "bg-rose-500 ring-1 ring-rose-500/40" : riskScore >= 35 ? "bg-amber-400" : "bg-emerald-400"
                }`}
                style={{ width: `${Math.max(5, riskScore)}%` }}
              />
            </div>
          </div>
        </div>

        {/* 4 Deep Binary Posture Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {/* Tile 1: Binary Format & Subsystem */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Format &amp; Subsystem</span>
            <div className="font-bold text-text-primary text-xs truncate" title={formatStr}>
              {formatStr}
            </div>
            <div className="text-[10px] text-text-muted">
              {st.pe?.entry_point_rva != null
                ? `Entry RVA: 0x${Number(st.pe.entry_point_rva).toString(16)}`
                : st.elf?.entry_point != null
                  ? String(st.elf.entry_point).startsWith("0x")
                    ? `Entry: ${st.elf.entry_point}`
                    : `Entry: 0x${Number(st.elf.entry_point).toString(16)}`
                  : "Offset: 0x0000"}
            </div>
          </div>

          {/* Tile 2: Entropy & Packing */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Shannon Entropy</span>
            <div className="flex items-center gap-1.5 font-bold text-xs">
              <span className={entropy > 7.0 ? "text-rose-400" : entropy > 6.0 ? "text-amber-400" : "text-emerald-400"}>
                {entropy} / 8.0
              </span>
              {isPacked ? (
                <span className="rounded bg-rose-500/20 px-1 py-0.2 text-[9px] text-rose-400 font-bold">Packed</span>
              ) : (
                <span className="rounded bg-emerald-500/20 px-1 py-0.2 text-[9px] text-emerald-400 font-bold">Native</span>
              )}
            </div>
            <div className="text-[10px] text-text-muted">
              {isPacked ? "High byte randomness (UPX/crypto)" : "Linear code/data distribution"}
            </div>
          </div>

          {/* Tile 3: Authenticode / Signing */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Code Signing &amp; Integrity</span>
            <div className="font-bold text-xs truncate">
              {st.pe?.authenticode?.signed ? (
                <span className="text-emerald-400">Authenticode Signed</span>
              ) : (
                <span className="text-amber-400">Unsigned Binary</span>
              )}
            </div>
            <div className="text-[10px] text-text-muted truncate">
              {st.pe?.authenticode?.signed ? `Cert size: ${st.pe.authenticode.cert_size} B` : "No digital signature attached"}
            </div>
          </div>

          {/* Tile 4: Exploit Mitigations */}
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Kernel Mitigations</span>
            <div className="font-bold text-xs text-text-primary truncate">
              {st.pe?.mitigations && st.pe.mitigations.length > 0 ? (
                <span className="text-emerald-400">{st.pe.mitigations.length} Mitigations</span>
              ) : (
                <span className="text-rose-400">0 Active Mitigations</span>
              )}
            </div>
            <div className="text-[10px] text-text-muted truncate">
              {st.pe?.mitigations?.join(", ") || "ASLR/DEP Disabled"}
            </div>
          </div>
        </div>

        {/* Primary Threat Factors List */}
        {st.risk_factors && st.risk_factors.length > 0 && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-3.5 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-rose-400">
              <span className="flex items-center gap-1.5">
                <Icon name="alert" size={13} />
                Detected Static Threat Factors ({st.risk_factors.length})
              </span>
              <span className="text-[10px] uppercase text-text-faint">Rule Assessment</span>
            </div>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-1.5 text-[11px] text-text-muted list-disc list-inside">
              {st.risk_factors.map((rf, idx) => (
                <li key={idx} className="leading-snug">
                  {rf}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ── Security API & Threat Intent Cockpit ────────────────────────────────── */

const SECURITY_API_CATEGORIES = [
  {
    category: "Process Injection & Memory Manipulation",
    tactic: "Defense Evasion / Privilege Escalation",
    technique: "T1055",
    description: "Allocates executable memory in foreign or local processes, writes shellcode, or hijacks remote thread execution.",
    symbols: ["VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection", "mmap", "mprotect", "ptrace", "process_vm_writev", "dlopen", "dlsym"],
    suspiciousness: "high" as const,
  },
  {
    category: "Defense Evasion & Anti-Analysis",
    tactic: "Defense Evasion",
    technique: "T1497 / T1622",
    description: "Probes for debugger traps, hypervisors, and sandbox hooks to terminate execution or evade behavioral instrumentation.",
    symbols: ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString", "rdtsc", "GetTickCount", "UnhookWindowsHookEx", "PTRACE_TRACEME"],
    suspiciousness: "high" as const,
  },
  {
    category: "Persistence & Host Autostart",
    tactic: "Persistence",
    technique: "T1547 / T1053",
    description: "Installs autorun entries, modifies registry Run keys, registers system services, or stages cron/systemd scripts.",
    symbols: ["RegSetValueEx", "RegCreateKeyEx", "SetWindowsHookEx", "CreateService", "StartService", "SchTasks", "LaunchAgent", "systemd", ".bashrc", "RunOnce"],
    suspiciousness: "medium" as const,
  },
  {
    category: "Command & Control (C2) Networking",
    tactic: "Command and Control",
    technique: "T1071 / T1095",
    description: "Initiates low-level network socket connections, resolves remote DNS hosts, or establishes HTTP/TLS beacon sessions.",
    symbols: ["WSAStartup", "socket", "connect", "InternetOpen", "HttpSendRequest", "URLDownloadToFile", "curl_easy_init", "send", "recv", "beacon", "reverse_tcp"],
    suspiciousness: "medium" as const,
  },
  {
    category: "Credential Access & Reconnaissance",
    tactic: "Credential Access / Discovery",
    technique: "T1003 / T1082",
    description: "Harvester of user credentials, LSASS tokens, SAM registry hives, and active process privileges.",
    symbols: ["GetComputerName", "GetUserName", "NetUserEnum", "EnumProcesses", "LookupPrivilegeValue", "OpenProcessToken", "MiniDumpWriteDump", "CryptUnprotectData", "lsass", "mimikatz", "shadow"],
    suspiciousness: "high" as const,
  },
  {
    category: "Cryptographic & Ransomware Routines",
    tactic: "Impact",
    technique: "T1486",
    description: "Generates cryptographic keys, initializes symmetric/asymmetric ciphers, and rapidly encrypts victim files.",
    symbols: ["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "AES_encrypt", "EVP_EncryptInit", "ransom", ".locked", "decrypt_instructions", "wallet"],
    suspiciousness: "high" as const,
  },
];

export function SecurityApisIntentInspector({ st }: { st?: SampleStatic }) {
  if (!st || !st.available) return null;

  const observedStrings = new Set([
    ...(st.strings || []),
    ...(st.categorized_strings?.security_apis || []),
  ]);
  const capabilities = st.capabilities || [];

  const categoryMatches = SECURITY_API_CATEGORIES.map((cat) => {
    const backendCap = capabilities.find((c) => c.category.toLowerCase().includes(cat.category.toLowerCase().slice(0, 10)));
    const matchedSymbols = new Set<string>();
    if (backendCap) {
      backendCap.matched.forEach((m) => matchedSymbols.add(m));
    }
    cat.symbols.forEach((sym) => {
      for (const s of observedStrings) {
        if (s.includes(sym)) {
          matchedSymbols.add(sym);
          break;
        }
      }
    });

    return {
      ...cat,
      matched: Array.from(matchedSymbols),
    };
  }).filter((c) => c.matched.length > 0);

  if (categoryMatches.length === 0) return null;

  return (
    <Panel
      kicker="Deep Binary Inspection"
      title="Import Address Table (IAT) &amp; Security API Threat Intent"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {categoryMatches.length} Intent Categories Identified
        </span>
      }
    >
      <div className="space-y-4 font-mono text-xs">
        <p className="text-text-muted text-[11px] leading-relaxed">
          Correlated imported functions and binary symbols against known ATT&amp;CK tradecraft primitives to deduce payload behavior prior to live detonation.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {categoryMatches.map((cat, idx) => (
            <div
              key={idx}
              className={`rounded-xl border p-3.5 space-y-2.5 transition ${
                cat.suspiciousness === "high"
                  ? "border-rose-500/30 bg-rose-500/5 hover:border-rose-500/50"
                  : "border-amber-500/30 bg-amber-500/5 hover:border-amber-500/50"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        cat.suspiciousness === "high" ? "bg-rose-400" : "bg-amber-400"
                      }`}
                    />
                    <span className="font-bold text-text-primary text-xs">{cat.category}</span>
                  </div>
                  <div className="flex items-center gap-1 text-[10px] text-text-faint">
                    <span>{cat.tactic}</span>
                    <span>·</span>
                    <span className="text-accent">{cat.technique}</span>
                  </div>
                </div>

                <span
                  className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                    cat.suspiciousness === "high"
                      ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                      : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                  }`}
                >
                  {cat.suspiciousness}
                </span>
              </div>

              <p className="text-[11px] text-text-muted leading-relaxed">
                {cat.description}
              </p>

              <div className="space-y-1 pt-1 border-t border-border-subtle/50">
                <span className="text-[10px] uppercase text-text-faint block">Identified API Symbols ({cat.matched.length}):</span>
                <div className="flex flex-wrap gap-1">
                  {cat.matched.map((m) => (
                    <span
                      key={m}
                      className="rounded bg-bg-surface border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-primary select-all"
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

/* ── Modular Static Analysis Workspace ───────────────────────────────────── */

function StaticAnalysis({
  sample,
  runs = [],
  st: initialSt,
  isLoading: initialLoading,
  isError: initialError,
  unavailable: initialUnavailable,
}: {
  sample: any;
  runs?: RunSummary[];
  st?: SampleStatic;
  isLoading?: boolean;
  isError?: boolean;
  unavailable?: boolean;
}) {
  const [staticTab, setStaticTab] = useState<"overview" | "structure" | "imports" | "strings" | "bytes" | "history">("overview");

  const { data: fetchedSt, isLoading: isQueryLoading, isError: isQueryError } = useQuery({
    queryKey: ["sample", "static", sample.sample_id],
    queryFn: () => getSampleStatic(sample.sample_id),
    retry: false,
    enabled: initialSt === undefined,
  });

  const st = initialSt ?? fetchedSt;
  const isLoading = initialLoading ?? isQueryLoading;
  const isError = initialError ?? isQueryError;
  const unavailable = initialUnavailable ?? (st !== undefined && st.available === false);

  return (
    <div className="mt-6 space-y-6">
      {/* Safe SOC Static Triage Status Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 font-mono text-xs">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/20 text-emerald-400">
            <Icon name="shield" size={14} />
          </span>
          <div>
            <span className="font-bold text-emerald-300">Mode 1: Safe Static Triage (Zero Execution Risk)</span>
            <p className="text-[11px] text-text-muted">
              Deep binary telemetry extracted directly from raw file bytes without executing. External threat pivots linked to VirusTotal.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={getVirusTotalFileUrl(sample.sha256)}
            target="_blank"
            rel="noopener noreferrer"
            title="Inspect SHA-256 file report on VirusTotal"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-1.5 text-[11px] font-bold text-accent transition hover:bg-accent/25 focus:ring-1 focus:ring-accent/40"
          >
            <span>VirusTotal Intelligence</span>
            <Icon name="external" size={11} />
          </a>
          <span className="rounded bg-emerald-500/20 px-2 py-1 text-[10px] font-bold text-emerald-400 uppercase">
            Static Safe
          </span>
        </div>
      </div>

      {isLoading && <p className="p-4 text-xs text-text-muted font-mono">Analyzing bytes…</p>}
      {isError && (
        <p className="p-4 text-xs text-text-muted font-mono">
          Static analysis unavailable — {sample.sample_id} could not be analyzed.
        </p>
      )}
      {unavailable && (
        <p className="p-4 text-xs text-text-muted font-mono">
          Static analysis unavailable — {sample.sample_id} was uploaded before byte persistence. Re-upload the file to enable it.
        </p>
      )}

      {st && st.available && (
        <div className="space-y-4">
          {/* Tab Navigation Strip */}
          <div className="flex flex-wrap items-center gap-1.5 border-b border-border-subtle pb-2.5 font-mono text-xs">
            {[
              { id: "overview", label: "Overview", icon: "box" as const },
              { id: "structure", label: "File Structure", icon: "terminal" as const },
              { id: "imports", label: "Imports & Capabilities", icon: "shield" as const },
              { id: "strings", label: "Strings & Indicators", icon: "notes" as const },
              { id: "bytes", label: "Raw Bytes", icon: "copy" as const },
              { id: "history", label: "Analysis History", icon: "activity" as const },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setStaticTab(tab.id as any)}
                className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-mono text-xs font-semibold transition ${
                  staticTab === tab.id
                    ? "bg-accent text-white shadow-xs"
                    : "border border-border-subtle/50 bg-bg-surface/70 text-text-muted hover:border-border-subtle hover:text-text-primary"
                }`}
              >
                <Icon name={tab.icon} size={12} />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          {/* Tab Content */}
          {staticTab === "overview" && (
            <StaticOverviewTab sample={sample} st={st} onNavigateTab={setStaticTab} />
          )}
          {staticTab === "structure" && (
            <FileStructureTab st={st} sampleName={sample.original_name} />
          )}
          {staticTab === "imports" && (
            <ImportsCapabilitiesTab st={st} />
          )}
          {staticTab === "strings" && (
            <StringsIndicatorsTab sampleId={sample.sample_id} st={st} />
          )}
          {staticTab === "bytes" && (
            <RawBytesTab st={st} sampleName={sample.original_name} />
          )}
          {staticTab === "history" && (
            <AnalysisHistoryTab sampleId={sample.sample_id} sampleName={sample.original_name} runs={runs} />
          )}
        </div>
      )}
    </div>
  );
}


export function EntropyHistogramChart({ histogram }: { histogram?: number[] }) {
  if (!histogram || histogram.length === 0) return null;
  return (
    <div className="space-y-1.5 border-t border-border-subtle pt-3">
      <div className="flex items-center justify-between font-mono text-[10px] text-text-faint">
        <span>Section Entropy Sliding Histogram (32 Sequential Byte Chunks)</span>
        <span className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> &lt;5.5 Code</span>
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> 5.5-7.0 Data</span>
          <span className="inline-flex items-center gap-1"><span className="h-1.5 w-1.5 rounded-full bg-rose-500" /> &gt;7.0 Packed</span>
        </span>
      </div>
      <div className="flex h-12 items-end gap-1 rounded-lg border border-border-subtle bg-bg-inset p-1.5">
        {histogram.map((val, idx) => {
          const pct = Math.min(100, (val / 8.0) * 100);
          const color = val > 7.0 ? "bg-rose-500 ring-1 ring-rose-500/40" : val > 5.5 ? "bg-amber-400" : "bg-emerald-400";
          return (
            <div
              key={idx}
              className={`flex-1 rounded-t transition-all hover:opacity-80 ${color}`}
              style={{ height: `${Math.max(8, pct)}%` }}
              title={`Chunk #${idx + 1}: ${val} / 8.0`}
            />
          );
        })}
      </div>
    </div>
  );
}

function tryDecodeString(s: string): { decoded: string; format: "Base64" | "Hex" } | null {
  const trimmed = s.trim();
  if (trimmed.length >= 8 && trimmed.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    try {
      const decoded = atob(trimmed);
      if (/^[\x20-\x7E\t\r\n]+$/.test(decoded) && decoded.length >= 4) {
        return { decoded, format: "Base64" };
      }
    } catch { /* not valid base64 — skip */ }
  }
  if (trimmed.length >= 8 && trimmed.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(trimmed)) {
    try {
      let dec = "";
      for (let i = 0; i < trimmed.length; i += 2) {
        dec += String.fromCharCode(parseInt(trimmed.substr(i, 2), 16));
      }
      if (/^[\x20-\x7E\t\r\n]+$/.test(dec) && dec.length >= 4) {
        return { decoded: dec, format: "Hex" };
      }
    } catch { /* not valid hex — skip */ }
  }
  return null;
}

export function CategorizedStringsPanel({ categorized, rawStrings }: { categorized?: SampleStatic["categorized_strings"]; rawStrings: string[] }) {
  const [activeTab, setActiveTab] = useState<"all" | "network" | "file_paths" | "commands" | "registry" | "security_apis">("all");
  const [search, setSearch] = useState("");
  const [selectedString, setSelectedString] = useState<{ raw: string; decoded?: string; format?: string } | null>(null);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedDecoded, setCopiedDecoded] = useState(false);

  const currentList = useMemo(() => {
    let list: string[] = [];
    if (activeTab === "all") list = rawStrings;
    else if (categorized && categorized[activeTab]) list = categorized[activeTab];
    if (!search) return list;
    const q = search.toLowerCase();
    return list.filter((s) => s.toLowerCase().includes(q));
  }, [activeTab, categorized, rawStrings, search]);

  const handleSelectString = (s: string) => {
    const dec = tryDecodeString(s);
    setSelectedString({
      raw: s,
      decoded: dec?.decoded,
      format: dec?.format,
    });
    setCopiedRaw(false);
    setCopiedDecoded(false);
  };

  return (
    <div className="space-y-3 border-t border-border-subtle pt-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1 font-mono text-[10px]">
          {[
            { id: "all", label: `All (${rawStrings.length})` },
            { id: "network", label: `Network (${categorized?.network?.length ?? 0})` },
            { id: "file_paths", label: `File Paths (${categorized?.file_paths?.length ?? 0})` },
            { id: "commands", label: `Commands (${categorized?.commands?.length ?? 0})` },
            { id: "registry", label: `Registry (${categorized?.registry?.length ?? 0})` },
            { id: "security_apis", label: `Security APIs (${categorized?.security_apis?.length ?? 0})` },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`rounded-lg px-2.5 py-1 transition ${
                activeTab === t.id
                  ? "bg-accent/15 font-bold text-accent shadow-sm"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter string list..."
          className="rounded-lg border border-border-subtle bg-bg-base px-2 py-1 font-mono text-xs text-text-primary focus:border-accent/60 outline-none"
        />
      </div>

      <div className="max-h-64 overflow-y-auto rounded-xl border border-border-subtle bg-bg-elevated/20 p-2 font-mono text-[11px] leading-relaxed text-text-primary">
        {currentList.length === 0 ? (
          <p className="text-text-faint text-center py-4">No strings found in this category.</p>
        ) : (
          currentList.slice(0, 150).map((s, idx) => {
            const dec = tryDecodeString(s);
            const isSelected = selectedString?.raw === s;
            return (
              <div
                key={idx}
                onClick={() => handleSelectString(s)}
                className={`flex items-center justify-between gap-2 rounded px-2 py-1 cursor-pointer transition ${
                  isSelected
                    ? "bg-accent/20 text-accent font-semibold ring-1 ring-accent/40"
                    : "hover:bg-accent/10"
                }`}
                title="Click to inspect and decode"
              >
                <span className="truncate flex-1">{s}</span>
                {dec && (
                  <span className="shrink-0 rounded bg-accent/20 border border-accent/40 px-1.5 py-0.2 text-[9px] font-bold uppercase text-accent">
                    {dec.format}
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Quick String Inspector & Plaintext Decoder Drawer */}
      {selectedString && (
        <div className="rounded-xl border border-accent/40 bg-accent/5 p-3 font-mono text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold text-accent flex items-center gap-1.5">
              <Icon name="search" size={12} />
              <span>String Inspector {selectedString.format && `· Obfuscated ${selectedString.format} Detected`}</span>
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  void navigator.clipboard.writeText(selectedString.raw);
                  setCopiedRaw(true);
                  setTimeout(() => setCopiedRaw(false), 2000);
                }}
                className="press text-accent hover:underline text-[10px] font-bold"
              >
                {copiedRaw ? "Copied Raw!" : "Copy Raw"}
              </button>
              <button
                onClick={() => setSelectedString(null)}
                className="text-text-muted hover:text-text-primary text-xs"
                aria-label="Close string inspector"
              >
                <Icon name="x" size={12} />
              </button>
            </div>
          </div>

          <div className="rounded-lg border border-border-subtle bg-bg-base/80 p-2 text-[11px] text-text-primary break-all max-h-24 overflow-y-auto">
            {selectedString.raw}
          </div>

          {selectedString.decoded && (
            <div className="space-y-1 pt-1 border-t border-accent/20">
              <div className="flex items-center justify-between text-[10px] font-bold text-emerald-400">
                <span className="inline-flex items-center gap-1">
                  <Icon name="check" size={11} />
                  <span>Decoded Plaintext ({selectedString.format}):</span>
                </span>
                <button
                  onClick={() => {
                    void navigator.clipboard.writeText(selectedString.decoded!);
                    setCopiedDecoded(true);
                    setTimeout(() => setCopiedDecoded(false), 2000);
                  }}
                  className="press text-emerald-400 hover:underline"
                >
                  {copiedDecoded ? "Copied Decoded!" : "Copy Decoded"}
                </button>
              </div>
              <pre className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-[11px] text-emerald-300 whitespace-pre-wrap break-all max-h-28 overflow-y-auto font-mono">
                {selectedString.decoded}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PreExecutionForecastView({
  sample,
  forecast,
  isLoading,
  isError,
  detonating,
  executionTimer,
  onProceed,
}: {
  sample: { sample_id: string; original_name: string; detected_platform: string };
  forecast?: BehavioralForecast;
  isLoading: boolean;
  isError: boolean;
  detonating: boolean;
  executionTimer: number;
  onProceed: () => void;
}) {
  const [isExpanded, setIsExpanded] = useState(true);

  const threatLevel = (forecast?.predicted_threat_level || "unknown").toUpperCase();
  const threatTone =
    threatLevel === "MALICIOUS"
      ? "text-rose-400 bg-rose-500/20 border-rose-500/40"
      : threatLevel === "SUSPICIOUS"
        ? "text-amber-400 bg-amber-500/20 border-amber-500/40"
        : threatLevel === "CLEAN" || threatLevel === "NO_INDICATORS" || threatLevel === "NO_INDICATORS_FOUND_LIMITED"
          ? "text-emerald-400 bg-emerald-500/20 border-emerald-500/40"
          : "text-text-muted bg-bg-surface border-border-subtle";

  return (
    <div className="overflow-hidden rounded-2xl border border-amber-500/40 bg-bg-surface/95 shadow-xl backdrop-blur">
      {/* Top Banner Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-base/80 px-5 py-3.5 text-xs">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-amber-500/40 bg-amber-500/15 text-amber-400 shadow-[0_0_12px_rgba(245,158,11,0.25)]">
            <Icon name="eye" size={15} />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-text-primary text-sm">
                Layer 1: Pre-Execution Threat Forecast
              </span>
              <span className="rounded bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-300 uppercase">
                Zero-Execution Heuristics
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Pre-detonation behavioral forecast for {sample.original_name} ({sample.detected_platform}) · Predicts anticipated actions, C2 endpoints &amp; MITRE techniques before execution
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {forecast && (
            <div className="flex items-center gap-2">
              <span className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-bold uppercase ${threatTone}`}>
                <Icon name="shield" size={12} />
                <span>{threatLevel}</span>
              </span>
              <span className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-muted">
                Confidence: <strong className="text-text-primary">{forecast.confidence_score}%</strong>
              </span>
              {forecast.static_risk_score !== undefined && (
                <span className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-muted">
                  Static Score: <strong className="text-text-primary">{forecast.static_risk_score}/100</strong>
                </span>
              )}
            </div>
          )}

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-muted hover:text-text-primary"
            title={isExpanded ? "Collapse forecast" : "Expand forecast"}
          >
            <Icon name={isExpanded ? "chevronDown" : "chevronRight"} size={12} />
            <span>{isExpanded ? "Collapse" : "Expand"}</span>
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="p-5 space-y-4">
          {isLoading ? (
            <div className="py-8 text-center text-text-muted space-y-2">
              <Icon name="refresh" size={20} className="mx-auto animate-spin text-accent" />
              <p className="text-xs">Analyzing raw sample heuristics &amp; synthesizing behavioral forecast...</p>
            </div>
          ) : isError ? (
            <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 text-xs text-text-muted flex items-center justify-between">
              <span>Zero-execution forecast is unavailable for this sample bytes. You can still proceed directly to Layer 2 live sandbox detonation.</span>
            </div>
          ) : forecast ? (
            <>
              {/* Summary callout & Senior Reverse-Engineering Assessment */}
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 text-xs space-y-3">
                <div className="flex items-center justify-between gap-2 border-b border-amber-500/20 pb-2">
                  <div className="flex items-center gap-2 font-bold text-amber-300">
                    <Icon name="notes" size={13} />
                    <span>Technical Threat Assessment &amp; Reverse-Engineering Dossier</span>
                  </div>
                  {forecast.entropy !== undefined && (
                    <span className="text-[10px] text-text-faint">
                      Shannon Entropy: <strong className="text-text-primary">{forecast.entropy.toFixed(2)}</strong> / 8.0
                      {forecast.is_packed ? " · (Packed / Encrypted Bytecode)" : " · (Plaintext / Unpacked)"}
                    </span>
                  )}
                </div>

                <div className="space-y-1.5">
                  <p className="text-text-primary text-xs leading-relaxed font-sans">
                    {forecast.summary}
                  </p>
                  {forecast.threat_justification && (
                    <p className="text-[11px] text-text-muted leading-relaxed italic border-l-2 border-amber-500/40 pl-2.5 my-1">
                      {forecast.threat_justification}
                    </p>
                  )}
                </div>

                {forecast.technical_dossier?.threat_findings && forecast.technical_dossier.threat_findings.length > 0 && (
                  <div className="pt-1 border-t border-amber-500/15 space-y-1">
                    <span className="text-[10px] font-bold uppercase text-amber-400/90 tracking-wider block">
                      Key Technical Evidence Points:
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-[11px]">
                      {forecast.technical_dossier.threat_findings.map((finding, fidx) => (
                        <div key={fidx} className="flex items-start gap-1.5 rounded-lg bg-bg-surface/80 px-2.5 py-1.5 border border-border-subtle/70">
                          <span className="text-accent mt-0.5">•</span>
                          <span className="text-text-muted">{finding}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {forecast.explanations && forecast.explanations.length > 0 && (
                  <div className="pt-1 flex flex-wrap gap-1.5 text-[10px] text-text-muted">
                    {forecast.explanations.map((exp, eidx) => (
                      <span key={eidx} className="rounded bg-bg-surface px-2 py-0.5 border border-border-subtle/60">
                        {exp}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* 4 Forecast Decks */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                {/* Deck 1: Anticipated Actions */}
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                    <span className="font-bold text-text-primary flex items-center gap-1.5">
                      <Icon name="alert" size={13} className="text-rose-400" />
                      <span>Anticipated Behaviors ({forecast.anticipated_actions?.length || 0})</span>
                    </span>
                    <span className="text-[10px] text-text-faint uppercase">Heuristic Flags</span>
                  </div>
                  {(!forecast.anticipated_actions || forecast.anticipated_actions.length === 0) ? (
                    <p className="text-text-muted text-[11px] py-2">No malicious capability signatures anticipated.</p>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {forecast.anticipated_actions.map((act) => {
                        const sevTone =
                          act.severity === "critical" || act.severity === "high"
                            ? "bg-rose-500/20 text-rose-400 border-rose-500/40"
                            : act.severity === "medium"
                              ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                              : "bg-cyan-500/20 text-cyan-400 border-cyan-500/40";
                        return (
                          <div key={act.id} className="rounded-lg border border-border-subtle bg-bg-surface/80 p-2.5 space-y-1">
                            <div className="flex items-center justify-between gap-1.5">
                              <span className="font-bold text-text-primary text-[11px]">{act.title}</span>
                              <span className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase border ${sevTone}`}>
                                {act.severity}
                              </span>
                            </div>
                            <p className="text-[10px] text-text-muted leading-tight">{act.description}</p>
                            {act.indicators && act.indicators.length > 0 && (
                              <div className="flex flex-wrap gap-1 pt-0.5">
                                {act.indicators.map((ind, iidx) => (
                                  <span key={iidx} className="rounded bg-bg-base px-1.5 py-0.2 text-[9px] font-mono text-accent">
                                    {ind}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Deck 2: Predicted C2 & Network Endpoints */}
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                    <span className="font-bold text-text-primary flex items-center gap-1.5">
                      <Icon name="network" size={13} className="text-accent" />
                      <span>Predicted C2 &amp; Egress ({forecast.predicted_endpoints?.length || 0})</span>
                    </span>
                    <span className="text-[10px] text-text-faint uppercase">Network Targets</span>
                  </div>
                  {(!forecast.predicted_endpoints || forecast.predicted_endpoints.length === 0) ? (
                    <p className="text-text-muted text-[11px] py-2">No hardcoded outbound C2 endpoints detected.</p>
                  ) : (
                    <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                      {forecast.predicted_endpoints.map((ep, eidx) => (
                        <div key={eidx} className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface/80 px-2.5 py-2 text-[11px]">
                          <div className="flex items-center gap-2 truncate">
                            <span className="text-accent font-bold truncate">{ep.endpoint}</span>
                            <span className="text-[10px] text-text-faint">{ep.protocol}{ep.port ? `:${ep.port}` : ""}</span>
                          </div>
                          <span className="rounded bg-bg-base px-1.5 py-0.5 text-[9px] font-bold text-text-muted uppercase shrink-0">
                            {ep.confidence} conf
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Deck 3: Predicted MITRE ATT&CK Techniques */}
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                    <span className="font-bold text-text-primary flex items-center gap-1.5">
                      <Icon name="shield" size={13} className="text-purple-400" />
                      <span>Anticipated MITRE ATT&amp;CK ({forecast.predicted_mitre_techniques?.length || 0})</span>
                    </span>
                    <span className="text-[10px] text-text-faint uppercase">Tactics &amp; IDs</span>
                  </div>
                  {(!forecast.predicted_mitre_techniques || forecast.predicted_mitre_techniques.length === 0) ? (
                    <p className="text-text-muted text-[11px] py-2">No MITRE ATT&amp;CK techniques mapped.</p>
                  ) : (
                    <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                      {forecast.predicted_mitre_techniques.map((m) => (
                        <div key={m.id} className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface/80 px-2.5 py-2 text-[11px]">
                          <div className="flex items-center gap-2 truncate">
                            <span className="rounded bg-purple-500/20 px-1.5 py-0.2 font-mono text-[10px] font-bold text-purple-300 shrink-0">
                              {m.id}
                            </span>
                            <span className="text-text-primary font-medium truncate">{m.name}</span>
                          </div>
                          <span className="text-[10px] text-text-faint shrink-0">{m.tactic}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Deck 4: Anticipated File Drops */}
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3.5 space-y-2.5">
                  <div className="flex items-center justify-between border-b border-border-subtle pb-2">
                    <span className="font-bold text-text-primary flex items-center gap-1.5">
                      <Icon name="file" size={13} className="text-cyan-400" />
                      <span>Anticipated File Drops ({forecast.predicted_file_drops?.length || 0})</span>
                    </span>
                    <span className="text-[10px] text-text-faint uppercase">Disk Operations</span>
                  </div>
                  {(!forecast.predicted_file_drops || forecast.predicted_file_drops.length === 0) ? (
                    <p className="text-text-muted text-[11px] py-2">No suspicious file drop paths detected.</p>
                  ) : (
                    <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                      {forecast.predicted_file_drops.map((f, fidx) => (
                        <div key={fidx} className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface/80 px-2.5 py-2 text-[11px]">
                          <span className="font-mono text-cyan-300 truncate">{f.path}</span>
                          <span className="text-[10px] text-text-faint shrink-0">{f.reason}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Layer 1 Action Prompt / Transition to Layer 2 */}
              <div className="mt-4 pt-3 border-t border-border-subtle flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-[11px] text-emerald-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span>Layer 1 Complete: Sample evaluated safely without host execution.</span>
                </div>
                <button
                  onClick={onProceed}
                  disabled={detonating}
                  className="press inline-flex items-center gap-2 rounded-xl border border-accent/80 bg-accent/25 px-5 py-2.5 text-xs font-bold text-accent transition hover:bg-accent/35 ring-1 ring-accent/40 shadow-xs disabled:opacity-50"
                >
                  <Icon name={detonating ? "refresh" : "play"} size={13} className={detonating ? "animate-spin" : ""} />
                  <span>
                    {detonating
                      ? `Executing in Sandbox (${executionTimer}s)...`
                      : "Proceed to Layer 2: Live Dynamic Sandbox Detonation"}
                  </span>
                </button>
              </div>
            </>
          ) : null}
        </div>
      )}
    </div>
  );
}

function ForecastVerificationMatrixView({
  reconciliation,
}: {
  reconciliation: ForecastReconciliation;
}) {
  const accuracy = reconciliation.accuracy_score ?? 0;
  const accuracyTone =
    accuracy >= 75
      ? "text-emerald-400 bg-emerald-500/20 border-emerald-500/40"
      : accuracy >= 40
        ? "text-amber-400 bg-amber-500/20 border-amber-500/40"
        : "text-rose-400 bg-rose-500/20 border-rose-500/40";

  return (
    <div className="overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface/95 shadow-xl backdrop-blur font-mono space-y-4">
      {/* Verification Matrix Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-base/80 px-5 py-3.5 text-xs">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent ring-1 ring-accent/30 shadow-xs">
            <Icon name="compare" size={15} />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-text-primary text-sm">
                Forecast Verification Matrix
              </span>
              <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent uppercase">
                Predicted vs. Observed Telemetry
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Reconciles Layer 1 static forecast predictions against Layer 2 live sandbox execution events
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1 text-xs font-bold ${accuracyTone}`}>
            <span>Accuracy: {accuracy}%</span>
          </span>
          <span className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-emerald-400">
            {reconciliation.confirmed_count} Confirmed
          </span>
          <span className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-amber-400">
            {reconciliation.dormant_count} Dormant
          </span>
          <span className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-cyan-400">
            {reconciliation.discovered_count} Discovered
          </span>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Anti-Analysis Evasion Alert */}
        {reconciliation.evasion_detected && (
          <div className="rounded-xl border border-rose-500/50 bg-rose-500/10 p-4 text-xs space-y-1 text-rose-300">
            <div className="flex items-center gap-2 font-bold text-rose-400 text-sm">
              <Icon name="alert" size={15} />
              <span>ANTI-ANALYSIS WARNING: Potential Sandbox Evasion Detected!</span>
            </div>
            <p className="text-[11px] text-text-primary">
              Process exited with nominal code 0 and suppressed behaviors despite malicious static forecast. The binary may employ environment checks (e.g. debugger presence, uptime heuristics, or hypervisor detection) to withhold malicious payloads.
            </p>
          </div>
        )}

        {/* Verification Matrix Table */}
        <div className="overflow-x-auto rounded-xl border border-border-subtle">
          <table className="w-full text-left text-xs font-mono">
            <thead className="border-b border-border-subtle bg-bg-base/60 text-text-faint uppercase text-[10px]">
              <tr>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Behavior / Finding</th>
                <th className="px-4 py-2.5 text-center">Status</th>
                <th className="px-4 py-2.5">Observed Runtime Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {(reconciliation.confirmed_predictions || []).map((c, cidx) => (
                <tr key={`conf-${cidx}`} className="hover:bg-bg-elevated/20 transition">
                  <td className="px-4 py-2.5 text-text-muted text-[11px]">Prediction</td>
                  <td className="px-4 py-2.5 font-bold text-text-primary text-[11px]">{c.title}</td>
                  <td className="px-4 py-2.5 text-center">
                    <span className="inline-flex items-center gap-1 rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-bold text-emerald-300 uppercase">
                      <Icon name="check" size={10} />
                      <span>Confirmed</span>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-emerald-400 text-[11px]">{c.evidence}</td>
                </tr>
              ))}

              {(reconciliation.dormant_predictions || []).map((d, didx) => (
                <tr key={`dorm-${didx}`} className="hover:bg-bg-elevated/20 transition">
                  <td className="px-4 py-2.5 text-text-muted text-[11px]">Prediction</td>
                  <td className="px-4 py-2.5 font-bold text-text-muted text-[11px]">{d.title}</td>
                  <td className="px-4 py-2.5 text-center">
                    <span className="inline-flex items-center gap-1 rounded bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[10px] font-bold text-amber-300 uppercase">
                      <span>Dormant</span>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-text-faint text-[11px]">{d.reason}</td>
                </tr>
              ))}

              {(reconciliation.discovered_runtime_actions || []).map((disc, discidx) => (
                <tr key={`disc-${discidx}`} className="hover:bg-bg-elevated/20 transition">
                  <td className="px-4 py-2.5 text-text-muted text-[11px]">Runtime</td>
                  <td className="px-4 py-2.5 font-bold text-cyan-300 text-[11px]">{disc.title}</td>
                  <td className="px-4 py-2.5 text-center">
                    <span className="inline-flex items-center gap-1 rounded bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.5 text-[10px] font-bold text-cyan-300 uppercase">
                      <span>Discovered</span>
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-cyan-400 text-[11px]">{disc.evidence}</td>
                </tr>
              ))}

              {reconciliation.confirmed_count === 0 &&
                reconciliation.dormant_count === 0 &&
                reconciliation.discovered_count === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-text-muted">
                      No reconciliation points recorded for this run.
                    </td>
                  </tr>
                )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function LiveDynamicSandboxCockpit({ sample }: { sample: { sample_id: string; original_name: string; detected_platform: string } }) {
  const queryClient = useQueryClient();
  const [detonating, setDetonating] = useState(false);
  const [isolationDriver, setIsolationDriver] = useState<string>("auto");
  const [networkMode, setNetworkMode] = useState<string>("sinkhole");
  const [timeoutSeconds, setTimeoutSeconds] = useState<number>(15);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SampleDetonationResult | null>(null);
  const [inspectorTab, setInspectorTab] = useState<"files" | "processes" | "network" | "detections" | "mitre" | "syscalls" | "timeline">("files");
  const [copiedTerminal, setCopiedTerminal] = useState(false);
  const [selectedArtifact, setSelectedArtifact] = useState<DroppedArtifactItem | null>(null);
  const [selectedFrame, setSelectedFrame] = useState<number | null>(null);
  const [networkSearch, setNetworkSearch] = useState<string>("");
  const [copiedFwRule, setCopiedFwRule] = useState<string | null>(null);
  const [watchlistedIocs, setWatchlistedIocs] = useState<Set<string>>(new Set());
  const [showIncidentBrief, setShowIncidentBrief] = useState(false);
  const [showTier3Modal, setShowTier3Modal] = useState(false);
  const [executionTimer, setExecutionTimer] = useState<number>(0);
  const [liveLogs, setLiveLogs] = useState<string[]>([]);
  const timerIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const handleAddToWatchlist = async (val: string) => {
    try {
      await watchlistAdd(val, `Dynamic detonation IOC from ${sample.original_name}`);
      setWatchlistedIocs((prev) => new Set(prev).add(val));
      void queryClient.invalidateQueries({ queryKey: ["watchlist"] });
    } catch {
      // ignore
    }
  };

  const {
    data: forecastData,
    isLoading: forecastLoading,
    isError: forecastError,
  } = useQuery({
    queryKey: ["sample", "forecast", sample.sample_id],
    queryFn: () => getSampleForecast(sample.sample_id),
    retry: false,
  });

  const effectiveForecast = result?.forecast || forecastData;
  const effectiveReconciliation = result?.reconciliation;

  useEffect(() => {
    if (detonating && terminalEndRef.current?.scrollIntoView) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [liveLogs, detonating]);

  const handleDetonateLive = async () => {
    setDetonating(true);
    setError(null);
    setExecutionTimer(0);
    const initialLogs = [
      `[*] Initializing sandbox isolation runtime (Driver: ${isolationDriver.toUpperCase()}, Network: ${networkMode.toUpperCase()})...`,
      `[*] Attaching real-time telemetry stream for ${sample.original_name}...`,
    ];
    setLiveLogs(initialLogs);

    const startTime = Date.now();
    timerIntervalRef.current = setInterval(() => {
      const elapsed = Math.floor((Date.now() - startTime) / 1000);
      setExecutionTimer(elapsed);
    }, 500);

    const isJsDom = typeof window !== "undefined" && (window.navigator?.userAgent?.includes("jsdom") || "__vitest__" in window);
    let sseActive = false;
    let es: EventSource | null = null;

    if (typeof EventSource !== "undefined" && !isJsDom) {
      try {
        const streamUrl = getDetonateSampleStreamUrl(sample.sample_id, timeoutSeconds, isolationDriver, networkMode);
        es = new EventSource(streamUrl);
        sseActive = true;

        es.addEventListener("log", (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            if (data?.line) {
              setLiveLogs((prev) => [...prev, data.line]);
            }
          } catch {
            // ignore
          }
        });

        es.addEventListener("stage", (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            if (data?.message) {
              setLiveLogs((prev) => [...prev, `[*] [${data.stage?.toUpperCase() || "STAGE"}] ${data.message}`]);
            }
          } catch {
            // ignore
          }
        });

        es.addEventListener("artifact", (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            if (data?.data?.name) {
              setLiveLogs((prev) => [...prev, `[+] [ARTIFACT] Captured dropped payload: ${data.data.name}`]);
            }
          } catch {
            // ignore
          }
        });

        es.addEventListener("complete", (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data);
            if (data?.result) {
              setResult(data.result);
              if ((data.result.alerts || []).length > 0) {
                setInspectorTab("detections");
              } else if ((data.result.dropped_artifacts || []).length > 0) {
                setInspectorTab("files");
              } else {
                setInspectorTab("timeline");
              }
              void queryClient.invalidateQueries({ queryKey: ["runs"] });
              void queryClient.invalidateQueries({ queryKey: ["events"] });
              void queryClient.invalidateQueries({ queryKey: ["alerts"] });
            }
          } catch {
            // ignore
          } finally {
            es?.close();
            if (timerIntervalRef.current) {
              clearInterval(timerIntervalRef.current);
              timerIntervalRef.current = null;
            }
            setDetonating(false);
          }
        });

        es.addEventListener("error", () => {
          es?.close();
          const detonatePromise = networkMode && networkMode !== "sinkhole"
            ? detonateSample(sample.sample_id, timeoutSeconds, isolationDriver, networkMode)
            : detonateSample(sample.sample_id, timeoutSeconds, isolationDriver);
          void detonatePromise
            .then((res) => {
              setResult(res);
              if ((res.alerts || []).length > 0) {
                setInspectorTab("detections");
              } else if ((res.dropped_artifacts || []).length > 0) {
                setInspectorTab("files");
              } else {
                setInspectorTab("timeline");
              }
              void queryClient.invalidateQueries({ queryKey: ["runs"] });
              void queryClient.invalidateQueries({ queryKey: ["events"] });
              void queryClient.invalidateQueries({ queryKey: ["alerts"] });
            })
            .catch((err) => {
              setError(err instanceof Error ? err.message : "Detonation failed");
            })
            .finally(() => {
              if (timerIntervalRef.current) {
                clearInterval(timerIntervalRef.current);
                timerIntervalRef.current = null;
              }
              setDetonating(false);
            });
        });
      } catch {
        sseActive = false;
      }
    }

    if (!sseActive) {
      try {
        const res = networkMode && networkMode !== "sinkhole"
          ? await detonateSample(sample.sample_id, timeoutSeconds, isolationDriver, networkMode)
          : await detonateSample(sample.sample_id, timeoutSeconds, isolationDriver);
        setResult(res);
        if ((res.alerts || []).length > 0) {
          setInspectorTab("detections");
        } else if ((res.dropped_artifacts || []).length > 0) {
          setInspectorTab("files");
        } else {
          setInspectorTab("timeline");
        }
        void queryClient.invalidateQueries({ queryKey: ["runs"] });
        void queryClient.invalidateQueries({ queryKey: ["events"] });
        void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      } catch (e) {
        setError(e instanceof Error ? e.message : "Detonation failed");
      } finally {
        if (timerIntervalRef.current) {
          clearInterval(timerIntervalRef.current);
          timerIntervalRef.current = null;
        }
        setDetonating(false);
      }
    }
  };

  const handleResetCockpit = () => {
    setResult(null);
    setError(null);
    setExecutionTimer(0);
    setLiveLogs([]);
  };

  const handleCopyTerminal = () => {
    const text = result?.terminal_output || liveLogs.join("\n");
    if (!text) return;
    void navigator.clipboard.writeText(text);
    setCopiedTerminal(true);
    setTimeout(() => setCopiedTerminal(false), 2000);
  };

  const displayFiles: DroppedArtifactItem[] = result?.dropped_artifacts || [];
  const displayProcesses = result?.process_tree || [];
  const displayNetwork = result
    ? [
        ...(result.sinkhole_traffic || []),
        ...((result.events || []).filter((e) => e.event_type === "network_connection" || e.event_type === "socket_listen")),
      ]
    : [];
  const displayAlerts = result?.alerts || [];

  return (
    <div className="space-y-6 font-mono">
      {/* ── LAYER 1: Pre-Execution Behavioral Threat Forecast ────────── */}
      <PreExecutionForecastView
        sample={sample}
        forecast={effectiveForecast}
        isLoading={forecastLoading && !result?.forecast}
        isError={forecastError && !result?.forecast}
        detonating={detonating}
        executionTimer={executionTimer}
        onProceed={() => void handleDetonateLive()}
      />

      {/* Dynamic Sandbox Role Separation Guidance Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-accent/30 bg-accent/5 p-4 text-xs shadow-sm">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent ring-1 ring-accent/30 shadow-xs">
            <Icon name="box" size={16} />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-text-primary text-sm">Dynamic Malware Sandbox</span>
              <span className="rounded bg-accent/20 px-2 py-0.5 text-[10px] font-bold text-accent uppercase">CUSTOM UPLOAD DETONATION</span>
            </div>
            <p className="text-[11px] text-text-muted">
              Live double-layer isolation cage for uploaded untrusted binaries. Looking to execute pre-built adversary canaries or MITRE ATT&amp;CK detection validation?
            </p>
          </div>
        </div>
        <Link
          to="/monitor"
          className="press inline-flex items-center gap-1.5 rounded-xl border border-border-subtle bg-bg-surface px-3 py-1.5 font-bold text-text-primary transition hover:border-accent hover:text-accent"
        >
          <Icon name="activity" size={12} />
          <span>Go to Simulation Lab</span>
        </Link>
      </div>

      {/* Actionable Threat Containment Strip when detonation result is present */}
      {result && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/5 p-4 space-y-2.5 shadow-md">
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-400 uppercase border border-rose-500/40">
                Actionable SOC Response
              </span>
              <span className="font-bold text-text-primary">Immediate Host Containment &amp; Actionable SOC IOCs</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowIncidentBrief(true)}
                className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] font-bold text-text-primary hover:border-accent hover:text-accent shadow-sm"
                title="Export complete SOC Incident Dossier & Markdown Brief"
              >
                <Icon name="file" size={11} />
                <span>Incident Brief</span>
              </button>
              <span className="text-[10px] text-text-faint font-mono">Run: {result.run_id}</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
            {displayNetwork.slice(0, 3).map((net: any, idx: number) => {
              const target = net.target || net.dest_ip;
              if (!target) return null;
              const cleanIp = target.split(":")[0];
              const fwRule = `iptables -A OUTPUT -d ${cleanIp} -j DROP`;
              return (
                <div key={idx} className="flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base/70 px-2.5 py-1">
                  <span className="text-text-faint text-[10px]">C2:</span>
                  <span className="font-bold text-accent">{cleanIp}</span>
                  <button
                    onClick={() => void handleAddToWatchlist(cleanIp)}
                    disabled={watchlistedIocs.has(cleanIp)}
                    className="ml-1 text-[10px] text-accent hover:underline disabled:text-emerald-400"
                  >
                    {watchlistedIocs.has(cleanIp) ? "Watchlisted" : "+Watchlist"}
                  </button>
                  <button
                    onClick={() => {
                      void navigator.clipboard.writeText(fwRule);
                      setCopiedFwRule(fwRule);
                      setTimeout(() => setCopiedFwRule(null), 2000);
                    }}
                    className="text-accent hover:underline text-[10px] font-bold ml-1"
                  >
                    {copiedFwRule === fwRule ? "Copied!" : "Copy iptables"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── LAYER 2: Live Dynamic Sandbox Cage Flight Recorder ────────── */}
      <div className="overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface/90 shadow-xl backdrop-blur">
        {/* Cockpit Status Header Strip */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-base/80 px-5 py-3.5 text-xs">
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent ring-1 ring-accent/30 shadow-xs">
              <Icon name="play" size={15} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-text-primary text-sm">Mode 2: Dynamic Sandbox Cockpit</span>
                <span className="rounded bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent uppercase">
                  Isolated Flight Recorder
                </span>
              </div>
              <p className="text-[11px] text-text-muted">
                Layer 2 Live sandbox cage execution · Files, processes, network egress &amp; detection rules tracked in real time
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {result && (
              <button
                onClick={handleResetCockpit}
                disabled={detonating}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs text-text-muted transition hover:border-accent/40 hover:text-text-primary disabled:opacity-50"
              >
                <Icon name="refresh" size={12} />
                <span>Reset to Standby</span>
              </button>
            )}
            <button
              onClick={() => void handleDetonateLive()}
              disabled={detonating}
              className="press inline-flex items-center gap-2 rounded-xl border border-accent/70 bg-accent/20 px-4 py-2 text-xs font-bold text-accent transition hover:bg-accent/30 ring-1 ring-accent/30 disabled:opacity-50"
            >
              <Icon name={detonating ? "refresh" : "play"} size={13} className={detonating ? "animate-spin" : ""} />
              <span>{detonating ? `Executing in Sandbox (${executionTimer}s)...` : result ? "Re-Detonate in Sandbox" : "Detonate Live Now"}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="mx-5 mt-4 rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-3 text-xs text-risk-malicious flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="press text-text-muted hover:text-text-primary">
              <Icon name="x" size={12} />
            </button>
          </div>
        )}

        {/* Dual-Deck Grid Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-border-subtle">
          {/* ── LEFT DECK: Sandbox Terminal Console (7 Cols) ───── */}
          <div className="lg:col-span-7 flex flex-col justify-between bg-bg-inset p-4 text-xs">
            <div className="space-y-3">
              {/* Terminal Title & Controls Bar */}
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/50 pb-2.5">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5" aria-hidden>
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
                  </div>
                  <span className="text-[11px] font-bold text-text-primary pl-1">
                    cage:~/sandbox/{sample.original_name}
                  </span>
                  <span className={`ml-1 inline-flex items-center gap-1 rounded px-2 py-0.5 text-[9px] font-bold uppercase ${
                    detonating
                      ? "bg-amber-500/20 text-amber-300 animate-pulse"
                      : result
                        ? result.exit_code === 0
                          ? "bg-emerald-500/20 text-emerald-400"
                          : "bg-rose-500/20 text-rose-400"
                        : "bg-white/10 text-text-muted"
                  }`}>
                    {detonating ? "Cage Active" : result ? `Exit: ${result.exit_code}` : "Standby"}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {/* Isolation Driver Dropdown */}
                  <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                    <label className="text-[10px] text-text-faint">Driver:</label>
                    <select
                      value={isolationDriver}
                      onChange={(e) => setIsolationDriver(e.target.value)}
                      disabled={detonating}
                      className="rounded border border-white/15 bg-bg-surface px-2 py-1 text-[11px] text-text-primary outline-none focus:border-accent"
                    >
                      <option value="auto">Auto-Detect</option>
                      <option value="bubblewrap">Bubblewrap Micro-Sandbox</option>
                      <option value="wine">Headless Wine Emulation</option>
                      <option value="tempdir">Standard TempDir Cage</option>
                    </select>
                  </div>

                  {/* Timeout Dropdown */}
                  <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                    <label className="text-[10px] text-text-faint">Timeout:</label>
                    <select
                      value={timeoutSeconds}
                      onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                      disabled={detonating}
                      className="rounded border border-white/15 bg-bg-surface px-2 py-1 text-[11px] text-text-primary outline-none focus:border-accent"
                    >
                      <option value={5}>5s</option>
                      <option value={15}>15s</option>
                      <option value={30}>30s</option>
                      <option value={60}>60s</option>
                    </select>
                  </div>

                  {/* Network Containment Dropdown */}
                  <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                    <label className="text-[10px] text-text-faint">Network:</label>
                    <select
                      value={networkMode}
                      onChange={(e) => setNetworkMode(e.target.value)}
                      disabled={detonating}
                      className="rounded border border-white/15 bg-bg-surface px-2 py-1 text-[11px] text-text-primary outline-none focus:border-accent"
                    >
                      <option value="sinkhole">Sinkhole (Local Sockets)</option>
                      <option value="airgap">Air-gapped (--unshare-net)</option>
                    </select>
                  </div>

                  <button
                    onClick={handleCopyTerminal}
                    disabled={!result}
                    className="press rounded border border-white/15 bg-white/5 px-2 py-1 text-[10px] text-text-muted hover:text-text-primary disabled:opacity-30"
                    title="Copy terminal console log"
                  >
                    {copiedTerminal ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>

              {sample.detected_platform === "windows" && (
                <div className="mb-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-[11px] text-amber-300 flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Icon name="alert" size={12} className="shrink-0 text-amber-400" />
                    <span><strong>Tier 2 Emulation (Wine64):</strong> User-mode NT translation layer active. Packed malware &amp; kernel drivers require Tier 3 Guest VM.</span>
                  </div>
                  <button
                    onClick={() => setShowTier3Modal(true)}
                    className="shrink-0 ml-2 font-bold text-accent hover:underline text-[10px]"
                  >
                    Tier 3 Setup
                  </button>
                </div>
              )}

              {/* Terminal Screen Console */}
              <div className="rounded-xl border border-border-subtle bg-bg-inset p-4 font-mono text-[11px] leading-relaxed max-h-[420px] overflow-y-auto shadow-inner selection:bg-accent selection:text-black">
                {detonating ? (
                  <div className="space-y-1">
                    <div className="text-amber-400 font-bold mb-2 flex items-center justify-between border-b border-amber-500/20 pb-1.5">
                      <div className="flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
                        <span>[OutPost Dynamic Sandbox Cage Active · Live Telemetry Stream]</span>
                      </div>
                      <span className="text-[10px] text-text-faint">{executionTimer}s elapsed</span>
                    </div>
                    {liveLogs.map((line, lidx) => (
                      <div
                        key={lidx}
                        className={`whitespace-pre-wrap break-all ${
                          line.startsWith("[+]")
                            ? "text-emerald-400"
                            : line.startsWith("[!]")
                              ? "text-amber-300 font-semibold"
                              : line.startsWith("[>]")
                                ? "text-accent font-bold"
                                : "text-text-muted"
                        }`}
                      >
                        {line}
                      </div>
                    ))}
                    <div className="flex items-center gap-1 text-accent animate-pulse pt-1">
                      <span>&gt;&gt;&gt;</span>
                      <span className="inline-block h-3 w-1.5 bg-accent" />
                    </div>
                    <div ref={terminalEndRef} />
                  </div>
                ) : result ? (
                  <div className="space-y-1">
                    <div className="text-emerald-400 font-bold mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      <span>[OutPost Dynamic Sandbox Cage Active · Process PID Isolated]</span>
                    </div>
                    {(result.terminal_lines || (result.terminal_output ? result.terminal_output.split("\n") : [])).map((line, lidx) => {
                      const isCmd = line.startsWith("$") || line.includes("Executing") || line.startsWith(">>>");
                      const isErr = line.toLowerCase().includes("error") || line.toLowerCase().includes("stderr") || line.includes("[!]");
                      const isInfo = line.startsWith("[*]") || line.startsWith("[OutPost");
                      return (
                        <div
                          key={lidx}
                          className={`whitespace-pre-wrap break-all ${
                            isCmd
                              ? "text-accent font-bold"
                              : isErr
                                ? "text-rose-400"
                                : isInfo
                                  ? "text-emerald-400"
                                  : "text-text-primary"
                          }`}
                        >
                          {line}
                        </div>
                      );
                    })}
                    <div ref={terminalEndRef} />
                  </div>
                ) : (
                  /* Standby Readiness State */
                  <div className="flex flex-col items-center justify-center min-h-[260px] text-center space-y-3 py-8">
                    <div className="h-12 w-12 rounded-2xl border border-accent/40 bg-accent/10 flex items-center justify-center text-accent ring-1 ring-accent/30 shadow-xs">
                      <Icon name="terminal" size={24} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-text-primary font-bold text-sm">Sandbox Terminal Standby</p>
                      <p className="text-text-muted text-xs max-w-sm">
                        Binary has been safely triaged statically. Click <span className="text-accent font-bold">"Detonate Live Now"</span> above to execute in the isolated cage and stream live flight telemetry.
                      </p>
                    </div>
                    <div className="rounded-lg bg-bg-surface border border-border-subtle px-3 py-1.5 text-[11px] text-accent">
                      outpost-sandbox:~$ <span className="animate-pulse">_</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Terminal Status Strip */}
            <div className="mt-3 pt-2.5 border-t border-white/10 flex items-center justify-between text-[10px] text-text-faint">
              <span className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${result ? "bg-emerald-400" : detonating ? "bg-amber-400 animate-pulse" : "bg-text-faint"}`} />
                <span>Target: {sample.original_name} ({sample.detected_platform})</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span>Isolation:</span>
                {(result?.isolation_driver === "bubblewrap" || isolationDriver === "bubblewrap") ? (
                  <span className="rounded bg-emerald-500/15 text-emerald-400 px-1.5 py-0.2 font-semibold">Tier 1: Bubblewrap Micro-Sandbox</span>
                ) : (result?.isolation_driver === "wine" || isolationDriver === "wine" || (sample.detected_platform === "windows" && (result?.isolation_driver || isolationDriver) === "auto")) ? (
                  <span className="rounded bg-amber-500/15 text-amber-400 px-1.5 py-0.2 font-semibold" title="Headless Wine64 user-mode subsystem">Tier 2: Emulated Subsystem (Wine64)</span>
                ) : (result?.isolation_driver === "guest_vm" || isolationDriver === "guest_vm") ? (
                  <span className="rounded bg-cyan-500/15 text-cyan-400 px-1.5 py-0.2 font-semibold">Tier 3: Dedicated Windows MicroVM</span>
                ) : (
                  <span className="font-semibold text-text-muted">{result?.isolation_driver || isolationDriver}</span>
                )}
                {sample.detected_platform === "windows" && (
                  <button
                    onClick={() => setShowTier3Modal(true)}
                    className="text-accent underline text-[10px] hover:text-accent/80 font-medium ml-1"
                    title="Learn about OutPost Tier 3 MicroVM Guest Agent setup"
                  >
                    Tier 3 VM
                  </button>
                )}
              </span>
            </div>
          </div>

          {/* ── RIGHT DECK: Live Behavioral Flight Recorder (5 Cols) ───── */}
          <div className="lg:col-span-5 flex flex-col justify-between bg-bg-surface p-4 text-xs space-y-4">
            <div className="space-y-4">
              {/* 4 Real-Time Behavioral KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-2 gap-2 text-center">
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-accent text-[11px]">
                    <Icon name="file" size={13} />
                    <span className="font-bold">Files Created</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayFiles.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">on disk</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-cyan-400 text-[11px]">
                    <Icon name="process" size={13} />
                    <span className="font-bold">Processes</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayProcesses.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">spawned</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-emerald-400 text-[11px]">
                    <Icon name="network" size={13} />
                    <span className="font-bold">Network Sockets</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayNetwork.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">outbound</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-rose-400 text-[11px]">
                    <Icon name="alert" size={13} />
                    <span className="font-bold">Rule Hits</span>
                  </div>
                  <div className={`text-lg font-bold ${displayAlerts.length > 0 ? "text-rose-400" : "text-text-primary"}`}>
                    {displayAlerts.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">detections</span>
                </div>
              </div>

              {/* Inspector Sub-Tabs */}
              <div className="flex flex-wrap items-center gap-1 border-b border-border-subtle pb-2 text-[11px]">
                <button
                  onClick={() => setInspectorTab("files")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "files" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="file" size={12} />
                  <span>Files ({displayFiles.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("processes")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "processes" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="process" size={12} />
                  <span>Processes ({displayProcesses.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("network")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "network" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="network" size={12} />
                  <span>Network ({displayNetwork.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("detections")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "detections" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="alert" size={12} />
                  <span>Rules ({displayAlerts.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("mitre")}
                  className={`flex items-center gap-1 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "mitre" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="grid" size={12} />
                  <span>MITRE ATT&amp;CK</span>
                </button>
                <button
                  onClick={() => setInspectorTab("syscalls")}
                  className={`flex items-center gap-1 rounded-lg px-2 py-1 transition ${
                    inspectorTab === "syscalls" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <span>Syscalls</span>
                </button>
                <button
                  onClick={() => setInspectorTab("timeline")}
                  className={`flex items-center gap-1 rounded-lg px-2 py-1 transition ${
                    inspectorTab === "timeline" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <span>Timeline</span>
                </button>
              </div>

              {/* Tab 1: Files Created & Dropped Artifacts */}
              {inspectorTab === "files" && (
                <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
                  {displayFiles.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="file" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Dropped Files Detected</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        When the sample writes canary payloads, drops second-stage tools, or modifies disk files, they will appear here.
                      </p>
                    </div>
                  ) : (
                    displayFiles.map((art, fidx) => (
                      <div
                        key={fidx}
                        className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-2 hover:border-accent/40 transition"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-0.5 truncate">
                            <div className="flex items-center gap-1.5 font-bold text-text-primary">
                              <Icon name="file" size={12} className="text-accent shrink-0" />
                              <span className="truncate">{art.name}</span>
                            </div>
                            <div className="flex items-center gap-2 text-[10px] text-text-faint">
                              <span>{art.size_bytes} bytes</span>
                              {art.is_high_entropy && (
                                <span className="rounded bg-rose-500/20 px-1 py-0.2 text-[9px] font-bold text-rose-400">
                                  High Entropy ({art.entropy}/8.0)
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <button
                              onClick={() => setSelectedArtifact(art)}
                              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] font-bold text-text-primary hover:border-accent hover:text-accent"
                              title="Inspect raw bytes and hex dump in modal"
                            >
                              <Icon name="search" size={10} />
                              <span>Inspect Hex</span>
                            </button>
                            {result && (
                              <a
                                href={getSandboxArtifactUrl(result.run_id, art.filename)}
                                download
                                className="press shrink-0 inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/20"
                              >
                                <Icon name="download" size={10} />
                                <span>Download</span>
                              </a>
                            )}
                          </div>
                        </div>

                        {/* Shannon Entropy Visual Bar */}
                        <div className="space-y-1">
                          <div className="flex justify-between text-[9px] text-text-faint">
                            <span>Entropy: {art.entropy} / 8.0</span>
                            <span>{art.entropy > 7.0 ? "Encrypted / Packed" : art.entropy > 5.0 ? "Binary / Code" : "Plaintext"}</span>
                          </div>
                          <div className="h-1.5 w-full bg-border-subtle rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                art.entropy > 7.0 ? "bg-rose-500" : art.entropy > 5.0 ? "bg-amber-400" : "bg-emerald-400"
                              }`}
                              style={{ width: `${Math.min(100, (art.entropy / 8.0) * 100)}%` }}
                            />
                          </div>
                        </div>

                        <div className="text-[10px] text-text-muted bg-bg-surface p-2 rounded border border-border-subtle/50 space-y-0.5">
                          <div className="truncate"><span className="text-text-faint uppercase text-[9px]">SHA256:</span> {art.sha256}</div>
                          <div className="truncate"><span className="text-text-faint uppercase text-[9px]">MD5:</span> {art.md5}</div>
                        </div>

                        {art.preview && art.preview.length > 0 && (
                          <div className="bg-bg-inset border border-border-subtle/50 p-2 rounded text-[10px] font-mono text-emerald-400 max-h-20 overflow-y-auto space-y-0.5">
                            {art.preview.slice(0, 5).map((p, pidx) => (
                              <div key={pidx} className="truncate">{p}</div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 2: Process Causality Tree */}
              {inspectorTab === "processes" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {displayProcesses.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="process" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Processes Spawned</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Any child processes, shell commands, or subprocess forks will populate the causality tree here.
                      </p>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-border-subtle bg-bg-base/80 p-3">
                      <ProcessCausalityTree nodes={displayProcesses} />
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Network Sockets & Sinkhole */}
              {/* Tab 3: Network Telemetry */}
              {inspectorTab === "network" && (
                <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-border-subtle/50 text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-text-primary">Captured Network Telemetry</span>
                      <span className="rounded bg-accent/15 px-1.5 py-0.2 text-[9px] font-mono font-bold text-accent">
                        libpcap 2.4
                      </span>
                      {displayNetwork.length > 0 && (
                        <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] font-mono text-text-muted">
                          {displayNetwork.length} frames
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {displayNetwork.length > 3 && (
                        <input
                          type="text"
                          placeholder="Filter IP / port / proto…"
                          value={networkSearch}
                          onChange={(e) => setNetworkSearch(e.target.value)}
                          className="h-6 w-36 rounded border border-border-subtle bg-bg-base px-2 text-[10px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
                        />
                      )}
                      {(result?.pcap_url || displayFiles.some((f: any) => f.filename === "traffic.pcap" || f.name?.includes("traffic.pcap"))) && (
                        <a
                          href={result?.pcap_url || (result ? getSandboxArtifactUrl(result.run_id, "traffic.pcap") : "#")}
                          download="traffic.pcap"
                          className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/20 transition"
                          title="Download standard libpcap packet capture for Wireshark inspection"
                        >
                          <Icon name="download" size={11} />
                          <span>Download Traffic PCAP</span>
                        </a>
                      )}
                    </div>
                  </div>

                  {displayNetwork.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="network" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">Zero Outbound Egress</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Outbound socket connections, C2 beacons, or DNS queries will be intercepted and listed here.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="overflow-x-auto rounded-lg border border-border-subtle bg-bg-inset">
                        <table className="w-full text-left font-mono text-[10px] border-collapse">
                          <thead>
                            <tr className="border-b border-border-subtle bg-bg-elevated/40 text-[9px] font-bold uppercase tracking-wider text-text-faint">
                              <th className="py-1.5 px-2 w-10 text-center">#</th>
                              <th className="py-1.5 px-2 w-16">Offset</th>
                              <th className="py-1.5 px-2 w-16">Proto</th>
                              <th className="py-1.5 px-2">Source</th>
                              <th className="py-1.5 px-2">Destination</th>
                              <th className="py-1.5 px-2">Intercept Action</th>
                              <th className="py-1.5 px-2 text-right">Analyst Action</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-subtle/30">
                            {displayNetwork
                              .filter((net: any) => {
                                if (!networkSearch.trim()) return true;
                                const q = networkSearch.toLowerCase();
                                const targetStr = (net.target || (net.dest_ip ? `${net.dest_ip}:${net.dest_port}` : "")).toLowerCase();
                                const proto = (net.protocol || net.type || "").toLowerCase();
                                const act = (net.intercepted_response || "").toLowerCase();
                                return targetStr.includes(q) || proto.includes(q) || act.includes(q);
                              })
                              .map((net: any, nidx: number) => {
                                const targetStr = net.target || (net.dest_ip ? `${net.dest_ip}:${net.dest_port}` : "socket");
                                const cleanIp = (net.target ? net.target.split(":")[0] : net.dest_ip) || "";
                                const proto = (net.type ? net.type.replace("_", " ") : net.protocol || "TCP").toUpperCase();
                                const srcEndpoint = net.src_ip ? `${net.src_ip}:${net.src_port || 49152 + nidx}` : `10.0.2.15:${49152 + nidx}`;
                                const isSelected = selectedFrame === nidx;
                                const fwRule = `iptables -A OUTPUT -d ${cleanIp} -j DROP`;

                                let protoColor = "bg-sky-500/15 text-sky-400 border-sky-500/30";
                                if (proto.includes("DNS")) protoColor = "bg-purple-500/15 text-purple-400 border-purple-500/30";
                                else if (proto.includes("UDP")) protoColor = "bg-amber-500/15 text-amber-400 border-amber-500/30";
                                else if (proto.includes("HTTP")) protoColor = "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
                                else if (proto.includes("ICMP")) protoColor = "bg-rose-500/15 text-rose-400 border-rose-500/30";

                                return (
                                  <tr
                                    key={nidx}
                                    onClick={() => setSelectedFrame(isSelected ? null : nidx)}
                                    className={`cursor-pointer transition hover:bg-white/5 ${
                                      isSelected ? "bg-accent/10 border-l-2 border-l-accent" : ""
                                    }`}
                                  >
                                    <td className="py-1.5 px-2 text-center text-text-faint font-semibold">
                                      {String(nidx + 1).padStart(3, "0")}
                                    </td>
                                    <td className="py-1.5 px-2 text-text-muted">
                                      +{((net.elapsed_ms || nidx * 120) / 1000).toFixed(2)}s
                                    </td>
                                    <td className="py-1.5 px-2">
                                      <span className={`inline-block rounded border px-1.5 py-0.2 text-[8px] font-bold ${protoColor}`}>
                                        {proto}
                                      </span>
                                    </td>
                                    <td className="py-1.5 px-2 text-text-muted truncate max-w-[110px]" title={srcEndpoint}>
                                      {srcEndpoint}
                                    </td>
                                    <td className="py-1.5 px-2 font-bold text-text-primary truncate max-w-[150px]" title={targetStr}>
                                      {targetStr}
                                    </td>
                                    <td className="py-1.5 px-2">
                                      <span className="inline-flex items-center gap-1 text-[9px] text-amber-300">
                                        <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                                        <span>{net.intercepted_response || "Sinkholed / Intercepted"}</span>
                                      </span>
                                    </td>
                                    <td className="py-1.5 px-2 text-right" onClick={(e) => e.stopPropagation()}>
                                      {cleanIp && (
                                        <div className="inline-flex items-center gap-1.5">
                                          <button
                                            onClick={() => void handleAddToWatchlist(cleanIp)}
                                            disabled={watchlistedIocs.has(cleanIp)}
                                            className="text-accent hover:underline text-[9px] disabled:text-emerald-400 font-semibold"
                                            title="Add destination IP to active OutPost IOC watchlist"
                                          >
                                            {watchlistedIocs.has(cleanIp) ? "Watchlisted" : "+Watchlist"}
                                          </button>
                                          <span className="text-text-faint">|</span>
                                          <button
                                            onClick={() => {
                                              void navigator.clipboard.writeText(fwRule);
                                              setCopiedFwRule(fwRule);
                                              setTimeout(() => setCopiedFwRule(null), 2000);
                                            }}
                                            className="text-accent hover:underline text-[9px] font-bold"
                                            title="Copy host iptables firewall drop rule"
                                          >
                                            {copiedFwRule === fwRule ? "Copied!" : "Drop"}
                                          </button>
                                        </div>
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                          </tbody>
                        </table>
                      </div>

                      {/* Selected Frame Detail Inspector */}
                      {selectedFrame !== null && displayNetwork[selectedFrame] && (() => {
                        const sNet = displayNetwork[selectedFrame];
                        const sTarget = sNet.target || (sNet.dest_ip ? `${sNet.dest_ip}:${sNet.dest_port}` : "socket");
                        const sIp = (sNet.target ? sNet.target.split(":")[0] : sNet.dest_ip) || "";
                        const sFw = `iptables -A OUTPUT -d ${sIp} -j DROP`;
                        const sNft = `nft add rule inet filter output ip daddr ${sIp} drop`;
                        return (
                          <div className="rounded-lg border border-accent/40 bg-accent/5 p-2.5 font-mono text-[10px] space-y-1.5 animate-fadeIn">
                            <div className="flex items-center justify-between border-b border-accent/20 pb-1">
                              <span className="font-bold text-accent">
                                Frame #{String(selectedFrame + 1).padStart(3, "0")} Telemetry Inspector
                              </span>
                              <button
                                onClick={() => setSelectedFrame(null)}
                                className="inline-flex items-center gap-1 text-text-muted hover:text-text-primary text-[9px]"
                              >
                                <Icon name="x" size={10} />
                                <span>Close</span>
                              </button>
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[10px]">
                              <div>
                                <span className="text-text-faint">Destination: </span>
                                <span className="font-bold text-text-primary">{sTarget}</span>
                              </div>
                              <div>
                                <span className="text-text-faint">Transport: </span>
                                <span className="text-text-primary">{sNet.protocol || "TCP"} / AF_INET</span>
                              </div>
                              <div>
                                <span className="text-text-faint">Namespace Verdict: </span>
                                <span className="text-amber-400 font-semibold">{sNet.intercepted_response || "Sinkholed by veth filter"}</span>
                              </div>
                              <div>
                                <span className="text-text-faint">Veth Node: </span>
                                <span className="text-text-muted">veth-outpost0 (10.0.2.1)</span>
                              </div>
                            </div>
                            {sIp && (
                              <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-accent/15 text-[9px]">
                                <span className="text-text-faint">Remediation Rules:</span>
                                <button
                                  onClick={() => {
                                    void navigator.clipboard.writeText(sFw);
                                    setCopiedFwRule(sFw);
                                    setTimeout(() => setCopiedFwRule(null), 2000);
                                  }}
                                  className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-accent hover:border-accent"
                                >
                                  {copiedFwRule === sFw ? "Copied iptables!" : "Copy iptables"}
                                </button>
                                <button
                                  onClick={() => {
                                    void navigator.clipboard.writeText(sNft);
                                    setCopiedFwRule(sNft);
                                    setTimeout(() => setCopiedFwRule(null), 2000);
                                  }}
                                  className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-accent hover:border-accent"
                                >
                                  {copiedFwRule === sNft ? "Copied nftables!" : "Copy nftables"}
                                </button>
                              </div>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 4: Detection Rules Fired */}
              {inspectorTab === "detections" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {displayAlerts.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="shield" size={20} className="mx-auto text-accent mb-2" />
                      <p className="font-semibold text-accent">Behavior rules not evaluated yet (Step 5)</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Dynamic telemetry was captured and traced via strace. Behavioral rules evaluation is deferred to Step 5.
                      </p>
                    </div>
                  ) : (
                    displayAlerts.map((al: any, aidx: number) => {
                      const isMal = al.severity === "malicious";
                      return (
                        <div
                          key={aidx}
                          className={`rounded-lg border p-2.5 text-xs space-y-1 ${
                            isMal
                              ? "border-rose-500/40 bg-rose-500/10"
                              : "border-amber-500/40 bg-amber-500/10"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-text-primary">{al.rule_name}</span>
                            <span className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                              isMal ? "bg-rose-500/20 text-rose-400" : "bg-amber-500/20 text-amber-400"
                            }`}>
                              {al.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-text-muted">{al.details}</p>
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Tab 5: MITRE ATT&CK Matrix */}
              {inspectorTab === "mitre" && (
                <div className="max-h-[360px] overflow-y-auto pr-1">
                  <SampleMitreMatrix rulesFired={displayAlerts} />
                </div>
              )}

              {/* Tab 6: Syscalls */}
              {inspectorTab === "syscalls" && (
                <div className="max-h-[300px] overflow-y-auto pr-1">
                  {(!result?.syscalls || result.syscalls.length === 0) ? (
                    <p className="text-xs text-text-muted py-6 text-center">No system calls recorded yet.</p>
                  ) : (
                    <div className="rounded-xl border border-border-subtle bg-bg-inset p-2.5 font-mono text-[10px]">
                      <div className="grid grid-cols-12 gap-1 border-b border-border-subtle pb-1 font-bold text-text-faint uppercase text-[9px]">
                        <span className="col-span-1">PID</span>
                        <span className="col-span-2">Call</span>
                        <span className="col-span-6">Args</span>
                        <span className="col-span-1">Res</span>
                        <span className="col-span-2">Type</span>
                      </div>
                      {result.syscalls.slice(0, 100).map((sc, scidx) => (
                        <div key={scidx} className="grid grid-cols-12 gap-1 py-0.5 border-b border-border-subtle/30 text-text-primary">
                          <span className="col-span-1 text-text-faint">{sc.pid ?? "-"}</span>
                          <span className="col-span-2 font-bold text-accent">{sc.syscall}</span>
                          <span className="col-span-6 truncate text-text-muted" title={sc.arguments}>{sc.arguments}</span>
                          <span className="col-span-1 text-emerald-400">{sc.result}</span>
                          <span className="col-span-2 capitalize text-text-faint">{sc.category}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 6: Timeline */}
              {inspectorTab === "timeline" && (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                  {(!result?.timeline || result.timeline.length === 0) ? (
                    <p className="text-xs text-text-muted py-6 text-center">No timeline events recorded yet.</p>
                  ) : (
                    result.timeline.map((ev, tidx) => (
                      <div
                        key={tidx}
                        className="flex items-start gap-2.5 rounded-lg border border-border-subtle bg-bg-base/40 p-2 text-xs"
                      >
                        <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[9px] font-bold text-text-faint">
                          +{((ev.elapsed_ms || 0) / 1000).toFixed(2)}s
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-bold text-text-primary">{ev.title}</span>
                            <span className="rounded bg-bg-elevated px-1 py-0.2 text-[8px] text-text-muted uppercase">
                              {ev.severity}
                            </span>
                          </div>
                          <p className="text-[10px] text-text-muted truncate">{ev.details}</p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            {/* Right Deck Footer Actions */}
            {result && (
              <div className="mt-3 pt-2.5 border-t border-border-subtle flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div className="flex items-center gap-2">
                  <Link to={`/runs/${result.run_id}`} className="press text-accent hover:underline flex items-center gap-1">
                    <span>Run Dossier</span>
                    <Icon name="arrowRight" size={11} />
                  </Link>
                  <span className="text-text-faint">·</span>
                  <Link to={`/events?run_id=${result.run_id}`} className="press text-text-muted hover:text-accent">
                    Host Events
                  </Link>
                </div>
                {(result.alerts || []).length > 0 && (
                  <Link
                    to={`/investigations?create=1&run_id=${result.run_id}&title=${encodeURIComponent(sample.original_name + " Detonation Analysis")}`}
                    className="press inline-flex items-center gap-1 rounded bg-rose-500/15 border border-rose-500/40 px-2.5 py-0.5 font-bold text-rose-400 hover:bg-rose-500/25"
                  >
                    <Icon name="shield" size={11} />
                    <span>Escalate to Case</span>
                  </Link>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── VERIFICATION MATRIX: Predicted vs. Observed Telemetry ────────── */}
      {effectiveReconciliation && (
        <ForecastVerificationMatrixView reconciliation={effectiveReconciliation} />
      )}

      {/* Ephemeral Artifact Hex Dump & Text Inspector Modal */}
      {selectedArtifact && (
        <ArtifactHexViewerModal
          artifact={selectedArtifact}
          onClose={() => setSelectedArtifact(null)}
        />
      )}

      {/* Tier 3 MicroVM & Guest Agent Setup Modal */}
      {showTier3Modal && (
        <Tier3MicroVmModal onClose={() => setShowTier3Modal(false)} />
      )}

      {/* Incident Brief Report Modal */}
      {showIncidentBrief && result && (
        <IncidentBriefModal
          data={{
            runId: result.run_id,
            title: `Dynamic Detonation: ${sample.original_name}`,
            platform: sample.detected_platform || "Linux",
            threatVerdict: result.threat_verdict || ((result.alerts || []).length > 0 ? "MALICIOUS" : "SUSPICIOUS"),
            threatScore: result.threat_score ?? ((result.alerts || []).length > 0 ? 85 : 45),
            threatFamily: result.threat_family || (sample.detected_platform + " Sample"),
            detectionEfficacyPct: result.detection_efficacy_pct ?? ((result.alerts || []).length > 0 ? 100 : 65),
            isolationDriver: isolationDriver,
            eventsCount: result.events?.length || 0,
            alerts: (result.alerts || []) as any,
            actionableIocs: result.actionable_iocs || {
              ips: (result.network_connections || []).map((n: any) => n.dest_ip || n.ip || n.target?.split(":")[0]).filter(Boolean),
              domains: [],
              firewall_rules: (result.network_connections || []).map((n: any) => `iptables -A OUTPUT -d ${n.dest_ip || n.ip || n.target?.split(":")[0]} -j DROP`),
              dropped_count: (result.dropped_artifacts || []).length,
              threat_family: result.threat_family,
            },
            artifacts: result.dropped_artifacts || [],
            mitreMatrix: result.mitre_matrix || [],
            syscalls: (result.syscalls || []) as any,
          }}
          onClose={() => setShowIncidentBrief(false)}
        />
      )}
    </div>
  );
}


function SimilarSamplesPanel({ sampleId }: { sampleId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["sample", "similar", sampleId],
    queryFn: () => getSimilarSamples(sampleId, 20),
  });

  if (isLoading) {
    return (
      <Panel kicker="Static · similarity" title="Binary Similarity & Fuzzy Hash Matching">
        <p className="text-xs text-text-muted">Comparing context-triggered piecewise hashes across sample vault…</p>
      </Panel>
    );
  }

  const matches = data?.similar || [];

  return (
    <Panel
      kicker="Static · similarity"
      title="Binary Similarity & Fuzzy Hash Matching"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {matches.length} matching sample{matches.length === 1 ? "" : "s"}
        </span>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-3 text-xs">
          {data?.target_imphash && (
            <div className="rounded border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[11px]">
              <span className="text-text-faint">Target imphash: </span>
              <span className="text-accent font-bold">{data.target_imphash}</span>
            </div>
          )}
          {data?.target_fuzzy_hash && (
            <div className="rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] truncate max-w-md">
              <span className="text-text-faint">Target CTPH: </span>
              <span className="text-text-muted">{data.target_fuzzy_hash}</span>
            </div>
          )}
        </div>

        {matches.length === 0 ? (
          <p className="text-xs text-text-muted py-2">
            No related binary variants detected in the vault above the 20% similarity threshold.
          </p>
        ) : (
          <div className="space-y-2">
            {matches.map((m: any) => (
              <div key={m.sample_id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border-subtle bg-bg-base/60 p-3 hover:border-accent/40">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Link
                      to={`/samples/${m.sample_id}`}
                      className="font-mono text-xs font-semibold text-text-primary hover:text-accent truncate"
                    >
                      {m.original_name}
                    </Link>
                    {m.imphash_match && (
                      <span className="rounded bg-accent/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-accent">
                        IMPHASH MATCH
                      </span>
                    )}
                  </div>
                  <p className="font-mono text-[10px] text-text-faint truncate">
                    SHA256: {m.sha256}
                  </p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <span className="font-mono text-xs font-bold text-accent">{m.similarity}%</span>
                    <span className="block font-mono text-[10px] text-text-faint">similarity</span>
                  </div>
                  <div className="h-1.5 w-20 overflow-hidden rounded-full bg-bg-elevated">
                    <div
                      className="h-full rounded-full bg-accent"
                      style={{ width: `${m.similarity}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}

/* ── Sandbox detonation (roadmap 3.3) ───────────────────────────────────── */

const SANDBOX_PLATFORMS: { value: Platform | ""; label: string }[] = [
  { value: "", label: "Use sample OS" },
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
  { value: "macos", label: "macOS" },
];

function SandboxDetonation({ sample }: { sample: { sample_id: string; original_name: string; detected_platform: string } }) {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState("auto");
  const [platform, setPlatform] = useState<Platform | "">("");
  const [task, setTask] = useState<SandboxTask | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const mounted = useRef(true);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: providers } = useQuery({
    queryKey: ["sandbox", "providers"],
    queryFn: getSandboxProviders,
  });

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, []);

  const poll = async (taskId: string, attempt = 0) => {
    if (!mounted.current || attempt >= 120) {
      if (mounted.current) setPolling(false);
      return;
    }
    try {
      const t = await getSandboxTask(taskId);
      if (!mounted.current) return;
      setTask(t);
      if (t.status === "completed" || t.status === "error") {
        setPolling(false);
        void queryClient.invalidateQueries({ queryKey: ["runs", "q", sample.original_name] });
        return;
      }
    } catch {
      /* transient poll failure — keep trying */
    }
    pollRef.current = setTimeout(() => void poll(taskId, attempt + 1), 2500);
  };

  const detonate = async () => {
    setError(null);
    setTask(null);
    try {
      const t = await sandboxDetonate({
        sample_id: sample.sample_id,
        provider,
        platform: platform || undefined,
      });
      if (!mounted.current) return;
      setTask(t);
      if (t.status === "submitted" || t.status === "running") {
        setPolling(true);
        void poll(t.task_id);
      } else {
        void queryClient.invalidateQueries({ queryKey: ["runs", "q", sample.original_name] });
      }
    } catch (e) {
      if (mounted.current) setError(e instanceof Error ? e.message : "Detonation failed");
    }
  };

  const providerName = (id: string) => providers?.providers.find((p) => p.id === id)?.name ?? id;
  const isBusy = polling || task?.status === "submitted" || task?.status === "running";

  return (
    <Panel
      kicker="Sandbox · roadmap"
      title="Detonate in an external sandbox"
      className="mt-6"
      right={
        providers ? (
          <span
            className={`inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide ${
              providers.mode === "live" ? "text-risk-clean" : "text-text-faint"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                providers.mode === "live" ? "bg-risk-clean" : "bg-text-faint"
              }`}
              aria-hidden
            />
            {providers.mode === "live"
              ? `live · ${providerName(providers.active)}`
              : "roadmap · no provider configured"}
          </span>
        ) : undefined
      }
    >
      <p className="mb-4 max-w-2xl text-sm text-text-muted">
        Push the sample to an external cloud analysis provider and stream the report back
        through the detection pipeline as a normal run.
      </p>

      {providers && providers.mode !== "live" && (
        <div className="mb-4 rounded-xl border border-accent/30 bg-accent/5 p-4 font-mono text-xs text-text-muted">
          <p className="font-semibold text-text-primary flex items-center gap-1.5">
            <Icon name="box" size={14} className="text-accent" />
            Local Isolated Sandbox Active
          </p>
          <p className="mt-1 text-[11px] text-text-faint">
            Detonating runs directly in OutPost's local isolated subprocess sandbox with live process tracing, stdout/stderr capture, and detection rule evaluation. To optionally forward samples to external cloud analysis providers, configure API keys in{" "}
            <Link to="/settings" className="text-accent underline hover:text-accent-hover">
              Settings
            </Link>
            .
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <button
          onClick={() => setProvider("auto")}
          disabled={isBusy}
          className={`press rounded border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
            provider === "auto"
              ? "border-accent/60 bg-accent/10 text-accent"
              : "border-border-subtle text-text-muted hover:border-accent/40 hover:text-accent"
          }`}
        >
          auto
        </button>
        {providers?.providers.map((p) => (
          <button
            key={p.id}
            onClick={() => setProvider(p.id)}
            disabled={isBusy}
            className={`press inline-flex items-center gap-1.5 rounded border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
              provider === p.id
                ? "border-accent/60 bg-accent/10 text-accent"
                : "border-border-subtle text-text-muted hover:border-accent/40 hover:text-accent"
            }`}
            title={p.configured ? `Live detonation via ${p.name}` : `${p.name} needs an API key — use demo instead`}
          >
            {p.id === "demo" ? <Icon name="terminal" size={10} /> : <Icon name="box" size={10} />}
            {p.id}
            <span
              className={`rounded px-1 py-px text-[9px] uppercase tracking-wide ${
                p.configured ? "bg-risk-clean/15 text-risk-clean" : "bg-bg-elevated/60 text-text-faint"
              }`}
            >
              {p.configured ? "live" : "off"}
            </span>
          </button>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 font-mono text-[11px] text-text-muted">
          <Icon name="linux" size={11} className="text-text-faint" />
          Detonation OS
          <select
            value={platform}
            onChange={(e) => setPlatform(e.target.value as Platform | "")}
            disabled={isBusy}
            className="rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
            aria-label="Detonation OS"
          >
            {SANDBOX_PLATFORMS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.value === "" ? `${o.label} (${sample.detected_platform})` : o.label}
              </option>
            ))}
          </select>
        </label>
        <button
          onClick={() => void detonate()}
          disabled={isBusy}
          className="press inline-flex items-center gap-1.5 rounded border border-accent/60 bg-accent/10 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/20 disabled:cursor-default disabled:opacity-50"
        >
          <Icon name={isBusy ? "refresh" : "play"} size={12} className={isBusy ? "animate-spin" : undefined} />
          {isBusy ? "detonating…" : "detonate"}
        </button>
      </div>

      {error && <p className="mb-3 font-mono text-[11px] text-risk-malicious">{error}</p>}

      {task && (
        <div className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span
              className={`font-mono text-[10px] uppercase tracking-wide ${
                task.status === "completed"
                  ? "text-risk-clean"
                  : task.status === "error"
                    ? "text-risk-malicious"
                    : "text-accent"
              }`}
            >
              {task.status === "completed" ? "● completed" : task.status === "error" ? "● error" : `● ${task.status}`}
            </span>
            <span className="font-mono text-[10px] text-text-faint">
              {providerName(task.provider)} · {task.platform} · {task.task_id}
            </span>
          </div>
          {task.status === "completed" ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-xs text-text-primary">
                {task.events} events · {task.alerts} alerts · risk {task.risk_score}
              </span>
              <Link
                to={`/runs/${task.run_id}`}
                className="press inline-flex items-center gap-1 font-mono text-[11px] text-accent transition-colors hover:underline"
              >
                open run
                <Icon name="arrowRight" size={11} />
              </Link>
            </div>
          ) : task.status === "error" ? (
            <p className="font-mono text-[11px] text-risk-malicious">{task.error}</p>
          ) : (
            <p className="font-mono text-[11px] text-text-muted">Waiting for the sandbox report…</p>
          )}
        </div>
      )}
    </Panel>
  );
}

function ExploitMitigationsCard({ pe }: { pe?: PeMetadata | null }) {
  if (!pe) return null;
  const mitigations = pe.mitigations || [];
  const checks = [
    {
      name: "DEP / NX",
      desc: "Data Execution Prevention disables execution in non-code memory pages",
      active: mitigations.some((m) => m.toLowerCase().includes("dep") || m.toLowerCase().includes("nx")),
    },
    {
      name: "ASLR / Dynamic Base",
      desc: "Address Space Layout Randomization randomizes memory layout",
      active: mitigations.some((m) => m.toLowerCase().includes("aslr")),
    },
    {
      name: "High Entropy VA / 64-bit",
      desc: "64-bit high entropy virtual address layout support",
      active: mitigations.some((m) => m.toLowerCase().includes("high entropy") || m.toLowerCase().includes("64-bit")),
    },
    {
      name: "Control Flow Guard (CFG)",
      desc: "Validates indirect call targets against ROP/JOP hijacking",
      active: mitigations.some((m) => m.toLowerCase().includes("cfg") || m.toLowerCase().includes("control flow")),
    },
    {
      name: "SafeSEH / SEH",
      desc: "Structured Exception Handling overwrite mitigation",
      active: mitigations.some((m) => m.toLowerCase().includes("seh")),
    },
    {
      name: "Authenticode Signature",
      desc: "Digitally signed with cryptographic certificate",
      active: Boolean(pe.authenticode?.signed),
    },
  ];

  return (
    <div className="space-y-2 border-t border-border-subtle pt-3">
      <div className="flex items-center justify-between font-mono text-[10px] uppercase text-text-faint">
        <span>Exploit Mitigations:</span>
        <span>
          {checks.filter((c) => c.active).length} / {checks.length} Enforced
        </span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {checks.map((chk) => (
          <div
            key={chk.name}
            className={`flex items-start gap-2 rounded-lg border p-2 font-mono text-[11px] ${
              chk.active
                ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"
                : "border-border-subtle/60 bg-bg-base/40 text-text-muted"
            }`}
          >
            <span className={`mt-0.5 shrink-0 ${chk.active ? "text-emerald-400 font-bold" : "text-text-faint"}`}>
              <Icon name={chk.active ? "check" : "x"} size={12} />
            </span>
            <div className="space-y-0.5 min-w-0">
              <span className={`block font-bold truncate ${chk.active ? "text-emerald-300" : "text-text-muted"}`}>
                {chk.name}
              </span>
              <span className="block text-[9px] text-text-faint leading-tight line-clamp-1">{chk.desc}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function PeElfTable({ st }: { st: SampleStatic }) {
  const pe = st.pe;
  const elf = st.elf;

  return (
    <div className="space-y-4 font-mono">
      {pe && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone="accent" dot>
              {pe.machine} · {pe.bits ?? "?"}-bit
            </Chip>
            {pe.subsystem && (
              <span className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 text-[10px] text-text-primary">
                Subsystem: {pe.subsystem}
              </span>
            )}
            {pe.image_base && (
              <span className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 text-[10px] text-text-primary">
                Base: {pe.image_base}
              </span>
            )}
            {pe.entry_point_rva != null && (
              <span className="text-[11px] text-text-muted">entry RVA 0x{Number(pe.entry_point_rva).toString(16)}</span>
            )}
            {pe.imphash && (
              <span className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent">
                imphash: {pe.imphash}
              </span>
            )}
            {pe.authenticode && (
              <span
                className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                  pe.authenticode.signed
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    : "border-border-subtle bg-bg-elevated/40 text-text-faint"
                }`}
              >
                {pe.authenticode.signed
                  ? `Authenticode Signed (${pe.authenticode.cert_size ?? 0} B)`
                  : "Unsigned Binary"}
              </span>
            )}
            {pe.rich_header?.present && (
              <span
                className="rounded border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 text-[10px] text-purple-300"
                title={`XOR Key ${pe.rich_header.xor_key ?? "N/A"} · ${pe.rich_header.records_count ?? 0} compiler entries`}
              >
                Rich Hash: {pe.rich_header.hash ? `${pe.rich_header.hash.slice(0, 10)}…` : "N/A"}
              </span>
            )}
            <span className="text-[10px] text-text-faint">
              {pe.imports.length} import DLL{pe.imports.length === 1 ? "" : "s"}
            </span>
          </div>

          <ExploitMitigationsCard pe={pe} />

          {pe.sections.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/60">
              <table className="w-full min-w-[540px] text-left text-xs">
                <thead className="border-b border-border-subtle bg-bg-surface/80">
                  <tr className="text-[10px] uppercase tracking-wide text-text-faint">
                    <th className="px-3 py-2 font-normal">Section</th>
                    <th className="px-3 py-2 text-right font-normal">Virtual</th>
                    <th className="px-3 py-2 text-right font-normal">Raw</th>
                    <th className="px-3 py-2 text-center font-normal">Delta</th>
                    <th className="px-3 py-2 font-normal">Entropy</th>
                    <th className="px-3 py-2 font-normal">Perms</th>
                    <th className="px-3 py-2 font-normal">Flags</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {pe.sections.map((s) => {
                    const delta = s.raw_size > 0 ? Math.round(((s.virtual_size - s.raw_size) / s.raw_size) * 100) : 0;
                    const isPackedDelta = delta > 40;
                    const entropyVal = s.entropy ?? 0;
                    const isHighEntropy = entropyVal > 7.0;
                    const isRwX = Boolean(s.is_rwx || s.permissions?.includes("RWX"));

                    return (
                      <tr key={s.name} className="transition-colors hover:bg-bg-elevated/40">
                        <td className="px-3 py-2 font-bold text-text-primary">{s.name || "(null)"}</td>
                        <td className="px-3 py-2 text-right text-text-muted">0x{(s.virtual_size ?? 0).toString(16)}</td>
                        <td className="px-3 py-2 text-right text-text-muted">0x{(s.raw_size ?? 0).toString(16)}</td>
                        <td className="px-3 py-2 text-center">
                          {isPackedDelta ? (
                            <span
                              className="rounded bg-amber-500/15 px-1.5 py-0.2 text-[9px] font-bold text-amber-400"
                              title="Virtual memory exceeds raw disk size — unpacked expansion"
                            >
                              +{delta}%
                            </span>
                          ) : (
                            <span className="text-[10px] text-text-faint">{delta >= 0 ? `+${delta}%` : `${delta}%`}</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {s.entropy !== undefined ? (
                            <div className="flex items-center gap-1.5">
                              <span
                                className={`text-[10px] font-bold ${
                                  isHighEntropy ? "text-rose-400" : entropyVal > 6.0 ? "text-amber-400" : "text-emerald-400"
                                }`}
                              >
                                {s.entropy.toFixed(2)}
                              </span>
                              <div className="h-1.5 w-12 overflow-hidden rounded-full bg-bg-elevated">
                                <div
                                  className={`h-full rounded-full ${
                                    isHighEntropy ? "bg-rose-500" : entropyVal > 6.0 ? "bg-amber-400" : "bg-emerald-400"
                                  }`}
                                  style={{ width: `${Math.min(100, (s.entropy / 8.0) * 100)}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-[10px] text-text-faint">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {isRwX ? (
                            <span
                              className="inline-flex items-center gap-1 rounded border border-rose-500/50 bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-400"
                              title="Read, Write, and Execute permissions — self-modifying code or shellcode injection danger"
                            >
                              <span>RWX</span>
                              <Icon name="alert" size={10} />
                            </span>
                          ) : s.permissions ? (
                            <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[10px] font-bold text-text-muted">
                              {s.permissions}
                            </span>
                          ) : (
                            <span className="text-[10px] text-text-faint">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <span className="block max-w-[140px] truncate text-[10px] text-text-faint" title={s.flags.join(" · ")}>
                            {s.flags.join(" · ") || "—"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {pe.imports.length > 0 && (
            <div className="space-y-1.5 pt-1">
              <span className="text-[10px] uppercase text-text-faint">Linked DLL Imports ({pe.imports.length})</span>
              <div className="flex flex-wrap gap-1.5">
                {pe.imports.map((dll) => (
                  <span
                    key={dll}
                    className="cursor-default rounded border border-accent/40 bg-accent/5 px-2 py-0.5 text-[10px] font-medium text-accent transition-colors hover:bg-accent/15"
                  >
                    {dll}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {elf && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone="clean" dot>
              {elf.machine} · ELF{elf.class} · {elf.type}
            </Chip>
            <span className="text-[11px] text-text-muted">
              entry {elf.entry_point != null ? (String(elf.entry_point).startsWith("0x") ? String(elf.entry_point) : `0x${Number(elf.entry_point).toString(16)}`) : "0x0"}
            </span>
            <span className="text-[10px] text-text-faint">{(elf.sections || []).length} sections · {elf.endian || "little"}-endian</span>
          </div>

          {(elf.sections || []).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {(elf.sections || []).slice(0, 40).map((s) => (
                <span
                  key={`${s.name}-${s.type}`}
                  className="rounded border border-border-subtle bg-bg-elevated/40 px-2 py-0.5 text-[10px] text-text-muted"
                  title={`type ${s.type} · ${s.size} bytes`}
                >
                  {s.name || "(anon)"}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function SampleDetailPage() {
  const { sampleId = "" } = useParams();
  const [dossierTab, setDossierTab] = useState<"static" | "dynamic" | "history" | "similarity">("static");

  const { data: sample, isLoading, isError } = useQuery({
    queryKey: ["sample", sampleId],
    queryFn: () => getSample(sampleId),
  });

  const { data: st, isLoading: isAnalyzing, isError: isStaticError, refetch: refetchStatic } = useQuery({
    queryKey: ["sample", "static", sampleId],
    queryFn: () => getSampleStatic(sampleId),
    retry: false,
    enabled: Boolean(sampleId),
  });

  // Runs that detonated this binary — filtered by its sample name.
  const { data: runs = [] } = useQuery({
    queryKey: ["runs", "q", sample?.original_name ?? ""],
    queryFn: () => getRuns({ q: sample?.original_name ?? "" }),
    enabled: sample !== undefined,
  });

  if (isLoading) return <p className="p-8 text-sm text-text-muted font-mono">Loading sample…</p>;
  if (isError || !sample) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-12">
        <Panel kicker="Malware Analysis Vault · 404" title="Sample not found">
          <p className="text-sm text-text-muted">
            Couldn't find sample <span className="font-mono text-text-primary">{sampleId}</span> in the vault.
          </p>
          <div className="mt-4">
            <Link to="/samples" className="press inline-flex items-center gap-1.5 font-mono text-xs text-accent underline">
              <Icon name="chevronLeft" size={12} />
              Return to Malware Analysis Vault
            </Link>
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1440px] px-6 py-6 lg:px-8 font-sans">
      {/* Redesigned Compact Technical Header */}
      <SampleWorkspaceHeader
        sample={sample}
        st={st}
        isAnalyzing={isAnalyzing}
        onRunStatic={() => void refetchStatic()}
        onSwitchToDynamic={() => setDossierTab("dynamic")}
      />

      {/* Persistent Technical Identification Strip */}
      <SampleIdentificationStrip sample={sample} st={st} />

      {/* Analysis Workspace Mode Switcher */}
      <div className="mt-8 rounded-2xl border border-border-subtle bg-bg-surface/80 p-2 shadow-sm font-sans">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <button
            onClick={() => setDossierTab("static")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "static"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-xs"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-semibold">
                <Icon name="box" size={14} />
                Mode 1: Static Triage
              </span>
              <span className="rounded bg-emerald-500/20 px-1.5 py-0.2 text-[9px] font-semibold text-emerald-400 uppercase font-mono">
                Safe · No Exec
              </span>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Raw bytes inspection, Shannon entropy, YARA rules &amp; VirusTotal pivots.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("dynamic")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "dynamic"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-xs"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-semibold">
                <Icon name="play" size={14} />
                Mode 2: Dynamic Sandbox
              </span>
              <span className="rounded bg-accent/20 px-1.5 py-0.2 text-[9px] font-semibold text-accent uppercase font-mono">
                Double-Layer
              </span>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Layer 1 zero-execution behavioral forecast followed by Layer 2 live sandbox execution &amp; verification matrix.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("history")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "history"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-xs"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-semibold">
                <Icon name="activity" size={14} />
                Detonation Runs ({runs.length})
              </span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] font-semibold text-text-faint uppercase font-mono">
                History
              </span>
            </div>
            <p className="text-xs text-text-muted mt-0.5">
              Historical sandbox runs, risk scores, and protocol network forensics.
            </p>
          </button>

          <button
            onClick={() => setDossierTab("similarity")}
            className={`flex flex-col items-start gap-1 rounded-xl p-3 text-left transition ${
              dossierTab === "similarity"
                ? "border border-accent/60 bg-accent/15 text-accent shadow-xs"
                : "border border-transparent bg-bg-base/40 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            }`}
          >
            <div className="flex w-full items-center justify-between">
              <span className="flex items-center gap-1.5 text-xs font-semibold">
                <Icon name="copy" size={14} />
                Binary Similarity
              </span>
              <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] font-bold text-text-faint uppercase">
                CTPH
              </span>
            </div>
            <p className="text-[11px] text-text-muted">
              Fuzzy hash comparison across vault samples for shared code reuse.
            </p>
          </button>
        </div>
      </div>

      {dossierTab === "static" && (
        <StaticAnalysis
          sample={sample}
          runs={runs}
          st={st}
          isLoading={isAnalyzing}
          isError={isStaticError}
          unavailable={st !== undefined && st.available === false}
        />
      )}

      {dossierTab === "dynamic" && (
        <div className="mt-6 space-y-6">
          <LiveDynamicSandboxCockpit sample={sample} />
          <details className="rounded-xl border border-border-subtle bg-bg-surface/60 p-4 transition">
            <summary className="cursor-pointer font-mono text-xs text-text-muted hover:text-accent select-none">
              ▸ Advanced Sandbox Task Dispatcher (Asynchronous Background Jobs)
            </summary>
            <div className="mt-4">
              <SandboxDetonation sample={sample} />
            </div>
          </details>
        </div>
      )}

      {dossierTab === "similarity" && (
        <div className="mt-6">
          <SimilarSamplesPanel sampleId={sample.sample_id} />
        </div>
      )}

      {dossierTab === "history" && (
        <Panel kicker="Detonations" title={`Runs of ${sample.original_name}`} className="mt-6" pad={false}>
          {runs.length === 0 ? (
            <p className="p-6 text-sm text-text-muted">This sample hasn't been detonated yet — click "Detonate in sandbox" to analyze live.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="border-b border-border-subtle">
                  <tr className="text-xs font-semibold text-text-muted">
                    <th className="px-4 py-2.5">Run</th>
                    <th className="px-4 py-2.5">Started</th>
                    <th className="px-4 py-2.5">Alerts</th>
                    <th className="px-4 py-2.5">Severity</th>
                    <th className="px-4 py-2.5 text-right">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((r: RunSummary) => (
                    <tr key={r.run_id} className="border-b border-border-subtle/50 transition-colors hover:bg-bg-elevated/30">
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/runs/${r.run_id}`}
                          className="press font-mono text-xs text-accent transition-colors hover:underline"
                        >
                          {r.run_id ? r.run_id.slice(0, 12) : "unknown"}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">
                        {r.started_at ? r.started_at.slice(0, 19).replace("T", " ") : "—"}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">{r.alert_count}</td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`font-mono text-[10px] ${
                            r.highest_severity === "malicious"
                              ? "text-risk-malicious"
                              : r.highest_severity === "suspicious"
                                ? "text-risk-suspicious"
                                : "text-risk-clean"
                          }`}
                        >
                          ● {r.highest_severity ?? "clean"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-[11px] text-text-primary">{r.risk_score}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {runs && runs.length > 0 && (
        <Panel kicker="Protocol Forensics" title="Aggregated Network & C2 Conversation Analysis">
          <NetworkProtocolInspector sampleId={sampleId} />
        </Panel>
      )}
    </div>
  );
}

