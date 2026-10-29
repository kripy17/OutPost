import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { getVirusTotalIocUrl, iocTotal } from "../../routes/samplesHelpers";
import { watchlistAdd } from "../../lib/api";
import type { SampleRow, SampleStatic } from "../../types";

interface StaticOverviewTabProps {
  sample: SampleRow;
  st?: SampleStatic;
  onNavigateTab: (tab: "structure" | "imports" | "strings" | "bytes" | "history") => void;
}

export function StaticOverviewTab({ sample, st, onNavigateTab }: StaticOverviewTabProps) {
  const [watchlisted, setWatchlisted] = useState<Set<string>>(new Set());
  const [watchlistError, setWatchlistError] = useState<string | null>(null);

  const handleWatchlist = async (val: string) => {
    try {
      await watchlistAdd(val, `from sample ${sample.sample_id}`);
      setWatchlisted((prev) => new Set(prev).add(val));
      setWatchlistError(null);
    } catch {
      setWatchlistError(`Failed to add ${val} to watchlist`);
    }
  };

  const riskScore = st?.static_risk_score ?? 0;
  const entropy = st?.entropy ?? 0;
  const isPacked = Boolean(st?.is_packed || entropy > 7.1);
  const totalIocs = st ? iocTotal(st.iocs) : 0;
  const yaraRules = sample.yara_rules || [];
  const capabilities = st?.capabilities || [];

  // Determine heuristic assessment verdict
  let verdictTitle = "No Indicators Found (Limited Static Scope)";
  let verdictBadge = "No Indicators";
  let verdictTone = "border-emerald-500/40 bg-emerald-500/10 text-emerald-400";
  if (yaraRules.length > 0 || riskScore >= 70) {
    verdictTitle = yaraRules.length > 0 ? "Signature Matched: Malicious Payload" : "Heuristic Assessment: High-Risk Malicious";
    verdictBadge = "Malicious";
    verdictTone = "border-rose-500/50 bg-rose-500/15 text-rose-400";
  } else if (riskScore >= 35 || isPacked) {
    verdictTitle = "Heuristic Assessment: Suspicious Binary";
    verdictBadge = "Suspicious";
    verdictTone = "border-amber-500/50 bg-amber-500/15 text-amber-400";
  }

  // Synthesize notable findings from genuine analyzer outputs
  interface NotableFinding {
    id: string;
    name: string;
    severity: "malicious" | "suspicious" | "info";
    source: string;
    observedValue: string;
    reason: string;
    targetTab: "structure" | "imports" | "strings" | "bytes" | "history";
  }

  const findings: NotableFinding[] = [];

  // 1. YARA signatures
  yaraRules.forEach((rule, idx) => {
    findings.push({
      id: `yara-${idx}`,
      name: `YARA Signature: ${rule}`,
      severity: "malicious",
      source: "YARA Engine",
      observedValue: rule,
      reason: "Matched byte pattern or import signature rule defined in OutPost ruleset.",
      targetTab: "strings",
    });
  });

  // 2. High Entropy / Packing
  if (isPacked || entropy > 7.0) {
    findings.push({
      id: "finding-entropy",
      name: "High Shannon Entropy / Packed Code",
      severity: entropy > 7.4 ? "malicious" : "suspicious",
      source: "Entropy Calculator",
      observedValue: `${entropy.toFixed(2)} / 8.0`,
      reason: "High byte randomness indicates encrypted shellcode or UPX packing obfuscation.",
      targetTab: "structure",
    });
  }

  // 3. PE RWX section
  if (st?.pe?.sections) {
    st.pe.sections.forEach((sec) => {
      if (sec.is_rwx || sec.permissions?.includes("RWX")) {
        findings.push({
          id: `sec-rwx-${sec.name}`,
          name: `RWX Section: ${sec.name}`,
          severity: "malicious",
          source: "PE Header Parser",
          observedValue: `${sec.name} (RWX)`,
          reason: "Section has concurrent Read, Write, and Execute permissions — typical of self-modifying code or shellcode injection.",
          targetTab: "structure",
        });
      }
    });
  }

  // 4. Detected capabilities
  capabilities.forEach((cap, cidx) => {
    findings.push({
      id: `cap-${cidx}`,
      name: `Capability: ${cap.category}`,
      severity: cap.confidence === "high" ? "suspicious" : "info",
      source: cap.source || "Static Pattern Heuristics",
      observedValue: cap.matched.slice(0, 3).join(", "),
      reason: `Observed strings/imports indicative of ${cap.category.toLowerCase()}.`,
      targetTab: "imports",
    });
  });

  // 5. Extracted IOCs (if any)
  if (st?.iocs) {
    if (st.iocs.ips.length > 0) {
      findings.push({
        id: "finding-ioc-ip",
        name: "Embedded Hardcoded IP Address",
        severity: "suspicious",
        source: "String IOC Extractor",
        observedValue: st.iocs.ips.slice(0, 2).join(", "),
        reason: "Candidate IPv4 endpoints found in binary strings. May indicate C2 command endpoints.",
        targetTab: "strings",
      });
    }
    if (st.iocs.urls.length > 0) {
      findings.push({
        id: "finding-ioc-url",
        name: "Embedded HTTP/HTTPS URL",
        severity: "suspicious",
        source: "String IOC Extractor",
        observedValue: st.iocs.urls[0],
        reason: "Candidate URL extracted from strings table.",
        targetTab: "strings",
      });
    }
  }

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* SECTION 1: Analysis Assessment */}
      <Panel kicker="Static Threat Triage" title="Analysis Assessment &amp; Threat Inferences">
        <div className="space-y-4">
          {/* Main Assessment Header Card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 rounded-xl border border-border-subtle bg-bg-base/70 p-4">
            <div className="md:col-span-2 space-y-2">
              <div className="flex items-center gap-2">
                <span className={`rounded border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${verdictTone}`}>
                  {verdictBadge}
                </span>
                <span className="text-[11px] text-text-faint">
                  Static Heuristic Assessment (Zero Execution Risk)
                </span>
              </div>
              <h2 className="text-base font-bold text-text-primary">{verdictTitle}</h2>
              <p className="text-xs text-text-muted leading-relaxed font-sans">
                Analyzed static characteristics of <span className="font-semibold text-text-primary">{sample.original_name}</span>. Assessments represent heuristic inferences derived from static byte patterns, PE/ELF structure, and string extraction, not dynamic runtime confirmation.
              </p>
            </div>

            {/* Static Risk Gauge */}
            <div className="flex flex-col justify-center items-start md:items-end rounded-lg bg-bg-surface/60 p-3 border border-border-subtle/60">
              <span className="text-[10px] uppercase tracking-wider text-text-faint">Static Risk Score</span>
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
              <span className="text-[9px] text-text-faint mt-1">
                Scale: 0-34 Clean · 35-69 Suspicious · 70-100 Malicious
              </span>
            </div>
          </div>

          {/* 6 Structured Technical Metrics Aligned in Rows */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 text-[11px]">
            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">Shannon Entropy</span>
              <div className="flex items-center gap-1 font-bold">
                <span className={entropy > 7.0 ? "text-rose-400" : entropy > 6.0 ? "text-amber-400" : "text-emerald-400"}>
                  {entropy.toFixed(2)}
                </span>
                <span className="text-text-faint text-[9px]">/ 8.0</span>
              </div>
              <div className="text-[9px] text-text-muted">{entropy > 7.0 ? "High Randomness" : "Standard Density"}</div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">Packing / Obfuscation</span>
              <div className="font-bold">
                {isPacked ? (
                  <span className="text-rose-400">Suspected Packed</span>
                ) : (
                  <span className="text-emerald-400">Native / Unpacked</span>
                )}
              </div>
              <div className="text-[9px] text-text-muted">{isPacked ? "UPX / Custom Crypt" : "Linear PE Sections"}</div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">YARA Matches</span>
              <div className="font-bold text-text-primary">
                {yaraRules.length} signature{yaraRules.length === 1 ? "" : "s"}
              </div>
              <div className="text-[9px] text-text-muted">{yaraRules.length > 0 ? "Rules matched" : "Zero rule hits"}</div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">Extracted IOCs</span>
              <div className="font-bold text-text-primary">{totalIocs} candidate IOCs</div>
              <div className="text-[9px] text-text-muted">IPs, URLs, Domains</div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">Capabilities</span>
              <div className="font-bold text-text-primary">{capabilities.length} detected</div>
              <div className="text-[9px] text-text-muted">MITRE tactic groups</div>
            </div>

            <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
              <span className="text-[9px] uppercase text-text-faint block">Static Engine</span>
              <div className="font-bold text-text-primary">OutPost Static v2.4</div>
              <div className="text-[9px] text-text-muted">Bounds Checked</div>
            </div>
          </div>

          {/* Risk Factors Explanation */}
          {st?.risk_factors && st.risk_factors.length > 0 && (
            <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs font-bold text-text-primary">
                <span className="flex items-center gap-1.5">
                  <Icon name="shield" size={13} className="text-amber-400" />
                  Classification Rationale &amp; Contributing Risk Factors ({st.risk_factors.length})
                </span>
                <span className="text-[10px] uppercase text-text-faint">Heuristic Scoring Factors</span>
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

      {/* SECTION: Decoded Malware Family Configurations */}
      {st?.decoded_configs && st.decoded_configs.length > 0 && (
        <Panel kicker="Extracted C2 Profile" title={`Decoded Malware Family Configuration (${st.decoded_configs.length})`}>
          <div className="space-y-3 font-mono">
            {st.decoded_configs.map((cfg, idx) => (
              <div key={idx} className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rose-500/20 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-rose-500/30 border border-rose-500/50 px-2 py-0.5 text-xs font-bold text-rose-300">
                      {cfg.family} {cfg.version || ""}
                    </span>
                    <span className="text-[11px] text-text-faint">In-Memory Decrypted RAT/Beacon Profile</span>
                  </div>
                  <span className="rounded bg-bg-surface px-2 py-0.5 text-[10px] text-rose-400 font-bold border border-border-subtle uppercase">
                    Confidence: {cfg.confidence || "High"}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                  <div>
                    <span className="text-[10px] uppercase text-text-faint block">Primary C2 Endpoint</span>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className="font-bold text-rose-300 break-all">{cfg.c2_endpoint || cfg.c2_server || "N/A"}</span>
                      {(cfg.c2_endpoint || cfg.c2_server) && (
                        <button
                          onClick={() => handleWatchlist(cfg.c2_endpoint || cfg.c2_server!)}
                          className={`rounded px-1.5 py-0.5 text-[10px] border transition ${
                            watchlisted.has(cfg.c2_endpoint || cfg.c2_server!)
                              ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                              : "bg-bg-surface text-accent border-border-subtle hover:bg-bg-elevated"
                          }`}
                          title="Add to Watchlist"
                        >
                          {watchlisted.has(cfg.c2_endpoint || cfg.c2_server!) ? "Watchlisted" : "+ Watchlist"}
                        </button>
                      )}
                    </div>
                  </div>
                  {cfg.port && (
                    <div>
                      <span className="text-[10px] uppercase text-text-faint block">Port</span>
                      <span className="font-bold text-text-primary">{cfg.port}</span>
                    </div>
                  )}
                  {cfg.mutex && (
                    <div>
                      <span className="text-[10px] uppercase text-text-faint block">Bot Mutex</span>
                      <span className="font-bold text-amber-300">{cfg.mutex}</span>
                    </div>
                  )}
                  {cfg.encryption && (
                    <div>
                      <span className="text-[10px] uppercase text-text-faint block">Encryption / Cipher</span>
                      <span className="font-bold text-cyan-300">{cfg.encryption}</span>
                    </div>
                  )}
                  {cfg.campaign_id && (
                    <div>
                      <span className="text-[10px] uppercase text-text-faint block">Campaign / Build</span>
                      <span className="font-bold text-text-primary">{cfg.campaign_id}</span>
                    </div>
                  )}
                  {cfg.pastebin_fallback && (
                    <div className="col-span-full">
                      <span className="text-[10px] uppercase text-text-faint block">Pastebin C2 Fallback</span>
                      <a href={cfg.pastebin_fallback} target="_blank" rel="noopener noreferrer" className="font-bold text-cyan-400 hover:underline">
                        {cfg.pastebin_fallback}
                      </a>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* SECTION: YARA Signatures & Exact Byte Matches */}
      {st?.yara?.matches && st.yara.matches.length > 0 && (
        <Panel kicker="Signature Matching" title={`YARA Rule Detections (${st.yara.matches.length})`}>
          <div className="space-y-3 font-mono">
            {st.yara.matches.map((m, idx) => (
              <div key={idx} className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-rose-400">{m.rule}</span>
                    {m.tags && m.tags.map((t, tidx) => (
                      <span key={tidx} className="rounded bg-bg-surface px-1.5 py-0.5 text-[9px] text-text-faint border border-border-subtle uppercase">
                        {t}
                      </span>
                    ))}
                  </div>
                  <span className="text-[10px] text-text-faint">Matched Strings: {m.strings?.length || 0}</span>
                </div>
                {m.meta?.description && (
                  <p className="text-[11px] text-text-muted">{m.meta.description}</p>
                )}
                {m.strings && m.strings.length > 0 && (
                  <div className="overflow-x-auto mt-2">
                    <table className="w-full text-left text-[11px] border-collapse bg-bg-surface/50 rounded-lg">
                      <thead>
                        <tr className="border-b border-border-subtle text-[9px] uppercase text-text-faint">
                          <th className="py-1 px-2.5">Identifier</th>
                          <th className="py-1 px-2.5">Offset</th>
                          <th className="py-1 px-2.5">Matched Preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {m.strings.slice(0, 5).map((s, sidx) => (
                          <tr key={sidx} className="border-b border-border-subtle/40">
                            <td className="py-1 px-2.5 font-bold text-text-muted">{s.identifier}</td>
                            <td className="py-1 px-2.5 text-cyan-400">{s.offset_hex}</td>
                            <td className="py-1 px-2.5 font-mono text-text-primary break-all">{s.matched_bytes}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* SECTION: Evidence-Backed Assessment Factors */}
      {st?.assessment_factors && st.assessment_factors.length > 0 && (
        <Panel kicker="Factor Weights &amp; Provenance" title={`Evidence Factor Breakdown (${st.assessment_factors.length})`}>
          <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                  <th className="py-2 px-3">Assessment Factor</th>
                  <th className="py-2 px-3 w-20">Weight</th>
                  <th className="py-2 px-3 w-24">Signal</th>
                  <th className="py-2 px-3 w-24">Reliability</th>
                  <th className="py-2 px-3">Concrete Evidence Snippet</th>
                </tr>
              </thead>
              <tbody>
                {st.assessment_factors.map((af, afidx) => (
                  <tr key={afidx} className="border-b border-border-subtle/40 hover:bg-bg-elevated/20">
                    <td className="py-2 px-3 font-semibold text-text-primary">{af.factor}</td>
                    <td className="py-2 px-3 font-bold text-amber-400">+{af.weight}</td>
                    <td className="py-2 px-3 uppercase text-[10px] text-text-muted">{af.signal_type}</td>
                    <td className="py-2 px-3">
                      <span className="rounded bg-bg-surface px-1.5 py-0.5 text-[9px] text-cyan-300 border border-border-subtle uppercase">
                        {af.reliability}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-text-muted break-all text-[11px]">{af.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* SECTION: Archive Container Deep-Inspection */}
      {st?.archive && st.archive.is_archive && (
        <Panel kicker="Container Forensics" title={`Archive Container Inspection (${st.archive.format?.toUpperCase()})`}>
          <div className="space-y-3 font-mono">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-[11px]">
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                <span className="text-[9px] uppercase text-text-faint block">Total Members</span>
                <span className="font-bold text-text-primary">{st.archive.total_members}</span>
              </div>
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                <span className="text-[9px] uppercase text-text-faint block">Uncompressed Size</span>
                <span className="font-bold text-text-primary">{st.archive.total_uncompressed_bytes?.toLocaleString()} B</span>
              </div>
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                <span className="text-[9px] uppercase text-text-faint block">Compression Ratio</span>
                <span className="font-bold text-text-primary">{st.archive.max_compression_ratio}:1</span>
              </div>
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                <span className="text-[9px] uppercase text-text-faint block">Zip Bomb Guard</span>
                <span className={`font-bold ${st.archive.zip_bomb_suspected ? "text-rose-400" : "text-emerald-400"}`}>
                  {st.archive.zip_bomb_suspected ? "Suspicious Ratio" : "Safe / Verified"}
                </span>
              </div>
            </div>
            {st.archive.members && st.archive.members.length > 0 && (
              <div className="overflow-x-auto rounded-lg border border-border-subtle bg-bg-base/50">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                      <th className="py-2 px-3">Filename</th>
                      <th className="py-2 px-3">Format</th>
                      <th className="py-2 px-3">Compressed</th>
                      <th className="py-2 px-3">Uncompressed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {st.archive.members.slice(0, 10).map((m, midx) => (
                      <tr key={midx} className="border-b border-border-subtle/50 hover:bg-bg-elevated/30">
                        <td className="py-1.5 px-3 font-semibold text-text-primary">{m.filename}</td>
                        <td className="py-1.5 px-3 uppercase text-text-muted">{m.format}</td>
                        <td className="py-1.5 px-3 text-text-faint">{m.size_compressed} B</td>
                        <td className="py-1.5 px-3 text-text-faint">{m.size_uncompressed} B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* SECTION 2: Findings Requiring Inspection */}
      <Panel
        kicker="Investigation Focus"
        title={`Findings Requiring Inspection (${findings.length})`}
        right={
          <span className="text-[10px] text-text-faint font-mono">
            Click row to navigate directly to supporting technical evidence
          </span>
        }
      >
        {findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
            <Icon name="check" size={20} className="mx-auto text-emerald-400 mb-2" />
            <p className="font-semibold text-text-primary">No Suspicious Static Findings</p>
            <p className="text-[11px] text-text-muted mt-1">
              Static heuristics did not identify notable anomalies, suspicious imports, or signature triggers.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint tracking-wider">
                  <th className="py-2 px-3">Finding / Rule</th>
                  <th className="py-2 px-3 w-24">Severity</th>
                  <th className="py-2 px-3 w-32">Source</th>
                  <th className="py-2 px-3">Observed Value</th>
                  <th className="py-2 px-3">Reason / Context</th>
                  <th className="py-2 px-3 text-right w-24">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/50">
                {findings.map((f) => {
                  const isMal = f.severity === "malicious";
                  const isSusp = f.severity === "suspicious";
                  return (
                    <tr
                      key={f.id}
                      onClick={() => onNavigateTab(f.targetTab)}
                      className="cursor-pointer hover:bg-bg-elevated/40 transition-colors"
                    >
                      <td className="py-2 px-3 font-semibold text-text-primary">{f.name}</td>
                      <td className="py-2 px-3">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                            isMal
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : isSusp
                                ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                : "bg-bg-elevated text-text-muted"
                          }`}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-text-muted">{f.source}</td>
                      <td className="py-2 px-3 text-text-primary font-mono text-[11px] truncate max-w-[200px]" title={f.observedValue}>
                        {f.observedValue}
                      </td>
                      <td className="py-2 px-3 text-text-muted text-[11px] font-sans leading-tight">
                        {f.reason}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onNavigateTab(f.targetTab);
                          }}
                          className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-accent hover:border-accent"
                        >
                          <span>Go</span>
                          <Icon name="arrowRight" size={10} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* SECTION 3: File Facts */}
      <Panel kicker="Executable Metadata" title="File Facts &amp; Technical Architecture">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">File Format</span>
            <div className="font-bold text-text-primary">
              {st?.pe ? "Portable Executable (PE)" : st?.elf ? "Executable and Linkable Format (ELF)" : "Raw Binary Stream"}
            </div>
            <div className="text-[10px] text-text-muted">
              {st?.pe ? `${st.pe.machine} · ${st.pe.bits}-bit` : st?.elf ? `${st.elf.machine} · ${st.elf.class}-bit` : "Generic payload"}
            </div>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Entry Point &amp; Base</span>
            <div className="font-bold text-text-primary">
              {st?.pe?.entry_point_rva !== null && st?.pe?.entry_point_rva !== undefined
                ? `RVA 0x${st.pe.entry_point_rva.toString(16)}`
                : st?.elf?.entry_point
                  ? `0x${st.elf.entry_point.toString(16)}`
                  : "0x00000000"}
            </div>
            <div className="text-[10px] text-text-muted">
              Image Base: {st?.pe?.image_base || "0x400000"}
            </div>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Structural Counts</span>
            <div className="font-bold text-text-primary">
              {st?.pe ? `${st.pe.sections.length} Sections · ${st.pe.imports.length} Imports` : st?.elf ? `${st.elf.sections.length} Sections` : "N/A"}
            </div>
            <div className="text-[10px] text-text-muted">
              {st?.strings.length || 0} extracted strings
            </div>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
            <span className="text-[10px] uppercase text-text-faint block">Security Mitigations</span>
            <div className="font-bold text-text-primary">
              {st?.pe?.mitigations && st.pe.mitigations.length > 0 ? (
                <span className="text-emerald-400">{st.pe.mitigations.length} Active Mitigations</span>
              ) : (
                <span className="text-rose-400">0 Mitigations Enforced</span>
              )}
            </div>
            <div className="text-[10px] text-text-muted">
              {st?.pe?.authenticode?.signed ? "Authenticode Signed" : "Unsigned Binary"}
            </div>
          </div>
        </div>
      </Panel>

      {/* SECTION 4: Matched Signatures and Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* YARA Signatures Table */}
        <Panel kicker="Signatures" title={`Matched YARA Rules (${yaraRules.length})`}>
          {yaraRules.length === 0 ? (
            <p className="text-xs text-text-muted py-4">No bundled YARA rules matched this binary.</p>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/60">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                    <th className="py-2 px-3">Rule Name</th>
                    <th className="py-2 px-3 w-28">Source</th>
                    <th className="py-2 px-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {yaraRules.map((r) => (
                    <tr key={r} className="hover:bg-bg-elevated/40">
                      <td className="py-2 px-3 font-bold text-accent">{r}</td>
                      <td className="py-2 px-3 text-text-muted">OutPost Core Ruleset</td>
                      <td className="py-2 px-3 text-right">
                        <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-bold text-rose-400">
                          Matched
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* Candidate Indicators Table */}
        <Panel
          kicker="Indicators"
          title={`Candidate IOCs (${totalIocs})`}
          right={
            <span className="text-[10px] text-text-faint">
              Candidate indicators extracted from strings
            </span>
          }
        >
          {watchlistError && <p className="text-[11px] text-risk-malicious mb-2">{watchlistError}</p>}
          {totalIocs === 0 ? (
            <p className="text-xs text-text-muted py-4">No candidate IOCs extracted from binary.</p>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/60 max-h-64 overflow-y-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint sticky top-0">
                    <th className="py-2 px-3 w-16">Type</th>
                    <th className="py-2 px-3">Value</th>
                    <th className="py-2 px-3 text-right w-24">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/50">
                  {st &&
                    (
                      [
                        { key: "ips" as const, label: "IP" },
                        { key: "urls" as const, label: "URL" },
                        { key: "domains" as const, label: "Domain" },
                        { key: "hashes" as const, label: "Hash" },
                        { key: "emails" as const, label: "Email" },
                      ] as const
                    ).flatMap((group) =>
                      st.iocs[group.key].slice(0, 15).map((val) => (
                        <tr key={`${group.key}-${val}`} className="hover:bg-bg-elevated/40">
                          <td className="py-2 px-3 text-text-faint uppercase text-[10px] font-bold">
                            {group.label}
                          </td>
                          <td className="py-2 px-3 text-text-primary font-mono text-[11px] truncate max-w-[200px]" title={val}>
                            {val}
                          </td>
                          <td className="py-2 px-3 text-right">
                            <div className="inline-flex items-center gap-1.5">
                              <Link
                                to={`/search?q=${encodeURIComponent(val)}`}
                                title={`Search OutPost event history for ${val}`}
                                className="press inline-flex h-5 w-5 items-center justify-center rounded border border-border-subtle bg-bg-surface text-text-muted hover:border-accent hover:text-accent"
                              >
                                <Icon name="search" size={9} />
                              </Link>
                              <a
                                href={getVirusTotalIocUrl(group.key, val)}
                                target="_blank"
                                rel="noopener noreferrer"
                                title={`VirusTotal external threat intelligence lookup for ${val}`}
                                aria-label={`VirusTotal external threat intelligence lookup for ${val}`}
                                className="press inline-flex h-5 items-center gap-0.5 rounded border border-accent/40 bg-accent/10 px-1.5 font-mono text-[9px] font-semibold text-accent hover:bg-accent/20"
                              >
                                <span>VT</span>
                                <Icon name="external" size={8} />
                              </a>
                              <button
                                onClick={() => void handleWatchlist(val)}
                                disabled={watchlisted.has(val)}
                                title={watchlisted.has(val) ? "On watchlist" : "Add to watchlist"}
                                className="press inline-flex h-5 w-5 items-center justify-center rounded border border-border-subtle bg-bg-surface text-text-faint hover:border-accent hover:text-accent disabled:text-risk-clean"
                              >
                                <Icon name={watchlisted.has(val) ? "check" : "plus"} size={9} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      )),
                    )}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
