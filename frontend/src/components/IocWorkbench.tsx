import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";
import { watchlistImport } from "../lib/api";

export type IndicatorType = "ip" | "domain" | "url" | "hash" | "email";

export interface ExtractedIndicator {
  raw: string;
  refanged: string;
  defanged: string;
  type: IndicatorType;
  subType?: string; // e.g. "sha256", "md5", "private_ip", "public_ip"
  isPrivate?: boolean;
}

// Defanging / Refanging Utilities
export function refangText(text: string): string {
  return text
    .replace(/\[:\/\/\]/gi, "://")
    .replace(/\[:\]\/\//gi, "://")
    .replace(/hxxps?:\/\//gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https://" : "http://"))
    .replace(/hxxps?/gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https" : "http"))
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[:\]|\{:\}/g, ":")
    .replace(/\[@\]|\(@\)|\{@\}/g, "@");
}

export function defangText(text: string): string {
  return text
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}

export function extractIndicators(inputText: string): ExtractedIndicator[] {
  if (!inputText.trim()) return [];

  // First refang the input so regexes can match standardized patterns
  const normalized = refangText(inputText);
  const results: ExtractedIndicator[] = [];
  const seen = new Set<string>();

  // 1. URLs
  const urlRegex = /https?:\/\/[^\s"'<>\)\]\}]+/gi;
  const urls = normalized.match(urlRegex) || [];
  for (const u of urls) {
    const clean = u.replace(/[.,;!?]+$/, "");
    if (!seen.has(clean.toLowerCase())) {
      seen.add(clean.toLowerCase());
      results.push({
        raw: clean,
        refanged: clean,
        defanged: defangText(clean),
        type: "url",
      });
    }
  }

  // 2. Email Addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emails = normalized.match(emailRegex) || [];
  for (const em of emails) {
    const clean = em.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: em,
        refanged: clean,
        defanged: defangText(clean),
        type: "email",
      });
    }
  }

  // 3. IPv4 Addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = normalized.match(ipRegex) || [];
  for (const ip of ips) {
    if (!seen.has(ip)) {
      seen.add(ip);
      const isPriv = isPrivateIpv4(ip);
      results.push({
        raw: ip,
        refanged: ip,
        defanged: defangText(ip),
        type: "ip",
        subType: isPriv ? "private_ip" : "public_ip",
        isPrivate: isPriv,
      });
    }
  }

  // 4. Hashes (SHA256, SHA1, MD5)
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const sha256s = normalized.match(sha256Regex) || [];
  for (const h of sha256s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "sha256",
      });
    }
  }

  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha1s = normalized.match(sha1Regex) || [];
  for (const h of sha1s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "sha1",
      });
    }
  }

  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const md5s = normalized.match(md5Regex) || [];
  for (const h of md5s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "md5",
      });
    }
  }

  // 5. Domains / FQDNs
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|ai|xyz|biz|info|top|ru|cn|me|app|dev|cloud|live|online|site|space|tech|store|cc|to|pw|su|ws|click|link|vip|pro)\b/gi;
  const domains = normalized.match(domainRegex) || [];
  for (const d of domains) {
    const clean = d.toLowerCase().replace(/^[./]+/, "");
    // Skip if already in URL, email or seen
    if (!seen.has(clean) && !clean.includes("@")) {
      seen.add(clean);
      results.push({
        raw: d,
        refanged: clean,
        defanged: defangText(clean),
        type: "domain",
      });
    }
  }

  return results;
}

const SAMPLE_TEXT = `CRITICAL THREAT ADVISORY: Cobalt Strike & C2 Beacon Infrastructure
Observed C2 server communicating at hxxps[://]beacon-infra[.]xyz/update/agent[.]exe
Alternate secondary staging IP: 198[.]51[.]100[.]44:443
Internal pivoting attempted towards staging server 10.0.4.15 and 192.168.1.100.
Sender phishing address: alert-security[@]service-update-portal[.]com
Known payload hashes:
MD5: e4d909c290d0fb1ca068ffaddf22cbd0
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
Backup fast-flux resolver: ns1[.]evil-dynamic-dns[.]org`;

export function IocWorkbench() {
  const [inputText, setInputText] = useState("");
  const [activeFilter, setActiveFilter] = useState<"all" | IndicatorType>("all");
  const [showDefanged, setShowDefanged] = useState(false);
  const [importStatus, setImportStatus] = useState<string | null>(null);
  const [isImporting, setIsImporting] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const indicators = useMemo(() => extractIndicators(inputText), [inputText]);

  const counts = useMemo(() => {
    return {
      all: indicators.length,
      ip: indicators.filter((i) => i.type === "ip").length,
      domain: indicators.filter((i) => i.type === "domain").length,
      url: indicators.filter((i) => i.type === "url").length,
      hash: indicators.filter((i) => i.type === "hash").length,
      email: indicators.filter((i) => i.type === "email").length,
    };
  }, [indicators]);

  const filteredIndicators = useMemo(() => {
    if (activeFilter === "all") return indicators;
    return indicators.filter((i) => i.type === activeFilter);
  }, [indicators, activeFilter]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleCopyAll = (defanged: boolean) => {
    const list = filteredIndicators.map((i) => (defanged ? i.defanged : i.refanged)).join("\n");
    handleCopy(list, defanged ? "all-defanged" : "all-refanged");
  };

  const handleAddAllToWatchlist = async () => {
    if (indicators.length === 0) return;
    setIsImporting(true);
    setImportStatus(null);
    try {
      const entries = indicators.map((i) => ({
        value: i.refanged,
        label: `Workbench IOC [${i.type.toUpperCase()}]`,
      }));
      const res = await watchlistImport(entries);
      setImportStatus(`Successfully added ${res.imported} indicator(s) to Infrastructure Watchlist.`);
    } catch (err: any) {
      setImportStatus(`Failed to import to watchlist: ${err?.message || "Check backend connectivity"}`);
    } finally {
      setIsImporting(false);
    }
  };

  const handleExportJson = () => {
    const bundle = {
      exported_at: new Date().toISOString(),
      generator: "OutPost IOC Workbench",
      total: indicators.length,
      indicators: indicators.map((i) => ({
        type: i.type,
        sub_type: i.subType || null,
        refanged: i.refanged,
        defanged: i.defanged,
        is_private: i.isPrivate ?? false,
      })),
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `outpost-ioc-workbench-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Workbench Header & Description */}
      <div className="rounded-2xl border border-cyan-500/30 bg-cyan-950/20 p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-500/40 bg-cyan-500/15 text-cyan-400">
              <Icon name="zap" size={20} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-text-primary">IOC Defanger &amp; Extractor Workbench</h3>
                <span className="rounded bg-cyan-500/15 border border-cyan-500/40 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-300 uppercase">
                  Threat Intelligence Extraction
                </span>
              </div>
              <p className="text-xs text-text-muted mt-0.5">
                Paste raw unstructured logs, phishing headers, or defanged advisories (<code className="text-cyan-300">hxxp://</code>, <code className="text-cyan-300">[.]</code>, <code className="text-cyan-300">[@]</code>). Automatically extract, sanitize, cross-examine, and add to Watchlist.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setInputText(SAMPLE_TEXT)}
              className="press rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary hover:bg-bg-elevated transition"
            >
              Load Sample Text
            </button>
            {inputText && (
              <button
                onClick={() => setInputText("")}
                className="press rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-rose-400 hover:bg-rose-500/10 transition"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Input Textarea */}
      <div className="rounded-2xl border border-border-subtle bg-bg-surface p-4 space-y-3">
        <div className="flex items-center justify-between text-xs font-mono text-text-muted">
          <span>Unstructured Input / Advisory Paste</span>
          <span>{inputText.length} characters</span>
        </div>
        <textarea
          rows={5}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste raw advisory, email headers, firewall syslog, or defanged threat report (e.g. hxxps[://]c2-server[.]com/evil[.]bin, 192[.]168[.]1[.]1, admin[@]evil[.]com)..."
          className="w-full rounded-xl border border-border-subtle bg-bg-base p-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-cyan-500/60 focus:outline-none resize-y"
        />
      </div>

      {/* Indicator Summary & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Category Filters */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
          <button
            onClick={() => setActiveFilter("all")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "all"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            All ({counts.all})
          </button>
          <button
            onClick={() => setActiveFilter("ip")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "ip"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            IPv4 ({counts.ip})
          </button>
          <button
            onClick={() => setActiveFilter("domain")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "domain"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            Domains ({counts.domain})
          </button>
          <button
            onClick={() => setActiveFilter("url")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "url"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            URLs ({counts.url})
          </button>
          <button
            onClick={() => setActiveFilter("hash")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "hash"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            Hashes ({counts.hash})
          </button>
          <button
            onClick={() => setActiveFilter("email")}
            className={`press rounded-lg px-3 py-1.5 border transition ${
              activeFilter === "email"
                ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
          >
            Emails ({counts.email})
          </button>
        </div>

        {/* Global Transformation & Export Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Defang Toggle */}
          <button
            onClick={() => setShowDefanged(!showDefanged)}
            className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-xs transition ${
              showDefanged
                ? "border-amber-500/40 bg-amber-500/10 text-amber-300 font-bold"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
            }`}
            title="Toggle between refanged and safe defanged display"
          >
            <Icon name="shield" size={12} />
            <span>{showDefanged ? "Defanged (Safe)" : "Refanged (Active)"}</span>
          </button>

          {/* Bulk Watchlist Import */}
          <button
            onClick={() => void handleAddAllToWatchlist()}
            disabled={isImporting || indicators.length === 0}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 font-mono text-xs font-bold text-accent hover:bg-accent/25 transition disabled:opacity-50"
            title="Import all extracted indicators into OutPost's Watchlist"
          >
            <Icon name={isImporting ? "refresh" : "target"} size={13} className={isImporting ? "animate-spin" : ""} />
            <span>Add All to Watchlist</span>
          </button>

          {/* Copy All */}
          <button
            onClick={() => handleCopyAll(showDefanged)}
            disabled={filteredIndicators.length === 0}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary hover:bg-bg-elevated transition disabled:opacity-50"
          >
            <Icon name="copy" size={12} />
            <span>{copiedKey === (showDefanged ? "all-defanged" : "all-refanged") ? "✓ Copied!" : "Copy Filtered"}</span>
          </button>

          {/* Export JSON */}
          <button
            onClick={handleExportJson}
            disabled={indicators.length === 0}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary hover:bg-bg-elevated transition disabled:opacity-50"
            title="Download structured JSON report"
          >
            <Icon name="download" size={12} />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {importStatus && (
        <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3 font-mono text-xs text-emerald-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Icon name="check" size={14} />
            <span>{importStatus}</span>
          </div>
          <button onClick={() => setImportStatus(null)} className="text-text-faint hover:text-text-primary">✕</button>
        </div>
      )}

      {/* Extracted Indicators Table / Grid */}
      {filteredIndicators.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-border-subtle bg-bg-surface/50 p-12 text-center">
          <Icon name="search" size={24} className="mx-auto text-text-faint mb-2" />
          <p className="font-mono text-sm font-semibold text-text-muted">No indicators extracted</p>
          <p className="text-xs text-text-faint mt-1">Paste text above to parse IPs, domains, hashes, and URLs in real-time.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
          <div className="border-b border-border-subtle bg-bg-elevated/40 px-4 py-2.5 font-mono text-xs font-bold text-text-muted grid grid-cols-12 gap-2">
            <span className="col-span-2">Type</span>
            <span className="col-span-7">Indicator Value</span>
            <span className="col-span-3 text-right">Actions</span>
          </div>

          <div className="divide-y divide-border-subtle/40">
            {filteredIndicators.map((item, idx) => {
              const displayVal = showDefanged ? item.defanged : item.refanged;
              const copyKey = `item-${idx}`;
              return (
                <div key={idx} className="px-4 py-2.5 font-mono text-xs grid grid-cols-12 gap-2 items-center hover:bg-bg-elevated/30 transition">
                  {/* Type Badge */}
                  <div className="col-span-2 flex items-center gap-1.5">
                    <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                      item.type === "ip"
                        ? item.isPrivate
                          ? "bg-slate-500/15 text-slate-300 border border-slate-500/30"
                          : "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                        : item.type === "domain"
                        ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                        : item.type === "url"
                        ? "bg-purple-500/15 text-purple-400 border border-purple-500/30"
                        : item.type === "hash"
                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                        : "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                    }`}>
                      {item.subType ? item.subType.replace("_", " ") : item.type}
                    </span>
                  </div>

                  {/* Indicator Value */}
                  <div className="col-span-7 truncate font-medium text-text-primary" title={item.refanged}>
                    <span className={showDefanged ? "text-amber-300" : ""}>{displayVal}</span>
                    {item.isPrivate && (
                      <span className="ml-2 text-[10px] text-text-faint font-normal">(Internal / RFC1918)</span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="col-span-3 flex items-center justify-end gap-2">
                    <button
                      onClick={() => handleCopy(displayVal, copyKey)}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[11px] text-text-muted hover:text-text-primary hover:bg-bg-elevated transition"
                      title="Copy indicator to clipboard"
                    >
                      {copiedKey === copyKey ? "✓ Copied" : "Copy"}
                    </button>

                    <Link
                      to={`/search?q=${encodeURIComponent(item.refanged)}`}
                      className="press rounded border border-accent/40 bg-accent/10 px-2 py-1 text-[11px] font-semibold text-accent hover:bg-accent/20 transition flex items-center gap-1"
                      title="Query OutPost database and telemetry for this indicator"
                    >
                      <Icon name="search" size={10} />
                      <span>Search</span>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default IocWorkbench;
