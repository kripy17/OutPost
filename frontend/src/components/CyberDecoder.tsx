import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "./Icon";
import { copyToClipboard } from "../lib/clipboard";
import {
  analyzeAndDecode,
  defangIoc,
  refangIoc,
  type CyberDecoderOutput,
  type IocMatch,
} from "../lib/cyberDecoder";

const SAMPLES = [
  {
    name: "PowerShell Base64",
    payload: "dwBoAG8AYQBtAGkAIAAvAGEAbABsAA==", // "whoami /all" in UTF-16LE
  },
  {
    name: "Hex Shellcode",
    payload: "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68",
  },
  {
    name: "URL Percent-Encoded",
    payload: "%2e%2e%2f%2e%2e%2fetc%2fpasswd%00",
  },
  {
    name: "Defanged C2 URL",
    payload: "hxxps://malicious-c2[.]top/payloads/beacon[.]bin",
  },
];

export function CyberDecoder({ initialValue = "" }: { initialValue?: string }) {
  const navigate = useNavigate();
  const [input, setInput] = useState(initialValue);
  const [output, setOutput] = useState<CyberDecoderOutput | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [inputSha256, setInputSha256] = useState<string>("");

  useEffect(() => {
    if (!input.trim()) {
      setOutput(null);
      setInputSha256("");
      return;
    }

    const res = analyzeAndDecode(input);
    setOutput(res);

    // Compute SHA-256 via Web Crypto if available
    if (typeof window !== "undefined" && window.crypto?.subtle) {
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      window.crypto.subtle
        .digest("SHA-256", data)
        .then((buf) => {
          const hashArray = Array.from(new Uint8Array(buf));
          const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
          setInputSha256(hashHex);
        })
        .catch(() => setInputSha256(""));
    }
  }, [input]);

  const handleCopy = (text: string, id: string) => {
    copyToClipboard(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDefangToggle = () => {
    if (!input.trim()) return;
    if (output?.isDefanged) {
      setInput(refangIoc(input));
    } else {
      setInput(defangIoc(input));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Quick Samples */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle/50 pb-4">
        <div>
          <h2 className="flex items-center gap-2 font-mono text-base font-semibold text-text-primary">
            <span className="flex h-6 w-6 items-center justify-center rounded-md border border-accent/40 bg-accent/15 text-accent">
              <Icon name="terminal" size={13} />
            </span>
            Payload Decoder · Forensic Deobfuscator
          </h2>
          <p className="mt-1 text-xs text-text-muted">
            Inspect, deobfuscate, and extract indicators from encoded PowerShell commands, Hex shellcode, URL parameters, and defanged IOCs.
          </p>
        </div>

        {/* Quick Sample Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[10px] text-text-faint uppercase mr-1">Samples:</span>
          {SAMPLES.map((s) => (
            <button
              key={s.name}
              type="button"
              onClick={() => setInput(s.payload)}
              className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted hover:border-accent/40 hover:text-accent transition-colors"
            >
              {s.name}
            </button>
          ))}
          {input && (
            <button
              type="button"
              onClick={() => setInput("")}
              className="rounded-lg border border-border-subtle bg-bg-surface px-2 py-1 font-mono text-[11px] text-risk-malicious/80 hover:text-risk-malicious transition-colors"
              title="Clear input"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Input Textarea & Controls */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono text-text-muted">
          <span>Target Payload / Obfuscated String:</span>
          <div className="flex items-center gap-3">
            {inputSha256 && (
              <span className="text-[11px] text-text-faint" title={`Input SHA-256: ${inputSha256}`}>
                SHA256: <span className="text-text-primary">{inputSha256.slice(0, 16)}…</span>
              </span>
            )}
            <button
              type="button"
              onClick={handleDefangToggle}
              disabled={!input.trim()}
              className="rounded border border-border-subtle bg-bg-elevated px-2 py-0.5 text-[11px] text-text-primary hover:border-accent/40 disabled:opacity-40"
            >
              {output?.isDefanged ? "Refang IOCs (Live)" : "Defang IOCs (Safe)"}
            </button>
          </div>
        </div>

        <div className="relative rounded-xl border border-border-subtle bg-bg-surface focus-within:border-accent/60 focus-within:ring-1 focus-within:ring-accent/40 transition-all">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste Base64, PowerShell -enc, Hex (\x41\x42 or 4142), URL-encoded (%20), or defanged IOC string..."
            rows={4}
            className="w-full resize-y bg-transparent p-3.5 font-mono text-xs text-text-primary placeholder:text-text-faint focus:outline-none"
            spellCheck={false}
          />
        </div>
      </div>

      {/* Extracted IOCs Strip */}
      {output && output.extractedIocs.length > 0 && (
        <div className="rounded-xl border border-accent/30 bg-accent/5 p-4 space-y-2">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 font-mono text-xs font-semibold text-accent uppercase tracking-wider">
              <Icon name="search" size={12} />
              Extracted Indicators ({output.extractedIocs.length})
            </span>
            <span className="text-[11px] text-text-muted">Click an IOC to query in OutPost</span>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            {output.extractedIocs.map((ioc: IocMatch) => (
              <div
                key={`${ioc.type}-${ioc.value}`}
                className="flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs font-mono shadow-sm"
              >
                <span className="text-[9px] uppercase px-1 py-0.2 bg-bg-elevated rounded text-text-faint font-semibold">
                  {ioc.type}
                </span>
                <span className="text-text-primary">{ioc.value}</span>
                <Link
                  to={`/search?q=${encodeURIComponent(ioc.value)}`}
                  className="ml-1 text-accent hover:underline hover:text-accent-bright"
                  title="Search IOC across all OutPost telemetry"
                >
                  <Icon name="search" size={11} />
                </Link>
                <button
                  type="button"
                  onClick={() => handleCopy(ioc.value, `ioc-${ioc.value}`)}
                  className="text-text-muted hover:text-text-primary"
                  title="Copy indicator"
                >
                  {copiedId === `ioc-${ioc.value}` ? (
                    <span className="text-signal text-[10px]">✓</span>
                  ) : (
                    <Icon name="copy" size={11} />
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Decoded Candidates */}
      {output && output.candidates.length > 0 ? (
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-border-subtle/40 pb-2">
            <span className="font-mono text-xs font-bold text-text-muted uppercase tracking-wider">
              Decoded Representations ({output.candidates.length})
            </span>
          </div>

          <div className="grid gap-4">
            {output.candidates.map((c) => (
              <div
                key={c.id}
                className="group rounded-xl border border-border-subtle bg-bg-surface p-4 space-y-2.5 transition-all hover:border-accent/40"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-text-primary">{c.name}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 font-mono text-[9px] uppercase ${
                        c.confidence === "high"
                          ? "border border-signal/40 bg-signal/10 text-signal"
                          : "border border-border-subtle text-text-faint"
                      }`}
                    >
                      {c.confidence} confidence
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleCopy(c.decoded, c.id)}
                      className="press flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1 font-mono text-[11px] text-text-muted hover:text-text-primary hover:border-accent/50"
                    >
                      {copiedId === c.id ? (
                        <>
                          <span className="text-signal">✓</span> Copied
                        </>
                      ) : (
                        <>
                          <Icon name="copy" size={11} /> Copy
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => navigate(`/search?q=${encodeURIComponent(c.decoded.slice(0, 120))}`)}
                      className="press flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-elevated px-2.5 py-1 font-mono text-[11px] text-accent hover:border-accent/50"
                      title="Search decoded content across OutPost runs"
                    >
                      <Icon name="search" size={11} /> Search in OutPost
                    </button>
                  </div>
                </div>

                <p className="text-[11px] text-text-muted">{c.description}</p>

                <div className="overflow-x-auto rounded-lg border border-border-subtle/60 bg-bg-elevated/70 p-3">
                  <pre className="font-mono text-xs text-text-primary whitespace-pre-wrap break-all leading-relaxed">
                    {c.decoded}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : input.trim() ? (
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-8 text-center">
          <p className="font-mono text-xs text-text-muted">
            No standard obfuscated encoding (Base64, Hex, URL, Defang) identified for this payload.
          </p>
          <div className="mt-4 flex justify-center">
            <button
              type="button"
              onClick={() => handleDefangToggle()}
              className="rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-xs text-text-primary hover:border-accent/40"
            >
              Defang input anyway
            </button>
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-text-faint font-mono text-xs">
          Paste an encoded or obfuscated payload above or choose a sample to inspect.
        </div>
      )}
    </div>
  );
}
