import { useState } from "react";
import { Panel } from "../ui";
import { getRules } from "../../lib/api";

type Format = "suricata" | "sigma";

export default function RulesPanel({ runId }: { runId: string }) {
  const [format, setFormat] = useState<Format>("suricata");
  const [text, setText] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = async (fmt: Format) => {
    setFormat(fmt);
    setLoading(true);
    setError(null);
    try {
      setText(await getRules(runId, fmt));
    } catch {
      setError("Could not generate rules — is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const copy = async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <Panel
      kicker="Operate"
      title="Detection rules"
      right={
        <div className="flex items-center gap-1">
          {(["suricata", "sigma"] as Format[]).map((f) => (
            <button
              key={f}
              onClick={() => void load(f)}
              className={`rounded px-2 py-1 font-mono text-[10px] uppercase tracking-wide transition-colors duration-150 ${
                format === f && text !== null
                  ? "bg-bg-elevated text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              {f}
            </button>
          ))}
          {text && (
            <button
              onClick={() => void copy()}
              className="press ml-2 rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            >
              {copied ? "Copied ✓" : "Copy"}
            </button>
          )}
        </div>
      }
    >
      {loading && <p className="text-sm text-text-muted">Generating…</p>}
      {error && <p className="text-sm text-risk-malicious">{error}</p>}
      {!loading && !error && text === null && (
        <button onClick={() => void load("suricata")} className="text-sm text-accent hover:underline">
          Generate rules from this run's findings →
        </button>
      )}
      {text !== null && (
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-bg-elevated p-3 font-mono text-xs leading-relaxed text-text-primary">
          {text}
        </pre>
      )}
    </Panel>
  );
}
