import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Icon, platformIconName } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { getRuns, getSample } from "../lib/api";
import type { RunSummary } from "../types";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SampleDetailPage() {
  const { sampleId = "" } = useParams();
  const [copied, setCopied] = useState(false);

  const { data: sample, isLoading, isError } = useQuery({
    queryKey: ["sample", sampleId],
    queryFn: () => getSample(sampleId),
  });

  // Runs that detonated this binary — filtered by its sample name.
  const { data: runs = [] } = useQuery({
    queryKey: ["runs", "q", sample?.original_name ?? ""],
    queryFn: () => getRuns({ q: sample?.original_name ?? "" }),
    enabled: sample !== undefined,
  });

  const copyHash = async () => {
    if (!sample) return;
    try {
      await navigator.clipboard.writeText(sample.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable — the title tooltip still carries the hash */
    }
  };

  if (isLoading) return <p className="p-8 text-sm text-text-muted">Loading sample…</p>;
  if (isError || !sample) {
    return (
      <p className="p-8 text-sm text-risk-malicious">
        Couldn't load sample <span className="font-mono">{sampleId}</span>.
      </p>
    );
  }

  const platName = sample.detected_platform === "windows" ? "Windows" : sample.detected_platform === "linux" ? "Linux" : sample.detected_platform === "macos" ? "macOS" : "unknown";
  const platIcon = sample.detected_platform === "macos" || sample.detected_platform === "windows" || sample.detected_platform === "linux" ? platformIconName(sample.detected_platform) : "terminal";

  return (
    <div className="mx-auto max-w-5xl px-6 py-8 lg:px-10">
      <nav className="mb-6 flex items-center gap-2 font-mono text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/samples" className="transition-colors hover:text-accent">
          Sample vault
        </Link>
        <span aria-hidden>/</span>
        <span className="text-text-primary">{sample.original_name}</span>
      </nav>

      <PageHeader
        kicker="Intelligence · sample"
        title={
          <>
            {sample.original_name}{" "}
            <span className="font-normal text-text-muted">— {sample.family ?? "untyped"}</span>
          </>
        }
        lede={`Detected ${sample.detected_platform} from magic bytes · ${formatBytes(sample.size)} · uploaded ${sample.created_at.slice(0, 19).replace("T", " ")} UTC`}
        actions={
          <div className="flex items-center gap-2">              <Link
                to={`/footprint?sample=${sample.sample_id}`}
                className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              >
                Digital footprint
                <Icon name="arrowRight" size={12} />
              </Link>
            <button
              onClick={() => void copyHash()}
              className="press inline-flex items-center gap-1.5 rounded border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10"
              title={sample.sha256}
            >
              <Icon name={copied ? "check" : "copy"} size={12} />
              {copied ? "copied" : "copy hash"}
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Panel kicker="Signature" title="Full SHA-256">
          <code className="block break-all rounded border border-border-subtle bg-bg-elevated/50 px-3 py-2 font-mono text-xs leading-relaxed text-text-primary">
            {sample.sha256}
          </code>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Chip tone={sample.detected_platform === "macos" ? "suspicious" : sample.detected_platform === "linux" ? "clean" : "accent"} dot title={`Detected ${sample.detected_platform}`}>
              <Icon name={platIcon} size={11} />
              {platName}
            </Chip>
            {sample.malware_family && (
              <Chip tone="malicious" dot title="VirusTotal family">
                {sample.malware_family}
              </Chip>
            )}
            {sample.vt_detections !== null ? (
              <Chip tone={sample.vt_detections > 0 ? "malicious" : "clean"} dot>
                {sample.vt_detections} VT detection{sample.vt_detections === 1 ? "" : "s"}
              </Chip>
            ) : (
              <Chip tone="muted">no VT intel</Chip>
            )}
          </div>
        </Panel>

        <Panel kicker="YARA" title={`Signatures matched (${sample.yara_rules.length})`}>
          {sample.yara_rules.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {sample.yara_rules.map((r) => (
                <span
                  key={r}
                  className="rounded border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[11px] text-accent"
                >
                  {r}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-text-muted">No bundled YARA rules matched this binary.</p>
          )}
        </Panel>
      </div>

      <Panel kicker="Detonations" title={`Runs of ${sample.original_name}`} className="mt-6" pad={false}>
        {runs.length === 0 ? (
          <p className="p-6 text-sm text-text-muted">This sample hasn't been detonated yet — head to Monitor to run it.</p>
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
                        {r.run_id.slice(0, 12)}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted">
                      {r.started_at.slice(0, 19).replace("T", " ")}
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
    </div>
  );
}
