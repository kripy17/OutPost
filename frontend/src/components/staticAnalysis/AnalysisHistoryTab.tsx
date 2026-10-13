import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { getSimilarSamples } from "../../lib/api";
import { NetworkProtocolInspector } from "../NetworkProtocolInspector";
import type { RunSummary } from "../../types";

interface AnalysisHistoryTabProps {
  sampleId: string;
  sampleName: string;
  runs: RunSummary[];
}

export function AnalysisHistoryTab({ sampleId, sampleName, runs }: AnalysisHistoryTabProps) {
  const { data: similarData, isLoading: loadingSimilar } = useQuery({
    queryKey: ["sample", "similar", sampleId],
    queryFn: () => getSimilarSamples(sampleId, 20),
  });

  const similarMatches = similarData?.similar || [];

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* SECTION 1: Historical Execution Runs */}
      <Panel
        kicker="Detonation Telemetry"
        title={`Detonation Runs for ${sampleName} (${runs.length})`}
        right={
          <span className="text-[10px] text-text-faint">
            Historical dynamic sandbox runs
          </span>
        }
      >
        {runs.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
            <Icon name="activity" size={20} className="mx-auto text-text-faint mb-2" />
            <p className="font-semibold text-text-primary">Zero Detonation Runs</p>
            <p className="text-[11px] text-text-muted mt-1">
              This sample hasn't been executed in the dynamic sandbox yet.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-surface/80 text-[10px] uppercase text-text-faint">
                  <th className="py-2 px-3">Run Identifier</th>
                  <th className="py-2 px-3">Started Timestamp</th>
                  <th className="py-2 px-3 text-center">Alerts</th>
                  <th className="py-2 px-3">Highest Severity</th>
                  <th className="py-2 px-3 text-right">Risk Score</th>
                  <th className="py-2 px-3 text-right">Dossier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/50">
                {runs.map((r: RunSummary) => {
                  const isMal = r.highest_severity === "malicious";
                  const isSusp = r.highest_severity === "suspicious";
                  return (
                    <tr key={r.run_id} className="hover:bg-bg-elevated/40 transition-colors">
                      <td className="py-2 px-3">
                        <Link
                          to={`/runs/${r.run_id}`}
                          className="font-mono text-xs font-bold text-accent hover:underline"
                        >
                          {r.run_id}
                        </Link>
                      </td>
                      <td className="py-2 px-3 text-text-muted text-[11px]">
                        {r.started_at ? `${r.started_at.slice(0, 19).replace("T", " ")} UTC` : "—"}
                      </td>
                      <td className="py-2 px-3 text-center font-bold text-text-primary">
                        {r.alert_count}
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                            isMal
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : isSusp
                                ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          }`}
                        >
                          ● {r.highest_severity || "clean"}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right font-bold text-text-primary">
                        {r.risk_score}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <Link
                          to={`/runs/${r.run_id}`}
                          className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-accent hover:border-accent"
                        >
                          <span>View Run</span>
                          <Icon name="arrowRight" size={10} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* SECTION 2: Binary Similarity & Fuzzy Hash Matching */}
      <Panel
        kicker="Cross-Sample Correlation"
        title="Binary Similarity &amp; Fuzzy Hash Matching (CTPH / SSDEEP)"
        right={
          <span className="text-[10px] text-text-faint">
            {similarMatches.length} matching sample{similarMatches.length === 1 ? "" : "s"}
          </span>
        }
      >
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            {similarData?.target_imphash && (
              <div className="rounded border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[11px]">
                <span className="text-text-faint">Target imphash: </span>
                <span className="text-accent font-bold">{similarData.target_imphash}</span>
              </div>
            )}
            {similarData?.target_fuzzy_hash && (
              <div className="rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] truncate max-w-md">
                <span className="text-text-faint">Target CTPH: </span>
                <span className="text-text-muted">{similarData.target_fuzzy_hash}</span>
              </div>
            )}
          </div>

          {loadingSimilar ? (
            <p className="text-xs text-text-muted py-2">Calculating fuzzy hash similarity across vault...</p>
          ) : similarMatches.length === 0 ? (
            <p className="text-xs text-text-muted py-2">
              No related binary variants detected in the vault above the 20% similarity threshold.
            </p>
          ) : (
            <div className="space-y-2">
              {similarMatches.map((m: any) => (
                <div
                  key={m.sample_id}
                  className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border-subtle bg-bg-base/60 p-3 hover:border-accent/40"
                >
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

      {/* SECTION 3: Aggregated Network & Protocol Forensics */}
      {runs.length > 0 && (
        <Panel kicker="Protocol Forensics" title="Aggregated Network &amp; C2 Conversation Analysis">
          <NetworkProtocolInspector sampleId={sampleId} />
        </Panel>
      )}
    </div>
  );
}
