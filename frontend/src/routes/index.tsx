import { useQuery } from "@tanstack/react-query";
import RunList from "../components/RunHistory/RunList";
import { PageHeader, Panel, Stat } from "../components/ui";
import { BASE_URL, getRuns } from "../lib/api";

export default function RunHistoryPage() {
  const { data, isLoading, isError } = useQuery({ queryKey: ["runs"], queryFn: () => getRuns() });

  const runs = data ?? [];
  const totalAlerts = runs.reduce((n, r) => n + r.alert_count, 0);
  const malicious = runs.filter((r) => r.highest_severity === "malicious").length;
  const totalRisk = runs.reduce((n, r) => n + (r.risk_score ?? 0), 0);

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Operations · archive"
        title="Session history"
        lede="Live monitoring sessions and bounded analyses, newest first."
      />

      {!isLoading && !isError && (
        <Panel className="mb-6 overflow-hidden" pad={false}>
          <dl className="grid grid-cols-2 divide-border-subtle sm:grid-cols-4 sm:divide-x">
            <div className="px-5 py-4">
              <Stat label="sessions" value={runs.length} />
            </div>
            <div className="px-5 py-4">
              <Stat label="alerts" value={totalAlerts} />
            </div>
            <div className="px-5 py-4">
              <Stat label="malicious" value={malicious} tone="malicious" />
            </div>
            <div className="px-5 py-4">
              <Stat label="cumulative risk" value={totalRisk} />
            </div>
          </dl>
        </Panel>
      )}

      {isLoading && <p className="text-sm text-text-muted">Loading…</p>}
      {isError && (
        <Panel className="border-risk-malicious/40">
          <p className="text-sm text-risk-malicious">
            Couldn't reach the OutPost backend — is it running on <span className="font-mono">{BASE_URL}</span>?
          </p>
        </Panel>
      )}
      {data && <RunList runs={data} />}
    </div>
  );
}
