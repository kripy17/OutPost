import { Icon } from "./Icon";
import { type DataProvenance, determineProvenance } from "../lib/provenance";

export type { DataProvenance };



export function DataProvenanceBadge({
  source,
  log_source,
  provenance,
  className = "",
}: {
  source?: string | null;
  log_source?: string | null;
  provenance?: DataProvenance;
  className?: string;
}) {
  const prov = provenance ?? determineProvenance(source, log_source);

  if (prov === "LIVE") {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-emerald-400 ${className}`}
        title="Authoritative live host telemetry from connected collector"
      >
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" aria-hidden />
        LIVE
      </span>
    );
  }

  if (prov === "SIMULATION") {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full border border-purple-500/40 bg-purple-500/10 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-purple-300 ${className}`}
        title="Deterministic attack scenario from Simulation Lab (test telemetry)"
      >
        <Icon name="zap" size={9} className="text-purple-400" />
        SIMULATION
      </span>
    );
  }

  if (prov === "SANDBOX") {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full border border-sky-500/40 bg-sky-500/10 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-wider text-sky-300 ${className}`}
        title="Dynamic malware detonation from external or isolated sandbox"
      >
        <Icon name="box" size={9} className="text-sky-400" />
        SANDBOX
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border border-border-subtle bg-bg-elevated/40 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-text-faint ${className}`}
      title="Historical record with unknown provenance"
    >
      UNKNOWN
    </span>
  );
}

export default DataProvenanceBadge;
