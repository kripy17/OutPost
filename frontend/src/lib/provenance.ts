export type DataProvenance = "LIVE" | "SIMULATION" | "SANDBOX" | "UNKNOWN";

export function determineProvenance(source?: string | null, log_source?: string | null): DataProvenance {
  if (!source && !log_source) return "UNKNOWN";
  if (source === "live" || log_source === "auditd" || log_source === "sysmon" || log_source === "ebpf" || log_source === "endpoint_security") {
    return "LIVE";
  }
  if (source === "simulation" || source === "monitor" || source === "webapp-demo" || source === "seed") {
    return "SIMULATION";
  }
  if (source?.startsWith("sandbox:") || source === "sandbox") {
    return "SANDBOX";
  }
  return "LIVE";
}
