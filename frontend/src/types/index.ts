// Mirrors backend Pydantic models in app/core/schema.py exactly (docs/04).

export type Platform = "windows" | "linux" | "macos";

// GET /platform — the host OS the backend runs on. The webapp has no OS
// picker; it reads this on load and targets sessions at the detected OS.
export interface PlatformInfo {
  os: Platform;
  name: string;
  release: string;
  machine: string;
  python: string;
  collector: "sysmon" | "auditd" | string;
}
export type Reputation = "clean" | "suspicious" | "malicious" | "unknown";
export type SessionType = "live" | "analysis";
export type Severity = "suspicious" | "malicious";
export type EventType = "process_create" | "network_connection" | "file_write" | "registry_write";

export interface RunSummary {
  run_id: string;
  sample_name: string;
  platform: Platform;
  session_type: SessionType;
  started_at: string;
  completed_at: string | null;
  process_count: number;
  unique_ips: number;
  alert_count: number;
  highest_severity: Severity | null;
  risk_score: number;
}

export interface Alert {
  id: number | null;
  run_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  triggered_at: string;
  related_pid: number | null;
  related_ip: string | null;
  details: string;
}

export interface ProcessNode {
  pid: number;
  ppid: number | null;
  process_name: string;
  command_line: string | null;
  // Network risk annotation (docs/07 signature visual): worst reputation of
  // any destination this pid connected to, plus the distinct IPs behind it.
  flagged_reputation?: Reputation | null;
  network_ips?: string[];
  children: ProcessNode[];
}

export interface NetworkConnection {
  dest_ip: string;
  dest_port: number | null;
  protocol: string | null;
  first_seen: string;
  reputation: Reputation;
  abuse_score: number | null;
  vt_malicious_count: number | null;
  malware_family: string | null;
  watchlist: boolean | null;
  watchlist_label: string | null;
}

export interface EventOut {
  id: number | null;
  run_id: string;
  platform: Platform;
  event_type: EventType;
  timestamp: string;
  pid: number | null;
  ppid: number | null;
  process_name: string | null;
  command_line: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  protocol: string | null;
  file_path: string | null;
  registry_key: string | null;
}

export interface RunDetail {
  run: RunSummary;
  process_tree: ProcessNode[];
  network_connections: NetworkConnection[];
  timeline: EventOut[];
  alerts: Alert[];
  // Roadmap 2.4 — correlated kill-chain sequence (stage→stage links).
  kill_chain?: KillChainLink[];
  // Roadmap 2.2 — uploaded-sample reputation evidence (YARA + VirusTotal).
  sample_reputation?: SampleReputation | null;
}

export interface KillChainLink {
  from: string;
  to: string;
  count: number;
}

export interface SampleReputation {
  sample_id: string;
  sha256: string;
  yara_rules: string[];
  vt_detections: number | null;
  malware_family: string | null;
}

// -- Roadmap 2.3 — rule tuning ------------------------------------------------

export interface TuningKnob {
  param: string;
  rule_id: string;
  type: string;
  default: number;
  current: number;
  tuned: boolean;
}

export interface TuningResponse {
  count: number;
  knobs: TuningKnob[];
}

// -- Roadmap 3.1 — notification settings ---------------------------------------

export interface NotificationSettings {
  enabled: boolean;
  webhook_url: string;
}

// -- Webapp-first API surfaces (monitor / dynamic analysis / Phase 6) --------

export interface EventIn {
  run_id: string;
  platform: Platform;
  event_type: EventType;
  timestamp: string;
  pid: number | null;
  ppid: number | null;
  process_name: string | null;
  command_line: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  protocol: string | null;
  file_path: string | null;
  registry_key: string | null;
}

export interface IocMatch {
  run_id: string;
  sample_name: string;
  platform: Platform;
  event_type: EventType;
  timestamp: string;
  dest_ip: string | null;
  process_name: string | null;
  file_path: string | null;
  registry_key: string | null;
}

export interface IocSearchResponse {
  value: string;
  count: number;
  returned: number;
  matches: IocMatch[];
  // Uploaded binaries whose SHA-256 matches the query (roadmap 1.4).
  samples?: SampleMeta[];
}

// -- Sample binary upload / OS auto-detection (roadmap 1.4) ------------------

export interface SampleRow {
  sample_id: string;
  original_name: string;
  sha256: string;
  detected_platform: "windows" | "linux" | "macos" | "unknown";
  size: number;
  created_at: string;
  family: string | null;
  yara_rules: string[];
  vt_detections: number | null;
  malware_family: string | null;
  runs_count: number;
}

export interface SamplesResponse {
  total: number;
  returned: number;
  samples: SampleRow[];
}

export interface SampleMeta {
  sample_id: string;
  original_name: string;
  sha256: string;
  detected_platform: "windows" | "linux" | "macos";
  size: number;
  created_at: string;
  family?: string;
  yara_rules?: string;
  vt_detections?: number | null;
  malware_family?: string | null;
}

export interface CompareResponse {
  run_a: { run_id: string; sample_name: string };
  run_b: { run_id: string; sample_name: string };
  processes: { only_a: string[]; only_b: string[]; shared: string[] };
  ips: { only_a: string[]; only_b: string[]; shared: string[] };
}

export interface WatchlistEntry {
  value: string;
  label: string;
  added_at: string;
}

export interface WatchlistImportResponse {
  imported: number;
}

export interface Campaign {
  key: string;
  reputation: Reputation | null;
  watchlist: boolean;
  watchlist_label: string | null;
  runs: RunSummary[];
  span_start: string | null;
  span_end: string | null;
  iocs: {
    ips: CampaignIoc[];
    registry_keys: CampaignIoc[];
    file_paths: CampaignIoc[];
    processes: CampaignIoc[];
  };
  timeline: CampaignTimelineEvent[];
  // Roadmap 2.4 — correlated chain across members.
  chain_links?: KillChainLink[];
  chain_label?: string | null;
}

export interface RunNote {
  run_id: string;
  note: string;
  created_at: string;
}

// -- Campaigns (runs clustered by shared infrastructure) ---------------------

export interface CampaignIoc {
  value: string;
  runs: number;
}

export type CampaignTimelineEvent = EventOut & { sample_name: string };

// -- Risk scoring + ATT&CK (roadmap 1.3) ------------------------------------

export interface RuleMeta {
  rule_id: string;
  rule_name: string;
  technique: string;
  tactic: string;
  weight: number;
}

// -- Global event feed / Event Viewer (roadmap 1.1) -------------------------

export interface EventFeedEvent extends EventOut {
  sample_name: string;
  session_type: SessionType;
  run_severity: Severity | null;
}

export interface EventFeedResponse {
  total: number;
  returned: number;
  limit: number;
  offset: number;
  events: EventFeedEvent[];
}

export interface EventFeedParams {
  event_type?: EventType | "";
  platform?: Platform | "";
  severity?: Severity | "";
  q?: string;
  limit?: number;
  offset?: number;
}

// -- Dashboard / global findings feed ----------------------------------------

export interface GlobalAlert extends Alert {
  sample_name: string;
}

// -- Digital footprinting (roadmap scaffold) ---------------------------------

export interface FootprintSeedIp {
  ip: string;
  hits: number;
  first_seen: string;
  last_seen: string;
  run_count: number;
  reputation: Reputation;
  abuse_score: number | null;
  vt_malicious_count: number | null;
}

export interface FootprintPassive {
  source: "not_configured" | "synthetic_demo";
  resolutions: { domain: string; first_seen: string; last_seen: string; synthetic?: boolean }[];
  certificates: { cn: string; issuer: string; not_before: string; not_after: string; synthetic?: boolean }[];
  sibling_ips: { ip: string; relation: string; synthetic?: boolean }[];
}

export interface Footprint {
  sample: { sample_id: string; name: string; sha256: string; platform: Platform; family: string | null };
  runs: { run_id: string; sample_name: string; started_at: string; completed_at: string | null }[];
  seed_ips: FootprintSeedIp[];
  passive: FootprintPassive;
  status: { roadmap: boolean; generated: "mock" | null };
}
