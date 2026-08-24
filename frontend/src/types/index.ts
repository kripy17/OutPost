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
  /** Backend host identity — the Overview compares it to the fleet to answer
   *  "is THIS host monitored?" (auto-OS front door). */
  hostname: string;
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
  // Provenance — where the run came from (monitor / live / cli / seed /
  // sandbox:<provider>). Older backends omit it; the badge defaults to MON.
  source?: string;
  // The distinct fleet hosts whose events landed in this run.
  host_ids?: string[];
  started_at: string;
  completed_at: string | null;
  process_count: number;
  unique_ips: number;
  alert_count: number;
  highest_severity: Severity | null;
  risk_score: number;
}

export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface Alert {
  id: number | null;
  run_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  triggered_at: string;
  related_pid: number | null;
  related_ip: string | null;
  // PIDs behind composite rules (enumeration-burst recon sweep) — the Monitor
  // highlights exactly these nodes in the live process tree.
  related_pids?: number[];
  details: string;
  // Triage (analyst workflow): open → acknowledged → resolved, with the
  // optional analyst comment recorded at the transition.
  status: AlertStatus;
  status_comment: string | null;
  status_at: string | null;
}

// -- Alert triage (analyst workflow) ------------------------------------------

export type AllowlistKind = "ip" | "file" | "registry" | "process" | "hash";

export interface AllowlistEntry {
  id: number;
  run_id: string;
  kind: AllowlistKind;
  value: string;
  note: string | null;
  created_at: string;
  // How many already-open matching alerts the create call auto-acked (0 on GET).
  acked: number;
}

export interface Suppression {
  id: number;
  rule_id: string;
  run_id: string | null;
  // Optional value scope — a sample name, related IP, or detail substring.
  // Set = only matching alerts are suppressed (e.g. beaconing →
  // "detonate-demo.sh"); null = the whole rule scope.
  value: string | null;
  reason: string | null;
  created_at: string;
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
  /** When the reputation verdict was last fetched (cache age); null = never. */
  checked_at: string | null;
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
  // DNS query string (Sysmon DNS / DNS-aware collectors) — the DNS-channel
  // rules read this.
  query?: string | null;
  // TLS Server Name Indication from the handshake (Sysmon Event ID 3
  // DestinationHostname) — the TLS-SNI / DoH rules read this.
  tls_sni?: string | null;
  // The collector's original payload (JSON) — the Event Viewer's raw-record
  // pane. Null for events ingested before the column existed.
  raw_record?: string | null;
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
  // Explainability: the tuning knobs that deviated from stock while this run
  // was evaluated (captured once, immutable) — "scored under" context.
  effective_tuning?: Record<string, number | string>;
  // Storm guard: per-rule alert-cap suppressed counts (first-seen /
  // enumeration-burst / network-scan) held back on a long live session.
  suppressed_alerts?: Record<string, number>;
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

// -- Enumeration pattern tables (rule 15, T1082) ----------------------------
// One regex+label row per platform; operators edit these in the Rules page
// and the change applies live to the next ingested batch (no restart).

export interface EnumPatternRow {
  pattern: string;
  label: string;
}

export interface EnumPatternsResponse {
  platforms: Record<string, EnumPatternRow[]>;
  defaults: Record<string, EnumPatternRow[]>;
}

// Anti-forensics pattern tables (log-service-stop / log-clearing) — the same
// operator-editable per-platform regex tables as enumeration, keyed by kind
// ("service_stop" | "log_clear").
export type LogPatternKind = "service_stop" | "log_clear";

export interface LogPatternsResponse {
  kinds: Record<LogPatternKind, Record<string, EnumPatternRow[]>>;
  defaults: Record<LogPatternKind, Record<string, EnumPatternRow[]>>;
}

// -- Rule packs — versioned, diffable rule-set export/import -----------------
// The whole operational rule surface as one JSON document (git-diffable):
// tuning overrides, suppressions, enum-pattern tables, FP threshold.

export interface RulePackSuppression {
  id?: number;
  rule_id: string;
  run_id: string | null;
  reason: string | null;
  created_at?: string;
}

export interface RulePack {
  schema: number;
  exported_at: string;
  tuning: TuningKnob[];
  suppressions: RulePackSuppression[];
  enum_patterns: Record<string, EnumPatternRow[]>;
  fp_threshold: number;
}

export interface RulePackImportSummary {
  schema: number;
  tuning_applied: number;
  suppressions_added: number;
  suppressions_skipped: number;
  enum_patterns_applied: boolean;
  fp_threshold_applied: boolean;
}

// -- Roadmap 3.1 — notification settings ---------------------------------------

export interface NotificationSettings {
  enabled: boolean;
  webhook_url: string;
  slack_webhook: string;
  discord_webhook: string;
  telegram_bot_token: string;
  telegram_chat_id: string;
  smtp_host: string;
  smtp_port: string | number;
  smtp_user: string;
  smtp_pass: string;
  smtp_pass_set: boolean;
  smtp_from: string;
  smtp_to: string;
}

export interface NotificationSettingsIn {
  webhook_url?: string;
  slack_webhook?: string;
  discord_webhook?: string;
  telegram_bot_token?: string;
  telegram_chat_id?: string;
  smtp_host?: string;
  smtp_port?: string | number;
  smtp_user?: string;
  smtp_pass?: string;
  smtp_from?: string;
  smtp_to?: string;
}

// -- Threat-intel API keys (Settings) ----------------------------------------
// Per-key status for the Settings UI — the backend NEVER returns the raw key,
// only whether it's set, where it came from (db / env fallback), and a masked
// suffix.

export interface IntelKeyStatus {
  name: "abuseipdb" | "virustotal";
  set: boolean;
  source: "db" | "env" | "none";
  suffix: string;
  /** Rotation hint — when the key was stored (db source) and its age in days. */
  set_at: string | null;
  age_days: number | null;
}

export interface IntelKeysResponse {
  keys: IntelKeyStatus[];
}

export interface KeyTestResult extends IntelKeyStatus {
  ok: boolean;
  detail: string;
}

export interface RunReEnrichResponse {
  run_id: string;
  ips_cleared: number;
  reputation: Record<string, string>;
}

export interface IpIntelRefreshResponse {
  ip: string;
  abuse_score: number | null;
  vt_malicious_count: number | null;
  reputation: Reputation;
  checked_at: string | null;
}

export interface IntelFreshness {
  total: number;
  stale_count: number;
  oldest_checked_at: string | null;
  oldest_age_hours: number | null;
}

export interface RefreshStaleResponse {
  refreshed: number;
  rows: { ip: string; reputation: Reputation; checked_at: string | null }[];
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

export interface ReputationEvidence {
  abuse_score: number | null;
  vt_malicious_count: number | null;
  reputation: Reputation | null;
  checked_at: string | null;
}

export interface IocSearchResponse {
  value: string;
  count: number;
  returned: number;
  // Cached enrichment evidence for IP searches — the "is it bad?" half of
  // "have I seen this before?", so the verdict rides along with the matches.
  reputation?: ReputationEvidence | null;
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
  // True when the binary's entire detonation history comes from demo/synthetic
  // provenance — hidden by default on the vault page, flagged when shown.
  synthetic?: boolean;
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

// -- Static analysis (strings / IOCs / PE / ELF) -----------------------------

export interface StaticIocs {
  urls: string[];
  ips: string[];
  domains: string[];
  hashes: string[];
  emails: string[];
}

export interface PeSection {
  name: string;
  virtual_size: number;
  raw_size: number;
  flags: string[];
}

export interface PeMetadata {
  machine: string;
  bits: number | null;
  entry_point_rva: number | null;
  sections: PeSection[];
  imports: string[];
}

export interface ElfSection {
  name: string;
  type: number;
  size: number;
}

export interface ElfMetadata {
  class: number;
  endian: string;
  type: string;
  machine: string;
  entry_point: number;
  sections: ElfSection[];
}

export interface SampleStatic {
  sample_id: string;
  sha256: string;
  /** false when the sample's bytes were never stored (pre-persistence
   *  uploads) — the detail panel renders its re-upload state from this flag
   *  instead of a 404. */
  available: boolean;
  size: number;
  strings: string[];
  iocs: StaticIocs;
  pe: PeMetadata | null;
  elf: ElfMetadata | null;
  entropy?: number;
  is_packed?: boolean;
  capabilities?: Array<{ category: string; matched: string[]; confidence: string }>;
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
  // Honest total — the backend caps `timeline` at the 300 most recent rows.
  timeline_total?: number;
  // Roadmap 2.4 — correlated chain across members.
  chain_links?: KillChainLink[];
  chain_label?: string | null;
  propagation_graph?: PropagationGraph;
}

export interface PropagationNode {
  id: string;
  type: string;
  first_seen: string | null;
  events: number;
}

export interface PropagationEdge {
  source: string;
  target: string;
  type: string;
  label: string;
}

export interface PropagationGraph {
  nodes: PropagationNode[];
  edges: PropagationEdge[];
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
  // The alert severity the rule actually fires with (backend RULE_META) —
  // lets the coverage matrix tone chips by real severity, not weight.
  severity: Severity;
  // Per-alert remediation guidance — a short "what to do" checklist rendered
  // as an expandable block on each finding card.
  remediation?: string[];
}

// -- Global event feed / Event Viewer (roadmap 1.1) -------------------------

export interface EventFeedEvent extends EventOut {
  sample_name: string;
  session_type: SessionType;
  /** Run provenance — the Event Log's source tabs: live | webapp | sandbox. */
  source: string;
  /** The exact log channel a collector stamped on the event (auditd / sysmon)
   *  — the source tabs split the collector stream by this, not by platform. */
  log_source?: string | null;
  run_severity: Severity | null;
  host_id?: string | null;
}

// -- Agent fleet (which hosts stream telemetry) ------------------------------

export interface AgentInfo {
  host_id: string;
  last_seen: string;
  online: boolean;
  /** Heartbeated before but quiet past the silent window — the dead-agent flag. */
  silent?: boolean;
  /** Latest liveness ping — present when the agent heartbeats. */
  last_heartbeat?: string | null;
  heartbeat_age_seconds?: number | null;
  heartbeat_version?: string | null;
  /** How the host authenticated at its last heartbeat: 'agent' (the shared
   * OUTPOST_AGENT_TOKEN), 'admin'/'analyst' (browser roles), or 'local'
   * (auth off / no credential). Null when the host never heartbeated. */
  last_auth_role?: string | null;
  /** When the host last authenticated (heartbeat). */
  last_auth_at?: string | null;
  /** 'collector' = real agent heartbeat (collector-shipped host),
   * 'webapp' = event-only host (local detonations / sandbox runs). */
  identity?: "collector" | "webapp";
  /** Distinct event channels shipped by the host (auditd / sysmon / webapp). */
  channels?: string[];
  /** Per-channel event volume — the telemetry mix (auditd: 12, sysmon: 340, …). */
  channel_counts?: Record<string, number>;
  event_count: number;
  run_count: number;
  alert_count: number;
  platforms: string[];
  recent_run_ids?: string[];
  /** Latest live snapshot time — present when the agent shipped one. */
  last_snapshot_at?: string | null;
}

export interface AgentsResponse {
  total: number;
  online: number;
  silent: number;
  online_window_seconds: number;
  silent_window_seconds: number;
  agents: AgentInfo[];
}

// -- Analyst audit trail -------------------------------------------------------

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: string | null;
}

export interface AuditResponse {
  total: number;
  limit: number;
  action: string | null;
  events: AuditEntry[];
}

// -- False-positive feedback loop ----------------------------------------------

export interface FpSuggestion {
  kind: "threshold" | "suppress";
  param?: string;
  current?: number;
  suggested?: number;
  run_id?: string;
  rule_id?: string;
  detail: string;
}

export interface FpResponse {
  alert_id: number;
  rule_id: string;
  fp_count: number;
  suggestions: FpSuggestion[];
}

// -- Live system snapshot (processes + listening ports) ------------------------

export interface SnapshotProcess {
  pid: number;
  name: string;
  user?: string;
  cmdline?: string;
}

export interface SnapshotListener {
  proto: string;
  addr: string;
  port: number;
  pid: number | null;
}

export interface HostSnapshot {
  host_id: string;
  platform: string;
  collected_at: string;
  processes: SnapshotProcess[];
  listening: SnapshotListener[];
  stored_at?: string;
}

// -- Retention & backup --------------------------------------------------------

export interface RetentionStatus {
  retention_days: number;
  auto_prune: "off" | "hourly" | "daily";
  auto_prune_enabled: boolean;
  last_prune_at: string | null;
  next_prune_in_seconds: number | null;
}

// -- Rule false-positive surface (Rules page tuning panel) --------------------

export interface RuleFpSuggestion {
  kind: string;
  param: string;
  rule_id: string;
  current: number;
  suggested: number;
  detail: string;
}

export interface FpDayPoint {
  day: string;
  fired: number;
  fp: number;
}

export interface RuleFpEntry {
  rule_id: string;
  count: number;
  /** Total alerts fired for this rule (the FP-rate denominator). */
  fired_count: number;
  last_fp_at: string;
  over_threshold: boolean;
  suggestion: RuleFpSuggestion | null;
  /** 14-day fired/FP history — the FP-rate trend (FP ÷ fired over time). */
  history: FpDayPoint[];
}

export interface RuleFpResponse {
  threshold: number;
  default_threshold: number;
  rules: RuleFpEntry[];
}

// -- Triage queue (the analyst work list) -------------------------------------

export interface QueueAlert {
  id: number;
  run_id: string;
  sample_name: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  triggered_at: string;
  status: AlertStatus;
  status_comment: string | null;
  status_at: string | null;
  assignee: string | null;
  related_pid: number | null;
  related_ip: string | null;
  related_pids: number[];
  host_ids: string[];
  details: string;
  // P0.3: nullable link to the optional cross-workflow investigation overlay.
  investigation_id?: string | null;
  source?: string | null;
  run_source?: string | null;
}

export interface QueueResponse {
  total: number;
  open: number;
  acknowledged: number;
  resolved: number;
  sort: string;
  limit: number;
  offset: number;
  alerts: QueueAlert[];
}

// -- P1.1 — Investigations (P0.3 backend: optional cross-workflow case anchor) --
// Mirrors backend/app/core/schema.py InvestigationDTO + detail payload.

export type InvestigationStatus =
  | "created"
  | "triage"
  | "active"
  | "contained"
  | "resolved"
  | "closed";

export type InvestigationRefType = "artifact" | "run" | "host" | "ioc" | "campaign";

export type FindingSource = "detection" | "analyst" | "correlation";
export type Confidence = "high" | "medium" | "low";
export type Disposition =
  | "false-positive"
  | "confirmed-malicious"
  | "benign"
  | "watchlisted"
  | "escalated";

/** The P0 finding layer on top of the physical alerts rows — the backend
 *  FindingDTO is a compatible superset of Alert, so this extends Alert with
 *  the additive fields rather than duplicating the base. */
export interface Finding extends Alert {
  source: FindingSource;
  confidence: Confidence | null;
  disposition: Disposition | null;
  seen_at: string | null;
  investigation_id: string | null;
}

export interface Investigation {
  id: string;
  title: string;
  status: InvestigationStatus;
  severity: Severity | null;
  conclusion: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string | null;
  closed_at: string | null;
  finding_count: number;
  ref_count: number;
  tags: string[];
}

export interface InvestigationRef {
  investigation_id: string;
  ref_type: InvestigationRefType;
  ref_id: string;
  added_at: string;
}

export interface InvestigationNote {
  id: number;
  investigation_id: string;
  note: string;
  actor: string;
  created_at: string;
}

export interface InvestigationDetail extends Investigation {
  findings: Finding[];
  refs: InvestigationRef[];
  notes: InvestigationNote[];
}

export interface InvestigationListResponse {
  total: number;
  limit: number;
  offset: number;
  investigations: Investigation[];
}

// -- Host behavioral baseline (anomaly layer) ---------------------------------

export interface BaselineObservation {
  kind: string;
  value: string;
  count: number;
  last_seen: string;
}

export interface HostBaseline {
  host_id: string;
  total_observations: number;
  distinct_observations: number;
  processes: BaselineObservation[];
  networks: BaselineObservation[];
  anomaly_count: number;
}

export interface PruneResponse {
  deleted_runs: number;
  days: number;
  cutoff: string;
}

// -- Auth brute-force guard (read-only Settings view) -------------------------

export interface LockedIp {
  ip: string;
  remaining_seconds: number;
}

export interface RateLimitStatus {
  enabled: boolean;
  max_attempts: number;
  window_seconds: number;
  lockout_seconds: number;
  tracked_ips: number;
  locked_ips: number;
  locked: LockedIp[];
}

export interface EventFeedResponse {
  total: number;
  returned: number;
  limit: number;
  offset: number;
  events: EventFeedEvent[];
}

export type EventSource = "live" | "webapp" | "sandbox" | "auditd" | "sysmon";

/** Per-channel totals for the Event Log's source-tab rail — one query for all
 *  six tabs. `total` is the grand count (the "All sources" tab); `channels`
 *  buckets each filtered event into every channel it belongs to (auditd /
 *  sysmon are cross-cutting log_source stamps, so they overlap live). */
export interface ChannelCountsResponse {
  total: number;
  channels: Record<EventSource, number>;
}

/** /events/counts — the ENTIRE Event Log rail (category + channel buckets)
 *  in one request. `types` partitions `types.all` (which honors the active
 *  source facet); `channels` is the source split and never takes it. */
export interface EventCountsResponse {
  total: number;
  types: {
    all: number;
    process_create: number;
    network_connection: number;
    file_write: number;
    registry_write: number;
  };
  channels: {
    total: number;
    live: number;
    sandbox: number;
    webapp: number;
    auditd: number;
    sysmon: number;
  };
}

export interface EventFeedParams {
  event_type?: EventType | "";
  platform?: Platform | "";
  severity?: Severity | "";
  q?: string;
  // Process-centric drill-down: everything one PID did. Comma-separated list
  // supported (the recon-sweep jump — every enumerating PID at once).
  pid?: string;
  // Provenance facet — the Event Log's source tabs (Collectors / Webapp / Sandbox).
  source?: EventSource | "";
  // Synthetic provenance (seeds / webapp detonations / the sandbox demo) is
  // hidden by default — the Event Log reads as real telemetry first, like the
  // History archive. Explicit source tabs and pid drill-downs pass true.
  include_synthetic?: boolean;
  limit?: number;
  offset?: number;
}

// -- App metadata (GET /meta) ------------------------------------------------

export interface MetaInfo {
  demo_mode: boolean;
  version: string;
  /** True only while no onboarding choice is recorded AND no sessions exist —
   *  the router shows the welcome screen instead of an empty deck. */
  first_run: boolean;
  /** The first-run choice: "demo" | "empty", or null before it's made. */
  onboarding: string | null;
}

// -- Host watch (GET /hosts/{host}/watch) — Monitor 'watch a host' mode ------

export interface HostWatchResponse {
  run_id: string;
  open: boolean;
  run: RunSummary;
}

// -- Process summary (GET /events/process-summary) — the hover preview card --

export interface ProcessSummary {
  pid: number;
  ppid?: number | null;
  process_name: string | null;
  command_line: string | null;
  platform: Platform;
  host_id: string;
  run_id: string;
  sample_name: string;
  event_count: number;
  alert_count: number;
  children?: { pid: number; process_name: string | null; command_line: string | null }[];
  network_connections?: { dest_ip: string; dest_port: number | null; protocol: string | null }[];
  files_written?: string[];
  findings?: { id: number; rule_id: string; rule_name: string; severity: string; details: string }[];
}

export interface NetworkSummary {
  dest_ip: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  hosts: string[];
  processes: { pid: number; process_name: string | null; command_line: string | null }[];
  ports: { dest_port: number | null; protocol: string | null }[];
  watchlist?: { notes: string | null } | null;
  findings: { id: number; rule_id: string; rule_name: string; severity: string; details: string; run_id: string }[];
}

export interface FileSummary {
  file_path: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  hosts: string[];
  processes: { pid: number; process_name: string | null; command_line: string | null }[];
  findings: { id: number; rule_id: string; rule_name: string; severity: string; details: string; run_id: string }[];
}

// -- Dashboard / global findings feed ----------------------------------------

export interface GlobalAlert extends Alert {
  sample_name: string;
}

// -- YARA signature lab (custom rule authoring) ------------------------------

export interface YaraTestSample {
  sample_id: string;
  original_name: string;
  detected_platform: string;
  size: number;
  matched: boolean;
  hits: string[];
}

export interface YaraTestResponse {
  compiled: boolean;
  rule_name: string;
  error?: string;
  total?: number;
  matched?: number;
  samples?: YaraTestSample[];
}

export interface CustomYaraRule {
  name: string;
  family: string;
  description: string;
  strings: string[];
  source: string;
}

export interface CustomYaraRulesResponse {
  count: number;
  rules: CustomYaraRule[];
}

// -- Sandbox detonation adapter (roadmap 3.3) --------------------------------

export interface SandboxProviderInfo {
  id: string;
  name: string;
  configured: boolean;
}

export interface SandboxProvidersResponse {
  providers: SandboxProviderInfo[];
  active: string;
  mode: "live" | "demo";
}

export type SandboxTaskStatus = "submitted" | "running" | "completed" | "error";

export interface SandboxTask {
  task_id: string;
  run_id: string;
  sample_id: string;
  sample_name: string;
  provider: string;
  platform: Platform;
  status: SandboxTaskStatus;
  events: number;
  alerts: number;
  risk_score: number;
  highest_severity: Severity | null;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface SandboxDetonateIn {
  sample_id: string;
  provider: string;
  platform?: Platform;
  note?: string;
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
  /** When the reputation verdict was last fetched (cache age); null = never. */
  checked_at: string | null;
}

export interface FootprintPassive {
  source: "not_configured" | "synthetic_demo" | "live";
  resolutions: { domain: string; first_seen: string; last_seen: string; synthetic?: boolean }[];
  // crt.sh passive-DNS history — every hostname the CT logs have seen for the
  // seed infrastructure, aggregated into a first→last seen range per domain.
  // `source_ip` is the seed (or sibling) IP the name was observed from, so
  // infra beyond the apex domain is traceable back to its cohosted host.
  passive_dns: { domain: string; first_seen: string; last_seen: string; synthetic?: boolean; source_ip?: string }[];
  // Subdomain discovery — crt.sh `%.<apex>` CT-log enumeration over the
  // PTR-derived domain's apex, deduped against the passive-DNS history and
  // tagged with the seed IP it was observed from.
  subdomains?: { domain: string; apex?: string; first_seen: string; last_seen: string; synthetic?: boolean; source_ip?: string }[];
  certificates: { cn: string; issuer: string; not_before: string; not_after: string; synthetic?: boolean }[];
  sibling_ips: { ip: string; relation: string; synthetic?: boolean }[];
  // RDAP registration info per seed IP (live only): network name, CIDR,
  // organization, country, plus the WHOIS-style registration timeline
  // (registrar + created/updated/expires) from the same RDAP payload.
  networks: {
    ip: string;
    cidr: string;
    netname: string | null;
    org: string | null;
    country: string | null;
    registrar?: string | null;
    created?: string | null;
    updated?: string | null;
    expires?: string | null;
    synthetic?: boolean;
  }[];
  // ASN / owner mapping per seed IP (keyless ip-api.com, live only): the
  // autonomous-system identity the registration sits on.
  asn: { ip: string; asn: string | null; as_name: string | null; org: string | null; country: string | null; country_code: string | null }[];
  // WHOIS record for the PTR-derived domain's apex (domain-level RDAP, same
  // keyless provider): registrar, created/updated/expires, status, nameservers.
  whois?: {
    domain: string;
    registrar: string | null;
    created: string | null;
    updated: string | null;
    expires: string | null;
    status: string[];
    nameservers: string[];
    synthetic?: boolean;
  }[];
}

export interface FootprintBreachRow {
  email: string;
  breaches: string[];
  synthetic?: boolean;
}

export interface Footprint {
  sample: { sample_id: string; name: string; sha256: string; platform: Platform; family: string | null };
  runs: { run_id: string; sample_name: string; started_at: string; completed_at: string | null }[];
  seed_ips: FootprintSeedIp[];
  passive: FootprintPassive;
  breach: { source: "live" | "no_emails" | "synthetic_demo"; rows: FootprintBreachRow[] };
  status: { roadmap: boolean; generated: "mock" | null };
}

// Roadmap 2.5 — cross-sample infra topology: every IP that ≥2 samples
// reached, with the member samples and run ids. The campaign-correlation
// view: one C2 box, several binaries.
export interface TopologyClusterMember {
  sample_name: string;
  hits: number;
  run_ids: string[];
}

export interface TopologyCluster {
  ip: string;
  sample_count: number;
  members: TopologyClusterMember[];
  reputation: Reputation | "unknown";
  checked_at: string | null;
}

export interface TopologyResponse {
  clusters: TopologyCluster[];
  total_samples: number;
}

// -- P0.5/P0.6/P0.7 client contracts ------------------------------
// Global search (GET /search): one grouped envelope across findings, iocs,
// artifacts, hosts, sessions, investigations, campaigns.
export type SearchGroup =
  | "findings"
  | "iocs"
  | "artifacts"
  | "hosts"
  | "sessions"
  | "investigations"
  | "campaigns";

export interface SearchHit {
  group: SearchGroup;
  id: string;
  kind?: string | null;
  title: string;
  subtitle?: string | null;
  payload: Record<string, unknown>;
}

export interface SearchGroupResult {
  total: number;
  hits: SearchHit[];
}

export interface SearchResponse {
  q: string;
  qualifiers: Record<string, string>;
  groups: Record<SearchGroup, SearchGroupResult>;
}

// Host aggregate timeline (GET /hosts/{host_id}/timeline): the merged
// chronological feed of events/findings/sessions/iocs/investigations.
export type TimelineKind = "event" | "finding" | "session" | "ioc" | "investigation";

export interface HostTimelineEntry {
  kind: TimelineKind;
  timestamp: string;
  id: string;
  title: string;
  subtitle?: string | null;
  payload: Record<string, unknown>;
}

export interface HostTimeline {
  host_id: string;
  platform?: string | null;
  last_heartbeat?: string | null;
  total: number;
  limit: number;
  offset: number;
  timeline: HostTimelineEntry[];
}

// Analysis jobs (POST/GET /analysis): the persisted job record; run_id
// doubles as the job id.
export type AnalysisBackend =
  | "static"
  | "watched-host"
  | "external-provider"
  | "isolated-outpost";
export type AnalysisStatus = "queued" | "running" | "completed" | "failed" | "canceled";

export interface AnalysisJob {
  run_id: string;
  backend: AnalysisBackend;
  status: AnalysisStatus;
  timeout_seconds?: number | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  progress: number;
  result?: Record<string, unknown> | null;
  sample_name?: string | null;
  events: number;
  alerts: number;
  risk_score: number;
}

export interface AnalysisJobCreateIn {
  backend: AnalysisBackend;
  sample_id?: string;
  sample_name?: string;
  platform?: Platform;
  timeout_seconds?: number;
}

export interface AnalysisJobsResponse {
  total: number;
  limit: number;
  offset: number;
  jobs: AnalysisJob[];
}

/** One row of the observations-shaped payload (GET /analysis/{run_id}/
 *  observations). Static jobs emit {kind, data} pairs — strings/iocs/pe/elf
 *  from the stored analysis result; dynamic jobs emit raw event rows (no
 *  observations table exists — P0 defers it), which arrive as plain event
 *  dicts without a kind wrapper. The optional fields below cover that
 *  event-row fallback shape. */
export interface AnalysisObservation {
  kind?: string;
  data?: unknown;
  // event-row fallback (dynamic backends)
  id?: number | null;
  run_id?: string;
  event_type?: EventType;
  timestamp?: string;
  pid?: number | null;
  process_name?: string | null;
  command_line?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  file_path?: string | null;
  registry_key?: string | null;
}

export interface AnalysisObservationsResponse {
  backend: AnalysisBackend;
  observations: AnalysisObservation[];
}

export interface LocalMonitorStatus {
  active: boolean;
  run_id: string | null;
  interval?: number;
  events_emitted?: number;
  error?: string | null;
}

export interface DynamicDetonationResult {
  run_id: string;
  sample_id: string;
  sample_name: string;
  platform: Platform;
  verdict: "clean" | "suspicious" | "malicious";
  exit_code: number;
  stdout: string;
  stderr: string;
  risk_score: number;
  alerts_count: number;
  alerts: Alert[];
  process_tree: ProcessNode[];
  kill_chain?: KillChainLink[];
  events_count: number;
}

export interface DetectionSuite {
  run_id: string;
  sample_name?: string | null;
  counts: {
    sigma: number;
    suricata: number;
    yara: number;
    total: number;
  };
  sigma: string[];
  suricata: string[];
  yara: string[];
}

export interface AttackPlaybook {
  id: string;
  name: string;
  description: string;
  platform: Platform;
  severity: "clean" | "suspicious" | "malicious" | "critical";
  tactics: string[];
  techniques: string[];
}

export interface PlaybookDetonateResult {
  run_id: string;
  playbook_id: string;
  name: string;
  platform: Platform;
  event_count: number;
  alert_count: number;
  risk_score: number;
  highest_severity: Severity | null;
}


