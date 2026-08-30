// All backend calls, centralized — never inline fetch in components (docs/04).
// Structurally mirrors cli/outpost/lib/api_client.py: the webapp and CLI are
// two separate surfaces over the same API; nothing is CLI-only.

import type {
  AgentsResponse,
  RateLimitStatus,
  Alert,
  AlertStatus,
  AllowlistEntry,
  AllowlistKind,
  AuditResponse,
  CompareResponse,
  EnumPatternRow,
  EnumPatternsResponse,
  LogPatternKind,
  LogPatternsResponse,
  EventIn,
  Campaign,
  HostWatchResponse,
  MetaInfo,
  ChannelCountsResponse,
  EventCountsResponse,
  EventFeedParams,
  EventFeedResponse,
  Footprint,
  TopologyResponse,
  RuleFpResponse,
  FpResponse,
  GlobalAlert,
  HostSnapshot,
  IocSearchResponse,
  NotificationSettings,
  NotificationSettingsIn,
  Platform,
  PlatformInfo,
  PruneResponse,
  RetentionStatus,
  RuleMeta,
  RunDetail,
  RunNote,
  RunSummary,
  SampleMeta,
  SampleRow,
  SamplesResponse,
  SampleStatic,
  SampleDetonationResult,
  SandboxDetonateIn,
  SandboxProvidersResponse,
  SandboxTask,
  SessionType,
  CustomYaraRulesResponse,
  YaraTestResponse,
  Suppression,
  TuningResponse,
  WatchlistEntry,
  WatchlistImportResponse,
  QueueResponse,
  HostBaseline,
  ProcessSummary,
  NetworkSummary,
  FileSummary,
  RulePack,
  RulePackImportSummary,
  IntelKeysResponse,
  IntelKeyStatus,
  KeyTestResult,
  RunReEnrichResponse,
  IpIntelRefreshResponse,
  IntelFreshness,
  RefreshStaleResponse,
  SearchResponse,
  HostTimeline,
  TimelineKind,
  AnalysisBackend,
  AnalysisStatus,
  AnalysisJob,
  AnalysisJobCreateIn,
  AnalysisJobsResponse,
  AnalysisObservationsResponse,
  Finding,
  Investigation,
  InvestigationDetail,
  InvestigationListResponse,
  InvestigationStatus,
  InvestigationRef,
  InvestigationRefType,
  InvestigationNote,
} from "../types";

export const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// -- Optional auth (backend env-gated) --------------------------------------
// Token lives in localStorage; every request carries it when present. The
// login screen and the router gate read/write via these helpers.
const TOKEN_KEY = "outpost-token";

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export interface MeResponse {
  enabled: boolean;
  authenticated: boolean;
  role: "admin" | "analyst" | null;
  read_only: boolean;
  credential_mode: "hash" | "plaintext" | null;
  expires_at: number | null;
}

export async function getMe(): Promise<MeResponse> {
  const headers = authHeaders();
  const res = await fetch(`${BASE_URL}/auth/me`, { headers });
  if (!res.ok) throw new Error(`GET /auth/me → ${res.status}`);
  return res.json();
}

export async function login(password: string): Promise<{ token: string; role: string; read_only: boolean }> {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(detail || `POST /auth/login → ${res.status}`);
  }
  return res.json();
}

export async function setPassword(role: "admin" | "analyst", newPassword: string): Promise<{ role: string; credential_mode: string }> {
  const res = await fetch(`${BASE_URL}/auth/password`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ role, new_password: newPassword }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(detail || `POST /auth/password → ${res.status}`);
  }
  return res.json();
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = getAuthToken();
  const base: Record<string, string> = {};
  if (token) base.Authorization = `Bearer ${token}`;
  return { ...base, ...extra };
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json();
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`PUT ${path} → ${res.status}`);
  return res.json();
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "PATCH",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`PATCH ${path} → ${res.status}`);
  return res.json();
}

async function del(path: string): Promise<void> {
  const res = await fetch(`${BASE_URL}${path}`, { method: "DELETE", headers: authHeaders() });
  // DELETE contracts vary: 204 (no content) is the REST-canonical success, but
  // a backend may 200 with a body (e.g. a summary of what was removed). Both
  // are success — only a non-ok status is an error. Regression: this used to
  // require exactly 204, so a 200-with-body DELETE threw a misleading
  // "DELETE ... → 200" error.
  if (!res.ok) throw new Error(`DELETE ${path} → ${res.status}`);
}

// -- health -----------------------------------------------------------------
export async function getHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE_URL}/health`, { headers: authHeaders() });
    return res.ok;
  } catch {
    return false; // unreachable — the deck's pulse reads offline
  }
}

// Host-OS auto-detection (vision: no manual OS picker anywhere).
export async function getPlatform(): Promise<PlatformInfo> {
  return get<PlatformInfo>("/platform");
}

// App metadata — demo-mode flag (seeded data vs real telemetry) + version
// + first-run state (the router shows the welcome screen until it's resolved).
export async function getMeta(): Promise<MetaInfo> {
  return get<MetaInfo>("/meta");
}

// First-run choice: seed the labeled demo campaign, or start empty.
export async function onboard(choice: "demo" | "empty"): Promise<{ status: string; choice: string; demo_mode: boolean }> {
  return post("/setup/onboard", { choice });
}

export type ResetResult = {
  status: string;
  host_id: string;
  kept_runs: number;
  demo_mode: boolean;
  deleted_runs: number;
  deleted_events: number;
  deleted_alerts: number;
  deleted_samples?: number;
};

export async function resetStore(scope: "demo" | "all" = "demo", purgeSamples: boolean = false): Promise<ResetResult> {
  return post<ResetResult>("/setup/reset", { scope, purge_samples: purgeSamples });
}

// -- runs -------------------------------------------------------------------
export async function getRuns(params: { q?: string; host?: string; include_synthetic?: boolean; include_soak?: boolean } = {}): Promise<RunSummary[]> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.host) qs.set("host", params.host);
  // The archive API hides synthetic provenance (seeds / webapp detonations /
  // the sandbox demo) and soak-named collector baselines by default. Surfaces
  // that want the full story (Overview, palette, sample detonation history)
  // explicitly opt back in to keep their behavior; the History page passes
  // both flags explicitly from its toggles.
  qs.set("include_synthetic", params.include_synthetic === false ? "false" : "true");
  qs.set("include_soak", params.include_soak === false ? "false" : "true");
  return get<RunSummary[]>(`/runs?${qs.toString()}`);
}

export async function getRunDetail(runId: string): Promise<RunDetail> {
  return get<RunDetail>(`/runs/${runId}`);
}

export async function createRun(sampleName: string, platform: Platform, sessionType: SessionType, source?: string): Promise<{ run_id: string }> {
  return post<{ run_id: string }>("/runs", { sample_name: sampleName, platform, session_type: sessionType, ...(source ? { source } : {}) });
}

export async function completeRun(runId: string): Promise<void> {
  await post(`/runs/${runId}/complete`, {});
}

export async function ingestBatch(events: EventIn[]): Promise<{ accepted: number; alerts: number }> {
  return post<{ accepted: number; alerts: number }>("/ingest/batch", events);
}

// Campaign STIX bundle (cluster → MISP/OpenCTI) + MITRE Navigator layer, both
// as Blob downloads so the ExportButton's fetcher signature covers them.
export async function getCampaignStix(key: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/campaigns/${encodeURIComponent(key)}/export?format=stix`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /campaigns/${key}/export → ${res.status}`);
  return res.blob();
}

export async function getNavigatorLayer(): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/coverage/navigator`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /coverage/navigator → ${res.status}`);
  return res.blob();
}

export async function getRunExport(runId: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/export`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /runs/${runId}/export → ${res.status}`);
  return res.blob();
}

// Footprint threat-intel handoff — the passive layer (passive DNS, certs,
// registration/ASN) as a structured JSON payload or a flat CSV IOC sheet.
export async function exportFootprint(sampleId: string, format: "json" | "csv", mock: boolean): Promise<Blob> {
  const res = await fetch(
    `${BASE_URL}/footprint/${encodeURIComponent(sampleId)}/export?format=${format}&mock=${mock ? 1 : 0}`,
    { headers: authHeaders() }
  );
  if (!res.ok) throw new Error(`GET /footprint/${sampleId}/export → ${res.status}`);
  return res.blob();
}

export async function getRunIocsCsv(runId: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/iocs?format=csv`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /runs/${runId}/iocs → ${res.status}`);
  return res.blob();
}

// -- Phase 6 webapp surfaces --------------------------------------------------
export async function searchIocs(value: string): Promise<IocSearchResponse> {
  return get<IocSearchResponse>(`/ioc/search?value=${encodeURIComponent(value)}`);
}

export async function compareRuns(a: string, b: string): Promise<CompareResponse> {
  return get<CompareResponse>(`/runs/${a}/compare/${b}`);
}

export async function getRules(runId: string, format: "suricata" | "sigma"): Promise<string> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/rules?format=${format}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /runs/${runId}/rules → ${res.status}`);
  return res.text();
}

export async function watchlistList(): Promise<WatchlistEntry[]> {
  return get<WatchlistEntry[]>("/watchlist");
}

export async function watchlistAdd(value: string, label: string): Promise<WatchlistEntry> {
  return post<WatchlistEntry>("/watchlist", { value, label });
}

export async function watchlistRemove(value: string): Promise<void> {
  await del(`/watchlist/${encodeURIComponent(value)}`);
}

export async function watchlistExport(format: "json" | "csv"): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/watchlist/export?format=${format}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /watchlist/export → ${res.status}`);
  return res.blob();
}

export async function watchlistImport(entries: { value: string; label?: string }[]): Promise<WatchlistImportResponse> {
  return post<WatchlistImportResponse>("/watchlist/import", { entries });
}

// -- Roadmap 2.3 — rule tuning ------------------------------------------------
export async function getTuning(): Promise<TuningResponse> {
  return get<TuningResponse>("/rules/tuning");
}

export async function getEnumPatterns(): Promise<EnumPatternsResponse> {
  return get<EnumPatternsResponse>("/rules/enum-patterns");
}

export async function setEnumPatterns(patterns: Record<string, EnumPatternRow[]>): Promise<{ platforms: Record<string, EnumPatternRow[]> }> {
  const res = await fetch(`${BASE_URL}/rules/enum-patterns`, {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ patterns }),
  });
  if (!res.ok) throw new Error(`PUT /rules/enum-patterns → ${res.status}`);
  return res.json();
}

export async function getLogPatterns(): Promise<LogPatternsResponse> {
  return get<LogPatternsResponse>("/rules/log-patterns");
}

export async function resetRules(): Promise<{ tuning_cleared: number; suppressions_cleared: number; settings_cleared: number }> {
  const res = await fetch(`${BASE_URL}/rules/reset`, {
    method: "DELETE",
    headers: authHeaders({}),
  });
  if (!res.ok) throw new Error(`DELETE /rules/reset → ${res.status}`);
  return res.json();
}

export async function setLogPatterns(
  patterns: Record<LogPatternKind, Record<string, EnumPatternRow[]>>,
): Promise<{ kinds: Record<LogPatternKind, Record<string, EnumPatternRow[]>> }> {
  const res = await fetch(`${BASE_URL}/rules/log-patterns`, {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ patterns }),
  });
  if (!res.ok) throw new Error(`PUT /rules/log-patterns → ${res.status}`);
  return res.json();
}

export async function setTuning(param: string, value: string): Promise<{ current: string }> {
  return put<{ current: string }>(`/rules/tuning/${param}`, { value });
}

export async function getRuleFp(): Promise<RuleFpResponse> {
  return get<RuleFpResponse>("/rules/fp");
}

export async function setFpThreshold(threshold: number): Promise<{ threshold: number }> {
  return put<{ threshold: number }>("/rules/fp-threshold", { threshold });
}

export async function resetFpThreshold(): Promise<void> {
  return del("/rules/fp-threshold");
}

export async function resetTuning(param: string): Promise<void> {
  await del(`/rules/tuning/${param}`);
}

// -- Threat-intel API keys (Settings) ------------------------------------------
export async function getIntelKeys(): Promise<IntelKeysResponse> {
  return get<IntelKeysResponse>("/settings/keys");
}

export async function setIntelKey(name: string, value: string): Promise<IntelKeyStatus> {
  return put<IntelKeyStatus>(`/settings/keys/${name}`, { value });
}

export async function clearIntelKey(name: string): Promise<void> {
  return del(`/settings/keys/${name}`);
}

export async function testIntelKey(name: string): Promise<KeyTestResult> {
  return post<KeyTestResult>(`/settings/keys/${name}/test`, {});
}

/** Drop a run's cached IP/hash intel and re-run enrichment with the current
 *  keys — the 'I just added a key' button on run detail. */
export async function reEnrichRun(runId: string): Promise<RunReEnrichResponse> {
  return post<RunReEnrichResponse>(`/runs/${runId}/re-enrich`, {});
}

/** Bypass the enrichment TTL ONCE for one destination IP of a run — the
 *  per-row 'force refresh' on the run detail network panel. */
export async function refreshIpIntel(runId: string, ip: string): Promise<IpIntelRefreshResponse> {
  return post<IpIntelRefreshResponse>(`/runs/${runId}/enrichment/refresh?ip=${encodeURIComponent(ip)}`, {});
}

/** Global one-shot TTL bypass for any IP — the Footprint page's per-seed
 *  force refresh (sample-scoped, across runs). */
export async function refreshEnrichmentIp(ip: string): Promise<IpIntelRefreshResponse> {
  return post<IpIntelRefreshResponse>(`/enrichment/${encodeURIComponent(ip)}/refresh`, {});
}

/** Cache-age summary over the enrichment cache (Overview freshness strip). */
export async function getIntelFreshness(): Promise<IntelFreshness> {
  return get<IntelFreshness>("/intel/freshness");
}

/** The stale-only maintenance sweep: re-query just the cache rows past the
 *  TTL (oldest first, capped). Settings button + `outpost refresh --stale`. */
export async function refreshStaleIntel(max = 50): Promise<RefreshStaleResponse> {
  return post<RefreshStaleResponse>(`/intel/refresh-stale?max=${max}`, {});
}

// -- Rule packs — versioned, diffable rule-set export/import -------------------
export async function exportRulePack(): Promise<RulePack> {
  return get<RulePack>("/rules/pack");
}

export async function importRulePack(pack: RulePack): Promise<RulePackImportSummary> {
  return post<RulePackImportSummary>("/rules/pack", pack);
}

// -- Alert triage (analyst workflow) -------------------------------------------
export async function updateAlertStatus(alertId: number, status: AlertStatus, comment?: string): Promise<Alert> {
  return patch<Alert>(`/alerts/${alertId}`, { status, comment: comment ?? "" });
}

/** Attach/detach a finding to an investigation (PATCH /alerts/{id} with the
 *  nullable investigation_id link — P0.3). The backend PATCH contract
 *  requires `status`, so the caller passes the finding's CURRENT status —
 *  the link change never moves the triage state. Pass null to detach. */
export async function setAlertInvestigation(
  alertId: number,
  investigationId: string | null,
  currentStatus: AlertStatus,
): Promise<Alert> {
  return patch<Alert>(`/alerts/${alertId}`, { status: currentStatus, investigation_id: investigationId });
}

export async function getRunAllowlist(runId: string): Promise<AllowlistEntry[]> {
  return get<AllowlistEntry[]>(`/runs/${runId}/allowlist`);
}

export async function addRunAllowlist(runId: string, kind: AllowlistKind, value: string, note?: string): Promise<AllowlistEntry> {
  return post<AllowlistEntry>(`/runs/${runId}/allowlist`, { kind, value, note: note ?? "" });
}

export async function removeRunAllowlist(runId: string, entryId: number): Promise<void> {
  await del(`/runs/${runId}/allowlist/${entryId}`);
}

export async function getSuppressions(): Promise<Suppression[]> {
  return get<Suppression[]>("/rules/suppressions");
}

export async function addSuppression(ruleId: string, reason?: string, runId?: string, value?: string): Promise<Suppression> {
  return post<Suppression>("/rules/suppressions", {
    rule_id: ruleId,
    reason: reason ?? "",
    run_id: runId ?? null,
    value: value ?? null,
  });
}

export async function removeSuppression(id: number): Promise<void> {
  await del(`/rules/suppressions/${id}`);
}

// -- Roadmap 3.1 — notifications ----------------------------------------------
export async function getNotificationSettings(): Promise<NotificationSettings> {
  return get<NotificationSettings>("/notifications/settings");
}

export async function setNotificationSettings(body: NotificationSettingsIn): Promise<NotificationSettings> {
  const res = await fetch(`${BASE_URL}/notifications/settings`, {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`PUT /notifications/settings → ${res.status}`);
  return res.json();
}

// -- Campaigns (runs clustered by shared infrastructure) ---------------------
export async function getCampaigns(params: { include_synthetic?: boolean } = {}): Promise<Campaign[]> {
  const qs = new URLSearchParams();
  // Synthetic-provenance members are excluded by default (archive parity);
  // the page's toggle reveals them.
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  return get<Campaign[]>(`/campaigns${suffix ? `?${suffix}` : ""}`);
}

// -- Analyst notes (Tier 2 #7, docs/10) --------------------------------------
export async function getRunNotes(runId: string): Promise<RunNote[]> {
  return get<RunNote[]>(`/runs/${runId}/notes`);
}

export async function addRunNote(runId: string, note: string): Promise<RunNote> {
  return post<RunNote>(`/runs/${runId}/notes`, { note });
}

// -- Risk + ATT&CK (roadmap 1.3) ---------------------------------------------
export async function getRuleMeta(): Promise<RuleMeta[]> {
  return get<RuleMeta[]>("/rules/meta");
}

// -- Dashboard / global findings feed ----------------------------------------
export async function getRecentAlerts(limit = 20, provenance?: "real" | "synthetic" | ""): Promise<GlobalAlert[]> {
  const qs = new URLSearchParams();
  qs.set("limit", String(limit));
  if (provenance) qs.set("provenance", provenance);
  return get<GlobalAlert[]>(`/alerts?${qs.toString()}`);
}

// -- Agent fleet (which hosts stream telemetry) ------------------------------
// `identity` narrows the fleet server-side: collector / webapp / silent.
export async function getAgents(identity: string = ""): Promise<AgentsResponse> {
  const qs = identity ? `?identity=${encodeURIComponent(identity)}` : "";
  return get<AgentsResponse>(`/agents${qs}`);
}

// -- Host watch (Monitor 'watch a host' mode) --------------------------------
export async function watchHost(hostId: string): Promise<HostWatchResponse> {
  return get<HostWatchResponse>(`/hosts/${encodeURIComponent(hostId)}/watch`);
}

// -- Process summary (hover preview on process-jump links) -------------------
export async function getProcessSummary(pid: number): Promise<ProcessSummary> {
  return get<ProcessSummary>(`/events/process-summary?pid=${pid}`);
}

// -- Network summary (investigation context for destination IPs) --------------
export async function getNetworkSummary(ip: string): Promise<NetworkSummary> {
  return get<NetworkSummary>(`/events/network-summary?ip=${encodeURIComponent(ip)}`);
}

// -- File summary (investigation context for file paths) ----------------------
export async function getFileSummary(path: string): Promise<FileSummary> {
  return get<FileSummary>(`/events/file-summary?path=${encodeURIComponent(path)}`);
}

// -- Auth brute-force guard (read-only Settings view) ------------------------
export async function getRateLimitStatus(): Promise<RateLimitStatus> {
  return get<RateLimitStatus>("/auth/ratelimit");
}

// -- Analyst audit trail ------------------------------------------------------
export async function getAudit(params: { limit?: number; action?: string } = {}): Promise<AuditResponse> {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.action) qs.set("action", params.action);
  const suffix = qs.toString();
  return get<AuditResponse>(`/audit${suffix ? `?${suffix}` : ""}`);
}

// -- False-positive feedback loop ---------------------------------------------
export async function markFalsePositive(alertId: number, comment = ""): Promise<FpResponse> {
  return post<FpResponse>(`/alerts/${alertId}/false-positive`, { comment });
}

// -- Live system snapshot (processes + listening ports) -----------------------
export async function getHostSnapshot(hostId: string): Promise<HostSnapshot> {
  return get<HostSnapshot>(`/agents/${encodeURIComponent(hostId)}/snapshot`);
}

// -- Retention & backup -------------------------------------------------------
export async function getRetention(): Promise<RetentionStatus> {
  return get<RetentionStatus>("/admin/retention");
}

export async function setRetention(
  days: number,
  autoPrune: "off" | "hourly" | "daily" = "off",
): Promise<RetentionStatus> {
  return post<RetentionStatus>("/admin/retention", { retention_days: days, auto_prune: autoPrune });
}

export async function pruneRuns(days?: number): Promise<PruneResponse> {
  return post<PruneResponse>("/admin/prune", { days: days ?? null });
}

export async function downloadBackup(): Promise<Blob> {
  const resp = await fetch(`${BASE_URL}/admin/backup`, {
    headers: { Authorization: `Bearer ${getAuthToken() ?? ""}` },
  });
  if (!resp.ok) throw new Error(`Backup failed (${resp.status})`);
  return resp.blob();
}

export async function restoreBackup(data: ArrayBuffer): Promise<{ restored: boolean; safety_copy: string }> {
  const resp = await fetch(`${BASE_URL}/admin/restore`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      Authorization: `Bearer ${getAuthToken() ?? ""}`,
    },
    body: data,
  });
  if (!resp.ok) {
    const body = (await resp.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `Restore failed (${resp.status})`);
  }
  return resp.json();
}

// -- Sample upload / OS auto-detection (roadmap 1.4) -------------------------
export async function getSamples(params: { q?: string; limit?: number; include_synthetic?: boolean } = {}): Promise<SamplesResponse> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  // Binaries whose entire detonation history is demo/synthetic are hidden by
  // default — the vault reads as real artifacts first.
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  return get<SamplesResponse>(`/samples${suffix ? `?${suffix}` : ""}`);
}

export async function getSample(sampleId: string): Promise<SampleRow> {
  return get<SampleRow>(`/samples/${sampleId}`);
}

export async function getSampleStatic(sampleId: string): Promise<SampleStatic> {
  return get<SampleStatic>(`/samples/${sampleId}/static`);
}

export async function detonateSample(sampleId: string, timeout = 15): Promise<SampleDetonationResult> {
  return post<SampleDetonationResult>(`/samples/${encodeURIComponent(sampleId)}/detonate?timeout=${timeout}`, {});
}

export async function downloadSample(sampleId: string, name: string): Promise<void> {
  const res = await fetch(`${BASE_URL}/samples/${sampleId}/download`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /samples/${sampleId}/download → ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function exportSamplesCsv(params: { q?: string; include_synthetic?: boolean } = {}): Promise<Blob> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  const res = await fetch(`${BASE_URL}/samples/export${suffix ? `?${suffix}` : ""}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /samples/export → ${res.status}`);
  return res.blob();
}

export async function deleteSample(sampleId: string): Promise<{ status: string; sample_id: string }> {
  await del(`/samples/${encodeURIComponent(sampleId)}`);
  return { status: "ok", sample_id: sampleId };
}

export async function deleteAllSamples(): Promise<{ status: string; deleted: number }> {
  await del("/samples");
  return { status: "ok", deleted: 0 };
}


export async function exportEventsCsv(params: EventFeedParams = {}): Promise<Blob> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  if (params.pid) qs.set("pid", params.pid);
  if (params.source) qs.set("source", params.source);
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  const res = await fetch(`${BASE_URL}/events/export${suffix ? `?${suffix}` : ""}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /events/export → ${res.status}`);
  return res.blob();
}

export async function bulkUpdateAlertStatus(ids: number[], status: AlertStatus, comment?: string): Promise<{ updated: number }> {
  return post<{ updated: number }>("/alerts/bulk", { ids, status, comment: comment ?? "" });
}

export interface AlertQueueParams {
  status?: string;
  rule_id?: string;
  severity?: string;
  host_id?: string;
  assignee?: string;
  campaign?: string;
  // "real" (host/sandbox telemetry) or "synthetic" (seed/webapp-demo/
  // sandbox:demo) — the same split the History archive hides by default.
  provenance?: string;
  q?: string;
  sort?: string;
  limit?: number;
  offset?: number;
}

export async function getAlertQueue(params: AlertQueueParams): Promise<QueueResponse> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  }
  return get<QueueResponse>(`/alerts/queue?${qs.toString()}`);
}

export async function getHostBaseline(hostId: string): Promise<HostBaseline> {
  return get<HostBaseline>(`/baselines/${encodeURIComponent(hostId)}`);
}

export async function resetHostBaseline(hostId: string): Promise<void> {
  return del(`/baselines/${encodeURIComponent(hostId)}`);
}

// Generic CSV download helper — fetch a Blob then trigger a browser save.
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function uploadSample(name: string, file: Blob): Promise<SampleMeta> {
  const res = await fetch(`${BASE_URL}/samples?name=${encodeURIComponent(name)}`, {
    method: "POST",
    headers: authHeaders(),
    body: file,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(detail || `POST /samples → ${res.status}`);
  }
  return res.json();
}

// -- YARA signature lab --------------------------------------------------------
export async function testYaraRule(rule: string, sampleIds?: string[]): Promise<YaraTestResponse> {
  return post<YaraTestResponse>("/yara/test", { rule, sample_ids: sampleIds ?? null });
}

export async function getCustomYaraRules(): Promise<CustomYaraRulesResponse> {
  return get<CustomYaraRulesResponse>("/yara/rules");
}

export async function saveCustomYaraRule(rule: string, family?: string, description?: string): Promise<{ name: string; strings: string[] }> {
  return post<{ name: string; strings: string[] }>("/yara/rules", { rule, family: family ?? "custom", description: description ?? "" });
}

export async function deleteCustomYaraRule(name: string): Promise<void> {
  await del(`/yara/rules/${encodeURIComponent(name)}`);
}

// -- Sandbox detonation adapter (roadmap 3.3) ---------------------------------
export async function getSandboxProviders(): Promise<SandboxProvidersResponse> {
  return get<SandboxProvidersResponse>("/sandbox/providers");
}

export async function sandboxDetonate(body: SandboxDetonateIn): Promise<SandboxTask> {
  return post<SandboxTask>("/sandbox/detonate", body);
}

export async function getSandboxTask(taskId: string): Promise<SandboxTask> {
  return get<SandboxTask>(`/sandbox/tasks/${taskId}`);
}

// -- Digital footprinting (roadmap scaffold) ---------------------------------
export async function getFootprint(sampleId: string, mock = false): Promise<Footprint> {
  return get<Footprint>(`/footprint/${sampleId}${mock ? "?mock=1" : ""}`);
}

/** Cross-sample infra topology — IPs shared by ≥2 samples (campaign clusters). */
export async function getFootprintTopology(): Promise<TopologyResponse> {
  return get<TopologyResponse>("/footprint/topology");
}

// -- Global event feed / Event Viewer (roadmap 1.1) --------------------------
export async function getEvents(params: EventFeedParams = {}): Promise<EventFeedResponse> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  if (params.pid) qs.set("pid", params.pid);
  if (params.source) qs.set("source", params.source);
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const suffix = qs.toString();
  return get<EventFeedResponse>(`/events${suffix ? `?${suffix}` : ""}`);
}

/** The whole Event Log rail (category + channel buckets) in ONE request —
 *  replaces the old pattern of one COUNT probe per category badge plus a
 *  channel-counts call (7 requests per filter change → 1). Accepts the same
 *  filters as getEvents, `source` included (it narrows the type buckets;
 *  the channel buckets are the source split and ignore it server-side). */
export async function getEventCounts(
  params: Omit<EventFeedParams, "limit" | "offset"> = {},
): Promise<EventCountsResponse> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  if (params.pid) qs.set("pid", params.pid);
  if (params.source) qs.set("source", params.source);
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  return get<EventCountsResponse>(`/events/counts${suffix ? `?${suffix}` : ""}`);
}

/** Per-channel totals for the source-tab rail — one request instead of one
 *  per tab. Accepts the same filters as getEvents minus `source` (the split
 *  dimension); `total` feeds the "All sources" tab, `channels` the rest.
 *  Kept for API-surface stability; the Event Log now uses getEventCounts. */
export async function getEventChannelCounts(
  params: Omit<EventFeedParams, "source" | "limit" | "offset"> = {},
): Promise<ChannelCountsResponse> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  if (params.pid) qs.set("pid", params.pid);
  if (params.include_synthetic !== undefined) qs.set("include_synthetic", String(params.include_synthetic));
  const suffix = qs.toString();
  return get<ChannelCountsResponse>(`/events/channel-counts${suffix ? `?${suffix}` : ""}`);
}

// -- P0.5/P0.6/P0.7 client surfaces -------------------------------------

/** Global search (GET /search) — grouped results across every
 *  analyst-facing resource. `q` may carry qualifiers (type: status:
 *  severity: disposition: host: rule: case:); `limit` caps hits per group. */
export async function globalSearch(q: string, limit = 10): Promise<SearchResponse> {
  return get<SearchResponse>(`/search?q=${encodeURIComponent(q)}&limit=${limit}`);
}

/** Host aggregate timeline (GET /hosts/{host_id}/timeline) — the merged
 *  chronological feed. `kind` restricts to one resource kind; `eventType`
 *  narrows event rows; `q` matches display fields; limit/offset paginate. */
export async function getHostTimeline(
  hostId: string,
  params: {
    kind?: TimelineKind;
    eventType?: string;
    q?: string;
    limit?: number;
    offset?: number;
  } = {},
): Promise<HostTimeline> {
  const qs = new URLSearchParams();
  if (params.kind) qs.set("kind", params.kind);
  if (params.eventType) qs.set("event_type", params.eventType);
  if (params.q) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const suffix = qs.toString();
  return get<HostTimeline>(`/hosts/${encodeURIComponent(hostId)}/timeline${suffix ? `?${suffix}` : ""}`);
}

/** Start an analysis job (POST /analysis). `isolated-outpost` is a reserved
 *  backend — the API returns 501 until an isolated execution env exists. */
export async function createAnalysisJob(body: AnalysisJobCreateIn): Promise<AnalysisJob> {
  return post<AnalysisJob>("/analysis", body);
}

/** List/filter persisted analysis jobs (GET /analysis). */
export async function listAnalysisJobs(params: {
  backend?: AnalysisBackend;
  status?: AnalysisStatus;
  artifact_id?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<AnalysisJobsResponse> {
  const qs = new URLSearchParams();
  if (params.backend) qs.set("backend", params.backend);
  if (params.status) qs.set("status", params.status);
  if (params.artifact_id) qs.set("artifact_id", params.artifact_id);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const suffix = qs.toString();
  return get<AnalysisJobsResponse>(`/analysis${suffix ? `?${suffix}` : ""}`);
}

/** One persisted job (GET /analysis/{run_id}). */
export async function getAnalysisJob(runId: string): Promise<AnalysisJob> {
  return get<AnalysisJob>(`/analysis/${encodeURIComponent(runId)}`);
}

/** Cancel a queued/running job (POST /analysis/{run_id}/cancel). */
export async function cancelAnalysisJob(runId: string): Promise<AnalysisJob> {
  return post<AnalysisJob>(`/analysis/${encodeURIComponent(runId)}/cancel`, {});
}

/** Observations-shaped payload (GET /analysis/{run_id}/observations). Static
 *  jobs return the stored analysis result as {kind, data} rows (strings /
 *  iocs / pe / elf); dynamic jobs return the run's events — no observations
 *  table exists (P0 defers it), so nothing is persisted here. */
export async function getAnalysisObservations(runId: string): Promise<AnalysisObservationsResponse> {
  return get<AnalysisObservationsResponse>(`/analysis/${encodeURIComponent(runId)}/observations`);
}

/** Findings attached to an analysis run (GET /analysis/{run_id}/findings) —
 *  the existing alerts/run relationship, same assembly as /runs/{id}/alerts.
 *  No cross-run aggregation in P0. */
export async function getAnalysisFindings(runId: string): Promise<Finding[]> {
  return get<Finding[]>(`/analysis/${encodeURIComponent(runId)}/findings`);
}

// -- P1.1 — Investigations (P0.3 backend: the optional case anchor) -----------

/** Create an investigation (POST /investigations) — title + optional tags. */
export async function createInvestigation(body: {
  title: string;
  tags?: string[];
}): Promise<Investigation> {
  return post<Investigation>("/investigations", body);
}

/** List investigations (GET /investigations) — status/q filters, paged. */
export async function listInvestigations(params: {
  status?: InvestigationStatus;
  q?: string;
  limit?: number;
  offset?: number;
} = {}): Promise<InvestigationListResponse> {
  const qs = new URLSearchParams();
  if (params.status) qs.set("status", params.status);
  if (params.q) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const suffix = qs.toString();
  return get<InvestigationListResponse>(`/investigations${suffix ? `?${suffix}` : ""}`);
}

/** One investigation workspace payload (GET /investigations/{id}). */
export async function getInvestigation(investigationId: string): Promise<InvestigationDetail> {
  return get<InvestigationDetail>(`/investigations/${encodeURIComponent(investigationId)}`);
}

/** Update title/tags/status/conclusion (PATCH /investigations/{id}). */
export async function patchInvestigation(
  investigationId: string,
  body: {
    title?: string;
    tags?: string[];
    status?: InvestigationStatus;
    conclusion?: string | null;
  },
): Promise<Investigation> {
  return patch<Investigation>(`/investigations/${encodeURIComponent(investigationId)}`, body);
}

/** Add an evidence ref (POST /investigations/{id}/refs). */
export async function addInvestigationRef(
  investigationId: string,
  body: { ref_type: InvestigationRefType; ref_id: string },
): Promise<InvestigationRef> {
  return post<InvestigationRef>(`/investigations/${encodeURIComponent(investigationId)}/refs`, body);
}

/** Remove one evidence ref (DELETE /investigations/{id}/refs/{ref_id}). */
export async function removeInvestigationRef(investigationId: string, refId: string): Promise<void> {
  return del(`/investigations/${encodeURIComponent(investigationId)}/refs/${encodeURIComponent(refId)}`);
}

/** Append an analyst note (POST /investigations/{id}/notes). */
export async function addInvestigationNote(
  investigationId: string,
  body: { note: string },
): Promise<InvestigationNote> {
  return post<InvestigationNote>(`/investigations/${encodeURIComponent(investigationId)}/notes`, body);
}

/** Close with a conclusion (POST /investigations/{id}/close). */
export async function closeInvestigation(
  investigationId: string,
  body: { conclusion: string },
): Promise<Investigation> {
  return post<Investigation>(`/investigations/${encodeURIComponent(investigationId)}/close`, body);
}

/** Reopen a closed investigation (POST /investigations/{id}/reopen). */
export async function reopenInvestigation(investigationId: string): Promise<Investigation> {
  return post<Investigation>(`/investigations/${encodeURIComponent(investigationId)}/reopen`, {});
}

/** Start in-process local host live monitor (POST /agents/local/start). */
export async function startLocalMonitor(payload?: { run_id?: string; interval?: number }): Promise<any> {
  return post<any>("/agents/local/start", payload || {});
}

/** Stop in-process local host live monitor (POST /agents/local/stop). */
export async function stopLocalMonitor(): Promise<any> {
  return post<any>("/agents/local/stop", {});
}

/** Get status of in-process local host live monitor (GET /agents/local/status). */
export async function getLocalMonitorStatus(): Promise<any> {
  return get<any>("/agents/local/status");
}

/** Execute dynamic trace detonation in isolated sandbox (POST /sandbox/detonate/dynamic). */
export async function detonateDynamic(body: { sample_id: string }): Promise<any> {
  return post<any>("/sandbox/detonate/dynamic", body);
}

/** Get structured Sigma, Suricata, and YARA detection suite for a run (GET /runs/{id}/rules/suite). */
export async function getRunDetectionSuite(runId: string): Promise<any> {
  return get<any>(`/runs/${encodeURIComponent(runId)}/rules/suite`);
}

/** List curated attack scenario playbooks (GET /sandbox/playbooks). */
export async function getPlaybooks(): Promise<any[]> {
  return get<any[]>("/sandbox/playbooks");
}

/** Detonate a curated attack scenario playbook (POST /sandbox/detonate/playbook). */
export async function detonatePlaybook(playbookId: string): Promise<any> {
  return post<any>("/sandbox/detonate/playbook", { playbook_id: playbookId });
}

/** Get 1-click curl and PowerShell bootstrap agent commands (GET /agents/bootstrap-command). */
export async function getAgentBootstrapCommands(): Promise<{
  server: string;
  agent_token_configured: boolean;
  linux_command: string;
  macos_command: string;
  windows_command: string;
}> {
  return get<any>("/agents/bootstrap-command");
}

/** Get isolation status and pending remediation actions for a host (GET /agents/{host_id}/containment). */
export async function getHostContainment(hostId: string): Promise<{
  host_id: string;
  isolated: boolean;
  isolated_at: string | null;
  isolated_by: string | null;
  reason: string | null;
  pending_actions: any[];
  updated_at: string | null;
}> {
  return get<any>(`/agents/${encodeURIComponent(hostId)}/containment`);
}

/** Set host network isolation status (POST /agents/{host_id}/isolate). */
export async function isolateHost(
  hostId: string,
  payload: { isolated: boolean; reason?: string },
): Promise<any> {
  return post<any>(`/agents/${encodeURIComponent(hostId)}/isolate`, payload);
}

/** Queue process kill remediation action (POST /agents/{host_id}/kill-process). */
export async function killHostProcess(
  hostId: string,
  payload: { pid?: number; process_name?: string },
): Promise<any> {
  return post<any>(`/agents/${encodeURIComponent(hostId)}/kill-process`, payload);
}

/** Search sample vault for binary-similar samples (GET /samples/{sample_id}/similar). */
export async function getSimilarSamples(sampleId: string, minSimilarity: number = 20): Promise<any> {
  return get<any>(`/samples/${encodeURIComponent(sampleId)}/similar?min_similarity=${minSimilarity}`);
}

/** Transpile Sigma YAML detection rule (POST /rules/sigma/transpile). */
export async function transpileSigmaRule(sigmaYaml: string): Promise<any> {
  return post<any>("/rules/sigma/transpile", { sigma_yaml: sigmaYaml });
}

/** Get full live host X-Ray snapshot (metrics, active processes, open sockets). */
export async function getHostXRaySnapshot(): Promise<{
  metrics: {
    cpu_percent: number;
    memory_used_mb: number;
    memory_total_mb: number;
    memory_percent: number;
    process_count: number;
    connection_count: number;
    platform: string;
    timestamp: string;
  };
  processes: Array<{
    pid: number;
    ppid: number;
    name: string;
    cmdline: string;
    exe: string;
    user: string;
    status: string;
    cpu_percent: number;
    memory_mb: number;
    threads: number;
    started_at: string;
    create_time?: number;
    package_status?: string;
    package_label?: string;
  }>;
  sockets: Array<{
    pid: number | null;
    process_name: string;
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
  }>;
  process_count: number;
  socket_count: number;
}> {
  return get<any>("/system/xray/snapshot");
}

/** Deep inspection of a single process PID (lineage, sockets, files, environment, security posture). */
export async function getProcessXRay(pid: number): Promise<{
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  exe: string;
  user: string;
  status: string;
  cpu_percent: number;
  memory_mb: number;
  threads: number;
  started_at: string;
  create_time?: number;
  cwd: string;
  environment: Record<string, string>;
  lineage: Array<{ pid: number; name: string; relation: "ancestor" | "self" | "child" }>;
  sockets: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
  }>;
  open_files: Array<{ path: string; fd: number }>;
  detailed_fds?: Array<{
    fd: number;
    path: string;
    kind: "file" | "socket" | "pipe" | "anon_inode" | "device" | "memfd" | "shm";
    access: string;
    is_deleted: boolean;
    is_memfd: boolean;
    is_shm: boolean;
  }>;
  device_access?: {
    microphone: boolean;
    camera: boolean;
    screen_capture: boolean;
    audio_playback: boolean;
    audio_capture: boolean;
    video_capture: boolean;
    gpu: boolean;
    gpu_clients_count: number;
    gpu_nodes: string[];
    sleep_inhibition: boolean;
  };
  disk_io?: {
    read_bytes: number;
    write_bytes: number;
    read_mb: number;
    write_mb: number;
    syscr: number;
    syscw: number;
    read_bytes_sec: number;
    write_bytes_sec: number;
    io_rate_label: string;
  };
  launch_chain?: {
    supervisor: string;
    service: string;
    container: string;
    cgroup_slice: string;
    cgroup_scope: string;
    chain: Array<{ role: string; name: string; type: string }>;
  };
  sparkline?: {
    points: Array<{ timestamp: string; seconds_ago: number; cpu_percent: number; memory_mb: number }>;
    sample_interval_sec: number;
    window_seconds: number;
    latest_cpu: number;
    latest_mem_mb: number;
  };
  security?: {
    seccomp?: string;
    no_new_privs?: boolean;
    capabilities_effective?: Array<{ name: string; raw_name: string; is_dangerous: boolean }>;
    capabilities_permitted?: Array<{ name: string; raw_name: string; is_dangerous: boolean }>;
    service_unit?: string;
    cgroup?: string;
    container_id?: string;
    namespaces?: Record<string, string>;
    mapped_libraries?: string[];
    package_provenance?: { status: string; label: string; managed: boolean; package?: string; path?: string };
  };
  cgroup?: {
    container_runtime: string;
    container_id: string | null;
    container_short_id: string | null;
    systemd_service: string | null;
    cgroup_slice: string | null;
    cgroup_scope: string | null;
    is_containerized: boolean;
    raw_cgroup: string | null;
  };
  correlated_events: any[];
  correlated_alerts: any[];
}> {
  return get<any>(`/system/forensics/process/${pid}`);
}

export const getProcessForensics = getProcessXRay;
export const getHostForensicsSnapshot = getHostXRaySnapshot;

/** Terminate a process via Host X-Ray (POST /system/xray/process/{pid}/kill). */
export async function killProcessXRay(pid: number, signal: "SIGTERM" | "SIGKILL" = "SIGTERM"): Promise<{
  pid: number;
  signal: string;
  success: boolean;
  message: string;
  timestamp: string;
}> {
  return post<any>(`/system/xray/process/${pid}/kill`, { signal });
}

/** Lifecycle control on a process (freeze/resume/terminate/kill) with PID identity verification. */
export async function controlProcessXRay(
  pid: number,
  action: "freeze" | "resume" | "terminate" | "kill",
  expectedCreateTime?: number
): Promise<{
  pid: number;
  action: string;
  signal: string;
  success: boolean;
  message: string;
  timestamp: string;
}> {
  return post<any>(`/system/xray/process/${pid}/action`, {
    action,
    expected_create_time: expectedCreateTime,
  });
}

/** Export complete forensic snapshot (.xray.json) for a process PID. */
export async function getForensicCapsule(pid: number): Promise<any> {
  return get<any>(`/system/xray/process/${pid}/capsule`);
}

/** Get hierarchical process causality tree for dynamic execution analysis. */
export async function getProcessTree(): Promise<Array<{
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  exe: string;
  user: string;
  status: string;
  cpu_percent: number;
  memory_mb: number;
  threads: number;
  started_at: string;
  package_status?: string;
  package_label?: string;
  children: any[];
}>> {
  return get<any>("/system/xray/tree");
}

/** Get categorized network matrix across threat domains. */
export async function getNetworkMatrix(): Promise<{
  public_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
    is_public_bound?: boolean;
  }>;
  loopback_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
  }>;
  outbound_connections: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    is_external?: boolean;
    is_suspicious_port?: boolean;
    endpoint_type?: string;
  }>;
  multicast_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
  }>;
  summary: {
    public_listeners_count: number;
    loopback_listeners_count: number;
    outbound_count: number;
    multicast_count: number;
    total_sockets: number;
  };
}> {
  return get<any>("/system/xray/network");
}

/** Get automated behavioral heuristic explanations & finding cards. */
export async function getBehavioralExplanations(): Promise<Array<{
  id: string;
  tone: "critical" | "attention" | "info";
  title: string;
  domain: string;
  why: string;
  evidence: string[];
  evidence_count: number;
  next_step: string;
}>> {
  return get<any>("/system/xray/explanations");
}

/** Execute a simulation scenario live (POST /sandbox/simulate/live). */
export async function runLiveSimulation(scenarioId: string): Promise<{
  run_id: string;
  scenario_id: string;
  name: string;
  platform: string;
  terminal_output: string;
  terminal_lines: string[];
  stages: Array<{
    stage: number;
    name: string;
    cmd: string;
    exit_code: number;
    status: string;
  }>;
  events_count: number;
  alerts_count: number;
  alerts: any[];
  risk_score: number;
  process_tree: any[];
}> {
  return post<any>("/sandbox/simulate/live", { playbook_id: scenarioId });
}

/** Capture a new host system baseline for differential comparison. */
export async function captureBaselineSnapshot(): Promise<{
  timestamp: string;
  process_count: number;
  processes: any[];
  network: any;
  metrics: any;
}> {
  return post<any>("/system/xray/snapshot/baseline", {});
}

/** Get differential delta (+/-) between baseline and current live host state. */
export async function getSnapshotDifferential(): Promise<{
  baseline_timestamp: string;
  current_timestamp: string;
  added_processes: any[];
  removed_processes: any[];
  new_listeners: any[];
  closed_listeners: any[];
  new_outbound: any[];
  closed_outbound: any[];
  temp_drops: any[];
  metrics_delta: {
    cpu_delta: number;
    memory_mb_delta: number;
    process_count_delta: number;
    socket_count_delta: number;
  };
  summary: {
    added_processes_count: number;
    removed_processes_count: number;
    new_listeners_count: number;
    closed_listeners_count: number;
    new_outbound_count: number;
    closed_outbound_count: number;
    temp_drops_count: number;
  };
}> {
  return get<any>("/system/xray/snapshot/diff");
}

/** Compare two forensic capsules (.xray.json) side-by-side. */
export async function compareForensicCapsules(capsuleA: any, capsuleB: any): Promise<{
  capsule_a: any;
  capsule_b: any;
  capabilities_diff: {
    only_in_a: string[];
    only_in_b: string[];
    common: string[];
  };
  libraries_diff: {
    only_in_a: string[];
    only_in_b: string[];
    common_count: number;
  };
  seccomp_match: boolean;
}> {
  return post<any>("/system/xray/capsule/compare", { capsule_a: capsuleA, capsule_b: capsuleB });
}

/** Retrieve target catalog (Omarchy X-Ray style): Apps, Processes, Ports, Devices. */
export async function getXRayTargetCatalog(): Promise<{
  total_targets_count: number;
  quick_inspect: {
    audio: number;
    camera: number;
    gpu: number;
    microphone: number;
  };
  open_apps: Array<{
    id: string;
    pid: number;
    name: string;
    title: string;
    exe: string;
    user: string;
    memory_mb: number;
  }>;
  active_devices: Array<{
    id: string;
    name: string;
    pid: number;
    node: string;
    process_name: string;
  }>;
  processes: any[];
  ports: any[];
}> {
  return get<any>("/system/xray/catalog");
}

/** Unified full target dossier for X-Ray Command Cockpit. */
export async function getXRayFullTargetDossier(pid: number): Promise<{
  target: {
    pid: number;
    ppid: number;
    name: string;
    cmdline: string;
    exe: string;
    cwd: string;
    user: string;
    status: string;
    started_at: string;
    create_time?: number;
    threads: number;
    memory_mb: number;
    memory_gib_str: string;
    cpu_percent: number;
    disk_io_str: string;
    gpu_clients_count: number;
    uptime_str: string;
  };
  launch_chain: {
    supervisor: string;
    service_scope: string;
    is_grouped: boolean;
    description: string;
    chain: Array<{ id: string; name: string; role: string; pid?: number; icon: string }>;
  };
  device_access: {
    microphone: { in_use: boolean; devices: string[]; label: string };
    camera: { in_use: boolean; devices: string[]; label: string };
    screen_capture: { in_use: boolean; label: string };
    audio_capture: { in_use: boolean; label: string };
    audio_playback: { in_use: boolean; devices: string[]; label: string };
    video_capture: { in_use: boolean; label: string };
    gpu: { in_use: boolean; nodes: string[]; client_count: number; label: string };
    sleep_inhibition: { in_use: boolean; label: string };
  };
  security: any;
  cgroup: any;
  process_tree: any[];
  connections: any[];
  files_ipc: Array<{
    fd: number;
    path: string;
    clean_path: string;
    is_deleted: boolean;
    is_memfd: boolean;
    kind: string;
    access: string;
  }>;
  findings: Array<{
    id: string;
    tone: string;
    title: string;
    why: string;
    evidence: string[];
  }>;
  correlated_events_count: number;
  correlated_alerts_count: number;
}> {
  return get<any>(`/system/xray/process/${pid}/full`);
}



