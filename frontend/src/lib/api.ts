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
  EventIn,
  Campaign,
  EventFeedParams,
  EventFeedResponse,
  Footprint,
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
  if (res.status !== 204) throw new Error(`DELETE ${path} → ${res.status}`);
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

// -- runs -------------------------------------------------------------------
export async function getRuns(params: { q?: string; host?: string } = {}): Promise<RunSummary[]> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.host) qs.set("host", params.host);
  const suffix = qs.toString();
  return get<RunSummary[]>(`/runs${suffix ? `?${suffix}` : ""}`);
}

export async function getRunDetail(runId: string): Promise<RunDetail> {
  return get<RunDetail>(`/runs/${runId}`);
}

export async function getAlerts(runId: string): Promise<Alert[]> {
  return get<Alert[]>(`/runs/${runId}/alerts`);
}

export async function createRun(sampleName: string, platform: Platform, sessionType: SessionType): Promise<{ run_id: string }> {
  return post<{ run_id: string }>("/runs", { sample_name: sampleName, platform, session_type: sessionType });
}

export async function completeRun(runId: string): Promise<void> {
  await post(`/runs/${runId}/complete`, {});
}

export async function ingestBatch(events: EventIn[]): Promise<{ accepted: number; alerts: number }> {
  return post<{ accepted: number; alerts: number }>("/ingest/batch", events);
}

// -- Roadmap 3.3 — STIX 2.1 export -------------------------------------------
export async function getRunStix(runId: string): Promise<unknown> {
  return get<unknown>(`/runs/${runId}/export?format=stix`);
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
  const res = await fetch(`${BASE_URL}/watchlist/${encodeURIComponent(value)}`, { method: "DELETE", headers: authHeaders() });
  if (res.status !== 204) throw new Error(`DELETE /watchlist/${value} → ${res.status}`);
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
  const res = await fetch(`${BASE_URL}/rules/tuning/${param}`, { method: "DELETE", headers: authHeaders() });
  if (res.status !== 204) throw new Error(`DELETE /rules/tuning/${param} → ${res.status}`);
}

// -- Alert triage (analyst workflow) -------------------------------------------
export async function updateAlertStatus(alertId: number, status: AlertStatus, comment?: string): Promise<Alert> {
  return patch<Alert>(`/alerts/${alertId}`, { status, comment: comment ?? "" });
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

export async function addSuppression(ruleId: string, reason?: string, runId?: string): Promise<Suppression> {
  return post<Suppression>("/rules/suppressions", { rule_id: ruleId, reason: reason ?? "", run_id: runId ?? null });
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
export async function getCampaigns(): Promise<Campaign[]> {
  return get<Campaign[]>("/campaigns");
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
export async function getRecentAlerts(limit = 20): Promise<GlobalAlert[]> {
  return get<GlobalAlert[]>(`/alerts?limit=${limit}`);
}

// -- Agent fleet (which hosts stream telemetry) ------------------------------
export async function getAgents(): Promise<AgentsResponse> {
  return get<AgentsResponse>("/agents");
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
export async function getSamples(params: { q?: string; limit?: number } = {}): Promise<SamplesResponse> {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  const suffix = qs.toString();
  return get<SamplesResponse>(`/samples${suffix ? `?${suffix}` : ""}`);
}

export async function getSample(sampleId: string): Promise<SampleRow> {
  return get<SampleRow>(`/samples/${sampleId}`);
}

export async function getSampleStatic(sampleId: string): Promise<SampleStatic> {
  return get<SampleStatic>(`/samples/${sampleId}/static`);
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

export async function exportSamplesCsv(params: { q?: string } = {}): Promise<Blob> {
  const qs = params.q ? `?q=${encodeURIComponent(params.q)}` : "";
  const res = await fetch(`${BASE_URL}/samples/export${qs}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /samples/export → ${res.status}`);
  return res.blob();
}

export async function exportEventsCsv(params: EventFeedParams = {}): Promise<Blob> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  const suffix = qs.toString();
  const res = await fetch(`${BASE_URL}/events/export${suffix ? `?${suffix}` : ""}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /events/export → ${res.status}`);
  return res.blob();
}

export async function exportAlertsCsv(): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/alerts/export`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET /alerts/export → ${res.status}`);
  return res.blob();
}

export async function bulkUpdateAlertStatus(ids: number[], status: AlertStatus, comment?: string): Promise<{ updated: number }> {
  return post<{ updated: number }>("/alerts/bulk", { ids, status, comment: comment ?? "" });
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

// -- Global event feed / Event Viewer (roadmap 1.1) --------------------------
export async function getEvents(params: EventFeedParams = {}): Promise<EventFeedResponse> {
  const qs = new URLSearchParams();
  if (params.event_type) qs.set("event_type", params.event_type);
  if (params.platform) qs.set("platform", params.platform);
  if (params.severity) qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  if (params.limit !== undefined) qs.set("limit", String(params.limit));
  if (params.offset !== undefined) qs.set("offset", String(params.offset));
  const suffix = qs.toString();
  return get<EventFeedResponse>(`/events${suffix ? `?${suffix}` : ""}`);
}
