// All backend calls, centralized — never inline fetch in components (docs/04).
// Structurally mirrors cli/outpost/lib/api_client.py: the webapp and CLI are
// two separate surfaces over the same API; nothing is CLI-only.

import type {
  Alert,
  CompareResponse,
  EventIn,
  Campaign,
  EventFeedParams,
  EventFeedResponse,
  GlobalAlert,
  IocSearchResponse,
  NotificationSettings,
  Platform,
  RuleMeta,
  RunDetail,
  RunNote,
  RunSummary,
  SampleMeta,
  SampleRow,
  SamplesResponse,
  SessionType,
  TuningResponse,
  WatchlistEntry,
  WatchlistImportResponse,
} from "../types";

export const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json();
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json();
}

// -- health -----------------------------------------------------------------
export async function getHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    return res.ok;
  } catch {
    return false; // unreachable — the deck's pulse reads offline
  }
}

// -- runs -------------------------------------------------------------------
export async function getRuns(params: { q?: string } = {}): Promise<RunSummary[]> {
  const suffix = params.q ? `?q=${encodeURIComponent(params.q)}` : "";
  return get<RunSummary[]>(`/runs${suffix}`);
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

export async function getRunExport(runId: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/export`);
  if (!res.ok) throw new Error(`GET /runs/${runId}/export → ${res.status}`);
  return res.blob();
}

export async function getRunIocsCsv(runId: string): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/iocs?format=csv`);
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
  const res = await fetch(`${BASE_URL}/runs/${runId}/rules?format=${format}`);
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
  const res = await fetch(`${BASE_URL}/watchlist/${encodeURIComponent(value)}`, { method: "DELETE" });
  if (res.status !== 204) throw new Error(`DELETE /watchlist/${value} → ${res.status}`);
}

export async function watchlistExport(format: "json" | "csv"): Promise<Blob> {
  const res = await fetch(`${BASE_URL}/watchlist/export?format=${format}`);
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

export async function setTuning(param: string, value: string): Promise<{ current: string }> {
  return post<{ current: string }>(`/rules/tuning/${param}`, { value });
}

export async function resetTuning(param: string): Promise<void> {
  const res = await fetch(`${BASE_URL}/rules/tuning/${param}`, { method: "DELETE" });
  if (res.status !== 204) throw new Error(`DELETE /rules/tuning/${param} → ${res.status}`);
}

// -- Roadmap 3.1 — notifications ----------------------------------------------
export async function getNotificationSettings(): Promise<NotificationSettings> {
  return get<NotificationSettings>("/notifications/settings");
}

export async function setNotificationSettings(webhookUrl: string): Promise<NotificationSettings> {
  const res = await fetch(`${BASE_URL}/notifications/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ webhook_url: webhookUrl }),
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

export async function uploadSample(name: string, file: Blob): Promise<SampleMeta> {
  const res = await fetch(`${BASE_URL}/samples?name=${encodeURIComponent(name)}`, {
    method: "POST",
    body: file,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(detail || `POST /samples → ${res.status}`);
  }
  return res.json();
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
