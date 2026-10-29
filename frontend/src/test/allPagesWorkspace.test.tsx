import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data });

const meResponse = {
  enabled: false,
  authenticated: true,
  role: "admin",
  read_only: false,
  credential_mode: "none",
  expires_at: null,
};

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const u = String(url);
      if (u.includes("/auth/me")) return Promise.resolve(ok(meResponse));
      if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
      if (u.includes("/platform")) {
        return Promise.resolve(
          ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }),
        );
      }
      if (u.includes("/alerts")) return Promise.resolve(ok([]));
      if (u.includes("/runs/dyn_db3a8da614ef")) {
        return Promise.resolve(
          ok({
            run: {
              run_id: "dyn_db3a8da614ef",
              sample_name: "analysis_probe.sh",
              platform: "linux",
              started_at: "2026-10-29T10:00:00Z",
              completed_at: "2026-10-29T10:01:00Z",
              origin: "observed",
              session_type: "analysis",
              kind: "analysis_job",
            },
            alerts: [],
            events: [],
            process_tree: [],
            coverage: [],
            run_notes: [],
            allowlist: [],
          }),
        );
      }
      if (u.includes("/runs")) {
        return Promise.resolve(
          ok([
            {
              run_id: "dyn_db3a8da614ef",
              sample_name: "analysis_probe.sh",
              platform: "linux",
              started_at: "2026-10-29T10:00:00Z",
              completed_at: "2026-10-29T10:01:00Z",
              origin: "observed",
            },
          ]),
        );
      }
      if (u.includes("/samples/sample_remcos_01/static")) {
        return Promise.resolve(
          ok({
            available: true,
            sample_id: "sample_remcos_01",
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size: 1024,
            strings: [],
            iocs: { urls: [], ips: [], domains: [], hashes: [], emails: [] },
            pe: null,
            elf: null,
          }),
        );
      }
      if (u.includes("/samples/sample_remcos_01")) {
        return Promise.resolve(
          ok({
            sample_id: "sample_remcos_01",
            original_name: "remcos_sample.exe",
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            detected_platform: "windows",
            size: 1024,
            created_at: "2026-10-29T10:00:00Z",
            malware_family: "remcos",
          }),
        );
      }
      if (u.includes("/analysis/job_sample_r")) {
        return Promise.resolve(
          ok({
            run_id: "job_sample_r",
            sample_name: "remcos_sample.exe",
            backend: "sandbox",
            status: "completed",
            submitted_at: "2026-10-29T10:00:00Z",
            completed_at: "2026-10-29T10:01:00Z",
            sample_id: "sample_remcos_01",
            findings_count: 0,
            evidence_count: 0,
          }),
        );
      }
      if (u.includes("/corpus/report")) {
        return Promise.resolve(ok({ count: 1, samples: [] }));
      }
      if (u.includes("/events/counts")) {
        return Promise.resolve(ok({ process: 0, network: 0, file: 0 }));
      }
      if (u.includes("/events/channel-counts")) {
        return Promise.resolve(ok({}));
      }
      if (u.includes("/events")) {
        return Promise.resolve(ok({ count: 0, events: [], total: 0 }));
      }
      if (u.includes("/rules/tuning")) {
        return Promise.resolve(ok({ count: 0, knobs: [] }));
      }
      if (u.includes("/rules/fp")) {
        return Promise.resolve(ok({ threshold: 5, default_threshold: 5, rules: [] }));
      }
      if (u.includes("/rules/sigma/custom")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/rules/sigma/community")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/yara/rules")) {
        return Promise.resolve(ok({ count: 0, rules: [] }));
      }
      if (u.includes("/rules/enum-patterns")) {
        return Promise.resolve(ok({ platforms: {}, defaults: {} }));
      }
      if (u.includes("/rules/log-patterns")) {
        return Promise.resolve(ok({ kinds: {}, defaults: {} }));
      }
      if (u.includes("/rules/pack")) {
        return Promise.resolve(ok({ schema: "1.0", exported_at: "", tuning: [], suppressions: [] }));
      }
      if (u.includes("/rules/suppressions")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/rules/meta")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/sandbox/techniques/matrix")) {
        return Promise.resolve(ok({ techniques: [] }));
      }
      if (u.includes("/sandbox/techniques")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/sandbox/playbooks")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/sandbox/drivers")) {
        return Promise.resolve(ok(["docker", "local"]));
      }
      if (u.includes("/sandbox/environment")) {
        return Promise.resolve(ok({ isolation: "docker", network: "sinkhole" }));
      }
      if (u.includes("/analysis")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/watchlist")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/search")) {
        return Promise.resolve(ok({ q: "", qualifiers: {}, groups: { findings: { total: 0, hits: [] }, iocs: { total: 0, hits: [] }, artifacts: { total: 0, hits: [] }, hosts: { total: 0, hits: [] }, sessions: { total: 0, hits: [] }, investigations: { total: 0, hits: [] }, campaigns: { total: 0, hits: [] } } }));
      }
      if (u.includes("/auth/ratelimit")) {
        return Promise.resolve(ok({ locked_ips: 0, max_attempts: 5, window_seconds: 60, lockout_seconds: 300 }));
      }
      if (u.includes("/admin/retention")) {
        return Promise.resolve(ok({ retention_days: 30, auto_prune: false }));
      }
      if (u.includes("/settings/keys")) {
        return Promise.resolve(ok({ keys: [] }));
      }
      if (u.includes("/intel/freshness")) {
        return Promise.resolve(ok({ last_sync: null, cached_indicators: 0 }));
      }
      if (u.includes("/notifications/settings")) {
        return Promise.resolve(
          ok({
            webhook_url: "",
            slack_webhook: "",
            discord_webhook: "",
            telegram_bot_token: "",
            telegram_chat_id: "",
            smtp_host: "",
            smtp_port: "587",
            smtp_user: "",
            smtp_pass: "",
            smtp_from: "",
            smtp_to: "",
            enabled: false,
            smtp_pass_set: false,
          }),
        );
      }
      return Promise.resolve(ok({}));
    }),
  );
});

async function mountRoute(path: string) {
  window.history.pushState({}, "", path);
  vi.resetModules();
  const { router } = await import("../appRouter");
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("All Primary Webapp Pages Render Cleanly", () => {
  it("renders /samples (Malware Vault)", async () => {
    await mountRoute("/samples");
    await waitFor(() => {
      expect(screen.getAllByText(/Malware Analysis Vault/i).length).toBeGreaterThan(0);
    });
  });

  it("renders /monitor (Simulation Lab)", async () => {
    await mountRoute("/monitor");
    await waitFor(() => {
      expect(screen.getByText(/Adversary Simulation & Dynamic Behavioral Sandbox/i)).toBeInTheDocument();
    });
  });

  it("renders /analysis (Detonation Runs)", async () => {
    await mountRoute("/analysis");
    await waitFor(() => {
      expect(screen.getByText(/Analysis Jobs & Background Tasks/i)).toBeInTheDocument();
    });
  });

  it("renders /events (Telemetry Stream)", async () => {
    await mountRoute("/events");
    await waitFor(() => {
      expect(screen.getByText(/Security Telemetry Stream/i)).toBeInTheDocument();
    });
  });

  it("renders /rules (Detection Rules & Studio)", async () => {
    await mountRoute("/rules");
    await waitFor(() => {
      expect(screen.getByText(/Detection Engineering Studio/i)).toBeInTheDocument();
    });
  });

  it("renders /coverage (ATT&CK Coverage)", async () => {
    await mountRoute("/coverage");
    await waitFor(() => {
      expect(screen.getByText(/MITRE ATT&CK Matrix/i)).toBeInTheDocument();
    });
  });

  it("renders /watchlist (Threat Watchlist)", async () => {
    await mountRoute("/watchlist");
    await waitFor(() => {
      expect(screen.getAllByText(/Personal watchlist/i).length).toBeGreaterThan(0);
    });
  });

  it("renders /search (Global Search)", async () => {
    await mountRoute("/search");
    await waitFor(() => {
      expect(screen.getAllByText(/IOC Search/i).length).toBeGreaterThan(0);
    });
  });

  it("renders /settings (Settings & Air-Gap)", async () => {
    await mountRoute("/settings");
    await waitFor(() => {
      expect(screen.getByText(/Administration/i)).toBeInTheDocument();
      expect(screen.queryByText(/Couldn't load settings — is the backend running\?/i)).not.toBeInTheDocument();
    });
  });

  it("renders /samples/sample_remcos_01 (Sample Detail)", async () => {
    await mountRoute("/samples/sample_remcos_01");
    await waitFor(() => {
      expect(screen.getAllByText(/remcos_sample\.exe/i).length).toBeGreaterThan(0);
    }, { timeout: 3000 });
  });

  it("renders /analysis/job_sample_r (Analysis Detail)", async () => {
    await mountRoute("/analysis/job_sample_r");
    await waitFor(() => {
      expect(screen.getByText(/Analysis workspace/i)).toBeInTheDocument();
    }, { timeout: 3000 });
  });

  it("renders /runs/dyn_db3a8da614ef (Run Detail)", async () => {
    await mountRoute("/runs/dyn_db3a8da614ef");
    await waitFor(() => {
      expect(screen.getAllByText(/analysis_probe\.sh/i).length).toBeGreaterThan(0);
    }, { timeout: 3000 });
  });
});
