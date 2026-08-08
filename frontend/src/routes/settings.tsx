import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader, Panel } from "../components/ui";
import { getNotificationSettings, setNotificationSettings } from "../lib/api";

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["notifications"],
    queryFn: getNotificationSettings,
  });
  const [webhook, setWebhook] = useState("");
  const [saved, setSaved] = useState(false);

  const save = useMutation({
    mutationFn: (url: string) => setNotificationSettings(url),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    },
  });

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <PageHeader
        kicker="Operations · settings"
        title={
          <>
            Alert notifications <span className="font-normal text-text-muted">— webhook on new malicious findings</span>
          </>
        }
        lede="Point OutPost at a webhook (Slack, Discord, ntfy, your own sink) and every new malicious alert posts a JSON payload there — no polling required."
      />

      {isLoading && <p className="mt-6 text-sm text-text-muted">Loading settings…</p>}
      {isError && <p className="mt-6 text-sm text-risk-malicious">Couldn't load settings — is the backend running?</p>}

      {data && (
        <div className="mt-6 space-y-4">
          <Panel
            title="Webhook endpoint"
            right={
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                  data.enabled
                    ? "border-accent/50 text-accent"
                    : "border-border-subtle text-text-faint"
                }`}
              >
                {data.enabled ? "enabled" : "disabled"}
              </span>
            }
          >
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="url"
                value={webhook || data.webhook_url}
                onChange={(e) => setWebhook(e.target.value)}
                placeholder="https://hooks.slack.com/services/…"
                className="w-full flex-1 rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
              />
              <button
                onClick={() => save.mutate((webhook || data.webhook_url).trim())}
                disabled={save.isPending}
                className="press rounded border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
              >
                {data.enabled ? "Update" : "Enable"}
              </button>
            </div>
            <p className="mt-3 font-mono text-[10px] text-text-faint">
              Payload: {"{ run_id, sample_name, rule_name, severity, details, triggered_at, related_ip }"} — one POST per
              alert, sent asynchronously on ingest.
            </p>
            {saved && <p className="mt-2 text-xs text-accent">Saved — live from the next alert.</p>}
          </Panel>
        </div>
      )}
    </div>
  );
}
