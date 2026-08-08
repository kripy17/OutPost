import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import {
  getMe,
  getNotificationSettings,
  setAuthToken,
  setNotificationSettings,
} from "../lib/api";
import type { NotificationSettings, NotificationSettingsIn } from "../types";

const inputCls =
  "w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none";

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="kicker mb-1 block">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={inputCls}
      />
    </label>
  );
}

function ChannelBadge({ active }: { active: boolean }) {
  return (
    <span
      className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
        active ? "border-accent/50 text-accent" : "border-border-subtle text-text-faint"
      }`}
    >
      {active ? "enabled" : "off"}
    </span>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: getMe, staleTime: 30_000 });
  const { data, isLoading, isError } = useQuery({
    queryKey: ["notifications"],
    queryFn: getNotificationSettings,
  });

  // Local draft — initialized when settings load, saved in one shot. Typed as
  // the full settings shape so read-only flags like smtp_pass_set survive edits.
  const [draft, setDraft] = useState<NotificationSettings | null>(null);
  const [saved, setSaved] = useState(false);

  const signOut = () => {
    setAuthToken(null);
    void queryClient.invalidateQueries({ queryKey: ["me"] });
  };

  const save = useMutation({
    mutationFn: (body: NotificationSettingsIn) => setNotificationSettings(body),
    onSuccess: (fresh) => {
      setDraft(fresh);
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    },
  });

  const ready = (draft ?? data) as NotificationSettings | undefined;
  const set = (patch: Partial<NotificationSettingsIn>) =>
    setDraft((d) => ({ ...(d ?? (data as NotificationSettings)), ...patch }));

  const webhookActive = Boolean(ready?.webhook_url);
  const slackActive = Boolean(ready?.slack_webhook);
  const discordActive = Boolean(ready?.discord_webhook);
  const telegramActive = Boolean(ready?.telegram_bot_token && ready?.telegram_chat_id);
  const smtpActive = Boolean(ready?.smtp_host && ready?.smtp_to);

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <PageHeader
        kicker="Operations · settings"
        title={
          <>
            Alert channels{" "}
            <span className="font-normal text-text-muted">— webhook, Slack, Discord, Telegram, email</span>
          </>
        }
        lede="Route findings to any number of channels: a generic JSON webhook, Slack, Discord, a Telegram bot, or SMTP email. Every channel receives the same alert the moment it fires — one POST per alert, sent asynchronously on ingest, plus a watchlist-hit message when a watched IOC appears in a new run."
      />

      {me?.enabled && (
        <div className="mb-6">
          <Panel
            kicker="Access"
            title="Session"
            right={
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                  me.authenticated
                    ? me.read_only
                      ? "border-risk-suspicious/50 text-risk-suspicious"
                      : "border-accent/50 text-accent"
                    : "border-border-subtle text-text-faint"
                }`}
              >
                {me.authenticated ? (me.read_only ? "analyst · read-only" : "admin · full access") : "signed out"}
              </span>
            }
          >
            <div className="flex flex-wrap items-center gap-2">
              <Icon name="shield" size={13} className={me.authenticated ? "text-accent" : "text-text-faint"} />
              <span className="text-xs text-text-muted">
                {me.authenticated
                  ? `Signed in as ${me.read_only ? "analyst" : "admin"}${me.read_only ? " — reads allowed, mutations blocked by the API gate." : " — full read/write access."}`
                  : "This server requires a password. Sign in to continue."}
              </span>
              {me.authenticated && (
                <button
                  onClick={signOut}
                  className="press ml-auto inline-flex items-center gap-1.5 rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/60 hover:text-risk-malicious"
                >
                  <Icon name="x" size={11} />
                  Sign out
                </button>
              )}
            </div>
          </Panel>
        </div>
      )}

      {isLoading && <p className="mt-6 text-sm text-text-muted">Loading settings…</p>}
      {isError && <p className="mt-6 text-sm text-risk-malicious">Couldn't load settings — is the backend running?</p>}

      {ready && (
        <div className="mt-6 space-y-4">
          <Panel
            title="Webhook endpoint"
            right={<ChannelBadge active={webhookActive} />}
          >
            <div className="space-y-3">
              <Field
                label="Webhook URL"
                value={ready.webhook_url ?? ""}
                onChange={(v) => set({ webhook_url: v })}
                placeholder="https://hooks.example.com/outpost"
              />
              <p className="font-mono text-[10px] text-text-faint">
                Receives the raw JSON payload: {"{ event, severity, rule_id, rule_name, run_id, details, triggered_at }"} per
                alert — compatible with ntfy, your own sink, or any generic receiver.
              </p>
            </div>
          </Panel>

          <Panel
            title="Slack"
            right={<ChannelBadge active={slackActive} />}
          >
            <Field
              label="Incoming webhook URL"
              value={ready.slack_webhook ?? ""}
              onChange={(v) => set({ slack_webhook: v })}
              placeholder="https://hooks.slack.com/services/T000/B000/XXXX"
            />
            <p className="mt-2 font-mono text-[10px] text-text-faint">Posts a text message per finding.</p>
          </Panel>

          <Panel
            title="Discord"
            right={<ChannelBadge active={discordActive} />}
          >
            <Field
              label="Webhook URL"
              value={ready.discord_webhook ?? ""}
              onChange={(v) => set({ discord_webhook: v })}
              placeholder="https://discord.com/api/webhooks/…/…"
            />
            <p className="mt-2 font-mono text-[10px] text-text-faint">Posts an embed colored by severity (red = malicious, amber = suspicious).</p>
          </Panel>

          <Panel
            title="Telegram"
            right={<ChannelBadge active={telegramActive} />}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Bot token"
                value={ready.telegram_bot_token ?? ""}
                onChange={(v) => set({ telegram_bot_token: v })}
                placeholder="123456:ABC-DEF…"
              />
              <Field
                label="Chat ID"
                value={ready.telegram_chat_id ?? ""}
                onChange={(v) => set({ telegram_chat_id: v })}
                placeholder="-1001234567890"
              />
            </div>
            <p className="mt-2 font-mono text-[10px] text-text-faint">
              Bot must be allowed to message the chat. Create one with @BotFather.
            </p>
          </Panel>

          <Panel
            title="SMTP email"
            right={<ChannelBadge active={smtpActive} />}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Host"
                value={ready.smtp_host ?? ""}
                onChange={(v) => set({ smtp_host: v })}
                placeholder="smtp.example.com"
              />
              <Field
                label="Port"
                value={String(ready.smtp_port ?? 587)}
                onChange={(v) => set({ smtp_port: v })}
                placeholder="587"
              />
              <Field label="User" value={ready.smtp_user ?? ""} onChange={(v) => set({ smtp_user: v })} />
              <Field
                label="Password"
                type="password"
                value=""
                onChange={(v) => set({ smtp_pass: v })}
                placeholder={ready.smtp_pass_set ? "•••••••• (kept)" : "password"}
              />
              <Field
                label="From"
                value={ready.smtp_from ?? ""}
                onChange={(v) => set({ smtp_from: v })}
                placeholder="outpost@example.com"
              />
              <Field
                label="To (comma-separated)"
                value={ready.smtp_to ?? ""}
                onChange={(v) => set({ smtp_to: v })}
                placeholder="soc@example.com, analyst@example.com"
              />
            </div>
            <p className="mt-2 font-mono text-[10px] text-text-faint">
              Plain-text email per finding. Port 465 uses implicit TLS; 587 upgrades with STARTTLS. Blank password keeps
              the stored one.
            </p>
          </Panel>

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={() => save.mutate((draft ?? (data as NotificationSettings)) as NotificationSettingsIn)}
              disabled={save.isPending || Boolean(me?.enabled && me.read_only)}
              className="press inline-flex items-center gap-2 rounded-lg border border-accent/60 bg-accent/10 px-5 py-2.5 font-mono text-sm font-medium text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)] disabled:cursor-default disabled:opacity-50"
            >
              <Icon name={save.isPending ? "refresh" : "check"} size={13} className={save.isPending ? "animate-spin" : ""} />
              {save.isPending ? "Saving…" : "Save channels"}
            </button>
            {saved && <p className="text-xs text-accent">Saved — live from the next alert.</p>}
            {me?.enabled && me.read_only && (
              <p className="text-xs text-text-muted">Read-only analyst — changes blocked by the API gate.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
