import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import {
  downloadBackup,
  getMe,
  getNotificationSettings,
  getRateLimitStatus,
  getRetention,
  pruneRuns,
  restoreBackup,
  saveBlob,
  setAuthToken,
  setNotificationSettings,
  setPassword,
  setRetention,
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

/** Read-only view of the login brute-force guard — the env-tunable knobs
 *  (AUTH_MAX_ATTEMPTS / AUTH_WINDOW_SECONDS / AUTH_LOCKOUT_SECONDS) plus the
 *  live state: how many IPs are tracked and currently locked out. Polls so
 *  an admin watching a live attack sees the lockout counter move. */
function LoginRateLimitPanel() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["auth", "ratelimit"],
    queryFn: getRateLimitStatus,
    refetchInterval: 15_000,
  });

  const knob = (label: string, env: string, value: number | undefined, unit = "") => (
    <div className="rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2.5">
      <p className="kicker">{label}</p>
      <p className="mt-0.5 font-mono text-lg font-semibold tabular-nums text-text-primary">
        {value ?? "…"}
        <span className="text-xs font-normal text-text-faint"> {unit}</span>
      </p>
      <p className="mt-0.5 font-mono text-[9px] text-text-faint">{env}</p>
    </div>
  );

  return (
    <Panel
      kicker="Access · security"
      title="Login brute-force guard"
      right={
        data ? (
          <span
            className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
              data.enabled ? "border-accent/50 text-accent" : "border-border-subtle text-text-faint"
            }`}
          >
            {data.enabled ? "active" : "auth off · inactive"}
          </span>
        ) : null
      }
    >
      {isError && (
        <p className="text-xs text-risk-malicious">Couldn't read the guard status — is the backend running?</p>
      )}
      {isLoading && <p className="text-xs text-text-muted">Reading guard status…</p>}
      {data && (
        <div className="space-y-3">
          <p className="text-xs leading-relaxed text-text-muted">
            Failed logins are counted per IP in a sliding window; crossing the threshold locks the IP out for the
            cooldown — even a correct password is refused during it. Values come from env at server start (read-only
            here; tune in the backend's environment).
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {knob("Max attempts", "AUTH_MAX_ATTEMPTS", data.max_attempts, "per window")}
            {knob("Window", "AUTH_WINDOW_SECONDS", data.window_seconds, "s")}
            {knob("Lockout", "AUTH_LOCKOUT_SECONDS", data.lockout_seconds, "s")}
            {knob("Tracked IPs", "live", data.tracked_ips)}
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2.5">
            <Icon name="shield" size={13} className={data.locked_ips > 0 ? "text-risk-malicious" : "text-risk-clean"} />
            <span className="text-xs text-text-muted">
              {data.locked_ips === 0
                ? "No IPs currently locked out."
                : `${data.locked_ips} IP${data.locked_ips === 1 ? " is" : "s are"} locked out — even valid passwords are refused until the cooldown expires.`}
            </span>
          </div>
          {data.locked.length > 0 && (
            <ul className="divide-y divide-border-subtle/60 rounded-lg border border-border-subtle">
              {data.locked.map((l) => (
                <li key={l.ip} className="flex items-center gap-2 px-3 py-2 font-mono text-[11px]">
                  <Icon name="x" size={11} className="text-risk-malicious" />
                  <span className="text-text-primary">{l.ip}</span>
                  <span className="ml-auto tabular-nums text-text-faint">locked for {l.remaining_seconds}s</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Panel>
  );
}

/** Retention & backup — the store can't grow forever. Set the retention
 *  window, prune old runs on demand, download a SQLite backup, or restore
 *  from one (the server keeps a safety copy of the pre-restore store). */
const SCHEDULE_LABELS: Record<string, string> = {
  off: "Off (manual only)",
  hourly: "Hourly",
  daily: "Daily",
};

function RetentionPanel() {
  const { data, isLoading } = useQuery({ queryKey: ["retention"], queryFn: getRetention });
  const queryClient = useQueryClient();
  const [days, setDays] = useState<string>("0");
  const [schedule, setSchedule] = useState<"off" | "hourly" | "daily">("off");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // Sync the picker with the server's stored schedule once it loads.
  useEffect(() => {
    if (data) setSchedule(data.auto_prune);
  }, [data]);

  const save = async () => {
    const d = Math.max(0, Math.floor(Number(days) || 0));
    setBusy("saving");
    try {
      const fresh = await setRetention(d, schedule);
      setDays(String(fresh.retention_days));
      void queryClient.invalidateQueries({ queryKey: ["retention"] });
      setMsg({
        ok: true,
        text:
          schedule === "off"
            ? `Retention set to ${fresh.retention_days}d — applied on the next manual prune.`
            : `Retention set to ${fresh.retention_days}d — auto-pruning ${schedule} from now on.`,
      });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Couldn't save retention." });
    } finally {
      setBusy(null);
    }
  };

  const prune = async () => {
    setBusy("prune");
    try {
      const out = await pruneRuns(days ? Math.floor(Number(days)) || undefined : undefined);
      setMsg({ ok: true, text: `Pruned ${out.deleted_runs} run(s) older than ${out.days}d (cutoff ${out.cutoff.slice(0, 19).replace("T", " ")}).` });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Prune failed." });
    } finally {
      setBusy(null);
    }
  };

  const backup = async () => {
    setBusy("backup");
    try {
      const blob = await downloadBackup();
      saveBlob(blob, `outpost-backup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.db`);
      setMsg({ ok: true, text: "Backup downloaded — keep it somewhere safe." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Backup failed." });
    } finally {
      setBusy(null);
    }
  };

  const onRestoreFile = async (file: File | undefined) => {
    if (!file) return;
    if (!window.confirm("Restore replaces the ENTIRE store with this backup. Continue?")) return;
    setBusy("restore");
    try {
      const out = await restoreBackup(await file.arrayBuffer());
      setMsg({ ok: true, text: `Restored from ${file.name} — safety copy saved as ${out.safety_copy}.` });
      window.location.reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Restore failed." });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel
      kicker="Operations · store"
      title="Retention & backup"
      right={
        <span className="flex items-center gap-2">
          {data?.auto_prune_enabled && (
            <span className="rounded-full border border-accent/50 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-accent">
              auto {data.auto_prune}
            </span>
          )}
          <span className="rounded-full border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-faint">
            {isLoading ? "…" : `${data?.retention_days ?? 0}d retention`}
          </span>
        </span>
      }
    >
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-3">
          <p className="kicker">Retention</p>
          <p className="text-xs leading-relaxed text-text-muted">
            Runs older than the window are pruned with their events, alerts, notes, and allowlists — the sample vault is
            never touched. 0 keeps everything (the default). Pick a schedule to prune on an interval instead of only on
            demand.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="number"
              min={0}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="w-24 rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
              aria-label="Retention days"
            />
            <span className="text-xs text-text-muted">days</span>
            <select
              value={schedule}
              onChange={(e) => setSchedule(e.target.value as "off" | "hourly" | "daily")}
              className="rounded border border-border-subtle bg-bg-base px-2 py-2 font-mono text-xs text-text-primary focus:border-accent/60 focus:outline-none"
              aria-label="Auto-prune schedule"
            >
              {Object.entries(SCHEDULE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <button
              onClick={() => void save()}
              disabled={busy !== null}
              className="press rounded-lg border border-accent/60 bg-accent/10 px-3 py-2 font-mono text-xs text-accent transition-colors hover:shadow-[var(--glow-accent)] disabled:opacity-50"
            >
              {busy === "saving" ? "Saving…" : "Save window"}
            </button>
            <button
              onClick={() => void prune()}
              disabled={busy !== null}
              className="press rounded-lg border border-risk-malicious/50 px-3 py-2 font-mono text-xs text-risk-malicious transition-colors hover:bg-risk-malicious/10 disabled:opacity-50"
              title="Delete runs older than the retention window now"
            >
              {busy === "prune" ? "Pruning…" : "Prune now"}
            </button>
          </div>
          {data?.auto_prune_enabled && (
            <p className="font-mono text-[10px] text-text-faint">
              last auto-prune: {data.last_prune_at ? data.last_prune_at.slice(0, 19).replace("T", " ") + "Z" : "never"}
              {data.next_prune_in_seconds !== null &&
                ` · next in ~${Math.floor(data.next_prune_in_seconds / 3600)}h ${Math.floor((data.next_prune_in_seconds % 3600) / 60)}m`}
            </p>
          )}
        </div>
        <div className="space-y-3">
          <p className="kicker">Backup & restore</p>
          <p className="text-xs leading-relaxed text-text-muted">
            Download a consistent SQLite snapshot of the whole store, or restore from one. Restoring replaces everything
            and the pre-restore store is kept as a safety copy.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void backup()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent disabled:opacity-50"
            >
              <Icon name="download" size={12} />
              {busy === "backup" ? "Backing up…" : "Download backup"}
            </button>
            <label className="press inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-risk-malicious/50 hover:text-risk-malicious disabled:opacity-50">
              <Icon name="file" size={12} />
              {busy === "restore" ? "Restoring…" : "Restore from file"}
              <input
                type="file"
                accept=".db,application/octet-stream"
                className="hidden"
                onChange={(e) => void onRestoreFile(e.target.files?.[0])}
              />
            </label>
          </div>
        </div>
      </div>
      {msg && <p className={`mt-3 text-xs ${msg.ok ? "text-accent" : "text-risk-malicious"}`}>{msg.text}</p>}
    </Panel>
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

  // Password rotation (admin only) — stored server-side as a salted PBKDF2 hash.
  const [pwRole, setPwRole] = useState<"admin" | "analyst">("admin");
  const [newPass, setNewPass] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const rotate = useMutation({
    mutationFn: ({ role, password }: { role: "admin" | "analyst"; password: string }) =>
      setPassword(role, password),
    onSuccess: () => {
      setNewPass("");
      setConfirmPass("");
      setPwMsg({ ok: true, text: "Password stored as a salted PBKDF2 hash — use it on the login screen from now on." });
      setTimeout(() => setPwMsg(null), 4000);
    },
    onError: (e: unknown) => {
      setPwMsg({ ok: false, text: e instanceof Error ? e.message : "Couldn't change the password." });
    },
  });
  const submitPassword = () => {
    if (newPass.length < 8) {
      setPwMsg({ ok: false, text: "Password must be at least 8 characters." });
      return;
    }
    if (newPass !== confirmPass) {
      setPwMsg({ ok: false, text: "Passwords don't match." });
      return;
    }
    rotate.mutate({ role: pwRole, password: newPass });
  };

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

      <div className="mb-6">
        <Panel
          kicker="Appearance"
          title="Theme & palette"
          right={
            <Link
              to="/themes"
              className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent transition-colors hover:underline"
            >
              open theme lab <Icon name="arrowRight" size={11} />
            </Link>
          }
        >
          <div className="flex flex-wrap items-center gap-2">
            <Icon name="sliders" size={13} className="text-accent" />
            <span className="text-xs text-text-muted">
              Toggle dark/light from the rail footer, or fine-tune the accent, base, and risk palettes in the theme lab.
            </span>
            <span className="ml-auto font-mono text-[10px] text-text-faint">persisted in localStorage</span>
          </div>
        </Panel>
      </div>

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

      <div className="mb-6">
        <LoginRateLimitPanel />
      </div>

      <div className="mb-6">
        <RetentionPanel />
      </div>

      {me?.enabled && me.authenticated && !me.read_only && (
        <div className="mb-6">
          <Panel
            kicker="Access · credentials"
            title="Change password"
            right={
              <span className="rounded-full border border-accent/40 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-accent">
                {me.credential_mode === "hash" ? "stored as salted hash" : "plaintext env (legacy)"}
              </span>
            }
          >
            <div className="flex flex-wrap items-end gap-2">
              <label className="block">
                <span className="kicker mb-1 block">Role</span>
                <select
                  value={pwRole}
                  onChange={(e) => setPwRole(e.target.value as "admin" | "analyst")}
                  className="rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
                >
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                </select>
              </label>
              <label className="block min-w-40 flex-1">
                <span className="kicker mb-1 block">New password</span>
                <input
                  type="password"
                  value={newPass}
                  onChange={(e) => setNewPass(e.target.value)}
                  placeholder="at least 8 characters"
                  className="w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </label>
              <label className="block min-w-40 flex-1">
                <span className="kicker mb-1 block">Confirm</span>
                <input
                  type="password"
                  value={confirmPass}
                  onChange={(e) => setConfirmPass(e.target.value)}
                  placeholder="repeat it"
                  className="w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </label>
              <button
                onClick={submitPassword}
                disabled={rotate.isPending}
                className="press rounded-lg border border-accent/60 bg-accent/10 px-4 py-2 font-mono text-xs font-medium text-accent transition-colors duration-150 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
              >
                {rotate.isPending ? "Storing…" : "Set password"}
              </button>
            </div>
            <p className="mt-2 text-[11px] text-text-muted">
              Stored server-side as a salted PBKDF2 hash — never in plaintext. Rotating a role's password invalidates
              that role's existing sessions.
            </p>
            {pwMsg && <p className={`mt-2 text-xs ${pwMsg.ok ? "text-accent" : "text-risk-malicious"}`}>{pwMsg.text}</p>}
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
