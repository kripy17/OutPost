// Agent fleet — which hosts are streaming telemetry into this console.
//
// Every event carries a host_id: webapp detonations and sandbox runs are
// attributed to 'local', while hosts running `outpost agent run` (or the
// collectors directly) ship under their own host label. The fleet page makes
// multi-host monitoring visible: heartbeat status, event/alert volume per
// host, and a one-line reminder of how to bring a new host online.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader, Panel } from "../components/ui";
import { getAgents, getHostBaseline, getHostSnapshot, resetHostBaseline } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import type { AgentInfo, HostBaseline } from "../types";

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function AgentRow({ agent }: { agent: AgentInfo }) {
  const recent = agent.recent_run_ids ?? [];
  const status: "online" | "offline" | "silent" = agent.silent ? "silent" : agent.online ? "online" : "offline";
  const statusTone =
    status === "online"
      ? "border-signal/40 bg-signal/10 text-signal"
      : status === "silent"
        ? "border-risk-malicious/50 bg-risk-malicious/10 text-risk-malicious"
        : "border-border-subtle text-text-faint";
  const dotTone =
    status === "online"
      ? "animate-outpost-pulse bg-signal"
      : status === "silent"
        ? "animate-outpost-pulse bg-risk-malicious"
        : "bg-text-faint";
  return (
    <li className="group relative overflow-hidden rounded-xl border border-border-subtle bg-bg-surface transition-all duration-150 hover:border-accent/40 hover:shadow-[var(--shadow-panel)]">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4">
        <span
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${
            status === "online"
              ? "border-signal/40 bg-signal/10 text-signal"
              : status === "silent"
                ? "border-risk-malicious/50 bg-risk-malicious/10 text-risk-malicious"
                : "border-border-subtle bg-bg-elevated/60 text-text-faint"
          }`}
        >
          <Icon name="terminal" size={18} />
        </span>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-text-primary">{agent.host_id}</span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-px font-mono text-[10px] ${statusTone}`}
              title={
                status === "silent"
                  ? "Heartbeated before but quiet for over the silent window — the collector may be down"
                  : undefined
              }
            >
              <span className={`h-1.5 w-1.5 rounded-full ${dotTone}`} aria-hidden />
              {status}
            </span>
            {agent.identity === "collector" && (
              <span
                className="inline-flex items-center gap-1 rounded-full border border-signal/40 bg-signal/10 px-2 py-px font-mono text-[10px] text-signal"
                title={`Real host agent${agent.heartbeat_version ? ` · ${agent.heartbeat_version}` : ""} · channels: ${agent.channels?.join(", ") || "—"} · last auth: ${agent.last_auth_role ?? "—"}${agent.last_auth_at ? ` ${relativeTime(agent.last_auth_at)}` : ""}`}
              >
                <Icon name="terminal" size={10} />
                collector
              </span>
            )}
            {agent.identity === "webapp" && (
              <span
                className="rounded-full border border-border-subtle bg-bg-elevated/60 px-2 py-px font-mono text-[10px] text-text-muted"
                title="No agent heartbeat — events came from this machine (webapp detonations, sandbox runs)"
              >
                webapp detonation
              </span>
            )}
            {agent.last_auth_role && (
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2 py-px font-mono text-[10px] ${
                  agent.last_auth_role === "agent"
                    ? "border-accent/40 bg-accent/10 text-accent"
                    : agent.last_auth_role === "local"
                      ? "border-border-subtle bg-bg-elevated/60 text-text-faint"
                      : "border-border-subtle bg-bg-elevated/60 text-text-muted"
                }`}
                title={`Authenticated ${agent.last_auth_role === "agent" ? "via the shared OUTPOST_AGENT_TOKEN" : agent.last_auth_role === "local" ? "without a credential (auth off / open mode)" : `as the ${agent.last_auth_role} role`}${agent.last_auth_at ? ` · ${relativeTime(agent.last_auth_at)}` : ""}`}
              >
                auth: {agent.last_auth_role === "agent" ? "agent token" : agent.last_auth_role}
              </span>
            )}
          </div>
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[11px] text-text-faint">
            <span>
              {agent.event_count} event{agent.event_count === 1 ? "" : "s"} · {agent.run_count} run{agent.run_count === 1 ? "" : "s"} · {agent.alert_count} alert{agent.alert_count === 1 ? "" : "s"}
            </span>
            <span className="inline-flex items-center gap-1">
              {agent.platforms.map((p) => (
                <span key={p} className="inline-flex items-center gap-1 capitalize">
                  <Icon name={platformIconName(p)} size={11} />
                  {p}
                </span>
              ))}
            </span>
            <span>last event {relativeTime(agent.last_seen)}</span>
            {agent.last_heartbeat && (
              <span className={agent.silent ? "font-semibold text-risk-malicious" : undefined}>
                heartbeat {relativeTime(agent.last_heartbeat)}
                {agent.silent && " · went silent"}
              </span>
            )}
            {agent.heartbeat_version && !agent.silent && (
              <span className="text-text-faint">{agent.heartbeat_version}</span>
            )}
          </p>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {recent.length > 0 && (
            <div className="flex items-center gap-1">
              {recent.map((rid) => (
                <Link
                  key={rid}
                  to={`/runs/${rid}`}
                  className="rounded border border-border-subtle bg-bg-elevated/50 px-1.5 py-0.5 font-mono text-[10px] text-text-faint transition-colors hover:border-accent/50 hover:text-accent"
                  title={`Open run ${rid.slice(0, 12)}`}
                >
                  {rid.slice(0, 6)}
                </Link>
              ))}
            </div>
          )}
          <Link
            to={`/history?host=${encodeURIComponent(agent.host_id)}`}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            title={`Every run that ${agent.host_id} contributed events to`}
          >
            <Icon name="clock" size={12} />
            Runs
          </Link>
          <Link
            to={`/events?q=${encodeURIComponent(agent.host_id)}`}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            title={`All events from ${agent.host_id}`}
          >
            <Icon name="list" size={12} />
            Events
          </Link>
        </div>
      </div>
    </li>
  );
}

/** Live system snapshot — the "what's running right now" view. Picks the
 *  newest snapshot host by default and polls every 10s so the process/port
 *  tables track the live host while it's streaming. */
function SnapshotPanel({ agents }: { agents: AgentInfo[] }) {
  const withSnap = agents.filter((a) => a.last_snapshot_at);
  const [host, setHost] = useState<string | null>(null);
  const selected =
    host !== null && withSnap.some((a) => a.host_id === host)
      ? host
      : withSnap.length > 0
        ? (withSnap[0].host_id ?? null)
        : null;
  const { data: snap, isError } = useQuery({
    queryKey: ["snapshot", selected],
    queryFn: () => getHostSnapshot(selected as string),
    enabled: selected !== null,
    refetchInterval: 10_000,
  });

  return (
    <Panel
      kicker="Live system snapshot"
      title={
        <>
          Running now{" "}
          {snap && (
            <span className="font-normal text-text-faint">— {snap.platform} · {snap.processes.length} processes · {snap.listening.length} listening</span>
          )}
        </>
      }
      right={
        selected !== null ? (
          <div className="flex flex-wrap items-center gap-1.5">
            {withSnap.map((a) => (
              <button
                key={a.host_id}
                onClick={() => setHost(a.host_id)}
                aria-pressed={selected === a.host_id}
                className={`press rounded-lg border px-2.5 py-1 font-mono text-[11px] transition-colors duration-150 ${
                  selected === a.host_id
                    ? "border-accent/60 bg-accent/10 text-accent"
                    : "border-border-subtle text-text-muted hover:text-text-primary"
                }`}
              >
                {a.host_id}
              </button>
            ))}
          </div>
        ) : undefined
      }
    >
      {withSnap.length === 0 && (
        <div className="py-4 text-center">
          <p className="text-sm text-text-muted">
            No host has shipped a live snapshot yet. Run{" "}
            <code className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-text-primary">outpost agent run</code>{" "}
            on a machine and its process + listening-port table appears here.
          </p>
        </div>
      )}
      {selected !== null && isError && (
        <div className="py-4 text-center">
          <Icon name="terminal" size={22} className="mx-auto text-text-faint" />
          <p className="mt-2 text-sm text-text-muted">
            No live snapshot for <span className="font-mono text-text-primary">{selected}</span> — its agent may be offline.
          </p>
        </div>
      )}
      {snap && (
        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <p className="kicker mb-1.5">Processes</p>
            <div className="max-h-[340px] overflow-auto rounded-lg border border-border-subtle">
              <table className="w-full text-left font-mono text-[11px]">
                <thead className="sticky top-0 bg-bg-elevated text-[10px] uppercase tracking-wide text-text-faint">
                  <tr>
                    <th className="px-2.5 py-1.5">PID</th>
                    <th className="px-2.5 py-1.5">Name</th>
                    <th className="px-2.5 py-1.5">User</th>
                    <th className="px-2.5 py-1.5">Cmdline</th>
                  </tr>
                </thead>
                <tbody>
                  {snap.processes.map((p) => (
                    <tr key={`${p.pid}-${p.name}`} className="border-t border-border-subtle/60 odd:bg-bg-surface">
                      <td className="px-2.5 py-1 tabular-nums text-text-muted">{p.pid}</td>
                      <td className="px-2.5 py-1 font-semibold text-text-primary">{p.name}</td>
                      <td className="px-2.5 py-1 text-text-muted">{p.user ?? "—"}</td>
                      <td className="max-w-[240px] truncate px-2.5 py-1 text-text-faint" title={p.cmdline}>
                        {p.cmdline ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div>
            <p className="kicker mb-1.5">Listening ports</p>
            <div className="max-h-[340px] overflow-auto rounded-lg border border-border-subtle">
              <table className="w-full text-left font-mono text-[11px]">
                <thead className="sticky top-0 bg-bg-elevated text-[10px] uppercase tracking-wide text-text-faint">
                  <tr>
                    <th className="px-2.5 py-1.5">Proto</th>
                    <th className="px-2.5 py-1.5">Address</th>
                    <th className="px-2.5 py-1.5">Port</th>
                    <th className="px-2.5 py-1.5">PID</th>
                  </tr>
                </thead>
                <tbody>
                  {snap.listening.map((l, i) => (
                    <tr key={`${l.proto}-${l.addr}-${l.port}-${i}`} className="border-t border-border-subtle/60 odd:bg-bg-surface">
                      <td className="px-2.5 py-1 uppercase text-text-muted">{l.proto}</td>
                      <td className="px-2.5 py-1 text-text-primary">{l.addr}</td>
                      <td className="px-2.5 py-1 tabular-nums text-text-muted">{l.port}</td>
                      <td className="px-2.5 py-1 tabular-nums text-text-faint">{l.pid ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

/** Host behavioral baselines — what each host normally executes / talks to,
 *  learned from its own telemetry. The anomaly layer flags first-times; this
 *  panel makes the learned profile visible and lets an operator reset it
 *  (e.g. after deliberately changing what a host should do). */
function BaselinePanel({ agents }: { agents: AgentInfo[] }) {
  const queryClient = useQueryClient();
  const hosts = agents.map((a) => a.host_id);
  const { data: baselines, isLoading } = useQuery({
    queryKey: ["baselines", hosts.join(",")],
    queryFn: async (): Promise<HostBaseline[]> => {
      const out: HostBaseline[] = [];
      for (const h of hosts) {
        try {
          out.push(await getHostBaseline(h));
        } catch {
          // 404/empty — host never shipped events; skip.
        }
      }
      return out;
    },
    enabled: hosts.length > 0,
  });
  const reset = useMutation({
    mutationFn: (hostId: string) => resetHostBaseline(hostId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["baselines"] }),
  });
  const rows = (baselines ?? []).filter((b) => b.total_observations > 0 || b.anomaly_count > 0);

  return (
    <Panel
      kicker="Behavioral baselines"
      title="Host profiles"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          anomaly layer — first-time processes & IPs fire baseline-anomaly
        </span>
      }
    >
      {isLoading && <div className="skeleton h-16 w-full" />}
      {!isLoading && rows.length === 0 && (
        <p className="py-3 text-center text-sm text-text-muted">
          No host has crossed the baseline gate yet — a host must ship{" "}
          <code className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[11px]">
            BASELINE_MIN_EVENTS
          </code>{" "}
          observations before first-times start firing.
        </p>
      )}
      {rows.length > 0 && (
        <div className="overflow-auto rounded-lg border border-border-subtle">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="sticky top-0 bg-bg-elevated text-[10px] uppercase tracking-wide text-text-faint">
              <tr>
                <th className="px-2.5 py-1.5">Host</th>
                <th className="px-2.5 py-1.5">Processes learned</th>
                <th className="px-2.5 py-1.5">IPs learned</th>
                <th className="px-2.5 py-1.5">Observations</th>
                <th className="px-2.5 py-1.5">Anomalies</th>
                <th className="px-2.5 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => (
                <tr key={b.host_id} className="border-t border-border-subtle/60 odd:bg-bg-surface">
                  <td className="px-2.5 py-1.5 font-semibold text-text-primary">{b.host_id}</td>
                  <td className="px-2.5 py-1.5 text-text-muted" title={b.processes.map((p) => `${p.value} ×${p.count}`).join("\n")}>
                    {b.processes.length} distinct
                  </td>
                  <td className="px-2.5 py-1.5 text-text-muted" title={b.networks.map((n) => `${n.value} ×${n.count}`).join("\n")}>
                    {b.networks.length} distinct
                  </td>
                  <td className="px-2.5 py-1.5 tabular-nums text-text-faint">{b.total_observations}</td>
                  <td className="px-2.5 py-1.5">
                    {b.anomaly_count > 0 ? (
                      <Link to="/triage" className="rounded-full border border-risk-suspicious/50 bg-risk-suspicious/10 px-2 py-px text-[10px] text-risk-suspicious hover:bg-risk-suspicious/20">
                        {b.anomaly_count} fired
                      </Link>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                  </td>
                  <td className="px-2.5 py-1.5 text-right">
                    <button
                      onClick={() => reset.mutate(b.host_id)}
                      disabled={reset.isPending}
                      className="press rounded border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-faint hover:border-risk-malicious/50 hover:text-risk-malicious disabled:opacity-50"
                    >
                      Reset
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

const IDENTITY_FILTERS = [
  { value: "", label: "All" },
  { value: "collector", label: "Collectors" },
  { value: "webapp", label: "Webapp" },
  { value: "silent", label: "Silent" },
] as const;

export default function AgentsPage() {
  const queryClient = useQueryClient();
  // Filter-in-URL (Event Log parity): ?identity=collector|webapp|silent is
  // the shareable/bookmarkable fleet view.
  const [searchParams, setSearchParams] = useSearchParams();
  const identity = searchParams.get("identity") ?? "";
  const { data, isLoading, isError } = useQuery({
    queryKey: ["agents", identity],
    queryFn: () => getAgents(identity),
    refetchInterval: 15_000,
  });

  // Live fleet: a heartbeat push flips a host to online (and the fleet-health
  // loop flips silent hosts) the moment it happens — the 15 s poll stays as
  // the fallback.
  useEventStream(
    () => undefined,
    undefined,
    undefined,
    () => {
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  );

  const agents = data?.agents ?? [];
  const totalEvents = agents.reduce((n, a) => n + a.event_count, 0);
  const totalAlerts = agents.reduce((n, a) => n + a.alert_count, 0);

  return (
    <div className="mx-auto max-w-[1200px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · fleet"
        title={
          <>
            Agents <span className="font-normal text-text-muted">— hosts streaming telemetry</span>
          </>
        }
        lede="Every event names the host it came from. Detonations and sandbox runs attribute to this server; hosts running the collector stream under their own label. Watch heartbeats, volume, and findings per machine."
        actions={
          <button
            onClick={() => window.location.reload()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            <Icon name="refresh" size={12} />
            Refresh
          </button>
        }
      />

      {/* Identity filter — ?identity= in the URL (Event Log parity). */}
      <div className="mb-5 flex flex-wrap items-center gap-2" role="group" aria-label="Filter fleet by identity">
        {IDENTITY_FILTERS.map((f) => {
          const active = (identity || "") === f.value;
          return (
            <button
              key={f.value || "all"}
              onClick={() => {
                const next = new URLSearchParams(searchParams);
                if (f.value) {
                  next.set("identity", f.value);
                } else {
                  next.delete("identity");
                }
                setSearchParams(next, { replace: true });
              }}
              aria-pressed={active}
              className={`press inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] transition-colors duration-150 ${
                active
                  ? "border-accent/60 bg-accent/10 text-accent"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/40 hover:text-accent"
              }`}
            >
              {f.label}
            </button>
          );
        })}
      </div>

      {/* Fleet summary strip */}
      <div className="mb-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {[
          { label: "Hosts", value: data?.total ?? "…", icon: "terminal" as const },
          { label: "Online now", value: data?.online ?? "…", icon: "activity" as const, tone: data?.online ? "text-signal" : "text-text-muted" },
          { label: "Silent hosts", value: data?.silent ?? "…", icon: "alert" as const, tone: data?.silent ? "text-risk-malicious" : "text-text-muted" },
          { label: "Events shipped", value: totalEvents.toLocaleString(), icon: "list" as const },
          { label: "Findings", value: totalAlerts.toLocaleString(), icon: "alert" as const, tone: totalAlerts ? "text-risk-malicious" : "text-text-muted" },
        ].map((s) => (
          <div key={s.label} className="panel flex items-center gap-3 px-5 py-4">
            <span className={`flex h-9 w-9 items-center justify-center rounded-lg border border-border-subtle bg-bg-elevated/60 ${s.tone ?? "text-text-muted"}`}>
              <Icon name={s.icon} size={16} />
            </span>
            <div>
              <p className="kicker">{s.label}</p>
              <p className="font-mono text-xl font-semibold tabular-nums text-text-primary">{s.value}</p>
            </div>
          </div>
        ))}
      </div>

      {isLoading && (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="skeleton h-20 w-full" />
          ))}
        </div>
      )}

      {isError && (
        <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't reach the fleet endpoint — is the backend running?
        </p>
      )}

      {!isLoading && !isError && agents.length === 0 && (
        <Panel kicker="Fleet" title={identity ? "No hosts match this filter" : "No agents yet"}>
          <div className="py-6 text-center">
            <Icon name="terminal" size={28} className="mx-auto text-text-faint" />
            {identity ? (
              <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-text-muted">
                No host fits <code className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[11px]">identity={identity}</code>{" "}
                right now.
                <button
                  onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
                  className="ml-2 text-accent underline-offset-2 hover:underline"
                >
                  Clear filter
                </button>
              </p>
            ) : (
              <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-text-muted">
                Telemetry appears here the moment any event lands. To bring a real host online, open the{" "}
                <Link to="/monitor" className="text-accent hover:underline">
                  Live Monitor
                </Link>
                , start a live session, then run{" "}
                <code className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-text-primary">outpost agent run</code>{" "}
                on the host — its auditd/Sysmon events stream in under this host's name.
              </p>
            )}
          </div>
        </Panel>
      )}

      {agents.length > 0 && (
        <>
          <Panel
            kicker="Fleet"
            title="Hosts"
            right={
              <span className="font-mono text-[10px] text-text-faint">
                online &lt; {data?.online_window_seconds}s · silent &gt; {data?.silent_window_seconds}s
              </span>
            }
          >
            <ul className="space-y-2.5">
              {agents.map((a) => (
                <AgentRow key={a.host_id} agent={a} />
              ))}
            </ul>
          </Panel>
          <div className="mt-5">
            <SnapshotPanel agents={agents} />
          </div>
          <div className="mt-5">
            <BaselinePanel agents={agents} />
          </div>
        </>
      )}
    </div>
  );
}
