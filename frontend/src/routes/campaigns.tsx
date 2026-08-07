import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { eventDetail, TYPE_STYLE } from "../components/TimelineView/TimelineView";
import { PageHeader } from "../components/ui";
import { getCampaigns } from "../lib/api";
import type { Campaign, CampaignIoc, Severity } from "../types";

const MAX_TIMELINE = 40;
const MAX_CHIPS = 10;

const SEV_DOT: Record<Severity, string> = {
  malicious: "text-risk-malicious",
  suspicious: "text-risk-suspicious",
};

const IOC_GROUPS: { key: keyof Campaign["iocs"]; label: string; chip: string }[] = [
  { key: "ips", label: "IPs", chip: "text-accent-amber border-accent-amber/40" },
  { key: "registry_keys", label: "Registry keys", chip: "text-risk-suspicious border-risk-suspicious/40" },
  { key: "file_paths", label: "File paths", chip: "text-risk-clean border-risk-clean/40" },
  { key: "processes", label: "Processes", chip: "text-text-muted border-border-subtle" },
];

function fmt(ts: string | null): string {
  return ts ? ts.slice(0, 19).replace("T", " ") : "—";
}

function ReputationBadge({ campaign }: { campaign: Campaign }) {
  const rep = campaign.reputation;
  const style =
    rep === "malicious"
      ? "border-risk-malicious/50 text-risk-malicious"
      : "border-risk-suspicious/50 text-risk-suspicious";
  return (
    <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${style}`}>
      {campaign.watchlist ? "★ " : ""}
      {rep ?? "unknown"}
      {campaign.watchlist_label ? ` — ${campaign.watchlist_label}` : ""}
    </span>
  );
}

function IocChip({ ioc, className = "" }: { ioc: CampaignIoc; className?: string }) {
  return (
    <span
      className={`truncate rounded border bg-bg-elevated/50 px-2 py-0.5 font-mono text-[11px] ${className}`}
      title={`${ioc.value} — seen in ${ioc.runs} run(s)`}
    >
      <span className={ioc.runs >= 2 ? "font-semibold text-text-primary" : "text-text-muted"}>{ioc.value}</span>
      <span className="ml-1.5 text-[10px] text-text-faint">×{ioc.runs}</span>
    </span>
  );
}

function CampaignCard({ campaign }: { campaign: Campaign }) {
  const shown = campaign.timeline.slice(0, MAX_TIMELINE);
  const hidden = campaign.timeline.length - shown.length;

  return (
    <article className="overflow-hidden rounded-lg border border-border-subtle bg-bg-surface">
      {/* header */}
      <header className="flex flex-wrap items-center gap-3 border-b border-border-subtle bg-bg-elevated/40 px-5 py-4">
        <span className="font-mono text-lg font-semibold tracking-tight text-text-primary">{campaign.key}</span>
        <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-faint">
          {campaign.runs.length} sample{campaign.runs.length === 1 ? "" : "s"}
        </span>
        <ReputationBadge campaign={campaign} />
        <span className="ml-auto font-mono text-[10px] tabular-nums uppercase tracking-wide text-text-faint">
          {fmt(campaign.span_start)} → {fmt(campaign.span_end)}
        </span>
      </header>

      <div className="grid grid-cols-1 gap-6 p-5 lg:grid-cols-[1fr_1.4fr]">
        {/* left: member runs + IOC evidence */}
        <div className="space-y-5">
          <section>
            <h3 className="mb-2 text-[10px] uppercase tracking-widest text-text-faint">Samples</h3>
            <ul className="space-y-1">
              {campaign.runs.map((r) => (
                <li key={r.run_id}>
                  <Link
                    to={`/runs/${r.run_id}`}
                    className="flex items-baseline gap-2 rounded border border-transparent px-2 py-1.5 transition-colors hover:border-border-subtle hover:bg-bg-elevated"
                  >
                    <span className="font-mono text-sm text-text-primary">{r.sample_name}</span>
                    <span className="font-mono text-[10px] text-text-faint">{r.run_id.slice(0, 12)}</span>
                    <span className="ml-auto flex items-center gap-2">
                      <span className="font-mono text-[10px] text-text-faint">
                        {r.alert_count} alert{r.alert_count === 1 ? "" : "s"}
                      </span>
                      <span
                        className={`text-xs ${r.highest_severity ? SEV_DOT[r.highest_severity] : "text-risk-clean"}`}
                      >
                        ●
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          {IOC_GROUPS.map(({ key, label, chip }) => {
            const items = campaign.iocs[key].slice(0, MAX_CHIPS);
            if (items.length === 0) return null;
            return (
              <section key={key}>
                <h3 className="mb-2 text-[10px] uppercase tracking-widest text-text-faint">
                  {label}
                  <span className="ml-2 normal-case text-text-faint/60">seen across {campaign.runs.length} run(s)</span>
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {items.map((ioc) => (
                    <IocChip key={`${key}-${ioc.value}`} ioc={ioc} className={chip} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>

        {/* right: combined timeline */}
        <section className="min-w-0">
          <h3 className="mb-2 text-[10px] uppercase tracking-widest text-text-faint">
            Combined timeline
            <span className="ml-2 normal-case text-text-faint/60">{campaign.timeline.length} events across all samples</span>
          </h3>
          <ol className="max-h-[28rem] space-y-0.5 overflow-y-auto pr-1">
            {shown.map((ev, i) => (
              <li
                key={`${ev.run_id}-${ev.id ?? ev.timestamp}-${i}`}
                className="flex items-baseline gap-3 rounded px-1 py-0.5 hover:bg-bg-elevated"
              >
                <span
                  className="w-28 shrink-0 truncate font-mono text-[10px] text-text-faint"
                  title={`${ev.sample_name} · ${ev.run_id.slice(0, 12)}`}
                >
                  {ev.sample_name}
                </span>
                <span className="w-16 shrink-0 font-mono text-xs text-text-faint">{ev.timestamp.slice(11, 19)}</span>
                <span className={`w-36 shrink-0 font-mono text-xs ${TYPE_STYLE[ev.event_type]}`}>{ev.event_type}</span>
                <span className="truncate font-mono text-xs text-text-muted">{eventDetail(ev)}</span>
              </li>
            ))}
          </ol>
          {hidden > 0 && (
            <p className="mt-2 text-[10px] text-text-faint">+ {hidden} more event(s) — open a run for the full timeline.</p>
          )}
        </section>
      </div>
    </article>
  );
}

export default function CampaignsPage() {
  const { data: campaigns = [], isLoading, isError } = useQuery({
    queryKey: ["campaigns"],
    queryFn: getCampaigns,
  });

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <PageHeader
        kicker="Hunt · campaigns"
        title={
          <>
            Campaigns <span className="font-normal text-text-muted">— shared infrastructure across your runs</span>
          </>
        }
        lede="Runs that touch the same IP are grouped automatically. Known-clean IPs (shared DNS, for instance) never form a campaign; watchlisted or externally-flagged infrastructure ranks first."
      />

      {isLoading && <p className="mt-8 text-sm text-text-muted">Grouping runs by shared infrastructure…</p>}
      {isError && (
        <p className="mt-8 text-sm text-risk-malicious">Couldn't load campaigns — is the OutPost backend running?</p>
      )}
      {!isLoading && !isError && campaigns.length === 0 && (
        <p className="mt-8 text-sm text-text-muted">
          No campaigns yet — two or more runs must connect to the same IP. Detonate a couple of samples and check again.
        </p>
      )}

      <div className="mt-8 space-y-6">
        {campaigns.map((c) => (
          <CampaignCard key={c.key} campaign={c} />
        ))}
      </div>
    </div>
  );
}
