import { Icon } from "./Icon";

export interface ExplanationCard {
  id: string;
  tone: "critical" | "attention" | "info";
  title: string;
  domain: string;
  why: string;
  evidence: string[];
  evidence_count: number;
  next_step: string;
}

export function BehavioralExplanationsView({
  explanations,
}: {
  explanations: ExplanationCard[];
}) {
  if (!explanations || explanations.length === 0) {
    return (
      <div className="rounded-2xl border border-border-subtle bg-bg-surface p-12 text-center font-mono text-xs">
        <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-xl bg-signal/15 text-signal">
          <Icon name="check" size={20} />
        </div>
        <p className="font-bold text-text-primary">Clean Behavioral Baseline</p>
        <p className="mt-1 text-text-muted">Zero behavioral heuristics, unmanaged binary drops, or suspicious sockets detected.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="flex items-center justify-between">
        <span className="font-bold text-text-primary flex items-center gap-2">
          <Icon name="alert" size={14} className="text-accent" />
          Automated Behavioral Heuristics ({explanations.length})
        </span>
        <span className="text-[11px] text-text-faint">Derived via real-time procfs & socket causality analysis</span>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {explanations.map((card) => {
          const isCritical = card.tone === "critical";
          const isAttention = card.tone === "attention";

          return (
            <div
              key={card.id}
              className={`flex flex-col justify-between rounded-2xl border p-5 transition-all shadow-sm ${
                isCritical
                  ? "border-risk-malicious/50 bg-risk-malicious/10 hover:border-risk-malicious/70"
                  : isAttention
                  ? "border-risk-suspicious/40 bg-risk-suspicious/10 hover:border-risk-suspicious/60"
                  : "border-border-subtle bg-bg-surface hover:border-border-strong"
              }`}
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className={`h-2.5 w-2.5 rounded-full ${
                      isCritical ? "bg-risk-malicious animate-pulse" : isAttention ? "bg-risk-suspicious" : "bg-signal"
                    }`} />
                    <h4 className="font-bold text-text-primary text-sm">{card.title}</h4>
                  </div>
                  <span className={`rounded-full px-2 py-0.5 text-[9px] uppercase font-bold ${
                    isCritical
                      ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/40"
                      : isAttention
                      ? "bg-risk-suspicious/20 text-risk-suspicious border border-risk-suspicious/40"
                      : "bg-signal/20 text-signal border border-signal/40"
                  }`}>
                    {card.domain}
                  </span>
                </div>

                <p className="text-[11px] leading-relaxed text-text-muted">
                  {card.why}
                </p>

                {/* Evidence Box */}
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-3 space-y-1.5">
                  <span className="text-[9px] font-bold uppercase tracking-wider text-text-faint">
                    Live System Evidence ({card.evidence_count})
                  </span>
                  <ul className="space-y-1">
                    {card.evidence.map((ev, i) => (
                      <li key={i} className="text-[11px] text-text-primary font-mono truncate">
                        • {ev}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Actionable Next Steps */}
              <div className="mt-4 pt-3 border-t border-border-subtle flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase text-text-faint font-bold">Action:</span>
                  <span className="text-[11px] text-accent font-semibold">{card.next_step}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default BehavioralExplanationsView;
