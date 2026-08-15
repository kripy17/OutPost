// Kill-chain stepper — maps a run's fired rules onto the MITRE chain stages,
// showing which phases of the attack lifecycle the sample actually exercised.
// Stage mapping and order live in lib/constants.ts (KILL_CHAIN_STAGE/ORDER),
// mirroring the backend's detection._KILL_CHAIN_STAGE so both stay in lockstep.
//
// Frame-less: run detail owns the Panel card and its kicker header; this
// component renders the stepper row itself so the deck can frame it.

import { KILL_CHAIN_ORDER, KILL_CHAIN_STAGE } from "../../lib/constants";
import { toneFill } from "../../lib/fillPatterns";
import type { Alert } from "../../types";

export default function KillChainStepper({ alerts }: { alerts: Alert[] }) {
  const reached = new Set(
    alerts.map((a) => KILL_CHAIN_STAGE[a.rule_id]).filter((s): s is string => Boolean(s)),
  );

  return (
    <>
      <ol className="flex items-start overflow-x-auto pb-1">
        {KILL_CHAIN_ORDER.map((stage, i) => {
          const hit = reached.has(stage);
          const isFullChain = stage === "Full Chain";
          return (
            <li key={stage} className="flex items-start">
              {i > 0 && (
                <span
                  className={`mt-3 h-0.5 w-5 shrink-0 sm:w-8 ${
                    reached.has(KILL_CHAIN_ORDER[i]) ? "bg-accent/70" : "bg-border-subtle"
                  }`}
                  aria-hidden
                />
              )}
              <div className="flex w-20 shrink-0 flex-col items-center gap-1.5 sm:w-24">
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full border font-mono text-[10px] transition-colors duration-200 ${
                    hit
                      ? isFullChain
                        ? "border-risk-malicious/70 text-risk-malicious"
                        : "border-accent/70 text-accent"
                      : "border-border-subtle text-text-faint"
                  }`}
                  style={hit ? (isFullChain ? toneFill("critical") : toneFill("elevated")) : undefined}
                  title={hit ? `${stage} — observed` : `${stage} — not observed`}
                >
                  {hit ? (isFullChain ? "✸" : "✓") : "·"}
                </span>
                <span
                  className={`text-center font-mono text-[9px] leading-tight tracking-wide ${
                    hit ? "text-text-primary" : "text-text-faint"
                  }`}
                >
                  {stage}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
      {/* Stage fills are pattern-encoded, not just tinted (deck-wide fill
          language): solid = full chain, hatch = reached, hollow = not. */}
      <p className="mt-2 font-mono text-[9px] uppercase tracking-wide text-text-faint" aria-label="Stage fill key">
        solid = full chain · hatch = reached · hollow = not reached
      </p>
    </>
  );
}
