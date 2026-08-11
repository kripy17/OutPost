// Kill-chain stats — pure helper for the stepper and the run-detail card.
// Stage mapping lives in lib/constants.ts (KILL_CHAIN_STAGE/ORDER), mirroring
// the backend's detection._KILL_CHAIN_STAGE so both stay in lockstep.

import { KILL_CHAIN_STAGE } from "../../lib/constants";
import type { Alert } from "../../types";

/** Coverage stats for the Panel's right slot — one source of truth. */
export function killChainStats(alerts: Alert[]): { fired: number; stages: number } {
  const reached = new Set(
    alerts.map((a) => KILL_CHAIN_STAGE[a.rule_id]).filter((s): s is string => Boolean(s)),
  );
  return { fired: alerts.filter((a) => KILL_CHAIN_STAGE[a.rule_id]).length, stages: reached.size };
}
