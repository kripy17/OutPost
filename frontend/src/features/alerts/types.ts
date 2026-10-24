import { SeverityLevel } from "../../foundation/tokens";

export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface AlertItem {
  id: number;
  run_id: string;
  sample_name?: string | null;
  rule_id: string;
  rule_name: string;
  severity: SeverityLevel | string;
  triggered_at: string;
  related_pid?: number | null;
  related_ip?: string | null;
  details?: string | null;
  status: AlertStatus | string;
  status_comment?: string | null;
  status_at?: string | null;
  assignee?: string | null;
  occurrence_count: number;
  host_id?: string | null;
  evidence_event_ids?: number[] | string;
}

export interface AlertFilterState {
  status: "all" | "open" | "acknowledged" | "resolved";
  severity: "all" | SeverityLevel;
  query: string;
}

export interface RuleMeta {
  id: string;
  name: string;
  description?: string;
  severity: SeverityLevel;
  tactic?: string;
  technique?: string;
  technique_id?: string;
  required_telemetry?: string[];
}

export interface NeighborEvent {
  id: number;
  run_id: string;
  event_type: string;
  timestamp: string;
  process_name?: string | null;
  command_line?: string | null;
  pid?: number | null;
  ppid?: number | null;
  host_id?: string | null;
}
