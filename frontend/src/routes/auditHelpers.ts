// Pure helpers for the analyst audit trail — extracted so the action-chip
// label/color contract is unit-testable and stays in sync with the backend's
// action vocabulary (routes_admin writes these exact action strings).

export interface ActionMeta {
  label: string;
  cls: string;
}

const ACTION_META: Record<string, ActionMeta> = {
  "alert.status": { label: "triage", cls: "border-accent/50 text-accent bg-accent/10" },
  "alert.false-positive": { label: "false positive", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "auth.login": { label: "login", cls: "border-risk-clean/50 text-risk-clean bg-risk-clean/10" },
  "auth.login.failed": { label: "login failed", cls: "border-risk-malicious/50 text-risk-malicious bg-risk-malicious/10" },
  "auth.password": { label: "password", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "allowlist.add": { label: "allowlist", cls: "border-accent/50 text-accent bg-accent/10" },
  "allowlist.remove": { label: "allowlist", cls: "border-border-subtle text-text-muted bg-bg-elevated/60" },
  "suppression.add": { label: "suppress", cls: "border-accent/50 text-accent bg-accent/10" },
  "suppression.remove": { label: "suppress", cls: "border-border-subtle text-text-muted bg-bg-elevated/60" },
  "retention.prune": { label: "retention", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  "backup.create": { label: "backup", cls: "border-risk-clean/50 text-risk-clean bg-risk-clean/10" },
  "restore.apply": { label: "restore", cls: "border-risk-malicious/50 text-risk-malicious bg-risk-malicious/10" },
};

const UNKNOWN_META: ActionMeta = { label: "", cls: "border-border-subtle text-text-muted bg-bg-elevated/60" };

/** Resolve an audit action string to its chip label + styling. Unknown or\n *  future actions fall back to the raw action text with the neutral chip —\n *  never a hard error, so new backend actions render gracefully. */
export function actionMeta(action: string): ActionMeta {
  const known = ACTION_META[action];
  return known ?? { ...UNKNOWN_META, label: action };
}

/** The distinct action kinds offered by the audit filter bar, in display
 *  order — "" = all actions. */
export function auditActionKinds(): string[] {
  return ["", ...Object.keys(ACTION_META)];
}
