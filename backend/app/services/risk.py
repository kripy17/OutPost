"""Run risk scoring + MITRE ATT&CK metadata (roadmap 1.3).

Every detection rule carries an ATT&CK technique/tactic (analyst context) and
a weight. A run's risk score is the sum of the weights of the *distinct* rules
that fired, capped at 100 — distinct, so five beacon alerts don't stack into a
higher score than one beacon plus one persistence write.

`RULE_META` is the single source of truth; the `GET /rules/meta` endpoint and
the webapp's ATT&CK chips both read it.

NOTE: `severity` here must stay in sync with the severity passed to
`_make_alert` in services/detection.py — the coverage matrix tones its chips
by this field, so a drift would miscolor a rule (e.g. lolbin-abuse is
malicious at weight 14; suid-set is suspicious at weight 18).
"""

import json
from typing import Any, TypedDict


class RuleMeta(TypedDict, total=False):
    technique: str
    tactic: str
    weight: int
    severity: str  # the alert severity the rule actually fires with
    confidence: str  # default analytical confidence: high | medium | low
    required_telemetry: list[str]


RULE_META: dict[str, RuleMeta] = {
    "network-scan": {
        "technique": "T1595",
        "tactic": "Reconnaissance",
        "weight": 8,
        "severity": "suspicious",
    },
    "toolchain-build": {
        "technique": "T1587.001",
        "tactic": "Resource Development",
        "weight": 8,
        "severity": "suspicious",
    },
    "document-dropper": {
        "technique": "T1566.002",
        "tactic": "Initial Access",
        "weight": 18,
        "severity": "malicious",
    },
    "lateral-rdp-smb": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 10,
        "severity": "suspicious",
    },
    "screen-capture": {
        "technique": "T1113",
        "tactic": "Collection",
        "weight": 12,
        "severity": "suspicious",
    },
    "masquerading": {
        "technique": "T1036.005",
        "tactic": "Defense Evasion",
        "weight": 20,
        "severity": "malicious",
    },
    "suspicious-parent-child": {
        "technique": "T1204.002",
        "tactic": "Execution",
        "weight": 18,
        "severity": "malicious",
    },
    "lolbin-abuse": {
        "technique": "T1059",
        "tactic": "Execution",
        "weight": 14,
        "severity": "malicious",
    },
    "beaconing": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 15,
        "severity": "suspicious",
    },
    "registry-persistence": {
        "technique": "T1547.001",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "autostart-persistence": {
        "technique": "T1547",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "ssh-authorized-keys": {
        "technique": "T1098.004",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "scheduled-task": {
        "technique": "T1053.005",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "suid-set": {
        "technique": "T1548.001",
        "tactic": "Privilege Escalation",
        "weight": 18,
        "severity": "suspicious",
    },
    "credential-dump": {
        "technique": "T1003.001",
        "tactic": "Credential Access",
        "weight": 20,
        "severity": "malicious",
    },
    "suspicious-extension": {
        "technique": "T1036.003",
        "tactic": "Defense Evasion",
        "weight": 16,
        "severity": "malicious",
    },
    "shell-history-wipe": {
        "technique": "T1070.003",
        "tactic": "Defense Evasion",
        "weight": 12,
        "severity": "suspicious",
    },
    "enumeration-burst": {
        "technique": "T1082",
        "tactic": "Discovery",
        "weight": 14,
        "severity": "suspicious",
    },
    "data-staging": {
        "technique": "T1048",
        "tactic": "Exfiltration",
        "weight": 18,
        "severity": "malicious",
    },
    "rename-burst": {
        "technique": "T1486",
        "tactic": "Impact",
        "weight": 22,
        "severity": "malicious",
    },
    "first-seen-process": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 6,
        "severity": "suspicious",
    },
    "unusual-port": {
        "technique": "T1571",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "attack-chain": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 30,
        "severity": "malicious",
    },
    "baseline-anomaly": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 12,
        "severity": "suspicious",
    },
    "lateral-psexec-smb": {
        "technique": "T1021.002",
        "tactic": "Lateral Movement",
        "weight": 12,
        "severity": "suspicious",
    },
    "lateral-winrm-wmi": {
        "technique": "T1021.006",
        "tactic": "Lateral Movement",
        "weight": 12,
        "severity": "suspicious",
    },
    "lateral-smb-share": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 8,
        "severity": "suspicious",
    },
    "rdp-brute-force": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 14,
        "severity": "suspicious",
    },
    "log-service-stop": {
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
        "weight": 14,
        "severity": "malicious",
    },
    "log-clearing": {
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
        "weight": 16,
        "severity": "malicious",
    },
    "dns-tunneling": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 16,
        "severity": "suspicious",
    },
    "dns-long-label": {
        "technique": "T1568.002",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "dns-unusual-port": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 8,
        "severity": "suspicious",
    },
    "tls-sni-suspicious": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 12,
        "severity": "suspicious",
    },
    "tls-ja3-c2": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 20,
        "severity": "malicious",
    },
    "doh-resolver-use": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "fanout-contact": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 14,
        "severity": "suspicious",
    },
    "fanout-recurring": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 18,
        "severity": "suspicious",
    },
    "shadow-copy-deletion": {
        "technique": "T1490",
        "tactic": "Impact",
        "weight": 22,
        "severity": "malicious",
    },
    "remote-thread-injection": {
        "technique": "T1055.002",
        "tactic": "Privilege Escalation",
        "weight": 20,
        "severity": "malicious",
    },
    "ifeo-persistence": {
        "technique": "T1546.012",
        "tactic": "Persistence",
        "weight": 18,
        "severity": "malicious",
    },
    "macos-tcc-bypass": {
        "technique": "T1548.002",
        "tactic": "Defense Evasion",
        "weight": 20,
        "severity": "malicious",
    },
    "macos-launchagent-persistence": {
        "technique": "T1543.001",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "macos-dylib-hijack": {
        "technique": "T1574.002",
        "tactic": "Defense Evasion",
        "weight": 18,
        "severity": "malicious",
    },
    "macos-gatekeeper-bypass": {
        "technique": "T1553.001",
        "tactic": "Defense Evasion",
        "weight": 18,
        "severity": "malicious",
    },
    "anonymous-rwx-memory": {
        "technique": "T1055.001",
        "tactic": "Defense Evasion",
        "weight": 20,
        "severity": "malicious",
    },
    "fileless-unlinked-binary": {
        "technique": "T1027",
        "tactic": "Defense Evasion",
        "weight": 20,
        "severity": "malicious",
    },
    "gtfobins-suid-execution": {
        "technique": "T1548.001",
        "tactic": "Privilege Escalation",
        "weight": 18,
        "severity": "malicious",
    },
}

_RULE_REQUIRED_TELEMETRY: dict[str, list[str]] = {
    "network-scan": ["network"],
    "toolchain-build": ["process"],
    "document-dropper": ["process"],
    "lateral-rdp-smb": ["network"],
    "screen-capture": ["process"],
    "masquerading": ["process"],
    "suspicious-parent-child": ["process"],
    "lolbin-abuse": ["process"],
    "beaconing": ["network"],
    "registry-persistence": ["registry"],
    "autostart-persistence": ["file", "registry"],
    "ssh-authorized-keys": ["file"],
    "scheduled-task": ["process"],
    "suid-set": ["file"],
    "credential-dump": ["process"],
    "suspicious-extension": ["file"],
    "shell-history-wipe": ["file", "process"],
    "enumeration-burst": ["process"],
    "data-staging": ["file", "process"],
    "rename-burst": ["file"],
    "first-seen-process": ["process"],
    "unusual-port": ["network"],
    "attack-chain": ["process"],
    "baseline-anomaly": ["network"],
    "lateral-psexec-smb": ["file", "network"],
    "lateral-winrm-wmi": ["process", "network"],
    "lateral-smb-share": ["network"],
    "rdp-brute-force": ["network"],
    "log-service-stop": ["process"],
    "log-clearing": ["process", "file"],
    "dns-tunneling": ["dns", "network"],
    "dns-long-label": ["dns", "network"],
    "dns-unusual-port": ["dns", "network"],
    "tls-sni-suspicious": ["tls", "network"],
    "tls-ja3-c2": ["tls", "network"],
    "doh-resolver-use": ["dns", "network"],
    "fanout-contact": ["network"],
    "fanout-recurring": ["network"],
    "shadow-copy-deletion": ["process"],
    "remote-thread-injection": ["process"],
    "ifeo-persistence": ["registry"],
    "macos-tcc-bypass": ["process", "file"],
    "macos-launchagent-persistence": ["file"],
    "macos-dylib-hijack": ["file", "process"],
    "macos-gatekeeper-bypass": ["process", "file"],
    "anonymous-rwx-memory": ["process"],
    "fileless-unlinked-binary": ["process", "file"],
    "gtfobins-suid-execution": ["process"],
}

for _rid, _meta in RULE_META.items():
    _meta["required_telemetry"] = _RULE_REQUIRED_TELEMETRY.get(_rid, ["process"])


def evaluate_rule_coverage_for_run(conn, run_id: str) -> dict[str, Any]:
    """Inspect collector capabilities and event telemetry to determine rule coverage status.

    Derived primarily from collector capability / sensor health reports on enrolled hosts:
    If a sensor is active and healthy on the host (e.g. auditd/Sysmon file auditing is active),
    rules requiring that telemetry are 'evaluable', even if no events occurred during a quiet window.
    Rules are marked 'not_evaluable' when the sensor capability is missing, unconfigured, or disabled.
    """
    # 1. Identify associated host(s) for this run
    host_row = conn.execute(
        "SELECT DISTINCT host_id FROM events WHERE run_id = ? AND host_id IS NOT NULL LIMIT 1",
        (run_id,),
    ).fetchone()
    host_id = host_row["host_id"] if host_row else None

    collector_capabilities = set()
    sensor_health = {}

    if host_id:
        # Check collector heartbeat source health
        hb_row = conn.execute(
            "SELECT source_health_json FROM agent_heartbeats WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        if hb_row and hb_row["source_health_json"]:
            try:
                sh = json.loads(hb_row["source_health_json"])
                if isinstance(sh, dict):
                    sensor_health = sh
                    if sh.get("execution") in ("healthy", "ok", "degraded"):
                        collector_capabilities.add("process")
                    if sh.get("network") in ("healthy", "ok", "degraded"):
                        collector_capabilities.add("network")
                    if sh.get("file") in ("healthy", "ok", "degraded"):
                        collector_capabilities.add("file")
                    if sh.get("dns") in ("healthy", "ok", "degraded"):
                        collector_capabilities.add("dns")
            except Exception:
                pass

        # Check enrolled agent enforcement / telemetry capabilities
        agent_row = conn.execute(
            "SELECT enforcement_capabilities FROM enrolled_agents WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        if agent_row and agent_row["enforcement_capabilities"]:
            try:
                caps = json.loads(agent_row["enforcement_capabilities"])
                if isinstance(caps, list):
                    for c in caps:
                        collector_capabilities.add(str(c).lower())
            except Exception:
                pass

    # 2. Check event types present in the run (for offline / synthetic runs without agent health)
    rows = conn.execute("SELECT DISTINCT event_type FROM events WHERE run_id = ?", (run_id,)).fetchall()
    present_types = {r["event_type"] for r in rows if r["event_type"]}

    has_dns = False
    has_tls = False
    if "network_connection" in present_types or "dns_query" in present_types:
        try:
            sample_net = conn.execute(
                "SELECT query, tls_sni, ja3 FROM events WHERE run_id = ? AND (query IS NOT NULL OR tls_sni IS NOT NULL OR ja3 IS NOT NULL) LIMIT 1",
                (run_id,),
            ).fetchone()
            if sample_net:
                if sample_net["query"]:
                    has_dns = True
                if sample_net["tls_sni"] or sample_net["ja3"]:
                    has_tls = True
        except Exception:
            pass

    observed_categories = set()
    if "process_create" in present_types:
        observed_categories.add("process")
    if "network_connection" in present_types:
        observed_categories.add("network")
    if any(t in present_types for t in ("file_write", "file_delete", "file_permission")):
        observed_categories.add("file")
    if any(t in present_types for t in ("registry_set", "registry_key")):
        observed_categories.add("registry")
    if has_dns or "dns_query" in present_types:
        observed_categories.add("dns")
    if has_tls:
        observed_categories.add("tls")

    # Authoritative evaluable telemetry: collector capability (if reported) union observed events
    effective_evaluable_categories = collector_capabilities | observed_categories

    rule_statuses = {}
    for rule_id, meta in RULE_META.items():
        reqs = meta.get("required_telemetry", ["process"])
        evaluable = any(req in effective_evaluable_categories for req in reqs)
        missing = [req for req in reqs if req not in effective_evaluable_categories]
        rule_statuses[rule_id] = {
            "rule_id": rule_id,
            "status": "evaluable" if evaluable else "not_evaluable",
            "evaluable": evaluable,
            "required_telemetry": reqs,
            "missing_telemetry": missing,
        }

    return {
        "run_id": run_id,
        "host_id": host_id,
        "present_telemetry": sorted(effective_evaluable_categories),
        "observed_telemetry": sorted(observed_categories),
        "collector_capabilities": sorted(collector_capabilities),
        "sensor_health": sensor_health,
        "rule_statuses": rule_statuses,
    }


import math
from datetime import datetime, timezone
from typing import Any


def compute_entity_risk_score(
    alerts: list[dict | Any],
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    """Calculate per-entity threat risk scores accounting for:
    - Base rule weights & severity (malicious 1.25x multiplier)
    - Repetition factor (logarithmic boost for repeated detections on same entity)
    - Kill-chain progression (bonus when an entity touches multiple ATT&CK tactics)
    - Time decay (exponential decay relative to latest activity)
    """
    if not alerts:
        return {"overall_risk": 0, "entities": {}}

    clean_alerts = []
    latest_ts = reference_time
    for a in alerts:
        if hasattr(a, "model_dump"):
            d = a.model_dump()
        elif hasattr(a, "__dict__"):
            d = dict(a.__dict__)
        elif isinstance(a, dict):
            d = dict(a)
        else:
            continue

        ts = d.get("last_seen_at") or d.get("triggered_at")
        if isinstance(ts, str):
            try:
                if ts.endswith("Z"):
                    ts = ts[:-1] + "+00:00"
                dt = datetime.fromisoformat(ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                d["_dt"] = dt
                if latest_ts is None or dt > latest_ts:
                    latest_ts = dt
            except Exception:
                d["_dt"] = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            d["_dt"] = dt
            if latest_ts is None or dt > latest_ts:
                latest_ts = dt
        else:
            d["_dt"] = datetime.now(timezone.utc)

        clean_alerts.append(d)

    if latest_ts is None:
        latest_ts = datetime.now(timezone.utc)

    # Group alerts by entity key (compound process identity or network destination)
    entity_groups: dict[str, list[dict]] = {}
    for a in clean_alerts:
        ent = a.get("entity_key")
        if not ent:
            pid = a.get("related_pid")
            ip = a.get("related_ip")
            if pid:
                ent = f"proc:{pid}"
            elif ip:
                ent = f"net:{ip}"
            else:
                ent = "host:local"
        entity_groups.setdefault(ent, []).append(a)

    entity_scores: dict[str, dict[str, Any]] = {}
    for ent, ent_alerts in entity_groups.items():
        distinct_rules: dict[str, dict] = {}
        total_occurrences = 0
        tactics_seen: set[str] = set()
        latest_ent_ts = ent_alerts[0]["_dt"]

        for a in ent_alerts:
            rid = a.get("rule_id", "")
            occ = int(a.get("occurrence_count") or 1)
            total_occurrences += occ
            latest_ent_ts = max(latest_ent_ts, a["_dt"])

            tac = RULE_META.get(rid, {}).get("tactic")
            if tac:
                tactics_seen.add(tac.lower())

            if rid not in distinct_rules:
                sev = a.get("severity", RULE_META.get(rid, {}).get("severity", "suspicious"))
                distinct_rules[rid] = {
                    "weight": RULE_META.get(rid, {}).get("weight", 10),
                    "severity": sev,
                }

        base_weight = 0.0
        for rid, meta in distinct_rules.items():
            w = meta["weight"]
            # 1.25x severity multiplier for confirmed malicious findings
            sev_mult = 1.25 if meta["severity"] == "malicious" else 1.0
            base_weight += w * sev_mult

        # Repetition boost: repeated actions on same entity escalate threat (log-bounded)
        excess_repeats = max(0, total_occurrences - len(distinct_rules))
        repetition_boost = min(15.0, 2.5 * math.log(1.0 + excess_repeats)) if excess_repeats > 0 else 0.0

        # Kill-chain progression bonus: entity touching 2+ tactics indicates multi-stage attack
        num_tactics = len(tactics_seen)
        progression_bonus = min(25.0, (num_tactics - 1) * 8.0) if num_tactics > 1 else 0.0

        # Time decay relative to latest activity
        delta_hours = max(0.0, (latest_ts - latest_ent_ts).total_seconds() / 3600.0)
        time_decay = max(0.5, math.exp(-0.05 * delta_hours))

        ent_raw = (base_weight + repetition_boost + progression_bonus) * time_decay
        ent_final = min(100, int(round(ent_raw)))

        entity_scores[ent] = {
            "entity_key": ent,
            "risk_score": ent_final,
            "distinct_rules_count": len(distinct_rules),
            "total_occurrences": total_occurrences,
            "tactics": list(tactics_seen),
            "time_decay_factor": round(time_decay, 2),
        }

    sorted_scores = sorted([s["risk_score"] for s in entity_scores.values()], reverse=True)
    if not sorted_scores:
        overall = 0
    else:
        top_score = sorted_scores[0]
        other_contrib = sum(s * 0.15 for s in sorted_scores[1:])
        overall = min(100, int(round(top_score + other_contrib)))

    return {
        "overall_risk": overall,
        "entities": entity_scores,
    }


def compute_risk_score(
    rule_ids: list[str],
    alerts: list[dict | Any] | None = None,
) -> int:
    """Compute run threat risk score.
    
    If alerts are provided, computes per-entity risk accounting for severity,
    kill-chain progression, repetition, and time decay.
    If only rule_ids are provided, sums weights of distinct rules capped at 100.
    """
    if alerts:
        res = compute_entity_risk_score(alerts)
        return res["overall_risk"]

    total = sum(RULE_META.get(rid, {}).get("weight", 0) for rid in set(rule_ids))
    return min(100, total)


# Default detection confidence (distinct from severity and risk score):
# - "high": authoritative kernel/syscall telemetry, verified binary hash, or definite anti-forensics
# - "medium": signature or behavioral pattern matching on command-line/network heuristics
# - "low": statistical novelty or baseline anomaly without prior corroborating indicators
RULE_CONFIDENCE: dict[str, str] = {
    "masquerading": "high",
    "suspicious-parent-child": "high",
    "credential-dump": "high",
    "suid-set": "high",
    "gtfobins-suid-execution": "high",
    "shadow-copy-deletion": "high",
    "remote-thread-injection": "high",
    "ifeo-persistence": "high",
    "macos-tcc-bypass": "high",
    "macos-launchagent-persistence": "high",
    "macos-dylib-hijack": "high",
    "macos-gatekeeper-bypass": "high",
    "anonymous-rwx-memory": "high",
    "fileless-unlinked-binary": "high",
    "log-service-stop": "high",
    "log-clearing": "high",
    "ssh-authorized-keys": "high",
    "scheduled-task": "medium",
    "registry-persistence": "high",
    "autostart-persistence": "medium",
    "lolbin-abuse": "high",
    "document-dropper": "high",
    "lateral-psexec-smb": "high",
    "lateral-winrm-wmi": "high",
    "lateral-smb-share": "medium",
    "lateral-rdp-smb": "medium",
    "rdp-brute-force": "medium",
    "network-scan": "medium",
    "toolchain-build": "medium",
    "screen-capture": "medium",
    "beaconing": "medium",
    "rename-burst": "high",
    "first-seen-process": "low",
    "unusual-port": "medium",
    "attack-chain": "high",
    "baseline-anomaly": "low",
    "suspicious-extension": "medium",
    "shell-history-wipe": "medium",
    "enumeration-burst": "medium",
    "data-staging": "medium",
    "dns-tunneling": "medium",
    "dns-long-label": "medium",
    "dns-unusual-port": "medium",
    "tls-sni-suspicious": "medium",
    "tls-ja3-c2": "high",
    "doh-resolver-use": "medium",
    "fanout-contact": "medium",
    "fanout-recurring": "high",
}


def rule_confidence(rule_id: str) -> str:
    """Default confidence rating ('high', 'medium', 'low') for a detection rule."""
    if rule_id in RULE_META and "confidence" in RULE_META[rule_id]:
        return RULE_META[rule_id]["confidence"]
    return RULE_CONFIDENCE.get(rule_id, "medium")


def recalculate_run_risk(conn, run_id: str) -> int:
    """Recalculate and return active threat risk score for a run.

    Excludes alerts with disposition 'false-positive' or 'benign' so that
    analyst triage decisions accurately reflect active threat risk.
    """
    rows = conn.execute(
        """
        SELECT id, rule_id, severity, occurrence_count, triggered_at, last_seen_at,
               related_pid, related_ip, entity_key
        FROM alerts
        WHERE run_id = ?
          AND (disposition IS NULL OR disposition NOT IN ('false-positive', 'benign'))
        """,
        (run_id,),
    ).fetchall()
    if not rows:
        return 0
    active_rule_ids = [r["rule_id"] for r in rows]
    active_alerts = [dict(r) for r in rows]
    return compute_risk_score(active_rule_ids, alerts=active_alerts)


# Human rule names mirror detection.py's alert titles (single source of truth
# for the /rules/meta endpoint, the webapp chips, and the Navigator layer).
RULE_NAMES: dict[str, str] = {
    "network-scan": "Active scanning (network reconnaissance)",
    "toolchain-build": "Tool compiled from a writable location (capability development)",
    "document-dropper": "Document viewer spawned a script interpreter (spearphishing)",
    "lateral-rdp-smb": "Outbound RDP/SMB connection (lateral movement)",
    "screen-capture": "Screen capture / clipboard theft tool",
    "masquerading": "Process masquerading as system binary",
    "suspicious-parent-child": "Suspicious parent-child process relationship",
    "lolbin-abuse": "Living-off-the-land binary abuse",
    "beaconing": "C2-style beaconing",
    "registry-persistence": "Persistence via registry Run key",
    "autostart-persistence": "Persistence via shell/autostart file",
    "rename-burst": "Rapid file write burst (possible ransomware)",
    "first-seen-process": "First-seen process (novelty)",
    "unusual-port": "Connection to uncommon C2-style port",
    "attack-chain": "Coordinated attack chain",
    "baseline-anomaly": "Baseline anomaly",
    "ssh-authorized-keys": "SSH authorized_keys tampering",
    "suid-set": "SUID/SGID bit set (privilege escalation)",
    "scheduled-task": "Scheduled task created (persistence)",
    "credential-dump": "Credential dumping",
    "suspicious-extension": "Suspicious double-extension executable",
    "shell-history-wipe": "Shell history wiped (anti-forensics)",
    "enumeration-burst": "Discovery enumeration burst",
    "data-staging": "Data staging: archive then exfil",
    "lateral-psexec-smb": "PsExec / SMB-admin remote execution",
    "lateral-winrm-wmi": "WinRM / WMI remote execution",
    "lateral-smb-share": "SMB share enumeration (lateral movement)",
    "rdp-brute-force": "RDP connection burst (brute-force / spray)",
    "log-service-stop": "Logging service stopped/disabled (anti-forensics)",
    "log-clearing": "Event/journal logs purged (anti-forensics)",
    "dns-tunneling": "DNS tunneling (suspicious label burst)",
    "dns-long-label": "Long / high-entropy DNS query (DGA or tunneling)",
    "dns-unusual-port": "DNS query on a non-standard port",
    "tls-sni-suspicious": "TLS handshake with IP-literal or DGA-style SNI",
    "tls-ja3-c2": "Known C2 TLS client handshake (JA3 fingerprint)",
    "doh-resolver-use": "DNS-over-HTTPS from a script host",
    "fanout-contact": "Coordinated contact with one destination",
    "fanout-recurring": "Recurring coordinated fan-out",
    "shadow-copy-deletion": "Volume Shadow Copy & backup deletion (ransomware inhibitor)",
    "remote-thread-injection": "Remote thread injection into system process",
    "ifeo-persistence": "IFEO debugger registry persistence",
    "macos-tcc-bypass": "macOS TCC privacy database tampering",
    "macos-launchagent-persistence": "macOS LaunchAgent/LaunchDaemon persistence",
    "macos-dylib-hijack": "macOS dynamic linker injection (DYLD)",
    "macos-gatekeeper-bypass": "macOS Gatekeeper quarantine bypass",
    "anonymous-rwx-memory": "Unbacked RWX memory allocation (fileless shellcode staging)",
    "fileless-unlinked-binary": "Fileless execution from unlinked binary inode",
    "gtfobins-suid-execution": "Privilege escalation via SUID / breakout utility",
}


def rule_name(rule_id: str) -> str:
    """Human display name for a rule id (falls back to the id itself)."""
    return RULE_NAMES.get(rule_id, rule_id)


# Per-alert remediation guidance — every finding carries a short "what to do"
# checklist, turning detection into action (kill the PID, remove the
# persistence point, revoke the credential). Served by GET /rules/meta and
# rendered on the run detail alert list.
RULE_REMEDIATION: dict[str, list[str]] = {
    "network-scan": ["Identify the scanning PID and the target scope", "Block outbound to the scanned ranges at the firewall"],
    "toolchain-build": ["Remove the compiled artifact from the writable location", "Review what was compiled and why"],
    "document-dropper": ["Isolate the document and its parent application", "Scan the document with the YARA lab / AV", "Treat the spawned script host as compromised"],
    "lateral-rdp-smb": ["Verify the connection was intentional", "Segment RDP/SMB exposure at the network layer"],
    "screen-capture": ["Kill the capture process", "Check for exfil of the captured data"],
    "masquerading": ["Kill the masquerading process", "Inspect the binary path and hash in the sample vault"],
    "suspicious-parent-child": ["Terminate the child process chain", "Quarantine the parent sample"],
    "lolbin-abuse": ["Terminate the LOLBin invocation", "Decode/analyze the payload it fetched"],
    "beaconing": ["Block the beacon destination IP", "Inspect the beaconing process for persistence"],
    "registry-persistence": ["Delete the Run key value", "Kill the process registered to run"],
    "autostart-persistence": ["Remove the autostart file/symlink", "Kill the process it launches"],
    "rename-burst": ["Isolate the machine from the network immediately", "Preserve the encrypted files for recovery research"],
    "first-seen-process": ["Verify the process is expected on this host", "Quarantine if unknown"],
    "unusual-port": ["Block the C2 port at the firewall", "Inspect the connecting process"],
    "attack-chain": ["Treat the host as fully compromised", "Collect memory + disk images before cleanup"],
    "baseline-anomaly": ["Review the anomalous item against the host baseline", "Escalate if unexplained"],
    "ssh-authorized-keys": ["Remove the rogue key from authorized_keys", "Rotate the account's credentials"],
    "suid-set": ["Clear the SUID/SGID bit", "Review how the binary was replaced"],
    "scheduled-task": ["Delete the scheduled task", "Inspect the task payload"],
    "credential-dump": ["Reset the affected credentials", "Rotate service accounts the dump touched"],
    "suspicious-extension": ["Quarantine the double-extension file", "Block the file hash in the vault"],
    "shell-history-wipe": ["Preserve the shell session logs if possible", "Note the wipe as a deliberate anti-forensics act"],
    "enumeration-burst": ["Identify the enumerating PID (recon actors panel)", "Assume the host is being surveyed — hunt for the follow-on"],
    "data-staging": ["Block the exfil destination", "Find and secure the staged archive"],
    "lateral-psexec-smb": ["Revoke the account that mounted admin$", "Disable the remote-admin path used"],
    "lateral-winrm-wmi": ["Revoke WinRM/WMI access for the abused account", "Review remote-execution allowlists"],
    "lateral-smb-share": ["Identify what the enumerator accessed", "Restrict share permissions"],
    "rdp-brute-force": ["Block the source IP at the firewall", "Check for successful logons after the burst"],
    "log-service-stop": ["Re-enable the logging service", "Restore forwarding to the collector"],
    "log-clearing": ["Preserve any remaining log copies", "Treat the cleared window as unknown activity"],
    "dns-tunneling": ["Block the tunneled base domain at the DNS layer", "Inspect the resolving process"],
    "dns-long-label": ["Block the DGA domain", "Hunt for sibling DGA domains"],
    "dns-unusual-port": ["Block the non-standard DNS port", "Inspect the process doing covert DNS"],
    "tls-sni-suspicious": ["Block the SNI/destination at the egress proxy", "Inspect the TLS client process and its cert chain"],
    "tls-ja3-c2": ["Block the remote C2 IP and JA3 signature on firewall / proxy", "Isolate endpoint and inspect process memory for injected C2 beacon"],
    "doh-resolver-use": ["Review the script host's intent — DoH hides DNS from inspection", "Block the resolver at the firewall if unauthorized"],
    "fanout-contact": ["Block the shared destination IP", "Treat every contacting process as potentially compromised"],
    "fanout-recurring": [
        "Block the shared destination IP at the firewall/EDR",
        "Treat every contacting process as potentially compromised",
        "Hunt the run's timeline for what changed between each fan-out window — the plant keeps spawning new processes",
    ],
    "shadow-copy-deletion": [
        "Isolate the host immediately from the network to stop ransomware encryption",
        "Verify shadow storage and preserve uncorrupted volume backups",
        "Terminate the ransomware parent process tree",
    ],
    "remote-thread-injection": [
        "Terminate the target process or freeze its execution",
        "Extract process memory dump for injected shellcode or DLL payloads",
        "Inspect the source process lineage and persistent triggers",
    ],
    "ifeo-persistence": [
        "Remove the malicious Debugger / SilentProcessExit key under Image File Execution Options",
        "Kill any resident processes launched by the hook",
        "Audit registry permissions on HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    ],
    "macos-tcc-bypass": [
        "Inspect process lineage of the non-system binary that targeted TCC.db",
        "Audit and reset system privacy permissions using 'tccutil reset All'",
        "Verify Full Disk Access (FDA) entitlements on system binaries",
    ],
    "macos-launchagent-persistence": [
        "Unload the suspicious LaunchAgent/Daemon using 'launchctl bootout'",
        "Remove rogue .plist files from ~/Library/LaunchAgents or /Library/LaunchDaemons",
        "Review startup items in macOS System Settings -> General -> Login Items",
    ],
    "macos-dylib-hijack": [
        "Inspect the parent process execution environment for injected DYLD variables",
        "Verify Mach-O code signature validity using 'codesign --verify --deep'",
        "Quarantine untrusted dylib libraries",
    ],
    "macos-gatekeeper-bypass": [
        "Re-enable Gatekeeper system policy assessments using 'spctl --master-enable'",
        "Check recently downloaded files for missing com.apple.quarantine xattr",
        "Quarantine unauthorized third-party binaries",
    ],
    "anonymous-rwx-memory": [
        "Extract in-memory carved payload using OutPost dynamic forensics and run YARA scanning",
        "Terminate injecting parent process and inspect thread start addresses",
        "Enable hardware-enforced Data Execution Prevention (DEP / NX) system-wide",
    ],
    "fileless-unlinked-binary": [
        "Inspect open file descriptors in /proc/[pid]/fd to capture in-memory unlinked binary",
        "Immediately kill the unlinked process tree before memory space is unmapped",
        "Review initial execution vector (cron, shell script, or web shell)",
    ],
    "gtfobins-suid-execution": [
        "Audit all setuid and setgid binaries on the endpoint using 'find / -perm -4000'",
        "Remove unnecessary setuid bits from administrative utilities (find, vim, awk, nano)",
        "Restrict sudoers permissions to explicit commands with NOEXEC / NOPASSWD limits",
    ],
}
