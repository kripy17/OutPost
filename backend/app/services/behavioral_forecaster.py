"""Behavioral Forecaster & Two-Layer Malware Analysis Service.

Layer 1 (Zero-Execution):
  Statically forecasts anticipated binary behaviors, C2 endpoints, MITRE ATT&CK
  techniques, dropped artifacts, and estimated threat posture BEFORE execution.

Layer 2 (Reconciliation):
  Cross-references Layer 1 pre-execution forecasts against Layer 2 live sandbox
  runtime telemetry, computing verification accuracy, confirmed behaviors,
  dormant/evaded capabilities, and newly discovered runtime events.
"""

import re
from typing import Any

from . import static_analysis

_RE_INTERNAL_IP = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|255\.255\.255\.255)")


def generate_behavioral_forecast(
    raw_bytes: bytes,
    sample_name: str,
    static_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze sample bytes statically to forecast anticipated runtime execution behavior."""
    if not static_data:
        try:
            static_data = static_analysis.analyze_sample(raw_bytes)
        except Exception:
            static_data = {}

    strings = static_data.get("strings") or []
    if not strings and raw_bytes:
        strings = static_analysis.extract_strings(raw_bytes)

    iocs = static_data.get("iocs") or {}
    if not iocs and raw_bytes:
        iocs = static_analysis.extract_iocs(raw_bytes)

    entropy = static_data.get("entropy", 0.0)
    is_packed = static_data.get("is_packed", False)
    static_risk = static_data.get("static_risk_score", 0)
    capabilities = static_data.get("capabilities", [])
    elf_info = static_data.get("elf") or {}
    pe_info = static_data.get("pe") or {}

    anticipated_actions: list[dict[str, Any]] = []
    predicted_endpoints: list[dict[str, Any]] = []
    predicted_mitre: list[dict[str, Any]] = []
    predicted_file_drops: list[dict[str, Any]] = []
    forecast_explanations: list[str] = []

    # -------------------------------------------------------------------------
    # 1. Network C2 & External Communication Heuristics
    # -------------------------------------------------------------------------
    candidate_ips = [ip for ip in iocs.get("ips", []) if not _RE_INTERNAL_IP.match(ip)]
    candidate_domains = [
        d for d in iocs.get("domains", [])
        if not d.endswith((".local", ".internal", "example.com", "localhost"))
    ]
    candidate_urls = iocs.get("urls", [])

    has_net_apis = False
    net_api_names: list[str] = []

    # Check ELF/PE imports & symbols
    elf_symbols = elf_info.get("imports", []) + elf_info.get("symbols", [])
    pe_imports = [imp.get("name", "") for imp in pe_info.get("imports", [])] if pe_info else []
    all_syms = [s.lower() for s in elf_symbols + pe_imports]

    for api in ("connect", "socket", "getaddrinfo", "sendto", "recvfrom", "wsastartup", "internetopen"):
        if any(api in s for s in all_syms):
            has_net_apis = True
            net_api_names.append(api)

    for ip in candidate_ips[:5]:
        predicted_endpoints.append({
            "endpoint": ip,
            "type": "ipv4",
            "protocol": "TCP",
            "port": 443 if "443" in str(strings) else 80,
            "confidence": "high" if has_net_apis else "medium",
        })

    for d in candidate_domains[:5]:
        predicted_endpoints.append({
            "endpoint": d,
            "type": "domain",
            "protocol": "HTTP/HTTPS",
            "port": 443,
            "confidence": "high" if candidate_urls else "medium",
        })

    if predicted_endpoints or has_net_apis:
        anticipated_actions.append({
            "id": "act_net_c2",
            "category": "c2_beaconing",
            "title": "Outbound C2 Communication & Network Beaconing",
            "severity": "critical" if predicted_endpoints else "high",
            "description": f"Anticipated outbound socket creation targeting {len(predicted_endpoints)} candidate remote endpoint(s).",
            "confidence": "high" if (predicted_endpoints and has_net_apis) else "medium",
            "indicators": [e["endpoint"] for e in predicted_endpoints[:4]],
        })
        predicted_mitre.append({
            "id": "T1071.001",
            "name": "Web Protocols",
            "tactic": "Command and Control",
            "confidence": "high",
        })
        predicted_mitre.append({
            "id": "T1095",
            "name": "Non-Application Layer Protocol",
            "tactic": "Command and Control",
            "confidence": "medium",
        })
        forecast_explanations.append(
            f"Sample contains network communication primitives ({', '.join(net_api_names[:3]) or 'sockets'}) "
            f"and references {len(predicted_endpoints)} external endpoint(s) indicative of C2 beaconing."
        )

    # -------------------------------------------------------------------------
    # 2. Process Execution & Subshell Invocation
    # -------------------------------------------------------------------------
    subshell_keywords = ("/bin/sh", "/bin/bash", "cmd.exe", "powershell", "pwsh", "curl", "wget", "eval(")
    matched_subshells = [k for k in subshell_keywords if any(k in s.lower() for s in strings)]
    has_exec_apis = any(x in all_syms for x in ("execve", "fork", "clone", "system", "popen", "createprocess", "winexec"))

    if matched_subshells or has_exec_apis:
        anticipated_actions.append({
            "id": "act_subshell",
            "category": "subshell_execution",
            "title": "Subshell & Process Execution",
            "severity": "high",
            "description": f"Executable contains subprocess spawn signatures ({', '.join(matched_subshells or ['execve'])}).",
            "confidence": "high" if matched_subshells else "medium",
            "indicators": matched_subshells[:3],
        })
        if any("power" in s for s in matched_subshells):
            predicted_mitre.append({
                "id": "T1059.001",
                "name": "PowerShell",
                "tactic": "Execution",
                "confidence": "high",
            })
        elif any("cmd.exe" in s for s in matched_subshells):
            predicted_mitre.append({
                "id": "T1059.003",
                "name": "Windows Command Shell",
                "tactic": "Execution",
                "confidence": "high",
            })
        else:
            predicted_mitre.append({
                "id": "T1059.004",
                "name": "Unix Shell",
                "tactic": "Execution",
                "confidence": "high",
            })
        forecast_explanations.append(
            f"Subshell or command execution hooks detected ({', '.join(matched_subshells or ['subprocess API'])}). "
            "Engine anticipates execution of secondary scripts or system binaries."
        )

    # -------------------------------------------------------------------------
    # 3. Process Injection & In-Memory Execution
    # -------------------------------------------------------------------------
    has_injection = any(
        x in all_syms
        for x in ("ptrace", "memfd_create", "virtualalloc", "writeprocessmemory", "createremotethread", "mprotect")
    )
    if has_injection or any("memfd" in s.lower() for s in strings):
        anticipated_actions.append({
            "id": "act_injection",
            "category": "process_injection",
            "title": "Process Injection & In-Memory Execution",
            "severity": "critical",
            "description": "Low-level memory allocation or tracing primitives detected; anticipates code injection or fileless memory execution.",
            "confidence": "high",
            "indicators": ["memfd_create", "ptrace / remote thread APIs"],
        })
        predicted_mitre.append({
            "id": "T1055",
            "name": "Process Injection",
            "tactic": "Defense Evasion / Privilege Escalation",
            "confidence": "high",
        })
        forecast_explanations.append(
            "Identified in-memory execution or process injection hooks. "
            "Anticipates execution of fileless code in memory without writing directly to disk."
        )

    # -------------------------------------------------------------------------
    # 4. Persistence Hooks
    # -------------------------------------------------------------------------
    persist_indicators = [
        s for s in strings
        if any(p in s.lower() for p in ("/etc/cron", "crontab", "/etc/systemd", "run\\currentversion", "schtasks", ".bashrc"))
    ]
    if persist_indicators:
        anticipated_actions.append({
            "id": "act_persistence",
            "category": "persistence",
            "title": "Persistence Installation",
            "severity": "high",
            "description": f"References persistence vectors: {', '.join(persist_indicators[:2])}.",
            "confidence": "high",
            "indicators": persist_indicators[:3],
        })
        predicted_mitre.append({
            "id": "T1547.001",
            "name": "Registry Run Keys / Startup Folder",
            "tactic": "Persistence",
            "confidence": "high",
        })
        forecast_explanations.append(f"Anticipates persistence installation via autostart or cron hooks ({persist_indicators[0]}).")

    # -------------------------------------------------------------------------
    # 5. File Dropping & Ephemeral Artifacts
    # -------------------------------------------------------------------------
    dropped_candidates = set()
    for s in strings:
        if s.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) and len(s) > 5:
            dropped_candidates.add(s.strip())
        elif re.search(r"\.(sh|elf|exe|bin|payload|vbs|bat|ps1)\b", s, re.IGNORECASE):
            cleaned = s.strip()
            if "/" in cleaned or "\\" in cleaned:
                dropped_candidates.add(cleaned)

    for p in list(dropped_candidates)[:4]:
        predicted_file_drops.append({
            "path": p,
            "reason": "Hardcoded path reference in binary string table",
        })

    if predicted_file_drops:
        anticipated_actions.append({
            "id": "act_file_drop",
            "category": "file_modification",
            "title": "Dropped Payload / Ephemeral Artifacts",
            "severity": "medium",
            "description": f"Anticipated creation or modification of {len(predicted_file_drops)} file(s) in temporary or system directories.",
            "confidence": "medium",
            "indicators": [f["path"] for f in predicted_file_drops[:3]],
        })
        predicted_mitre.append({
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "confidence": "medium",
        })

    # -------------------------------------------------------------------------
    # 6. Defense Evasion & Anti-Analysis
    # -------------------------------------------------------------------------
    evasion_matches = [
        s for s in strings
        if any(e in s.lower() for e in ("ptrace", "isdebuggerpresent", "vmware", "vbox", "qemu", "sandbox", "antidebug"))
    ]
    if evasion_matches or is_packed:
        anticipated_actions.append({
            "id": "act_evasion",
            "category": "defense_evasion",
            "title": "Anti-Analysis & Sandbox Evasion",
            "severity": "medium",
            "description": "Detects sandbox evasion strings or high-entropy packing structure.",
            "confidence": "high" if is_packed else "medium",
            "indicators": (evasion_matches[:2] or []) + (["High entropy packer"] if is_packed else []),
        })
        predicted_mitre.append({
            "id": "T1497",
            "name": "Virtualization/Sandbox Evasion",
            "tactic": "Defense Evasion",
            "confidence": "medium",
        })

    # Deduplicate MITRE techniques
    unique_mitre: list[dict[str, Any]] = []
    seen_ids = set()
    for m in predicted_mitre:
        if m["id"] not in seen_ids:
            seen_ids.add(m["id"])
            unique_mitre.append(m)

    # Determine overall threat score and level
    threat_level = "clean"
    confidence = 40
    if static_risk >= 70 or any(a["severity"] == "critical" for a in anticipated_actions):
        threat_level = "malicious"
        confidence = min(95, 75 + len(anticipated_actions) * 5)
    elif static_risk >= 35 or len(anticipated_actions) > 0:
        threat_level = "suspicious"
        confidence = min(85, 50 + len(anticipated_actions) * 7)

    if not forecast_explanations:
        forecast_explanations.append(
            f"Static triage indicates standard binary structure with entropy {entropy:.2f}/8.0. "
            "No high-confidence malicious behaviors predicted prior to detonation."
        )

    summary = (
        f"OutPost Pre-Execution Forecast: Sample is estimated as {threat_level.upper()} "
        f"(Confidence: {confidence}%). " + " ".join(forecast_explanations[:2])
    )

    return {
        "sample_name": sample_name,
        "predicted_threat_level": threat_level,
        "confidence_score": confidence,
        "static_risk_score": static_risk,
        "entropy": entropy,
        "is_packed": is_packed,
        "summary": summary,
        "anticipated_actions": anticipated_actions,
        "predicted_endpoints": predicted_endpoints,
        "predicted_mitre_techniques": unique_mitre,
        "predicted_file_drops": predicted_file_drops,
        "explanations": forecast_explanations,
    }


def reconcile_forecast_vs_runtime(
    forecast: dict[str, Any],
    runtime_result: dict[str, Any],
) -> dict[str, Any]:
    """Cross-reference Layer 1 pre-execution forecast with Layer 2 dynamic execution telemetry."""
    confirmed: list[dict[str, Any]] = []
    dormant: list[dict[str, Any]] = []
    discovered: list[dict[str, Any]] = []

    events = runtime_result.get("events") or []
    sinkhole_traffic = runtime_result.get("sinkhole_traffic") or []
    dropped_artifacts = runtime_result.get("dropped_artifacts") or []
    alerts = runtime_result.get("alerts") or []
    exit_code = runtime_result.get("exit_code", 0)

    # 1. Check Network Predictions
    observed_endpoints: set[str] = set()
    for s in sinkhole_traffic:
        target = s.get("target") or ""
        if target:
            observed_endpoints.add(target.split(":")[0])
    for ev in events:
        if ev.get("event_type") == "network_connection" and ev.get("dest_ip"):
            observed_endpoints.add(ev["dest_ip"])

    pred_endpoints = forecast.get("predicted_endpoints") or []
    if pred_endpoints:
        matched_ep = False
        for pe in pred_endpoints:
            target_ip = pe.get("endpoint", "")
            if target_ip in observed_endpoints:
                matched_ep = True
                confirmed.append({
                    "action_id": "act_net_c2",
                    "title": f"Network C2 Connection ({target_ip})",
                    "status": "confirmed",
                    "evidence": f"Observed network socket connection targeting predicted endpoint {target_ip}",
                })
        if not matched_ep:
            if observed_endpoints:
                confirmed.append({
                    "action_id": "act_net_c2",
                    "title": "Network Communication (Discovered IP)",
                    "status": "confirmed",
                    "evidence": f"Observed outbound socket to {list(observed_endpoints)[0]}",
                })
            else:
                dormant.append({
                    "action_id": "act_net_c2",
                    "title": "Outbound C2 Communication",
                    "status": "dormant",
                    "reason": "Binary did not initiate network connections during sandbox timeout",
                })
    elif observed_endpoints:
        discovered.append({
            "title": f"Unexpected Network Connection to {list(observed_endpoints)[0]}",
            "type": "network",
            "evidence": f"Runtime socket opened to {list(observed_endpoints)[0]} without prior static URL/IP indicator",
        })

    # 2. Check Subshell & Process Execution
    observed_cmds: list[str] = []
    for ev in events:
        if ev.get("event_type") == "process_create":
            observed_cmds.append(ev.get("command_line") or ev.get("process_name") or "")

    has_subshell_pred = any(a.get("category") == "subshell_execution" for a in forecast.get("anticipated_actions", []))
    if has_subshell_pred:
        subshell_fired = any(
            any(k in c.lower() for k in ("sh", "bash", "python", "cmd", "pwsh", "powershell"))
            for c in observed_cmds
        )
        if subshell_fired or len(observed_cmds) > 1:
            confirmed.append({
                "action_id": "act_subshell",
                "title": "Subshell & Process Execution",
                "status": "confirmed",
                "evidence": f"Observed process execution: {observed_cmds[0][:60] if observed_cmds else 'child process'}",
            })
        else:
            dormant.append({
                "action_id": "act_subshell",
                "title": "Subshell Execution",
                "status": "dormant",
                "reason": "Process did not fork or invoke external subshells",
            })
    elif len(observed_cmds) > 1:
        discovered.append({
            "title": "Unexpected Child Process Spawned",
            "type": "process",
            "evidence": f"Executed: {observed_cmds[1][:60]}",
        })

    # 3. Check File Dropping / Payload Extraction
    has_file_pred = any(a.get("category") == "file_modification" for a in forecast.get("anticipated_actions", []))
    if has_file_pred:
        if dropped_artifacts or any(ev.get("event_type") == "file_write" for ev in events):
            confirmed.append({
                "action_id": "act_file_drop",
                "title": "Dropped File Creation",
                "status": "confirmed",
                "evidence": f"Extracted {len(dropped_artifacts)} dropped artifact(s) during execution",
            })
        else:
            dormant.append({
                "action_id": "act_file_drop",
                "title": "Dropped Payload Extraction",
                "status": "dormant",
                "reason": "No ephemeral payload files written to sandbox filesystem",
            })
    elif dropped_artifacts:
        discovered.append({
            "title": f"Captured {len(dropped_artifacts)} Unexpected Dropped Artifact(s)",
            "type": "filesystem",
            "evidence": f"Artifact: {dropped_artifacts[0].get('filename', 'dropped_file')}",
        })

    # 4. Check Process Injection
    has_inject_pred = any(a.get("category") == "process_injection" for a in forecast.get("anticipated_actions", []))
    if has_inject_pred:
        syscall_names = [sc.get("syscall") for sc in runtime_result.get("syscalls", [])]
        if "ptrace" in syscall_names or "memfd_create" in syscall_names:
            confirmed.append({
                "action_id": "act_injection",
                "title": "Process Injection / Memory Allocation",
                "status": "confirmed",
                "evidence": "Observed ptrace or memfd syscall invocation in runtime trace",
            })
        else:
            dormant.append({
                "action_id": "act_injection",
                "title": "Process Injection Primitives",
                "status": "dormant",
                "reason": "Injection syscalls did not trigger (requires target PID or specific privilege)",
            })

    # 5. Check Triggered Rules & Alerts
    if alerts:
        discovered.append({
            "title": f"Triggered {len(alerts)} Detection Rule Alert(s)",
            "type": "detection",
            "evidence": f"Rules: {', '.join(a.get('rule_id', '') for a in alerts[:3])}",
        })

    total_pred = max(1, len(forecast.get("anticipated_actions", [])))
    accuracy = min(100, int((len(confirmed) / total_pred) * 100)) if confirmed else (0 if total_pred > 0 else 100)

    # Sandbox evasion detection
    evasion_detected = False
    if (
        forecast.get("predicted_threat_level") == "malicious"
        and len(confirmed) == 0
        and exit_code == 0
        and len(events) <= 2
    ):
        evasion_detected = True

    return {
        "accuracy_score": accuracy,
        "confirmed_count": len(confirmed),
        "dormant_count": len(dormant),
        "discovered_count": len(discovered),
        "confirmed_predictions": confirmed,
        "dormant_predictions": dormant,
        "discovered_runtime_actions": discovered,
        "evasion_detected": evasion_detected,
    }
