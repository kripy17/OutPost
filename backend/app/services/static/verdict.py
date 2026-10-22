"""Evidence-based verdict and assessment engine for OutPost static analysis.

Replaces naive additive 0-100 score and 'BENIGN' labels with:
1. Indicators found.
2. Evidence quality (high/medium/low/none).
3. Explicit list of what could not be analyzed.
4. Verdict only when evidence supports it, with 'no indicators found (limited analysis)'
   as the authoritative non-malicious baseline.
"""

from typing import Any, Literal

VerdictOutcome = Literal[
    "malicious",
    "suspicious",
    "no_indicators_found_limited",
    "insufficient_evidence",
    "parser_failed",
]


def assess_static_evidence(
    findings: list[dict[str, Any]],
    capabilities: list[dict[str, Any]],
    embedded_indicators: list[dict[str, Any]],
    structural_anomalies: list[dict[str, Any]],
    benign_signals: list[dict[str, Any]],
    could_not_analyze: list[str],
    is_parser_error: bool = False,
    parser_error_reason: str = "",
) -> dict[str, Any]:
    """Calculate an evidence-based assessment of a sample.

    Instead of summing arbitrary points to 100, evaluates substantiated indicators
    of malicious intent vs. benign mitigations.
    """
    if is_parser_error:
        return {
            "verdict": "parser_failed",
            "verdict_reason": parser_error_reason or "Parser failed or aborted on input file",
            "evidence_quality": "none",
            "indicators_found_count": 0,
            "could_not_analyze": could_not_analyze or ["all_static_features"],
            "assessment_factors": [],
            "benign_factors": [],
            "confidence": "confirmed",
            # Legacy compatibility fields preserved for existing API consumers
            "static_severity": "clean",
            "static_risk_score": 0,
            "risk_factors": ["Parser execution failed"],
        }

    assessment_factors: list[dict[str, Any]] = []
    benign_factors: list[dict[str, Any]] = []

    # 1. Structural anomalies
    for anomaly in structural_anomalies:
        assessment_factors.append({
            "factor": anomaly.get("title", "Structural anomaly"),
            "weight": anomaly.get("weight", 15),
            "signal_type": "observed",
            "reliability": anomaly.get("reliability", "parsed"),
            "evidence": anomaly.get("evidence", ""),
        })

    # 2. Capabilities (differentiate parsed imports vs heuristic strings)
    for cap in capabilities:
        cat = cap.get("category", "")
        rel = cap.get("provenance", {}).get("reliability", cap.get("source", "heuristic"))
        is_observed = (rel == "parsed")

        weight = 10
        if cat in ("Process Injection", "Cryptographic & Ransomware", "Credential Access"):
            weight = 30 if is_observed else 15
        elif cat in ("Defense Evasion & Anti-Debug", "Fileless / In-Memory Execution", "Execution & Scripting"):
            weight = 25 if is_observed else 15
        elif cat in ("Persistence & Autostart", "Network Communications & C2"):
            weight = 20 if is_observed else 12

        assessment_factors.append({
            "factor": f"{cat}: {', '.join(cap.get('matched', [])[:3])}",
            "weight": weight,
            "signal_type": "observed" if is_observed else "inferred",
            "reliability": rel if rel in ("parsed", "matched", "inferred") else "inferred",
            "evidence": cap.get("provenance", {}).get("location", f"{len(cap.get('matched', []))} symbol matches"),
        })

    # High-confidence finding items (e.g. Office macro execution, LNK stealth, HTML smuggling)
    for finding in findings:
        conf = finding.get("provenance", {}).get("confidence", "")
        f_cat = finding.get("category", "")
        if conf in ("confirmed", "high") and f_cat in ("capability", "ioc", "structure"):
            title = finding.get("title", "")
            if not any(f.get("factor") == title for f in assessment_factors):
                assessment_factors.append({
                    "factor": title,
                    "weight": 25,
                    "signal_type": "observed",
                    "reliability": finding.get("provenance", {}).get("reliability", "parsed"),
                    "evidence": finding.get("provenance", {}).get("location", ""),
                })

    # 3. Malicious embedded indicators (strict external C2, known threat domains)
    malicious_iocs = [i for i in embedded_indicators if i.get("classification") == "malicious"]
    suspicious_iocs = [i for i in embedded_indicators if i.get("classification") == "suspicious"]

    for ioc in malicious_iocs:
        assessment_factors.append({
            "factor": f"High-confidence threat indicator: {ioc.get('value')}",
            "weight": 35,
            "signal_type": "observed",
            "reliability": "matched",
            "evidence": ioc.get("location", "embedded string"),
        })

    for ioc in suspicious_iocs:
        assessment_factors.append({
            "factor": f"Suspicious network destination or URL: {ioc.get('value')}",
            "weight": 15,
            "signal_type": "observed",
            "reliability": "matched",
            "evidence": ioc.get("location", "embedded string"),
        })

    # 4. Benign Signals (subtract threat posture)
    for benign in benign_signals:
        benign_factors.append({
            "factor": benign.get("title", "Benign indicator"),
            "weight": benign.get("weight", -20),
            "signal_type": "observed",
            "reliability": "parsed",
            "evidence": benign.get("evidence", ""),
        })

    # Weigh evidence
    malicious_weight = sum(f["weight"] for f in assessment_factors)
    benign_weight = sum(abs(b["weight"]) for b in benign_factors)
    net_score = max(0, malicious_weight - benign_weight)

    # Determine Evidence Quality
    parsed_count = sum(1 for f in assessment_factors if f["reliability"] in ("parsed", "matched"))
    if parsed_count >= 3:
        evidence_quality = "high"
    elif parsed_count >= 1 or len(assessment_factors) >= 2:
        evidence_quality = "medium"
    elif assessment_factors:
        evidence_quality = "low"
    else:
        evidence_quality = "none"

    # Check for authoritative malicious signals
    has_authoritative_signal = (
        any(f.get("provenance", {}).get("confidence") == "confirmed" and f.get("category") in ("ioc", "malicious") for f in findings)
        or any(i.get("classification") == "malicious" for i in embedded_indicators)
        or any(f.get("factor", "").startswith(("Decoded", "High-confidence threat indicator", "YARA rule match", "Known malicious")) for f in assessment_factors)
    )

    # Outcome derivation:
    # 1. 'malicious' strictly requires at least one authoritative signal
    if has_authoritative_signal and net_score >= 30:
        verdict = "malicious"
        verdict_reason = "Authoritative malicious threat indicators, matched signatures, or decoded configuration confirmed."
        confidence = "high"
        legacy_severity = "malicious"
    # 2. Benign signals mitigate heuristic false alarms
    elif benign_weight >= 30 and not has_authoritative_signal:
        if any("unrecognized" in c.lower() for c in could_not_analyze):
            verdict = "insufficient_evidence"
            verdict_reason = "Known benign metadata observed, but file format is unparseable."
            confidence = "low"
        else:
            verdict = "no_indicators_found_limited"
            verdict_reason = "Verified benign attributes (trusted signature, package hash, clean infrastructure) present."
            confidence = "high"
        legacy_severity = "clean"
    # 3. Anomaly threshold without authoritative signals caps at 'suspicious'
    elif net_score >= 25 or len(assessment_factors) >= 2:
        verdict = "suspicious"
        verdict_reason = "Elevated indicators or anomalous structural behaviors present; dynamic analysis required."
        confidence = "medium"
        legacy_severity = "suspicious"
    # 4. Zero indicators found
    elif not assessment_factors:
        if any("unrecognized" in c.lower() for c in could_not_analyze):
            verdict = "insufficient_evidence"
            verdict_reason = "File format unrecognized or unparseable; static evidence is insufficient."
            confidence = "low"
            legacy_severity = "clean"
        else:
            verdict = "no_indicators_found_limited"
            verdict_reason = "No threat indicators detected within static analysis boundaries; runtime execution required."
            confidence = "medium" if could_not_analyze else "high"
            legacy_severity = "clean"
    # 5. Low-confidence or inconclusive signals
    else:
        verdict = "insufficient_evidence"
        verdict_reason = "Minor non-conclusive signals observed but insufficient to substantiate a threat verdict."
        confidence = "low"
        legacy_severity = "clean"

    total_indicators = len(findings) + len(capabilities) + len(embedded_indicators)

    return {
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "evidence_quality": evidence_quality,
        "indicators_found_count": total_indicators,
        "could_not_analyze": could_not_analyze,
        "assessment_factors": assessment_factors,
        "benign_factors": benign_factors,
        "confidence": confidence,
        # Backward compatibility for existing schemas and tests
        "static_risk_score": min(100, net_score),
        "static_severity": legacy_severity,
        "risk_factors": [f["factor"] for f in assessment_factors],
    }
