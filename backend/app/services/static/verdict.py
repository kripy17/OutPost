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
    signature_info: dict[str, Any] | None = None,
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
            "signature_info": {"is_signed": False, "status": "unknown", "note": "Parser failed on file"},
            "score_description": "Aggregate sum of indicator weights (capped at 100), not an infection probability. The 'verdict' field is the primary authoritative evaluation.",
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

    # 2. Capabilities (informational technical capabilities vs compound threat combinations)
    # Capabilities describe what an executable can technically do (e.g. registry access, memory allocation).
    # In benign software, signed vendor tools, and OS libraries, standard API usage is NOT a threat indicator.
    # Capabilities only contribute to assessment_factors when corroborated by structural threat anomalies
    # (e.g. unreferenced overlay or non-standard RWX memory sections).
    has_unreferenced_overlay = any("overlay" in a.get("title", "").lower() for a in structural_anomalies)
    has_rwx_anomaly = any("rwx" in a.get("title", "").lower() and "upx" not in a.get("title", "").lower() for a in structural_anomalies)
    has_threat_ioc = any(i.get("classification") in ("malicious", "suspicious") for i in embedded_indicators)

    for cap in capabilities:
        cat = cap.get("category", "")
        rel = cap.get("provenance", {}).get("reliability", cap.get("source", "heuristic"))
        is_observed = (rel == "parsed")

        # Only elevate high-risk capabilities if corroborated by anomalous structural or threat context
        if has_unreferenced_overlay or has_rwx_anomaly or has_threat_ioc:
            if cat in ("Process Injection", "Cryptographic & Ransomware", "Fileless / In-Memory Execution"):
                assessment_factors.append({
                    "factor": f"{cat}: {', '.join(cap.get('matched', [])[:3])}",
                    "weight": 20 if is_observed else 15,
                    "signal_type": "observed" if is_observed else "inferred",
                    "reliability": rel if rel in ("parsed", "matched", "inferred") else "inferred",
                    "evidence": cap.get("provenance", {}).get("location", f"{len(cap.get('matched', []))} symbol matches"),
                })

    has_packer_factor = any("pack" in f.get("factor", "").lower() for f in assessment_factors)

    # High-confidence finding items (e.g. Office macro execution, LNK stealth, HTML smuggling)
    for finding in findings:
        conf = finding.get("provenance", {}).get("confidence", "")
        f_cat = finding.get("category", "")
        if conf in ("confirmed", "high") and f_cat in ("capability", "ioc", "structure"):
            title = finding.get("title", "")
            # Deduplicate packer findings if a packer factor is already recorded
            if has_packer_factor and "pack" in title.lower():
                continue
            # TLS Callbacks are a technical capability, not an independent threat finding
            if "tls callback" in title.lower():
                continue
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
        if benign.get("weight", 0) < 0:
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
    is_packed_binary = (
        any("packed" in c.lower() for c in could_not_analyze)
        or any("pack" in a.get("title", "").lower() for a in structural_anomalies)
    )

    # 2b. Installer / Self-Extracting archive (SFX) or compressed overlay without threat signals
    # Standard installers (NSIS, Inno Setup, 7-Zip SFX) carry compressed payloads as overlays;
    # without authoritative threat signals or corroborated injection capabilities, the verdict
    # is inconclusive ('insufficient_evidence') because static analysis cannot inspect compressed payloads.
    is_installer_or_overlay = (
        any("compressed overlay payload" in c.lower() for c in could_not_analyze)
        or any("installer/self-extractor" in a.get("title", "").lower() for a in structural_anomalies)
        or any("overlay data" in a.get("title", "").lower() for a in structural_anomalies)
    )
    has_corroborated_injection = any("Process Injection" in f.get("factor", "") for f in assessment_factors)

    if has_authoritative_signal and net_score >= 30:
        verdict = "malicious"
        verdict_reason = "Authoritative malicious threat indicators, matched signatures, or decoded configuration confirmed."
        confidence = "high"
        legacy_severity = "malicious"
    # 2. Packed or compressed binary structure without authoritative threat signals
    # Packing inherently limits static code visibility; dynamic sandbox analysis is required.
    elif is_packed_binary and not has_authoritative_signal:
        verdict = "insufficient_evidence"
        verdict_reason = "Packed or compressed binary structure detected; dynamic runtime analysis required for behavior assessment."
        confidence = "medium"
        legacy_severity = "insufficient_evidence"
    # 2b. Installer / Self-Extracting Archive with uninspected compressed overlay
    elif is_installer_or_overlay and not has_authoritative_signal and not has_corroborated_injection:
        verdict = "insufficient_evidence"
        verdict_reason = "Installer or self-extracting archive detected; compressed overlay payload not inspected by static analysis."
        confidence = "medium"
        legacy_severity = "insufficient_evidence"
    # 3. Benign signals mitigate heuristic false alarms (e.g. package provenance)
    elif benign_weight >= 20 and not has_authoritative_signal:
        if any("unrecognized" in c.lower() for c in could_not_analyze):
            verdict = "insufficient_evidence"
            verdict_reason = "Known benign metadata observed, but file format is unparseable."
            confidence = "low"
        else:
            verdict = "no_indicators_found_limited"
            verdict_reason = "Verified benign attributes (trusted package hash, clean infrastructure) present."
            confidence = "medium"
        legacy_severity = "no_indicators_found_limited"
    # 4. Anomaly threshold without authoritative signals caps at 'suspicious'
    elif net_score >= 25 or len(assessment_factors) >= 2:
        verdict = "suspicious"
        verdict_reason = "Elevated indicators or anomalous structural behaviors present; dynamic analysis required."
        confidence = "medium"
        legacy_severity = "suspicious"
    # 5. Zero indicators found
    elif not assessment_factors:
        is_managed = any("managed" in c.lower() for c in could_not_analyze)
        is_unrecognized = any("unrecognized" in c.lower() for c in could_not_analyze)
        if is_managed:
            verdict = "insufficient_evidence"
            verdict_reason = "Static analysis is inconclusive for managed .NET assembly; runtime execution required."
            confidence = "low"
            legacy_severity = "insufficient_evidence"
        elif is_unrecognized:
            verdict = "insufficient_evidence"
            verdict_reason = "File format unrecognized or unparseable; static evidence is insufficient."
            confidence = "low"
            legacy_severity = "insufficient_evidence"
        else:
            verdict = "no_indicators_found_limited"
            verdict_reason = "No threat indicators detected within static analysis boundaries."
            confidence = "medium"
            legacy_severity = "no_indicators_found_limited"
    # 6. Low-confidence or inconclusive signals
    else:
        verdict = "insufficient_evidence"
        verdict_reason = "Minor non-conclusive signals observed but insufficient to substantiate a threat verdict."
        confidence = "low"
        legacy_severity = "insufficient_evidence"

    total_indicators = len(findings) + len(capabilities) + len(embedded_indicators)

    # When verdict is insufficient_evidence or no_indicators_found_limited, risk score must not contradict it
    if verdict == "no_indicators_found_limited":
        reported_score = 0
    elif verdict == "insufficient_evidence":
        # Packed binaries carry a moderate structural anomaly score (capped at 25), never 100
        reported_score = min(25, net_score) if is_packed_binary else 0
    else:
        reported_score = min(100, net_score)

    # Signature info block
    sig_info = signature_info or {
        "is_signed": False,
        "status": "unsigned",
        "note": "No Authenticode digital signature directory present.",
    }

    return {
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "evidence_quality": evidence_quality,
        "indicators_found_count": total_indicators,
        "could_not_analyze": could_not_analyze,
        "assessment_factors": assessment_factors,
        "benign_factors": benign_factors,
        "signature_info": sig_info,
        "score_description": "Aggregate sum of indicator weights (capped at 100), not an infection probability. The 'verdict' field is the primary authoritative evaluation.",
        "confidence": confidence,
        # Backward compatibility for existing schemas and tests
        "static_risk_score": reported_score,
        "static_severity": legacy_severity,
        "risk_factors": [f["factor"] for f in assessment_factors],
    }
