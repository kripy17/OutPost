"""Finding provenance and confidence schema for OutPost analytical findings.

Every finding (capability, IOC, behavior, rule hit, anomaly) must record:
1. Source type (parser field, import table, string offset, YARA rule, capa rule, telemetry event).
2. Physical or structural location (offset, section, table, process).
3. Reliability tier:
   - 'parsed' (extracted directly from authoritative binary structure, e.g. PE header or IAT)
   - 'matched' (deterministic rule or signature match, e.g. YARA, regex, Capa)
   - 'inferred' (heuristic interpretation or substring association, e.g. string without import)
4. Confidence level:
   - 'confirmed'
   - 'high'
   - 'medium'
   - 'low'
"""

from typing import Any, Literal

ReliabilityType = Literal["parsed", "matched", "inferred"]
FindingConfidence = Literal["confirmed", "high", "medium", "low"]
FindingCategory = Literal["capability", "ioc", "behavior", "rule_hit", "anomaly", "structure"]


def create_provenance(
    source_type: str,
    location: str,
    reliability: ReliabilityType,
    confidence: FindingConfidence,
    timestamp: str | None = None,
    process: dict[str, Any] | None = None,
    evidence_excerpt: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Build a standard provenance record for a finding."""
    record: dict[str, Any] = {
        "source_type": source_type,
        "location": location,
        "reliability": reliability,
        "confidence": confidence,
    }
    if timestamp:
        record["timestamp"] = timestamp
    if process:
        record["process"] = process
    if evidence_excerpt:
        record["evidence_excerpt"] = evidence_excerpt[:300]
    if rule_id:
        record["rule_id"] = rule_id
    return record


def create_finding(
    finding_id: str,
    category: FindingCategory,
    title: str,
    description: str,
    provenance: dict[str, Any],
    mitre_techniques: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a fully-provenanced finding object."""
    finding: dict[str, Any] = {
        "id": finding_id,
        "category": category,
        "title": title,
        "description": description,
        "provenance": provenance,
        "mitre_techniques": mitre_techniques or [],
    }
    if metadata:
        finding["metadata"] = metadata
    return finding
