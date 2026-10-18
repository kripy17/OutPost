"""Static analysis service for OutPost.

Elevated with:
1. Evidence-based verdicts ('no indicators found (limited analysis)', 'suspicious', 'malicious')
   replacing raw 0-100 score and 'BENIGN' labels.
2. Full finding provenance tracking (source, reliability, confidence, location).
3. Explicit Analysis Fidelity Block on every report.
4. Deep format coverage (Office, PDF, LNK, Containers, Scripts, PE, ELF).
5. Strict embedded indicator validation (IP octets, TLDs, location ranking).
6. Family configuration decoders plugin interface (AgentTesla, Cobalt Strike).
7. Resource-constrained isolated worker execution (execute_in_isolated_worker).
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

from .static.fidelity import create_static_fidelity_block
from .static.formats.elf import is_elf, parse_deep_elf
from .static.formats.pe import is_pe, parse_deep_pe
from .static.indicators import extract_embedded_indicators, is_valid_domain
from .static.pipeline import (
    run_complete_static_pipeline,
)
from .static.provenance import create_provenance
from .static.verdict import assess_static_evidence
from .static.worker import execute_in_isolated_worker

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Legacy Validation Functions (for backward compatibility)
# ---------------------------------------------------------------------------


def _valid_ipv4(raw: bytes) -> bool:
    try:
        ip_str = raw.decode("ascii")
        parts = ip_str.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def _valid_domain(raw: bytes | str) -> bool:
    try:
        dom_str = raw.decode("ascii").lower() if isinstance(raw, (bytes, bytearray)) else str(raw).lower()
        return is_valid_domain(dom_str)
    except Exception:
        return False


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Legacy IOCs extractor interface."""
    indicators = extract_embedded_indicators(data)
    return {
        "ips": [i["value"] for i in indicators if i["type"] == "ipv4"],
        "urls": [i["value"] for i in indicators if i["type"] == "url"],
        "domains": [i["value"] for i in indicators if i["type"] == "domain"],
        "hashes": [hashlib.sha256(data).hexdigest()],
        "emails": [i["value"] for i in indicators if i["type"] == "email"],
    }


def parse_pe(data: bytes) -> dict[str, Any] | None:
    """Legacy PE parser wrapper."""
    if not is_pe(data):
        return None
    res = parse_deep_pe(data)
    return res if res.get("is_pe") else None


def parse_elf(data: bytes) -> dict[str, Any] | None:
    """Legacy ELF parser wrapper."""
    if not is_elf(data):
        return None
    res = parse_deep_elf(data)
    return res if res.get("is_elf") else None


def compute_static_risk_profile(
    entropy: float,
    capabilities: list[dict[str, Any]],
    is_packed: bool,
    pe_info: dict[str, Any] | None,
    elf_info: dict[str, Any] | None,
) -> dict[str, Any]:
    """Legacy risk profile adapter for backward compatibility."""
    assessment = assess_static_evidence(
        findings=[],
        capabilities=capabilities,
        embedded_indicators=[],
        structural_anomalies=[{"title": "Packed binary structure", "weight": 20, "reliability": "parsed"}] if is_packed else [],
        benign_signals=[],
        could_not_analyze=[],
    )
    return {
        "static_risk_score": assessment["static_risk_score"],
        "static_severity": assessment["static_severity"],
        "risk_factors": assessment["risk_factors"],
        "verdict": assessment["verdict"],
        "verdict_reason": assessment["verdict_reason"],
        "evidence_quality": assessment["evidence_quality"],
    }


def detect_capabilities(data: bytes, extracted_strings: list[str]) -> list[dict[str, Any]]:
    """Identify binary/script capabilities with provenance."""
    found: list[dict[str, Any]] = []
    combined_text = " ".join(extracted_strings)

    patterns = [
        ("Process Injection", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ptrace"]),
        ("Fileless / In-Memory Execution", ["MapViewOfFile", "VirtualProtect", "memfd_create"]),
        ("Defense Evasion & Anti-Debug", ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]),
        ("Persistence & Autostart", ["RegSetValueEx", "schtasks", "cron"]),
        ("Credential Access", ["LsaRetrievePrivateData", "MiniDumpWriteDump", "lsass", "sekurlsa"]),
        ("Cryptographic & Ransomware", ["CryptEncrypt", "BCryptEncrypt", "vssadmin delete shadows"]),
        ("Network Communications & C2", ["InternetOpen", "WSAStartup", "connect", "socket"]),
    ]

    for category, symbols in patterns:
        matched = [s for s in symbols if s in combined_text or s.encode("latin1") in data]
        if matched:
            prov = create_provenance(
                "string_offset",
                "Extracted Strings",
                "inferred",
                "medium" if len(matched) >= 2 else "low",
                evidence_excerpt=matched[0],
            )
            found.append({
                "category": category,
                "matched": matched,
                "confidence": "high" if len(matched) >= 2 else "medium",
                "source": "heuristic",
                "provenance": prov,
            })
    return found


# ---------------------------------------------------------------------------
# Fuzzy Hashing & Imphash
# ---------------------------------------------------------------------------


def compute_imphash(imports: list[str]) -> str | None:
    """Compute standard PE Import Hash (imphash) from resolved imports."""
    if not imports:
        return None
    normalized: list[str] = []
    for imp in imports:
        name = imp.strip().lower()
        for ext in (".dll", ".ocx", ".sys", ".drv", ".exe", ".cpl"):
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        if name:
            normalized.append(name)
    if not normalized:
        return None
    raw = ",".join(normalized)
    return hashlib.md5(raw.encode("ascii", errors="replace")).hexdigest()


def compute_fuzzy_hash(data: bytes) -> str:
    """Compute Context-Triggered Piecewise Hash (CTPH / fuzzy hash) fallback."""
    if not data:
        return "3::"
    bs = 3
    n = len(data)
    while bs * 64 < n and bs < 3072:
        bs *= 2
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    chunk1 = hashlib.md5(data[: min(n, bs * 64)]).digest()
    d1 = "".join(b64[b % 64] for b in chunk1)
    chunk2 = hashlib.md5(data[: min(n, bs * 32)]).digest()
    d2 = "".join(b64[b % 64] for b in chunk2)
    return f"{bs}:{d1}:{d2}"


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def compare_fuzzy_hashes(hash1: str, hash2: str) -> int:
    """Compare two fuzzy hashes and return similarity percentage (0-100)."""
    try:
        b1_str, d1_1, d1_2 = hash1.split(":", 2)
        b2_str, d2_1, d2_2 = hash2.split(":", 2)
        b1, b2 = int(b1_str), int(b2_str)
    except (ValueError, AttributeError):
        return 0

    s1, s2 = "", ""
    if b1 == b2:
        s1, s2 = d1_1, d2_1
    elif b1 == b2 * 2:
        s1, s2 = d1_1, d2_2
    elif b1 * 2 == b2:
        s1, s2 = d1_2, d2_1
    else:
        return 0

    if not s1 or not s2:
        return 0

    dist = _levenshtein(s1, s2)
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 100
    score = int((1.0 - (dist / max_len)) * 100)
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Optional CAPA Integration
# ---------------------------------------------------------------------------

_CAPA_TIMEOUT = float(os.getenv("OUTPOST_CAPA_TIMEOUT", "120"))


def parse_capa_rules(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Extract capability entries from a CAPA --json report with provenance."""
    if not isinstance(payload, dict):
        return []
    rules = payload.get("rules")
    entries: list[dict[str, Any]] = []

    def _meta_entry(name: str, meta: dict[str, Any]) -> dict[str, Any]:
        attack = [
            f"{a.get('name', '')} ({a.get('id', '')})".strip()
            for a in meta.get("attack") or []
            if isinstance(a, dict)
        ]
        mbc = [
            "{}::{} [{}]".format(m.get("object", ""), m.get("behavior", ""), m.get("id", ""))
            for m in meta.get("mbc") or []
            if isinstance(m, dict)
        ]
        refs = [r for r in attack + mbc if r.strip() and r.strip() != "()"]
        prov = create_provenance(
            "capa_rule",
            str(meta.get("namespace") or "capa"),
            "matched",
            "high",
            evidence_excerpt=str(name),
        )
        return {
            "category": str(name),
            "matched": refs,
            "confidence": "high",
            "source": "capa",
            "namespace": str(meta.get("namespace") or ""),
            "attack": attack,
            "mbc": mbc,
            "provenance": prov,
        }

    if isinstance(rules, dict):
        for name, rule in rules.items():
            meta = rule.get("meta") if isinstance(rule, dict) else None
            entries.append(_meta_entry(str(name), meta if isinstance(meta, dict) else {}))
    elif isinstance(rules, list):
        for match in rules:
            if not isinstance(match, dict):
                continue
            name = match.get("rule") or match.get("name") or ""
            meta = match.get("meta") if isinstance(match.get("meta"), dict) else {}
            if name:
                entries.append(_meta_entry(str(name), meta))
    return entries


def run_capa(data: bytes) -> dict[str, Any]:
    """Run Mandiant CAPA against the sample bytes if installed."""
    binary = shutil.which("capa")
    if not binary:
        return {"available": False, "error": "capa not installed", "capabilities": []}

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        proc = subprocess.run(
            [binary, "--json", tmp_path],
            capture_output=True,
            text=True,
            timeout=_CAPA_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"available": True, "error": f"capa timed out after {_CAPA_TIMEOUT}s", "capabilities": []}
    except Exception as exc:
        return {"available": False, "error": f"capa invocation failed: {exc}", "capabilities": []}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:200]
        return {
            "available": True,
            "error": f"capa exited {proc.returncode}" + (f": {detail}" if detail else ""),
            "capabilities": [],
        }

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"available": True, "error": "capa output was not valid JSON", "capabilities": []}
    return {"available": True, "capabilities": parse_capa_rules(payload)}


# ---------------------------------------------------------------------------
# Main Analysis Entrypoints
# ---------------------------------------------------------------------------


def analyze_sample(data: bytes) -> dict[str, Any]:
    """Perform complete in-process static analysis over raw bytes."""
    res = run_complete_static_pipeline(data)

    # Merge CAPA if installed
    capa_report = run_capa(data)
    res["capa"] = capa_report
    if capa_report.get("capabilities"):
        res["capabilities"] = res.get("capabilities", []) + capa_report["capabilities"]

    res["analysis_fidelity"] = create_static_fidelity_block(
        duration_ms=10,
        worker_sandboxed=False,
        format_type=res.get("format", "unknown"),
    )
    return res


def analyze_sample_isolated(data: bytes, timeout_sec: float = 10.0) -> dict[str, Any]:
    """Execute static analysis inside an isolated worker subprocess with rlimits."""
    return execute_in_isolated_worker(data, timeout_sec=timeout_sec)
