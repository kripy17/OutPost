"""Complete static analysis execution pipeline.

Orchestrates multi-format inspection, deep binary analysis, embedded indicators,
family config decoding, and evidence-based assessment.
"""

import hashlib
import math
import os
import re
from typing import Any

from .decoders.manager import run_family_decoders
from .formats.archive import analyze_archive, is_archive_or_container
from .formats.elf import is_elf, parse_deep_elf
from .formats.lnk import analyze_lnk, is_lnk_file
from .formats.office import analyze_office, is_office_document
from .formats.pdf import analyze_pdf, is_pdf_document
from .formats.pe import is_pe, parse_deep_pe
from .formats.script import analyze_script, is_script
from .indicators import extract_embedded_indicators
from .provenance import create_finding, create_provenance
from .strings import (
    categorize_string,
    categorize_strings,
    extract_strings,
    extract_strings_detailed,
)
from .verdict import assess_static_evidence
from .yara_scanner import scan_payload_yara

_SUSPICIOUS_CAPABILITY_PATTERNS = [
    (
        "Process Injection",
        [
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
            "ptrace", "process_vm_writev", "memfd_create",
        ],
    ),
    (
        "Fileless / In-Memory Execution",
        [
            "MapViewOfFile", "VirtualProtect", "ReflectiveLoader",
            "execveat", "fexecve", "memfd_create",
        ],
    ),
    (
        "Defense Evasion & Anti-Debug",
        [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "ptrace_traceme", "sys_ptrace",
        ],
    ),
    (
        "Persistence & Autostart",
        [
            "RegSetValueEx", "CreateService", "ChangeServiceConfig",
            "schtasks", "cron", "/etc/init.d", "systemd",
        ],
    ),
    (
        "Credential Access",
        [
            "LsaRetrievePrivateData", "SamIConnect", "MiniDumpWriteDump",
            "lsass", "sekurlsa", "sam._", "/etc/shadow",
        ],
    ),
    (
        "Cryptographic & Ransomware",
        [
            "CryptEncrypt", "CryptGenKey", "CryptAcquireContext",
            "BCryptEncrypt", "AES_encrypt", "vssadmin delete shadows",
        ],
    ),
    (
        "Network Communications & C2",
        [
            "InternetOpen", "InternetConnect", "HttpSendRequest",
            "WSAStartup", "connect", "getaddrinfo", "socket",
        ],
    ),
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy over raw byte buffer (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def compute_tlsh(data: bytes) -> str:
    """Compute TLSH fuzzy hash string.

    Returns TLSH hex digest string, or descriptive status if unavailable / insufficient length.
    """
    try:
        import tlsh
        if not hasattr(tlsh, "hash") or not callable(tlsh.hash):
            return "TLSH unavailable (py-tlsh not installed)"
        if len(data) < 50:
            return "TNULL (insufficient length < 50 bytes)"
        res = tlsh.hash(data)
        if not res or res == "TNULL":
            return "TNULL (insufficient variance/entropy)"
        return res
    except ImportError:
        return "TLSH unavailable (py-tlsh not installed)"
    except Exception as exc:
        return f"TLSH computation error: {exc}"


def calculate_entropy_histogram(data: bytes, bins: int = 32) -> list[dict[str, Any]]:
    """Compute local Shannon entropy chunks across the sample."""
    if not data or bins <= 0:
        return []
    chunk_size = max(1, len(data) // bins)
    hist: list[dict[str, Any]] = []
    for i in range(bins):
        start = i * chunk_size
        end = min(len(data), (i + 1) * chunk_size) if i < bins - 1 else len(data)
        chunk = data[start:end]
        hist.append({
            "bin": i,
            "offset": f"0x{start:08X}",
            "entropy": calculate_entropy(chunk),
            "size": len(chunk),
        })
    return hist


def generate_hex_preview(data: bytes, max_bytes: int = 512) -> list[dict[str, str]]:
    """Generate hex/ASCII inspection rows for analyst preview."""
    preview: list[dict[str, str]] = []
    chunk = data[:max_bytes]
    for i in range(0, len(chunk), 16):
        row = chunk[i : i + 16]
        hex_str = " ".join(f"{b:02X}" for b in row)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        preview.append({
            "offset": f"{i:08X}",
            "hex": hex_str,
            "ascii": ascii_str,
        })
    return preview


def check_os_package_baseline(data: bytes, file_path: str | None = None) -> list[dict[str, Any]]:
    """Check if payload matches a verified stock OS package binary or distribution asset."""
    signals: list[dict[str, Any]] = []
    if not data:
        return signals
    data_hash = hashlib.sha256(data).hexdigest()
    if file_path and file_path.startswith(("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/usr/lib/", "/usr/share/", "/etc/")):
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    on_disk_hash = hashlib.sha256(f.read()).hexdigest()
                if on_disk_hash == data_hash:
                    signals.append({
                        "title": "Verified Clean System Asset (OS Package Baseline)",
                        "weight": -50,
                        "reliability": "parsed",
                        "evidence": f"Matches verified host distribution asset at {file_path}",
                    })
            except Exception:
                pass
    return signals


def run_complete_static_pipeline(
    data: bytes,
    file_path: str | None = None,
    benign_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute complete static analysis pipeline over binary/document/script payload."""
    strings_detailed, strings_truncation = extract_strings_detailed(data)
    strings = [d["string"] for d in strings_detailed]
    categorized = categorize_strings(strings)
    entropy = calculate_entropy(data)
    entropy_hist = calculate_entropy_histogram(data, bins=32)
    hex_preview = generate_hex_preview(data, 512)

    findings: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    structural_anomalies: list[dict[str, Any]] = []
    benign_signals: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    embedded_indicators: list[dict[str, Any]] = []

    if strings_truncation.get("total_file_bytes", 0) > strings_truncation.get("scan_bytes_processed", 0):
        proc_mb = strings_truncation["scan_bytes_processed"] // (1024 * 1024)
        tot_mb = strings_truncation["total_file_bytes"] // (1024 * 1024)
        could_not_analyze.append(f"strings: scanned first {proc_mb} MB of {tot_mb} MB")

    if benign_evidence:
        benign_signals.extend(benign_evidence)
    benign_signals.extend(check_os_package_baseline(data, file_path))

    format_type = "unknown"
    pe_info = None
    elf_info = None
    office_info = None
    pdf_info = None
    lnk_info = None
    archive_info = None
    script_info = None

    sections_for_indicators: list[dict[str, Any]] = []

    # 1. Format-specific dispatch
    if is_pe(data):
        format_type = "pe"
        pe_info = parse_deep_pe(data)
        sections_for_indicators = pe_info.get("sections", [])
        findings.extend(pe_info.get("findings", []))
        capabilities.extend(pe_info.get("capabilities", []))
        structural_anomalies.extend(pe_info.get("structural_anomalies", []))
        benign_signals.extend(pe_info.get("benign_signals", []))
        could_not_analyze.extend(pe_info.get("could_not_analyze", []))
        if pe_info.get("indicators"):
            embedded_indicators.extend(pe_info["indicators"])

    elif is_elf(data):
        format_type = "elf"
        elf_info = parse_deep_elf(data)
        findings.extend(elf_info.get("findings", []))
        capabilities.extend(elf_info.get("capabilities", []))
        structural_anomalies.extend(elf_info.get("structural_anomalies", []))
        benign_signals.extend(elf_info.get("benign_signals", []))
        could_not_analyze.extend(elf_info.get("could_not_analyze", []))

    elif is_office_document(data):
        format_type = "office"
        office_info = analyze_office(data)
        findings.extend(office_info.get("findings", []))
        capabilities.extend(office_info.get("capabilities", []))
        could_not_analyze.extend(office_info.get("could_not_analyze", []))

    elif is_pdf_document(data):
        format_type = "pdf"
        pdf_info = analyze_pdf(data)
        findings.extend(pdf_info.get("findings", []))
        capabilities.extend(pdf_info.get("capabilities", []))
        could_not_analyze.extend(pdf_info.get("could_not_analyze", []))

    elif is_lnk_file(data):
        format_type = "lnk"
        lnk_info = analyze_lnk(data)
        findings.extend(lnk_info.get("findings", []))
        capabilities.extend(lnk_info.get("capabilities", []))
        could_not_analyze.extend(lnk_info.get("could_not_analyze", []))

    elif is_archive_or_container(data):
        format_type = "container"
        archive_info = analyze_archive(data)
        findings.extend(archive_info.get("findings", []))
        capabilities.extend(archive_info.get("capabilities", []))
        structural_anomalies.extend(archive_info.get("structural_anomalies", []))
        could_not_analyze.extend(archive_info.get("could_not_analyze", []))
        if archive_info.get("indicators"):
            embedded_indicators.extend(archive_info["indicators"])

    elif is_script(data):
        format_type = "script"
        script_info = analyze_script(data)
        findings.extend(script_info.get("findings", []))
        capabilities.extend(script_info.get("capabilities", []))
        could_not_analyze.extend(script_info.get("could_not_analyze", []))

    else:
        format_type = "unknown"
        could_not_analyze.append("Unrecognized file format; deep structural parsing unavailable")

    # 2. Strict Embedded Indicators
    embedded_indicators.extend(extract_embedded_indicators(data, sections_for_indicators))

    # 3. Family Malware Configuration Decoders
    decoded_configs = run_family_decoders(data, {"format": format_type})
    for cfg in decoded_configs:
        fam_name = cfg.get("family", "Unknown")
        c2_val = cfg.get("c2_endpoint") or cfg.get("c2_server") or (cfg.get("c2_servers", [None])[0] if cfg.get("c2_servers") else None)
        prov = create_provenance("parser_field", f"Config Decoder: {fam_name}", "parsed", "confirmed")
        findings.append(create_finding(
            f"malware-config-{fam_name.lower()}",
            "ioc",
            f"Decoded {fam_name} Malware Configuration",
            f"Extracted verified C2 endpoint ({c2_val}) via {fam_name} config decoder.",
            prov,
            ["T1071", "T1027"],
        ))
        if c2_val:
            embedded_indicators.append({
                "type": "c2_endpoint",
                "value": str(c2_val),
                "classification": "malicious",
                "location": f"Decoded {fam_name} Configuration",
                "location_rank": 1,
                "provenance": prov,
            })

    # 4. YARA Signature Matching
    yara_result = scan_payload_yara(data)
    for ymatch in yara_result.get("matches", []):
        r_name = ymatch["rule"]
        r_meta = ymatch.get("meta", {})
        r_ns = ymatch.get("namespace", "")
        r_impact = r_meta.get("verdict_impact", "authoritative")
        r_techs = [r_meta["mitre_technique"]] if "mitre_technique" in r_meta else []

        first_off = ymatch["strings"][0]["offset"] if ymatch.get("strings") else 0
        prov = create_provenance(
            "pattern_offset",
            f"Offset 0x{first_off:08X} (YARA namespace: {r_ns})",
            "matched",
            "confirmed",
            rule_id=r_name,
        )

        if r_impact == "authoritative":
            findings.append(create_finding(
                f"yara-{r_name.lower()}",
                "ioc",
                f"YARA Match: {r_name}",
                r_meta.get("description", f"Authoritative YARA rule '{r_name}' matched payload."),
                prov,
                r_techs,
            ))
            embedded_indicators.append({
                "type": "yara_rule",
                "value": r_name,
                "classification": "malicious",
                "location": f"YARA Namespace: {r_ns} (offset 0x{first_off:08X})",
                "location_rank": 1,
                "provenance": prov,
            })
        elif r_impact == "informational":
            if "packer" in r_ns or "packer" in ymatch.get("tags", []):
                has_existing_packer = bool((pe_info and pe_info.get("packer")) or (elf_info and elf_info.get("packer")))
                if not has_existing_packer and not any("packer" in f.get("title", "").lower() for f in findings):
                    could_not_analyze.append("packed_executable_code")
                    could_not_analyze.append("obfuscated_imports")
                    structural_anomalies.append({
                        "title": f"Packer identified ({r_name})",
                        "weight": 25,
                        "reliability": "matched",
                        "evidence": f"YARA rule '{r_name}' matched at offset 0x{first_off:08X}",
                    })

    # 5. Capability detection from imports vs strings
    # Check imports if available (PE or ELF)
    resolved_imports: list[str] = []
    if pe_info:
        resolved_imports.extend(pe_info.get("imports", []))
    if elf_info:
        resolved_imports.extend(elf_info.get("imported_symbols", []))
    all_symbols_text = " ".join(resolved_imports) if resolved_imports else ""

    _GENERIC_STRING_TOKENS = {"connect", "socket", "cron", "systemd", "/etc/init.d", "getaddrinfo", "chmod"}
    combined_text = " ".join(strings)

    for category, symbols in _SUSPICIOUS_CAPABILITY_PATTERNS:
        # Check if symbol appears in authoritative import table (high reliability, excluding generic OS libc tokens)
        parsed_matches = [
            s for s in symbols
            if s not in _GENERIC_STRING_TOKENS
            and s.lower() in all_symbols_text.lower()
        ]
        # Check if symbol appears in raw strings with whole-word boundary (excluding generic glibc tokens)
        heuristic_matches = [
            s for s in symbols
            if s not in _GENERIC_STRING_TOKENS
            and re.search(r"\b" + re.escape(s) + r"\b", combined_text, re.IGNORECASE)
            and s not in parsed_matches
        ]

        if parsed_matches:
            prov = create_provenance("import_table", f"Import Address Table ({len(parsed_matches)} symbols)", "parsed", "confirmed")
            capabilities.append({
                "category": category,
                "matched": parsed_matches,
                "confidence": "confirmed",
                "source": "import_table",
                "provenance": prov,
            })
        elif heuristic_matches:
            prov = create_provenance("string_offset", "Extracted Strings", "inferred", "low", evidence_excerpt=heuristic_matches[0])
            capabilities.append({
                "category": category,
                "matched": heuristic_matches,
                "confidence": "low",
                "source": "heuristic",
                "provenance": prov,
            })

    # Packing check
    is_packed = bool(pe_info and pe_info.get("packer")) or (entropy > 7.1 and format_type in ("pe", "elf"))

    # 5. Evidence-based Assessment
    assessment = assess_static_evidence(
        findings=findings,
        capabilities=capabilities,
        embedded_indicators=embedded_indicators,
        structural_anomalies=structural_anomalies,
        benign_signals=benign_signals,
        could_not_analyze=could_not_analyze,
        signature_info=pe_info.get("signature") if pe_info else None,
    )

    # Legacy IOCs mapping for backward compatibility with existing tests
    legacy_iocs = {
        "ips": [i["value"] for i in embedded_indicators if i["type"] == "ipv4"],
        "urls": [i["value"] for i in embedded_indicators if i["type"] == "url"],
        "domains": [i["value"] for i in embedded_indicators if i["type"] == "domain"],
        "hashes": [hashlib.sha256(data).hexdigest()],
        "emails": [i["value"] for i in embedded_indicators if i["type"] == "email"],
    }

    tlsh_hash = compute_tlsh(data)

    return {
        "format": format_type,
        "strings": strings,
        "strings_detailed": strings_detailed,
        "strings_truncation": strings_truncation,
        "categorized_strings": categorized,
        "iocs": legacy_iocs,
        "embedded_indicators": embedded_indicators,
        "decoded_configs": decoded_configs,
        "findings": findings,
        "pe": pe_info,
        "elf": elf_info,
        "office": office_info,
        "pdf": pdf_info,
        "lnk": lnk_info,
        "archive": archive_info,
        "script": script_info,
        "entropy": entropy,
        "entropy_histogram": entropy_hist,
        "is_packed": is_packed,
        "capabilities": capabilities,
        "imphash": pe_info.get("imphash_canonical") if pe_info else None,
        "tlsh": tlsh_hash,
        "fuzzy_hash": tlsh_hash,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_preview": hex_preview,
        "yara": yara_result,
        "yara_rules": yara_result.get("matched_rule_names", []),
        **assessment,
    }
