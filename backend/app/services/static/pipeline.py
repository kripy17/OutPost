"""Complete static analysis execution pipeline.

Orchestrates multi-format inspection, deep binary analysis, embedded indicators,
family config decoding, and evidence-based assessment.
"""

import hashlib
import math
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
from .verdict import assess_static_evidence

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


def extract_strings(data: bytes, max_strings: int = 300) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings (deduped, capped)."""
    out: list[str] = []
    seen: set[str] = set()

    # ASCII runs
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= 5:
                s = bytes(cur[:256]).decode("ascii", errors="replace")
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            cur.clear()
    if len(cur) >= 5:
        s = bytes(cur[:256]).decode("ascii", errors="replace")
        if s not in seen:
            seen.add(s)
            out.append(s)

    # UTF-16LE runs
    i = 0
    n = len(data)
    cur.clear()
    while i + 1 < n and len(out) < max_strings:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and 0x20 <= lo <= 0x7E:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= 5:
                s = bytes(cur[:256]).decode("ascii", errors="replace")
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            cur.clear()
            i += 1
    if len(cur) >= 5:
        s = bytes(cur[:256]).decode("ascii", errors="replace")
        if s not in seen:
            seen.add(s)
            out.append(s)

    return out[:max_strings]


def categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    """Categorize printable strings into analyst intelligence buckets."""
    buckets: dict[str, list[str]] = {
        "network": [],
        "file_paths": [],
        "commands": [],
        "registry": [],
        "security_apis": [],
    }
    for s in strings:
        lower = s.lower()
        if any(ext in lower for ext in (".com", ".net", ".org", "http://", "https://", "tcp://")):
            buckets["network"].append(s)
        elif any(p in lower for p in ("/etc/", "/tmp/", "/var/", "c:\\", "%temp%", "%appdata%")):
            buckets["file_paths"].append(s)
        elif any(c in lower for c in ("powershell", "cmd.exe", "whoami", "curl", "wget", "chmod", "iptables", "netstat")):
            buckets["commands"].append(s)
        elif any(r in s for r in ("HKLM\\", "HKCU\\", "CurrentVersion\\Run")):
            buckets["registry"].append(s)
        elif any(a in s for a in ("VirtualAlloc", "CreateThread", "WriteProcessMemory", "ptrace", "memfd_create")):
            buckets["security_apis"].append(s)
    return buckets


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


def run_complete_static_pipeline(data: bytes) -> dict[str, Any]:
    """Execute complete static analysis pipeline over binary/document/script payload."""
    strings = extract_strings(data)
    categorized = categorize_strings(strings)
    entropy = calculate_entropy(data)
    entropy_hist = calculate_entropy_histogram(data, bins=32)
    hex_preview = generate_hex_preview(data, 512)

    findings: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    structural_anomalies: list[dict[str, Any]] = []
    benign_signals: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []

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
        could_not_analyze.extend(archive_info.get("could_not_analyze", []))

    elif is_script(data):
        format_type = "script"
        script_info = analyze_script(data)
        findings.extend(script_info.get("findings", []))
        capabilities.extend(script_info.get("capabilities", []))
        could_not_analyze.extend(script_info.get("could_not_analyze", []))

    else:
        format_type = "generic_binary"
        could_not_analyze.append("Unrecognized file format; generic binary and string analysis applied")

    # 2. Strict Embedded Indicators
    embedded_indicators = extract_embedded_indicators(data, sections_for_indicators)

    # 3. Family Malware Configuration Decoders
    decoded_configs = run_family_decoders(data, {"format": format_type})
    for cfg in decoded_configs:
        prov = create_provenance("parser_field", f"Config Decoder: {cfg.get('family')}", "parsed", "confirmed")
        findings.append(create_finding(
            f"malware-config-{cfg.get('family', 'unknown').lower()}",
            "ioc",
            f"Decoded {cfg.get('family')} Malware Configuration",
            f"Extracted verified C2 endpoint ({cfg.get('c2_endpoint')}) via {cfg.get('family')} config decoder.",
            prov,
            ["T1071", "T1027"],
        ))
        if cfg.get("c2_endpoint"):
            embedded_indicators.append({
                "type": "c2_endpoint",
                "value": str(cfg.get("c2_endpoint")),
                "classification": "malicious",
                "location": f"Decoded {cfg.get('family')} Configuration",
                "location_rank": 1,
                "provenance": prov,
            })

    # 4. Capability detection from imports vs strings
    # Check imports if available (PE or ELF)
    resolved_imports = pe_info.get("imports", []) if pe_info else []
    all_symbols_text = " ".join(resolved_imports) if resolved_imports else ""

    combined_text = " ".join(strings)
    for category, symbols in _SUSPICIOUS_CAPABILITY_PATTERNS:
        # Check if symbol appears in authoritative import table (high reliability)
        parsed_matches = [s for s in symbols if s.lower() in all_symbols_text.lower()]
        # Check if symbol appears only in raw strings (inferred, lower reliability)
        heuristic_matches = [s for s in symbols if (s in combined_text or s.encode("latin1") in data) and s not in parsed_matches]

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
    )

    # Legacy IOCs mapping for backward compatibility with existing tests
    legacy_iocs = {
        "ips": [i["value"] for i in embedded_indicators if i["type"] == "ipv4"],
        "urls": [i["value"] for i in embedded_indicators if i["type"] == "url"],
        "domains": [i["value"] for i in embedded_indicators if i["type"] == "domain"],
        "hashes": [hashlib.sha256(data).hexdigest()],
        "emails": [i["value"] for i in embedded_indicators if i["type"] == "email"],
    }

    return {
        "format": format_type,
        "strings": strings,
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
        "fuzzy_hash": f"3:{hashlib.md5(data[:64]).hexdigest()}:{hashlib.md5(data[64:128]).hexdigest()}",
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_preview": hex_preview,
        **assessment,
    }
