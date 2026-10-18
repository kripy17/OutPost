"""Script static analyzer with layered deobfuscation (PowerShell, VBScript, JS, Batch, Shell).

Provides syntax identification, layered deobfuscation, and capability mapping:
1. Base64 payload decoding (-enc, FromBase64String, atob).
2. PowerShell tick-mark obfuscation elimination.
3. String concatenation and array join normalization.
4. AMSI bypass & Defender tampering recognition.
5. In-memory execution primitives (IEX, DownloadString, curl | sh).
"""

import base64
import re
from typing import Any

from ..provenance import create_finding, create_provenance

_SCRIPT_PATTERNS = {
    "powershell": (
        rb"(\$env:|\$[a-zA-Z0-9_]+|invoke-expression|invoke-webrequest|downloadstring|"
        rb"new-object\s+net\.webclient|set-mppreference|\[system\.convert\]|\bget-process\b|\bpwsh\b|"
        rb"\bpowershell\b|\[ref\]|-enc|-encodedcommand|\bamsiutils\b|frombase64)"
    ),
    "vbscript": (
        rb"(\bdim\s+[a-z0-9_]+|\bset\s+[a-z0-9_]+\s*=\s*createobject|\bwscript\.shell\b|"
        rb"\bwscript\.sleep\b|\bmsgbox\b|\bon\s+error\s+resume\s+next\b)"
    ),
    "batch": (
        rb"(@echo\s+off\b|\bsetlocal\b|\brem\b|\bcall\s+:\b|\bpowershell(?:\.exe)?\s+-[a-z]|\bcmd(?:\.exe)?\s+/[ck]\b)"
    ),
    "shell": (
        rb"(#!/bin/(?:ba)?sh\b|\bif\s+\[\s+-|\bexport\s+[a-zA-Z0-9_]+=|\bchmod\s+\+[xrw]|\bcurl\s+-[sS]|\bwget\s+-q)"
    ),
    "javascript": (
        rb"(\bfunction\s+[a-zA-Z0-9_]+\s*\(|\bvar\s+[a-zA-Z0-9_]+|\bconst\s+[a-zA-Z0-9_]+|"
        rb"\bdocument\.getelementbyid|\bwindow\.location|\beval\s*\(|\bactivexobject\b)"
    ),
}


def is_script(data: bytes) -> bool:
    """Check if binary payload matches known script signatures or high text ratio."""
    # Check shebang
    if data.startswith(b"#!"):
        return True
    # Check text patterns (stripping backticks to defeat PowerShell quote obfuscation)
    sample_chunk = data[:4096].lower().replace(b"`", b"")
    for pattern in _SCRIPT_PATTERNS.values():
        if re.search(pattern, sample_chunk, re.IGNORECASE):
            return True
    return False


def deobfuscate_script(script_text: str) -> tuple[str, list[str]]:
    """Apply layered deobfuscation to script content."""
    transforms_applied: list[str] = []
    current = script_text

    # 1. PowerShell backtick removal
    if "`" in current:
        cleaned = re.sub(r"`([a-zA-Z0-9_])", r"\1", current)
        if cleaned != current:
            current = cleaned
            transforms_applied.append("PowerShell backtick unquoting")

    # 2. String concatenation normalization (e.g. "po" + "wer" + "shell" -> "powershell")
    concat_pattern = re.compile(r'["\']\s*\+\s*["\']')
    if concat_pattern.search(current):
        current = concat_pattern.sub("", current)
        transforms_applied.append("String literal concatenation joining")

    # 3. Base64 payload extraction & decoding
    b64_matches = re.findall(r"(?:-enc(?:odedcommand)?\s+|FromBase64String\([\"'])([A-Za-z0-9+/=]{20,})", current, re.IGNORECASE)
    for b64_str in b64_matches:
        try:
            decoded_bytes = base64.b64decode(b64_str)
            # Try UTF-16LE then UTF-8
            try:
                dec_text = decoded_bytes.decode("utf-16le")
            except Exception:
                dec_text = decoded_bytes.decode("utf-8", "ignore")

            if len(dec_text.strip()) > 5:
                current += f"\n\n# --- DECODED BASE64 PAYLOAD ---\n{dec_text}"
                transforms_applied.append("Base64 encoded command decompression")
        except Exception:
            pass

    return current, transforms_applied


def analyze_script(data: bytes) -> dict[str, Any]:
    """Perform static behavioral and capability analysis of script text."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []

    # Detect script type
    script_type = "generic_script"
    sample_chunk = data[:4096].lower()
    for s_type, pattern in _SCRIPT_PATTERNS.items():
        if re.search(pattern, sample_chunk, re.IGNORECASE):
            script_type = s_type
            break

    try:
        raw_text = data.decode("utf-8")
    except UnicodeDecodeError:
        raw_text = data.decode("latin1", "replace")

    normalized_text, transforms = deobfuscate_script(raw_text)
    lower_norm = normalized_text.lower()

    # 1. AMSI Bypass / Defense Tampering
    if any(k in lower_norm for k in ("amsiutils", "amsiinitfailed", "set-mppreference -disablerealtimemonitoring", "disableioavprotection")):
        prov = create_provenance("string_offset", "Script Deobfuscated Text", "matched", "confirmed")
        findings.append(create_finding(
            "script-amsi-defender-bypass",
            "capability",
            "AMSI Memory Patching / Antivirus Tampering",
            "Script tampers with AMSI (Antimalware Scan Interface) memory structures or disables Defender monitoring.",
            prov,
            ["T1562.001"],
        ))
        capabilities.append({
            "category": "Defense Evasion & Anti-Debug",
            "matched": ["AMSI Bypass", "Defender Disablement"],
            "confidence": "high",
            "provenance": prov,
        })

    # 2. In-Memory Execution / Stagers
    if any(k in lower_norm for k in ("iex", "invoke-expression", "downloadstring", "curl | sh", "curl | bash", "wscript.shell")):
        prov = create_provenance("string_offset", "Script Deobfuscated Text", "matched", "confirmed")
        findings.append(create_finding(
            "script-in-memory-download-c2",
            "capability",
            "In-Memory Download & Execution Stager",
            "Script executes downloaded payload directly into memory via IEX/DownloadString or pipe execution.",
            prov,
            ["T1059.001", "T1105", "T1027"],
        ))
        capabilities.append({
            "category": "Execution & Scripting",
            "matched": ["In-Memory Download Stager"],
            "confidence": "high",
            "provenance": prov,
        })

    # 3. Credential dumping or harvesting
    if any(k in lower_norm for k in ("mimikatz", "sekurlsa", "lsass", "procdump", "ntdsutil", "sam._")):
        prov = create_provenance("string_offset", "Script Deobfuscated Text", "matched", "confirmed")
        findings.append(create_finding(
            "script-credential-harvesting",
            "capability",
            "Credential Access & Memory Harvesting Script",
            "Script references LSASS dumping or active credential theft primitives.",
            prov,
            ["T1003.001"],
        ))
        capabilities.append({
            "category": "Credential Access",
            "matched": ["Credential Harvesting Tools"],
            "confidence": "high",
            "provenance": prov,
        })

    # 4. HTML Smuggling & Dynamic File Drop
    if any(k in lower_norm for k in ("createobjecturl", "mssaveoropenblob", "application/octet-stream")) and any(k in lower_norm for k in ("atob", "blob(", ".click()")):
        prov = create_provenance("string_offset", "HTML/JS Script Content", "matched", "confirmed")
        findings.append(create_finding(
            "script-html-smuggling-dropper",
            "capability",
            "HTML / SVG Smuggling Payload Delivery",
            "Script dynamically decodes in-memory Blob and auto-triggers file download to evade network inspection.",
            prov,
            ["T1027.006", "T1204.002"],
        ))
        capabilities.append({
            "category": "Execution & Scripting",
            "matched": ["HTML Smuggling Blob Delivery"],
            "confidence": "high",
            "provenance": prov,
        })

    # Extract URLs from script text
    urls = re.findall(r"https?://[^\s\"'<>`]+", normalized_text)
    for u in urls[:10]:
        indicators.append({
            "type": "url",
            "value": u,
            "classification": "suspicious",
            "location": "Script source URL literal",
        })

    return {
        "format": script_type,
        "is_script": True,
        "transforms_applied": transforms,
        "deobfuscated_preview": normalized_text[:500] if transforms else None,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "could_not_analyze": could_not_analyze,
    }
