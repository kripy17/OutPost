"""PDF static document analyzer.

Analyzes PDF documents for suspicious objects, execution triggers, and embedded payloads:
1. /OpenAction and /AA (auto-executing actions on document launch or page view).
2. /JavaScript and /JS (embedded script execution blocks).
3. /Launch (external process invocation).
4. /EmbeddedFiles (embedded droppers/binaries).
5. /URI (hyperlinks).
"""

import re
import zlib
from typing import Any

from ..provenance import create_finding, create_provenance


def is_pdf_document(data: bytes) -> bool:
    """Check for %PDF- header within first 1024 bytes."""
    return b"%PDF-" in data[:1024]


def analyze_pdf(data: bytes) -> dict[str, Any]:
    """Parse PDF structure for weaponized objects and script execution triggers."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []

    pdf_version = "unknown"
    ver_match = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
    if ver_match:
        pdf_version = ver_match.group(1).decode("ascii", "ignore")

    # Catalog dictionary inspection
    has_open_action = bool(re.search(rb"/OpenAction\b", data))
    has_aa = bool(re.search(rb"/AA\b", data))
    has_javascript = bool(re.search(rb"/(?:JavaScript|JS)\b", data))
    has_launch = bool(re.search(rb"/Launch\b", data))
    has_embedded_files = bool(re.search(rb"/EmbeddedFiles\b", data))

    # Extract URIs
    uri_matches = re.findall(rb"/URI\s*\(([^)]+)\)", data)
    extracted_urls = []
    for u in uri_matches:
        try:
            url_str = u.decode("latin1", "ignore").strip()
            if url_str.startswith(("http://", "https://")):
                extracted_urls.append(url_str)
                indicators.append({
                    "type": "url",
                    "value": url_str,
                    "classification": "suspicious",
                    "location": "PDF /URI action dictionary",
                })
        except Exception:
            pass

    # 1. Auto-execution triggers
    if has_open_action or has_aa:
        prov = create_provenance("parser_field", "PDF Catalog /OpenAction or /AA", "parsed", "confirmed")
        findings.append(create_finding(
            "pdf-auto-action-trigger",
            "capability",
            "Automatic Action Trigger on Document Open",
            "PDF defines an /OpenAction or /AA event trigger executing code or launching tasks upon viewing.",
            prov,
            ["T1204.002"],
        ))
        capabilities.append({
            "category": "Persistence & Autostart",
            "matched": ["/OpenAction" if has_open_action else "/AA"],
            "confidence": "high",
            "provenance": prov,
        })

    # 2. JavaScript execution
    if has_javascript:
        prov = create_provenance("parser_field", "PDF Object Dictionary /JavaScript", "parsed", "confirmed")
        findings.append(create_finding(
            "pdf-embedded-javascript",
            "capability",
            "Embedded JavaScript Execution Logic in PDF",
            "PDF contains /JavaScript or /JS dictionaries capable of executing client-side script payloads.",
            prov,
            ["T1059.007", "T1204.002"],
        ))
        capabilities.append({
            "category": "Execution & Scripting",
            "matched": ["PDF /JavaScript Engine"],
            "confidence": "high",
            "provenance": prov,
        })

    # 3. Direct process launch
    if has_launch:
        prov = create_provenance("parser_field", "PDF Object Dictionary /Launch", "parsed", "confirmed")
        findings.append(create_finding(
            "pdf-launch-action",
            "capability",
            "External Command Launch Action (/Launch)",
            "PDF contains /Launch action configured to spawn external executable processes.",
            prov,
            ["T1204.002", "T1059"],
        ))
        capabilities.append({
            "category": "Execution & Scripting",
            "matched": ["/Launch Action"],
            "confidence": "high",
            "provenance": prov,
        })

    # 4. Embedded file droppers
    if has_embedded_files:
        prov = create_provenance("parser_field", "PDF Names Tree /EmbeddedFiles", "parsed", "confirmed")
        findings.append(create_finding(
            "pdf-embedded-files",
            "structure",
            "Embedded Binary Payload Inside PDF",
            "PDF specifies /EmbeddedFiles stream dictionary indicating potential dropped secondary payload.",
            prov,
            ["T1204.002"],
        ))

    # Decompress streams to extract hidden script text
    streams = re.findall(rb"stream[\r\n]+(.*?)[\r\n]+endstream", data, re.DOTALL)
    decompressed_scripts = 0
    for s in streams[:20]:
        try:
            decomp = zlib.decompress(s)
            if b"eval(" in decomp or b"unescape(" in decomp or b"String.fromCharCode" in decomp:
                decompressed_scripts += 1
                prov = create_provenance("parser_field", "FlateDecode Decompressed Stream", "parsed", "confirmed")
                findings.append(create_finding(
                    "pdf-obfuscated-stream-script",
                    "capability",
                    "Obfuscated JavaScript in Decompressed Stream",
                    "Found eval/unescape/fromCharCode script obfuscation patterns inside FlateDecode stream.",
                    prov,
                    ["T1027", "T1059.007"],
                ))
                break
        except Exception:
            continue

    if not streams:
        could_not_analyze.append("No FlateDecode object streams identified for deep content inspection")

    return {
        "format": "pdf",
        "version": pdf_version,
        "has_open_action": has_open_action,
        "has_javascript": has_javascript,
        "has_launch": has_launch,
        "has_embedded_files": has_embedded_files,
        "external_urls": extracted_urls,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "could_not_analyze": could_not_analyze,
    }
