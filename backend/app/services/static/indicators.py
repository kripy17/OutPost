"""Strict embedded indicator extraction and validation engine.

Replaces loose regular expression searches with:
1. Strict IPv4 octet validation (0-255) and RFC 1918 / loopback / multicast exclusion.
2. Domain validation with valid TLD structure and benign infrastructure exclusion.
3. Physical location ranking (code_section > data_section > resource > overlay > decoded).
4. Provenance and confidence tagging for every extracted indicator.
"""

import ipaddress
import re
from typing import Any

from .provenance import create_provenance

# Known benign domains and schemas commonly found in legitimate binaries & libraries
_BENIGN_INFRASTRUCTURE = {
    "microsoft.com", "windows.com", "w3.org", "xmlsoap.org",
    "openxmlformats.org", "purl.org", "github.com", "google.com",
    "digicert.com", "verisign.com", "sectigo.com", "identrust.com",
    "letsencrypt.org", "globalsign.com", "adobe.com", "apple.com",
    "example.com", "example.org", "example.net", "gnu.org",
    "kernel.org", "debian.org", "ubuntu.com", "python.org",
    "xiph.org", "translationproject.org", "freedesktop.org",
    "apache.org", "mozilla.org", "iana.org", "iso.org", "fsf.org",
}

# Regex matching clean ASCII URLs without control characters or NUL bytes
_RE_URL = re.compile(rb"https?://[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{2,24}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)", re.IGNORECASE)
_RE_IPV4_CANDIDATE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN_CANDIDATE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_RE_EMAIL_CANDIDATE = re.compile(rb"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

_SUSPICIOUS_DOMAIN_PATTERNS = (
    "duckdns.org", "no-ip.", "ddns.net", "ngrok.io", ".onion",
    "pastebin.com/raw", "hastebin.com", "temp.sh", "darknet", "c2.",
)

_COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "io", "co", "ru", "cn", "uk",
    "de", "jp", "fr", "br", "in", "ca", "au", "xyz", "top", "club", "info",
    "biz", "pro", "online", "site", "live", "cc", "me", "pw", "tk", "ga",
    "ml", "cf", "gq", "app", "dev", "cloud", "work", "icu", "su", "link",
    "example",
}

_COMMON_FILE_EXTENSIONS = {
    "xml", "bin", "dat", "txt", "log", "tmp", "json", "dll", "exe",
    "png", "jpg", "jpeg", "gif", "ico", "bmp", "rels", "ini", "cfg",
    "conf", "zip", "tar", "gz", "bz2", "7z", "iso", "vba", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "pdf", "py", "sh", "bat", "cmd", "ps1",
    "cpp", "c", "h", "hpp", "java", "class", "jar", "html", "htm", "css", "js",
}


def is_valid_public_ipv4(ip_str: str) -> bool:
    """Strictly validate IPv4 address and ensure it is not RFC 1918, loopback, or multicast."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        if addr.is_loopback or addr.is_multicast or addr.is_link_local:
            return False
        octets = addr.exploded.split(".")
        first = int(octets[0])
        second = int(octets[1])
        # Exclude RFC 1918 (10/8, 172.16/12, 192.168/16) and 0/8, 255/8
        if first == 10 or (first == 172 and 16 <= second <= 31) or (first == 192 and second == 168):
            return False
        if first in (0, 255):
            return False
        return True
    except Exception:
        return False


def is_valid_domain(domain_str: str) -> bool:
    """Verify domain has valid TLD and is not known benign vendor infrastructure or file extension."""
    domain_clean = domain_str.strip().lower()
    if len(domain_clean) < 4 or "." not in domain_clean:
        return False
    if domain_clean.endswith((".local", ".internal", ".lan", ".home", ".arpa", ".test", ".invalid")):
        return False

    parts = domain_clean.split(".")
    tld = parts[-1]
    if tld in _COMMON_FILE_EXTENSIONS:
        return False
    if tld not in _COMMON_TLDS:
        return False

    # Check benign vendor infrastructure
    for benign in _BENIGN_INFRASTRUCTURE:
        if domain_clean == benign or domain_clean.endswith("." + benign):
            return False

    return True


def extract_embedded_indicators(
    data: bytes,
    sections: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Extract and validate external C2, IPs, and URLs with location ranking and provenance."""
    indicators: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _determine_location(offset: int) -> tuple[str, int]:
        """Rank indicator by physical location."""
        if not sections:
            return "binary_payload", 3
        for sec in sections:
            start = sec.get("raw_ptr", 0)
            sz = sec.get("raw_size", 0)
            if start <= offset < start + sz:
                sec_name = sec.get("name", "")
                if sec_name in (".text", "CODE"):
                    return f"code_section ({sec_name})", 1
                if sec_name in (".data", ".rdata", "DATA"):
                    return f"data_section ({sec_name})", 2
                if sec_name in (".rsrc", "RESOURCE"):
                    return f"resource_section ({sec_name})", 3
                return f"section ({sec_name})", 3
        return "appended_overlay", 4

    # 1. IPv4 extraction
    for match in _RE_IPV4_CANDIDATE.finditer(data):
        ip_bytes = match.group(0)
        try:
            ip_str = ip_bytes.decode("ascii")
            if is_valid_public_ipv4(ip_str) and ip_str not in seen:
                seen.add(ip_str)
                loc_name, rank = _determine_location(match.start())
                prov = create_provenance(
                    "string_offset",
                    f"Offset 0x{match.start():08X} ({loc_name})",
                    "matched",
                    "high",
                    evidence_excerpt=ip_str,
                )
                indicators.append({
                    "type": "ipv4",
                    "value": ip_str,
                    "location": loc_name,
                    "location_rank": rank,
                    "offset": f"0x{match.start():08X}",
                    "classification": "informational",
                    "provenance": prov,
                })
        except Exception:
            pass

    seen_domains_in_urls: set[str] = set()

    # 2. URLs extraction
    for match in _RE_URL.finditer(data):
        url_bytes = match.group(0)
        try:
            # Strip NUL bytes and control characters immediately
            clean_bytes = re.split(rb"[\x00-\x1f\s\"'<>\\]", url_bytes)[0]
            url_str = clean_bytes.decode("latin1", errors="replace").rstrip(".,;)\"'<>\\")
            if url_str not in seen and len(url_str) >= 10:
                domain_match = re.search(r"https?://([^/:\s]+)", url_str)
                if domain_match:
                    host = domain_match.group(1).lower()
                    if is_valid_public_ipv4(host) or is_valid_domain(host):
                        seen.add(url_str)
                        seen_domains_in_urls.add(host)
                        # Also track base domain to avoid duplicate subdomains
                        parts = host.split(".")
                        if len(parts) >= 2:
                            seen_domains_in_urls.add(".".join(parts[-2:]))

                        loc_name, rank = _determine_location(match.start())
                        # Classify: generic documentation/licensing URLs are informational, not suspicious
                        is_ip_host = is_valid_public_ipv4(host)
                        has_suspicious_pattern = any(p in host for p in _SUSPICIOUS_DOMAIN_PATTERNS)
                        has_nonstandard_port = bool(re.search(r":(?!80\b|443\b)\d{2,5}", url_str))

                        if is_ip_host or has_suspicious_pattern or has_nonstandard_port:
                            classification = "suspicious"
                        else:
                            classification = "informational"

                        prov = create_provenance(
                            "string_offset",
                            f"Offset 0x{match.start():08X} ({loc_name})",
                            "matched",
                            "high" if classification == "suspicious" else "low",
                            evidence_excerpt=url_str,
                        )
                        indicators.append({
                            "type": "url",
                            "value": url_str,
                            "location": loc_name,
                            "location_rank": rank,
                            "offset": f"0x{match.start():08X}",
                            "classification": classification,
                            "provenance": prov,
                        })
        except Exception:
            pass

    # 3. Domains extraction (only extract standalone domains not already captured in URLs)
    for match in _RE_DOMAIN_CANDIDATE.finditer(data):
        dom_bytes = match.group(0)
        try:
            clean_dom = re.split(rb"[\x00-\x1f\s\"'<>\\]", dom_bytes)[0]
            dom_str = clean_dom.decode("ascii", errors="replace").lower()
            if is_valid_domain(dom_str) and dom_str not in seen and dom_str not in seen_domains_in_urls:
                # Also verify base domain is not already seen in a URL
                parts = dom_str.split(".")
                base_dom = ".".join(parts[-2:]) if len(parts) >= 2 else dom_str
                if base_dom in seen_domains_in_urls:
                    continue

                seen.add(dom_str)
                loc_name, rank = _determine_location(match.start())
                has_suspicious_pattern = any(p in dom_str for p in _SUSPICIOUS_DOMAIN_PATTERNS)
                classification = "suspicious" if has_suspicious_pattern else "informational"

                prov = create_provenance(
                    "string_offset",
                    f"Offset 0x{match.start():08X} ({loc_name})",
                    "matched",
                    "high" if classification == "suspicious" else "low",
                    evidence_excerpt=dom_str,
                )
                indicators.append({
                    "type": "domain",
                    "value": dom_str,
                    "location": loc_name,
                    "location_rank": rank,
                    "offset": f"0x{match.start():08X}",
                    "classification": classification,
                    "provenance": prov,
                })
        except Exception:
            pass

    # 4. Email extraction
    for match in _RE_EMAIL_CANDIDATE.finditer(data):
        email_bytes = match.group(0)
        try:
            email_str = email_bytes.decode("utf-8", errors="replace").lower()
            if email_str not in seen:
                seen.add(email_str)
                loc_name, rank = _determine_location(match.start())
                prov = create_provenance(
                    "string_offset",
                    f"Offset 0x{match.start():08X} ({loc_name})",
                    "matched",
                    "low",
                    evidence_excerpt=email_str,
                )
                indicators.append({
                    "type": "email",
                    "value": email_str,
                    "location": loc_name,
                    "location_rank": rank,
                    "offset": f"0x{match.start():08X}",
                    "classification": "informational",
                    "provenance": prov,
                })
        except Exception:
            pass

    # Sort indicators by location rank (code > data > resource > overlay)
    indicators.sort(key=lambda x: x.get("location_rank", 5))
    return indicators
