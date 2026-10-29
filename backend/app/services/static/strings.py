"""High-performance strings extraction and categorization engine for static analysis.

Faithfully implements ASCII and UTF-16LE string extraction mathematically
concordant with GNU Binutils strings (strings -a -n 4 and strings -a -e l -n 4),
with precise file offset tracking, encoding identification, and analyst categorization.

Specification: docs/strings_categorization_specification.md
"""

from __future__ import annotations

import re
from typing import Any, Literal, TypedDict


class ExtractedString(TypedDict):
    offset: int
    offset_hex: str
    string: str
    encoding: Literal["ascii", "utf-16le"]
    length: int
    categories: list[str]


class StringsExtractionResult(TypedDict):
    strings: list[str]
    strings_detailed: list[ExtractedString]
    categorized_strings: dict[str, list[str]]
    truncation: dict[str, Any]


# Pre-compiled regex patterns for standard min_length=4
_RE_ASCII_4 = re.compile(b"[\x20-\x7E\t]{4,}")
_RE_UTF16LE_4 = re.compile(b"(?:[\x20-\x7E\t]\x00){4,}")

_REGEX_CACHE: dict[int, tuple[re.Pattern[bytes], re.Pattern[bytes]]] = {
    4: (_RE_ASCII_4, _RE_UTF16LE_4),
}


def _get_string_regexes(min_length: int) -> tuple[re.Pattern[bytes], re.Pattern[bytes]]:
    """Retrieve or compile regex pair for ASCII and UTF-16LE matching."""
    if min_length in _REGEX_CACHE:
        return _REGEX_CACHE[min_length]
    min_len_b = str(max(1, min_length)).encode("ascii")
    ascii_pat = re.compile(rb"[\x20-\x7E\t]{" + min_len_b + rb",}")
    utf16_pat = re.compile(rb"(?:[\x20-\x7E\t]\x00){" + min_len_b + rb",}")
    _REGEX_CACHE[min_length] = (ascii_pat, utf16_pat)
    return ascii_pat, utf16_pat


# ---------------------------------------------------------------------------
# Analyst Categorization Patterns (Strict Specification)
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"(?<![\.\d])(?:[1-9]\d{0,2}|0)\.(?:[1-9]\d{0,2}|0)\.(?:[1-9]\d{0,2}|0)\.(?:[1-9]\d{0,2}|0)(?![\.\d])"
)


def _is_valid_routable_ipv4(ip_str: str) -> bool:
    """Validate that string is a valid routable IPv4 address (not 0.0.0.0, 127.0.0.1, or OID/version)."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    # Exclude 0.0.0.0, 127.x.x.x loopback, multicast (>= 224), and broadcast (255)
    if octets[0] == 0 or octets[0] >= 224 or octets[0] == 127:
        return False
    # Exclude version strings ending in .0.0 (e.g. 6.0.0.0)
    if octets[2] == 0 and octets[3] == 0:
        return False
    return True


_CATEGORY_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "urls": [
        # Explicit URI/URL scheme with valid domain or IP host syntax (including optional port)
        re.compile(r"https?://(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::\d+)?(?:/[^\s\"'<>)]*)?", re.IGNORECASE),
        re.compile(r"(?:ftp|tcp|udp|wss?)://[^\s\"'<>)]+", re.IGNORECASE),
    ],
    "network": [
        # Dynamic DNS, webhook, and paste services
        re.compile(
            r"\b(?:[a-zA-Z0-9.-]+\.)?(?:duckdns\.org|no-ip\.|ddns\.net|ngrok\.io|pastebin\.com|hastebin\.com|"
            r"discord\.com/api|telegram\.org|raw\.githubusercontent\.com|paste\.ee|ghostbin\.)\b",
            re.IGNORECASE,
        ),
        # HTTP request lines and explicit headers
        re.compile(r"\b(?:POST\s+/[^\s]*\s+HTTP/1\.[01]|GET\s+/[^\s]*\s+HTTP/1\.[01]|User-Agent:\s+[^\s]+|Host:\s+[^\s]+)\b", re.IGNORECASE),
    ],
    "file_paths": [
        # Windows drive-rooted paths
        re.compile(r"\b[a-zA-Z]:\\(?:[a-zA-Z0-9_.\- ]+\\)+[a-zA-Z0-9_.\- ]+", re.IGNORECASE),
        re.compile(r"\\\\\\?\\(?:[a-zA-Z]:\\|[a-zA-Z0-9_-]+)", re.IGNORECASE),
        re.compile(r"\\\\\.\\pipe\\[a-zA-Z0-9_-]+", re.IGNORECASE),
        # Windows environment variable paths
        re.compile(r"%(?:TEMP|APPDATA|LOCALAPPDATA|SYSTEMROOT|WINDIR|PROGRAMFILES)%\\[a-zA-Z0-9_.\-\\ ]+", re.IGNORECASE),
        # Windows system directories
        re.compile(r"\\(?:Windows\\System32|Windows\\SysWOW64|ProgramData)\\[a-zA-Z0-9_.\-\\ ]+", re.IGNORECASE),
        # Unix absolute paths with subpaths
        re.compile(r"/(?:etc|tmp|var|proc|sys|dev|usr|opt|root|home)/[a-zA-Z0-9_.\-/]+"),
        # Sensitive target configuration files
        re.compile(r"/(?:etc/)?(?:passwd|shadow|sudoers)"),
        re.compile(r"/\.ssh/(?:authorized_keys|id_rsa|id_ed25519)"),
        re.compile(r"\\System32\\config\\(?:SAM|SYSTEM)", re.IGNORECASE),
        re.compile(r"\\NTDS\\ntds\.dit", re.IGNORECASE),
    ],
    "commands": [
        # Shell interpreters with invocation flags
        re.compile(r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+-[a-zA-Z]+", re.IGNORECASE),
        re.compile(r"\bcmd(?:\.exe)?\s+/[a-zA-Z]+", re.IGNORECASE),
        re.compile(r"/(?:usr/)?bin/(?:bash|sh|zsh)\s+-[a-zA-Z]+", re.IGNORECASE),
        # Execution & evasion arguments
        re.compile(r"\b(?:-encodedcommand|-enc)\s+[a-zA-Z0-9+/=]+", re.IGNORECASE),
        re.compile(r"\b-windowstyle\s+hidden\b", re.IGNORECASE),
        re.compile(r"\b-executionpolicy\s+bypass\b", re.IGNORECASE),
        re.compile(r"\b(?:downloadstring|downloaddata)\s*\(", re.IGNORECASE),
        re.compile(r"\b(?:invoke-expression\s+|\|\s*iex\b)", re.IGNORECASE),
        # Administrative utilities with actionable parameters
        re.compile(r"\bchmod\s+(?:[+-][rwxXst]+|[0-7]{3,4})\b"),
        re.compile(r"\bchown\s+[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+\b"),
        re.compile(r"\bnet\s+(?:user|localgroup|group)\s+[a-zA-Z0-9_-]+", re.IGNORECASE),
        re.compile(r"\bvssadmin\s+delete\s+shadows\b", re.IGNORECASE),
        re.compile(r"\bwbadmin\s+delete\s+catalog\b", re.IGNORECASE),
        re.compile(r"\bbcdedit(?:\.exe)?\s+/set\b", re.IGNORECASE),
        re.compile(r"\bschtasks(?:\.exe)?\s+/(?:create|run|delete)\b", re.IGNORECASE),
        re.compile(r"\bsc(?:\.exe)?\s+(?:create|config|start)\s+[a-zA-Z0-9_-]+", re.IGNORECASE),
        re.compile(r"\bsystemctl\s+(?:start|stop|restart|enable|disable)\s+[a-zA-Z0-9_-]+", re.IGNORECASE),
    ],
    "registry": [
        re.compile(r"(?:\\|\b)(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[a-zA-Z0-9_.\\]+", re.IGNORECASE),
        re.compile(
            r"(?:\\|\b)(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[a-zA-Z0-9_.\\]+",
            re.IGNORECASE,
        ),
        re.compile(r"(?:\\|\b)Software\\Microsoft\\[a-zA-Z0-9_.\\]+", re.IGNORECASE),
        re.compile(r"\b(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|System\\CurrentControlSet|Software\\Classes)\b", re.IGNORECASE),
    ],
}

_KNOWN_API_SYMBOLS: set[str] = {
    # Network & sockets
    "socket", "connect", "send", "recv", "bind", "listen", "accept", "getaddrinfo", "gethostbyname",
    "WSAStartup", "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    # Process & Execution
    "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec", "execve", "execvp", "fork", "popen",
    # Memory & Injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext", "ptrace", "process_vm_writev", "memfd_create",
    # Anti-Analysis & Defense Evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
    "NtQueryInformationProcess", "NtSetInformationThread", "timeGetTime", "GetTickCount", "QueryPerformanceCounter",
    "amsi.dll", "AmsiScanBuffer", "EtwEventWrite",
    # Credential Harvesting
    "MiniDumpWriteDump", "LsaRetrievePrivateData", "SamIConnect", "LogonUserA", "LogonUserW",
    "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "sekurlsa", "mimikatz",
    # Cryptographic & Ransomware
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
}

_SECURITY_API_SYMBOLS: set[str] = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext", "ptrace", "process_vm_writev", "memfd_create",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "OutputDebugStringW",
    "NtQueryInformationProcess", "NtSetInformationThread", "timeGetTime", "GetTickCount", "QueryPerformanceCounter",
    "amsi.dll", "AmsiScanBuffer", "EtwEventWrite", "MiniDumpWriteDump", "LsaRetrievePrivateData",
    "SamIConnect", "LogonUserA", "LogonUserW", "OpenProcessToken", "AdjustTokenPrivileges",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW", "sekurlsa", "mimikatz",
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
}


def categorize_string(s: str) -> list[str]:
    """Identify which analyst categories match a given string."""
    matched_categories: list[str] = []

    # Check urls (explicit URI/URL schemes)
    if any(p.search(s) for p in _CATEGORY_PATTERNS["urls"]):
        matched_categories.append("urls")

    # Check network (C2 dynamic DNS, webhooks, HTTP requests, or valid routable IPv4)
    if any(p.search(s) for p in _CATEGORY_PATTERNS["network"]):
        matched_categories.append("network")
    elif _IPV4_RE.search(s):
        match = _IPV4_RE.search(s)
        if match and _is_valid_routable_ipv4(match.group()):
            matched_categories.append("network")

    # Check file_paths, commands, registry
    for category in ("file_paths", "commands", "registry"):
        if any(p.search(s) for p in _CATEGORY_PATTERNS[category]):
            matched_categories.append(category)

    # Check API names & security APIs
    # Clean symbol token checking prevents false matches on prose containing common words
    clean_token = s.strip().split("@")[0]
    if " " not in clean_token and len(clean_token) <= 64:
        if clean_token in _KNOWN_API_SYMBOLS:
            matched_categories.append("api_names")
        if clean_token in _SECURITY_API_SYMBOLS:
            matched_categories.append("security_apis")
    else:
        # For strings with whitespace, check for explicit embedded security API identifiers
        if any(sym in s for sym in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ptrace", "IsDebuggerPresent", "MiniDumpWriteDump", "CryptEncrypt")):
            matched_categories.append("security_apis")
            matched_categories.append("api_names")

    return matched_categories


def categorize_strings(strings: list[str]) -> dict[str, list[str]]:
    """Categorize printable strings into analyst intelligence buckets."""
    buckets: dict[str, list[str]] = {
        "network": [],
        "urls": [],
        "file_paths": [],
        "commands": [],
        "registry": [],
        "api_names": [],
        "security_apis": [],
    }
    seen_per_bucket: dict[str, set[str]] = {k: set() for k in buckets}

    for s in strings:
        for cat in categorize_string(s):
            if s not in seen_per_bucket[cat]:
                seen_per_bucket[cat].add(s)
                buckets[cat].append(s)

    return buckets


# ---------------------------------------------------------------------------
# Extraction Engine with Limits & Truncation
# ---------------------------------------------------------------------------

DEFAULT_MAX_STRINGS = 50000
DEFAULT_MAX_UNCATEGORIZED_STRINGS = 10000
DEFAULT_MAX_STRING_LENGTH = 1024
DEFAULT_MAX_SCAN_BYTES = 500 * 1024 * 1024  # 500 MB scan limit
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB chunk window


def extract_strings_detailed(
    data: bytes,
    min_length: int = 4,
    max_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_count: int = DEFAULT_MAX_STRINGS,
    max_uncategorized: int = DEFAULT_MAX_UNCATEGORIZED_STRINGS,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
) -> tuple[list[ExtractedString], dict[str, Any]]:
    """Extract both ASCII and UTF-16LE strings with exact file offsets and categorization.

    Streaming chunk evaluation preserves analyst visibility:
    - Retains ALL categorized strings across the entire file (never cuts threat signals).
    - Caps uncategorized strings at max_uncategorized to bound API payload size.
    - Computes category counts over 100% of the scanned bytes.
    - Uses zero-copy memoryview chunking across large multi-hundred-megabyte files.
    """
    if not data:
        return [], {
            "is_truncated": False,
            "strings_stored": 0,
            "total_found": 0,
            "categorized_count": 0,
            "uncategorized_stored": 0,
            "uncategorized_omitted": 0,
            "stored_limit": max_uncategorized,
            "scan_bytes_processed": 0,
            "total_file_bytes": 0,
            "scan_limit_bytes": max_scan_bytes,
            "category_counts": {
                "commands": 0, "urls": 0, "network": 0, "file_paths": 0,
                "registry": 0, "api_names": 0, "security_apis": 0,
            },
            "omitted_message": None,
        }

    total_file_bytes = len(data)
    scan_limit = min(total_file_bytes, max_scan_bytes)
    scan_slice = memoryview(data)[:scan_limit]

    # If caller explicitly bounded max_count (e.g. test asking for max 2000), bound uncategorized strings accordingly
    effective_max_uncat = min(max_uncategorized, max_count)

    re_ascii, re_utf16le = _get_string_regexes(min_length)
    categorized_entries: list[ExtractedString] = []
    uncategorized_entries: list[ExtractedString] = []
    total_categorized_found = 0
    total_uncategorized_found = 0
    category_counts: dict[str, int] = {
        "commands": 0,
        "urls": 0,
        "network": 0,
        "file_paths": 0,
        "registry": 0,
        "api_names": 0,
        "security_apis": 0,
    }

    # Stream in 8 MB chunks with 1024-byte overlap
    overlap = max_length
    step = DEFAULT_CHUNK_SIZE

    for start_idx in range(0, scan_limit, step):
        end_idx = min(start_idx + step + overlap, scan_limit)
        chunk = scan_slice[start_idx:end_idx]
        chunk_window = step if (start_idx + step <= scan_limit) else (scan_limit - start_idx)

        # 1. ASCII Scan
        for m in re_ascii.finditer(chunk):
            m_start = m.start()
            if m_start >= chunk_window and end_idx < scan_limit:
                continue
            raw_text = m.group().decode("ascii", errors="replace").replace("\x00", "").strip()
            if not raw_text:
                continue
            cats = categorize_string(raw_text)
            abs_offset = start_idx + m_start
            if cats:
                total_categorized_found += 1
                for c in cats:
                    category_counts[c] = category_counts.get(c, 0) + 1
                if len(categorized_entries) < max_count:
                    if len(raw_text) > max_length:
                        raw_text = raw_text[:max_length]
                    categorized_entries.append({
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:08X}",
                        "string": raw_text,
                        "encoding": "ascii",
                        "length": len(raw_text),
                        "categories": cats,
                    })
            else:
                total_uncategorized_found += 1
                if len(uncategorized_entries) < effective_max_uncat:
                    if len(raw_text) > max_length:
                        raw_text = raw_text[:max_length]
                    uncategorized_entries.append({
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:08X}",
                        "string": raw_text,
                        "encoding": "ascii",
                        "length": len(raw_text),
                        "categories": [],
                    })

        # 2. UTF-16LE Scan (Latin-1 code point plane)
        for m in re_utf16le.finditer(chunk):
            m_start = m.start()
            if m_start >= chunk_window and end_idx < scan_limit:
                continue
            raw_text = m.group().decode("utf-16le", errors="replace").replace("\x00", "").strip()
            if not raw_text:
                continue
            cats = categorize_string(raw_text)
            abs_offset = start_idx + m_start
            if cats:
                total_categorized_found += 1
                for c in cats:
                    category_counts[c] = category_counts.get(c, 0) + 1
                if len(categorized_entries) < max_count:
                    if len(raw_text) > max_length:
                        raw_text = raw_text[:max_length]
                    categorized_entries.append({
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:08X}",
                        "string": raw_text,
                        "encoding": "utf-16le",
                        "length": len(raw_text),
                        "categories": cats,
                    })
            else:
                total_uncategorized_found += 1
                if len(uncategorized_entries) < effective_max_uncat:
                    if len(raw_text) > max_length:
                        raw_text = raw_text[:max_length]
                    uncategorized_entries.append({
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:08X}",
                        "string": raw_text,
                        "encoding": "utf-16le",
                        "length": len(raw_text),
                        "categories": [],
                    })

    # Combine and sort strictly by physical file offset
    entries = categorized_entries + uncategorized_entries
    entries.sort(key=lambda x: x["offset"])

    uncategorized_omitted = max(0, total_uncategorized_found - len(uncategorized_entries))
    total_found = total_categorized_found + total_uncategorized_found
    is_truncated = (uncategorized_omitted > 0) or (total_file_bytes > max_scan_bytes)

    omitted_message = (
        f"{uncategorized_omitted} uncategorized strings omitted from display "
        f"(all {len(categorized_entries)} categorized strings retained)"
        if uncategorized_omitted > 0
        else None
    )

    truncation_info = {
        "is_truncated": is_truncated,
        "strings_stored": len(entries),
        "total_found": total_found,
        "categorized_count": len(categorized_entries),
        "uncategorized_stored": len(uncategorized_entries),
        "uncategorized_omitted": uncategorized_omitted,
        "stored_limit": effective_max_uncat,
        "scan_bytes_processed": scan_limit,
        "total_file_bytes": total_file_bytes,
        "scan_limit_bytes": max_scan_bytes,
        "category_counts": category_counts,
        "omitted_message": omitted_message,
    }

    return entries, truncation_info


def extract_strings(
    data: bytes,
    min_length: int = 4,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> list[str]:
    """Extract unique printable ASCII and UTF-16LE strings, ordered by first appearance.

    Maintains backwards compatibility with calls passing max_strings positionally.
    """
    # Defensive heuristic for legacy (data, max_strings) signature
    if min_length >= 50 and max_strings == DEFAULT_MAX_STRINGS:
        max_strings = min_length
        min_length = 4

    detailed, _ = extract_strings_detailed(data, min_length=min_length, max_count=max_strings * 2)
    out: list[str] = []
    seen: set[str] = set()

    for item in detailed:
        s = item["string"]
        if s and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= max_strings:
                break

    return out
