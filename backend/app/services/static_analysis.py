"""Dependency-free static analysis for uploaded samples.

Runs at triage time (on demand) over the stored bytes — no external tools, no
`pefile`/`elftools` dependencies (the backend is deliberately dependency-light;
see AGENTS.md). Produces three artifacts:

- strings      — printable ASCII + UTF-16LE runs (capped, deduped)
- iocs         — URLs, IPv4s, domains, hashes (MD5/SHA-1/SHA-256), emails
- pe / elf     — parsed executable metadata (machine, sections, imports / class)

Every parser is bounds-checked against truncated / adversarial inputs: a bad or
partial header yields `None` for that format, never an exception.
"""

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

_MAX_STRINGS = 300
_MIN_STRING_LEN = 5
_MAX_STRING_LEN = 256


def _ascii_strings(data: bytes) -> list[str]:
    """Runs of printable ASCII (0x20–0x7e), min length 5, truncated to 256."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(b)
        else:
            if len(cur) >= _MIN_STRING_LEN:
                out.append(bytes(cur[:_MAX_STRING_LEN]).decode("ascii", errors="replace"))
            cur.clear()
    if len(cur) >= _MIN_STRING_LEN:
        out.append(bytes(cur[:_MAX_STRING_LEN]).decode("ascii", errors="replace"))
    return out


def _utf16_strings(data: bytes) -> list[str]:
    """UTF-16LE runs (printable char + NUL byte pairs), min length 5 chars."""
    out: list[str] = []
    cur = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and 0x20 <= lo <= 0x7E:
            cur.append(lo)
            i += 2
        else:
            if len(cur) >= _MIN_STRING_LEN:
                out.append(bytes(cur[:_MAX_STRING_LEN]).decode("ascii", errors="replace"))
            cur.clear()
            i += 1
    if len(cur) >= _MIN_STRING_LEN:
        out.append(bytes(cur[:_MAX_STRING_LEN]).decode("ascii", errors="replace"))
    return out


def extract_strings(data: bytes) -> list[str]:
    """All printable strings — ASCII + UTF-16LE, deduped, capped at 300."""
    seen: set[str] = set()
    out: list[str] = []
    for s in _ascii_strings(data) + _utf16_strings(data):
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= _MAX_STRINGS:
            break
    return out


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

_RE_URL = re.compile(rb"https?://[^\s\"'<>\\]{4,200}", re.IGNORECASE)
_RE_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_RE_HASH = re.compile(rb"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")
_RE_EMAIL = re.compile(rb"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")


def _valid_ipv4(raw: bytes) -> bool:
    try:
        parts = raw.decode("ascii").split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Candidate IOCs inside the blob — deduped, order-preserved, capped.

    Domains are the noisiest bucket on purpose: this is a *triage* surface, so
    an analyst wants every plausible candidate, then one-click search to see
    whether it ever fired. Plain hex that looks like a hash is capped so a
    random 32-hex word doesn't flood the list.
    """
    urls, ips, domains, hashes, emails = [], [], [], [], []
    seen_u, seen_i, seen_d, seen_h, seen_e = set(), set(), set(), set(), set()

    for m in _RE_URL.finditer(data):
        v = m.group(0)[:200].decode("utf-8", errors="replace")
        if v not in seen_u:
            seen_u.add(v)
            urls.append(v)
    for m in _RE_IPV4.finditer(data):
        v = m.group(0).decode("ascii")
        if _valid_ipv4(m.group(0)) and v not in seen_i:
            seen_i.add(v)
            ips.append(v)
    for m in _RE_DOMAIN.finditer(data):
        v = m.group(0).decode("ascii").lower()
        if v not in seen_d:
            seen_d.add(v)
            domains.append(v)
    for m in _RE_HASH.finditer(data):
        v = m.group(0).decode("ascii").lower()
        if v not in seen_h:
            seen_h.add(v)
            hashes.append(v)
    for m in _RE_EMAIL.finditer(data):
        v = m.group(0).decode("utf-8", errors="replace")
        if v not in seen_e:
            seen_e.add(v)
            emails.append(v)

    return {
        "urls": urls[:200],
        "ips": ips[:200],
        "domains": domains[:200],
        "hashes": hashes[:50],
        "emails": emails[:50],
    }


# ---------------------------------------------------------------------------
# PE parser (MZ)
# ---------------------------------------------------------------------------

_PE_MACHINES = {
    0x014C: "x86",
    0xAA64: "ARM64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0x8664: "x86-64",
    0x0200: "IA64",
    0x5032: "RISC-V 32",
    0x5064: "RISC-V 64",
}

_SECTION_CHARS = {
    0x20000000: "executable",
    0x40000000: "readable",
    0x80000000: "writable",
}


def _rva_to_offset(sections: list[dict], rva: int) -> int | None:
    """Map an RVA to a file offset using the section table (virtual addr +
    raw pointer window). Returns None when the RVA falls outside any section."""
    for s in sections:
        va, vsize = s["virtual_address"], s["virtual_size"]
        raw_ptr, raw_size = s["raw_ptr"], s["raw_size"]
        window = max(vsize, raw_size)
        if va <= rva < va + window:
            delta = rva - va
            if delta < raw_size:
                return raw_ptr + delta
    return None


def _parse_rich_header(data: bytes, pe_offset: int) -> dict | None:
    """Extract Microsoft Rich Header toolchain fingerprint."""
    if pe_offset < 0x80 or len(data) < pe_offset:
        return None
    stub = data[0x40:pe_offset]
    rich_idx = stub.find(b"Rich")
    if rich_idx == -1 or rich_idx + 8 > len(stub):
        return None
    xor_key_bytes = stub[rich_idx + 4 : rich_idx + 8]
    xor_key = int.from_bytes(xor_key_bytes, "little")
    if xor_key == 0:
        return None

    decrypted = bytearray()
    for i in range(0, rich_idx, 4):
        chunk = stub[i : i + 4]
        if len(chunk) == 4:
            dw = int.from_bytes(chunk, "little") ^ xor_key
            decrypted.extend(dw.to_bytes(4, "little"))

    dans_pos = decrypted.find(b"DanS")
    if dans_pos == -1:
        dans_pos = decrypted.find(b"danS")

    if dans_pos != -1:
        rich_data = decrypted[dans_pos:]
        rich_hash = hashlib.md5(rich_data).hexdigest()
        records_count = (len(rich_data) - 16) // 8 if len(rich_data) >= 16 else 0
        return {
            "present": True,
            "hash": rich_hash,
            "xor_key": f"0x{xor_key:08X}",
            "records_count": max(0, records_count),
        }
    return None


def parse_pe(data: bytes) -> dict | None:
    """Parse a PE (MZ…) into machine / sections / imports metadata.

    Returns None for anything that isn't a well-formed PE — truncated MZ
    stubs, partial uploads, and renamed binaries all fall through safely.
    """
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return None
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return None
    coff = pe_off + 4
    machine = int.from_bytes(data[coff : coff + 2], "little")
    num_sections = int.from_bytes(data[coff + 2 : coff + 4], "little")
    opt_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
    opt_off = coff + 20
    if opt_off + 2 > len(data):
        return None
    opt_magic = int.from_bytes(data[opt_off : opt_off + 2], "little")
    bits = 64 if opt_magic == 0x20B else 32 if opt_magic == 0x10B else None
    entry_rva = None
    if bits and opt_off + 24 <= len(data):
        entry_rva = int.from_bytes(data[opt_off + 16 : opt_off + 20], "little")

    mitigations: list[str] = []
    if bits and opt_off + 72 <= len(data):
        dll_chars = int.from_bytes(data[opt_off + 70 : opt_off + 72], "little")
        if dll_chars & 0x0040:
            mitigations.append("ASLR (Dynamic Base)")
        if dll_chars & 0x0020:
            mitigations.append("High Entropy 64-bit ASLR")
        if dll_chars & 0x0100:
            mitigations.append("DEP / NX Compat")
        if dll_chars & 0x4000:
            mitigations.append("Control Flow Guard (CFG)")
        if dll_chars & 0x0400:
            mitigations.append("No SEH")

    authenticode = {"signed": False, "cert_size": 0}
    if bits:
        cert_dd_off = opt_off + (144 if bits == 64 else 128)
        if cert_dd_off + 8 <= len(data):
            cert_rva = int.from_bytes(data[cert_dd_off : cert_dd_off + 4], "little")
            cert_size = int.from_bytes(data[cert_dd_off + 4 : cert_dd_off + 8], "little")
            if cert_size > 0 and cert_rva > 0:
                authenticode = {
                    "signed": True,
                    "cert_size": cert_size,
                    "cert_offset": cert_rva,
                }

    rich_header = _parse_rich_header(data, pe_off)

    sections: list[dict] = []
    sect_off = opt_off + opt_size
    for i in range(min(num_sections, 96)):
        off = sect_off + i * 40
        if off + 40 > len(data):
            break
        raw_name = data[off : off + 8]
        name = raw_name.rstrip(b"\x00").decode("latin1", errors="replace")
        virtual_size = int.from_bytes(data[off + 8 : off + 12], "little")
        virtual_address = int.from_bytes(data[off + 12 : off + 16], "little")
        raw_size = int.from_bytes(data[off + 16 : off + 20], "little")
        raw_ptr = int.from_bytes(data[off + 20 : off + 24], "little")
        chars = int.from_bytes(data[off + 36 : off + 40], "little")
        flags = [label for mask, label in _SECTION_CHARS.items() if chars & mask]
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "flags": flags,
                "virtual_address": virtual_address,
                "raw_ptr": raw_ptr,
            }
        )

    # Import directory (data directory index 1): 20-byte descriptors, each
    # holding a Name RVA at offset 12; an all-zero descriptor terminates.
    # Data directories start at 96 (PE32) / 112 (PE32+); index 1 → +8.
    imports: list[str] = []
    if bits:
        dd_base = opt_off + (120 if bits == 64 else 104)
        if dd_base + 8 <= len(data):
            import_rva = int.from_bytes(data[dd_base : dd_base + 4], "little")
            if import_rva:
                cursor = _rva_to_offset(sections, import_rva)
                for _ in range(256):
                    if cursor is None or cursor + 20 > len(data):
                        break
                    name_rva = int.from_bytes(data[cursor + 12 : cursor + 16], "little")
                    if name_rva == 0:
                        break
                    noff = _rva_to_offset(sections, name_rva)
                    if noff is not None and noff < len(data):
                        end = data.find(b"\x00", noff)
                        if end == -1:
                            end = len(data)
                        dll = data[noff:end].decode("latin1", errors="replace")
                        if dll and dll not in imports:
                            imports.append(dll)
                    cursor += 20

    return {
        "machine": _PE_MACHINES.get(machine, f"0x{machine:04X}"),
        "bits": bits,
        "entry_point_rva": entry_rva,
        "sections": sections,
        "imports": imports,
        "imphash": compute_imphash(imports),
        "mitigations": mitigations,
        "authenticode": authenticode,
        "rich_header": rich_header,
    }



# ---------------------------------------------------------------------------
# ELF parser
# ---------------------------------------------------------------------------

_ELF_MACHINES = {
    0x03: "x86",
    0x3E: "x86-64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0xF3: "RISC-V",
}

_ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def parse_elf(data: bytes) -> dict | None:
    """Parse an ELF header + section table into metadata.

    Reads the fixed 64-byte header (class/endian/machine/type/entry), then the
    section header table with names resolved through .shstrtab. Bounds-checked
    against truncated inputs.
    """
    if not data.startswith(b"\x7fELF") or len(data) < 64:
        return None
    ei_class = data[4]  # 1=32-bit, 2=64-bit
    ei_data = data[5]  # 1=little, 2=big
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = "little" if ei_data == 1 else "big"

    try:
        e_type, e_machine = data[16], data[18]
        if ei_class == 1:
            e_entry = int.from_bytes(data[24:28], endian)
            sh_off = int.from_bytes(data[32:36], endian)
            sh_entsize = int.from_bytes(data[46:48], endian)
            sh_num = int.from_bytes(data[48:50], endian)
            sh_strndx = int.from_bytes(data[50:52], endian)
            shdr = 40
        else:
            e_entry = int.from_bytes(data[24:32], endian)
            sh_off = int.from_bytes(data[40:48], endian)
            sh_entsize = int.from_bytes(data[58:60], endian)
            sh_num = int.from_bytes(data[60:62], endian)
            sh_strndx = int.from_bytes(data[62:64], endian)
            shdr = 64
    except (ValueError, IndexError):
        return None

    if sh_entsize < shdr or sh_off <= 0 or sh_num <= 0:
        return None

    def _read_sh(i: int) -> dict | None:
        off = sh_off + i * sh_entsize
        if off + shdr > len(data):
            return None
        if ei_class == 1:
            name_off = int.from_bytes(data[off : off + 4], endian)
            sh_type = int.from_bytes(data[off + 4 : off + 8], endian)
            size = int.from_bytes(data[off + 20 : off + 24], endian)
        else:
            name_off = int.from_bytes(data[off : off + 4], endian)
            sh_type = int.from_bytes(data[off + 4 : off + 8], endian)
            size = int.from_bytes(data[off + 32 : off + 40], endian)
        return {"name_off": name_off, "sh_type": sh_type, "size": size}

    headers = [_read_sh(i) for i in range(min(sh_num, 256))]
    headers = [h for h in headers if h is not None]

    # .shstrtab holds the names — resolve it, then name every section.
    strtab = b""
    if 0 <= sh_strndx < len(headers) and sh_strndx < sh_num:
        st = headers[sh_strndx]
        # sh_offset lives at 16 (32-bit) / 24 (64-bit) within the header.
        off = sh_off + sh_strndx * sh_entsize
        if ei_class == 1:
            str_off = int.from_bytes(data[off + 16 : off + 20], endian)
        else:
            str_off = int.from_bytes(data[off + 24 : off + 32], endian)
        strtab = data[str_off : str_off + st["size"]]

    sections = []
    for i, h in enumerate(headers):
        name = ""
        if h["name_off"] < len(strtab):
            end = strtab.find(b"\x00", h["name_off"])
            if end != -1:
                name = strtab[h["name_off"] : end].decode("utf-8", errors="replace")
        sections.append({"name": name, "type": h["sh_type"], "size": h["size"]})

    return {
        "class": 64 if ei_class == 2 else 32,
        "endian": "big" if ei_data == 2 else "little",
        "type": _ELF_TYPES.get(e_type, f"0x{e_type:02X}"),
        "machine": _ELF_MACHINES.get(e_machine, f"0x{e_machine:02X}"),
        "entry_point": e_entry,
        "sections": sections,
    }


# ---------------------------------------------------------------------------
# Entropy & Capability Detection
# ---------------------------------------------------------------------------

from collections import Counter
from typing import Any


def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 3)


def calculate_entropy_histogram(data: bytes, bins: int = 32) -> list[float]:
    """Calculate sliding-window entropy across sequential chunks for visualization."""
    if not data:
        return [0.0] * bins
    total_len = len(data)
    chunk_size = max(1, total_len // bins)
    hist: list[float] = []
    for i in range(bins):
        start = i * chunk_size
        end = min(total_len, (i + 1) * chunk_size) if i < bins - 1 else total_len
        chunk = data[start:end]
        hist.append(calculate_entropy(chunk))
    return hist


_SUSPICIOUS_CAPABILITY_PATTERNS = [
    ("Process Injection", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "NtMapViewOfSection", "ptrace", "process_vm_writev", "dlopen", "dlsym"]),
    ("Fileless / In-Memory Execution", ["memfd_create", "/dev/shm", "execveat", "VirtualProtect", "mmap", "mprotect", "ReflectiveLoader", "shellcode"]),
    ("Defense Evasion & Anti-Debug", ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ptrace(PTRACE_TRACEME)", "UnhookWindowsHookEx", "GetTickCount", "rdtsc"]),
    ("Persistence & Autostart", ["RegSetValueEx", "RegCreateKeyEx", "SetWindowsHookEx", "SchTasks", "LaunchAgent", "/etc/cron", "systemd", ".bashrc", "RunOnce"]),
    ("Credential Access", ["lsass", "mimikatz", "SAM", "SECURITY", "CryptUnprotectData", "shadow", "/etc/passwd", "MiniDumpWriteDump", "OpenProcessToken"]),
    ("Reconnaissance & Enumeration", ["GetComputerName", "GetUserName", "NetUserEnum", "gethostbyname", "EnumProcesses", "GetAdaptersInfo", "whoami", "ipconfig", "ifconfig"]),
    ("Network Communications & C2", ["InternetOpen", "URLDownloadToFile", "socket", "connect", "WSAStartup", "curl_easy_init", "HttpSendRequest", "beacon", "reverse_tcp", "185.220."]),
    ("Cryptographic & Ransomware", ["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "AES_encrypt", "EVP_EncryptInit", "ransom", ".locked", "decrypt_instructions", "wallet"]),
]


def detect_capabilities(data: bytes, extracted_strings: list[str]) -> list[dict[str, Any]]:
    """Identify binary/script capabilities based on observed function symbols and strings."""
    found: list[dict[str, Any]] = []
    combined_text = " ".join(extracted_strings)

    for category, symbols in _SUSPICIOUS_CAPABILITY_PATTERNS:
        matched_symbols = [s for s in symbols if s in combined_text or s.encode("latin1") in data]
        if matched_symbols:
            found.append({
                "category": category,
                "matched": matched_symbols,
                "confidence": "high" if len(matched_symbols) >= 2 else "medium",
                "source": "heuristic",
            })
    return found


def categorize_strings(extracted_strings: list[str]) -> dict[str, list[str]]:
    """Categorize printable strings into analyst-friendly intelligence buckets."""
    buckets: dict[str, list[str]] = {
        "network": [],
        "file_paths": [],
        "commands": [],
        "registry": [],
        "security_apis": [],
    }

    for s in extracted_strings:
        lower = s.lower()
        if re.search(r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b|\.com\b|\.net\b|\.org\b|\.ru\b|\.xyz\b", lower):
            buckets["network"].append(s)
        elif re.search(r"^/etc/|^/tmp/|^/var/|^/usr/|C:\\|%[A-Z_]+%|\.(?:exe|dll|sh|py|bat|ps1)\b", s):
            buckets["file_paths"].append(s)
        elif any(kw in lower for kw in ["powershell", "cmd.exe", "whoami", "curl", "wget", "chmod", "iptables", "netstat", "bash -c"]):
            buckets["commands"].append(s)
        elif any(kw in s for kw in ["HKLM\\", "HKCU\\", "Software\\Microsoft\\Windows\\CurrentVersion"]):
            buckets["registry"].append(s)
        elif any(kw in s for kw in ["VirtualAlloc", "CreateThread", "WriteProcessMemory", "ptrace", "memfd_create", "CryptEncrypt", "socket", "connect"]):
            buckets["security_apis"].append(s)

    return buckets


# ---------------------------------------------------------------------------
# Imphash & Fuzzy Hashing (Binary Similarity)
# ---------------------------------------------------------------------------


def compute_imphash(imports: list[str]) -> str | None:
    """Compute standard PE Import Hash (imphash) from resolved imports.

    Normalizes import names to lowercase, strips common extensions (.dll, .ocx, .sys),
    joins with commas, and returns MD5 hex digest.
    """
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
    """Compute Context-Triggered Piecewise Hash (CTPH / fuzzy hash) without external libraries.

    Format: <blocksize>:<digest1>:<digest2>
    Enables zero-ML similarity clustering across malware families.
    """
    if not data:
        return "3::"

    n = len(data)
    bs = 3
    while bs * 64 < n and bs < 3072:
        bs *= 2

    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    def _hash_blocks(block_size: int) -> str:
        digest = []
        h1 = 0
        h2 = 0
        window = [0] * 7
        win_idx = 0

        for byte in data:
            old_b = window[win_idx]
            window[win_idx] = byte
            win_idx = (win_idx + 1) % 7

            h1 = (h1 + byte - old_b) % 65521
            h2 = (h2 + 7 * byte - sum(window)) % 65521
            roll = (h1 + (h2 << 16)) & 0xFFFFFFFF

            if (roll % block_size) == (block_size - 1):
                c = b64[(roll ^ byte) % len(b64)]
                if len(digest) < 64:
                    digest.append(c)
        return "".join(digest) or "A"

    d1 = _hash_blocks(bs)
    d2 = _hash_blocks(bs * 2)
    return f"{bs}:{d1}:{d2}"


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
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
    """Compare two fuzzy hashes and return a similarity percentage from 0 to 100."""
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
# CAPA (Mandiant) — optional subprocess-backed capability extraction
# ---------------------------------------------------------------------------

_CAPA_TIMEOUT = float(os.getenv("OUTPOST_CAPA_TIMEOUT", "120"))


def parse_capa_rules(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Extract capability entries from a CAPA --json report."""
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
        return {
            "category": str(name),
            "matched": refs,
            "confidence": "high",
            "source": "capa",
            "namespace": str(meta.get("namespace") or ""),
            "attack": attack,
            "mbc": mbc,
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
    """Run Mandiant CAPA against the sample bytes via its CLI."""
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
    except FileNotFoundError:
        return {"available": False, "error": "capa not installed", "capabilities": []}
    except subprocess.TimeoutExpired:
        return {"available": True, "error": f"capa timed out after {_CAPA_TIMEOUT}s", "capabilities": []}
    finally:
        if tmp_path:
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
# Entry point
# ---------------------------------------------------------------------------


def compute_static_risk_profile(
    entropy: float,
    capabilities: list[dict[str, Any]],
    is_packed: bool,
    pe_info: dict[str, Any] | None,
    elf_info: dict[str, Any] | None,
) -> dict[str, Any]:
    """Calculate an objective static threat score (0-100) and severity profile."""
    score = 0
    factors: list[str] = []

    # Packing / High entropy
    if entropy > 7.2:
        score += 35
        factors.append(f"Extremely high Shannon entropy ({entropy}/8.0) indicative of packed payload or encryption")
    elif entropy > 6.8:
        score += 20
        factors.append(f"Elevated Shannon entropy ({entropy}/8.0)")

    if is_packed:
        score += 15
        factors.append("Packed binary structure detected")

    # Capabilities
    cap_categories = {c.get("category", "") for c in capabilities}
    if "Process Injection" in cap_categories:
        score += 30
        factors.append("Process injection and remote thread allocation primitives detected")
    if "Fileless / In-Memory Execution" in cap_categories:
        score += 25
        factors.append("Fileless in-memory execution / memfd handles identified")
    if "Defense Evasion & Anti-Debug" in cap_categories:
        score += 20
        factors.append("Anti-debugging and sandbox evasion API checks present")
    if "Persistence & Autostart" in cap_categories:
        score += 20
        factors.append("Autorun, registry run-keys, or cron persistence hooks")
    if "Credential Access" in cap_categories:
        score += 30
        factors.append("Credential dumping and memory harvesting functions found")
    if "Cryptographic & Ransomware" in cap_categories:
        score += 25
        factors.append("High-volume encryption routines and ransomware IOCs identified")
    if "Network Communications & C2" in cap_categories:
        score += 15
        factors.append("Direct low-level network socket and C2 beaconing signatures")

    # Executable header checks
    if pe_info and pe_info.get("sections"):
        for sec in pe_info["sections"]:
            if sec.get("entropy", 0) > 7.5:
                score += 15
                factors.append(f"Section {sec.get('name')} exhibits anomalous entropy ({sec.get('entropy')})")
                break

    final_score = min(100, max(0, score))
    severity = "clean"
    if final_score >= 70:
        severity = "malicious"
    elif final_score >= 35:
        severity = "suspicious"

    return {
        "static_risk_score": final_score,
        "static_severity": severity,
        "risk_factors": factors,
    }


def analyze_sample(data: bytes) -> dict:
    """Full static analysis of a blob: strings, IOCs, PE/ELF metadata, entropy,
    capabilities (heuristic + optional CAPA), imphash, fuzzy_hash, and risk profile."""
    strings = extract_strings(data)
    entropy = calculate_entropy(data)
    entropy_hist = calculate_entropy_histogram(data, bins=32)
    categorized = categorize_strings(strings)
    capabilities = detect_capabilities(data, strings)

    capa_report = run_capa(data)
    capabilities = capabilities + (capa_report.get("capabilities") or [])

    pe_info = parse_pe(data)
    elf_info = parse_elf(data)
    imphash = pe_info.get("imphash") if pe_info else None
    fuzzy = compute_fuzzy_hash(data)

    is_packed = entropy > 7.1
    risk_profile = compute_static_risk_profile(entropy, capabilities, is_packed, pe_info, elf_info)

    return {
        "strings": strings,
        "categorized_strings": categorized,
        "iocs": extract_iocs(data),
        "pe": pe_info,
        "elf": elf_info,
        "entropy": entropy,
        "entropy_histogram": entropy_hist,
        "is_packed": is_packed,
        "capabilities": capabilities,
        "capa": capa_report,
        "imphash": imphash,
        "fuzzy_hash": fuzzy,
        **risk_profile,
    }



