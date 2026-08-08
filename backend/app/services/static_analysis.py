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

import re
from typing import Optional

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


def _rva_to_offset(sections: list[dict], rva: int) -> Optional[int]:
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


def parse_pe(data: bytes) -> Optional[dict]:
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


def parse_elf(data: bytes) -> Optional[dict]:
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

    def _read_sh(i: int) -> Optional[dict]:
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
# Entry point
# ---------------------------------------------------------------------------


def analyze_sample(data: bytes) -> dict:
    """Full static analysis of a blob: strings, IOCs, PE/ELF metadata."""
    return {
        "strings": extract_strings(data),
        "iocs": extract_iocs(data),
        "pe": parse_pe(data),
        "elf": parse_elf(data),
    }
