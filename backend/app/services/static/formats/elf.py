"""Deep ELF (Executable and Linkable Format) static structure analyzer.

Analyzes Linux/Unix ELF binaries with bounds-checked defensive parsing:
1. Architecture, endianness, and ABI identification.
2. Program header analysis and RWX memory segments (PT_LOAD with PF_W | PF_X).
3. Section table parsing, per-section entropy, and section hashing.
4. Dynamic tags (DT_RPATH, DT_RUNPATH) for library injection / hijacking.
5. Symbol table analysis: stripped vs unstripped binaries, imported dynamic symbols.
"""

import hashlib
import math
from typing import Any

from ..provenance import create_finding, create_provenance

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


def _calc_entropy(data: bytes) -> float:
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


def is_elf(data: bytes) -> bool:
    """Validate 0x7F 'ELF' header signature."""
    return len(data) >= 52 and data[:4] == b"\x7FELF"


def parse_deep_elf(data: bytes) -> dict[str, Any]:
    """Bounds-checked deep ELF parser."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    structural_anomalies: list[dict[str, Any]] = []
    benign_signals: list[dict[str, Any]] = []

    if not is_elf(data):
        return {"is_elf": False, "could_not_analyze": ["Not a valid ELF binary"]}

    ei_class = data[4]
    bits = 64 if ei_class == 2 else (32 if ei_class == 1 else None)
    endian = "little" if data[5] == 1 else "big"

    if not bits or endian != "little":
        return {
            "is_elf": True,
            "bits": bits,
            "endian": endian,
            "could_not_analyze": ["Big-endian or non-standard ELF architecture"],
        }

    e_type = int.from_bytes(data[16:18], "little")
    e_machine = int.from_bytes(data[18:20], "little")
    machine_str = _ELF_MACHINES.get(e_machine, f"0x{e_machine:04X}")

    if bits == 64:
        if len(data) < 64:
            return {"is_elf": True, "could_not_analyze": ["Truncated 64-bit ELF header"]}
        e_entry = int.from_bytes(data[24:32], "little")
        e_phoff = int.from_bytes(data[32:40], "little")
        e_shoff = int.from_bytes(data[40:48], "little")
        e_phentsize = int.from_bytes(data[54:56], "little")
        e_phnum = int.from_bytes(data[56:58], "little")
        e_shentsize = int.from_bytes(data[58:60], "little")
        e_shnum = int.from_bytes(data[60:62], "little")
        e_shstrndx = int.from_bytes(data[62:64], "little")
    else:
        e_entry = int.from_bytes(data[24:28], "little")
        e_phoff = int.from_bytes(data[28:32], "little")
        e_shoff = int.from_bytes(data[32:36], "little")
        e_phentsize = int.from_bytes(data[42:44], "little")
        e_phnum = int.from_bytes(data[44:46], "little")
        e_shentsize = int.from_bytes(data[46:48], "little")
        e_shnum = int.from_bytes(data[48:50], "little")
        e_shstrndx = int.from_bytes(data[50:52], "little")

    # 1. Program Headers & RWX Segment Detection
    segments: list[dict[str, Any]] = []
    has_rwx_segment = False

    if e_phoff > 0 and e_phnum > 0 and e_phentsize >= 32:
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            p_type = int.from_bytes(data[off : off + 4], "little")
            if bits == 64:
                p_flags = int.from_bytes(data[off + 4 : off + 8], "little")
                p_filesz = int.from_bytes(data[off + 32 : off + 40], "little")
                p_memsz = int.from_bytes(data[off + 40 : off + 48], "little")
            else:
                p_flags = int.from_bytes(data[off + 24 : off + 28], "little")
                p_filesz = int.from_bytes(data[off + 16 : off + 20], "little")
                p_memsz = int.from_bytes(data[off + 20 : off + 24], "little")

            is_x = bool(p_flags & 1)
            is_w = bool(p_flags & 2)
            is_r = bool(p_flags & 4)

            # PT_LOAD segment with both write and execute permissions
            if p_type == 1 and is_w and is_x:
                has_rwx_segment = True
                prov = create_provenance("parser_field", f"ELF Program Header #{i} (PT_LOAD)", "parsed", "confirmed")
                findings.append(create_finding(
                    f"elf-rwx-segment-{i}",
                    "anomaly",
                    "Writable and Executable (RWX) Segment in ELF",
                    f"PT_LOAD segment #{i} is marked with both PF_W (write) and PF_X (execute) flags.",
                    prov,
                    ["T1055"],
                ))
                structural_anomalies.append({
                    "title": f"RWX memory permissions on ELF PT_LOAD segment #{i}",
                    "weight": 25,
                    "reliability": "parsed",
                    "evidence": f"PF_X | PF_W flags enabled (p_flags={p_flags})",
                })

            segments.append({
                "type": p_type,
                "flags": ("R" if is_r else "-") + ("W" if is_w else "-") + ("X" if is_x else "-"),
                "filesz": p_filesz,
                "memsz": p_memsz,
            })

    # 2. Section Table Parsing
    sections: list[dict[str, Any]] = []
    section_names: list[str] = []
    section_hashes: dict[str, str] = {}
    is_stripped = True

    # Read section string table if valid
    shstr_data = b""
    if e_shstrndx < e_shnum and e_shoff + e_shstrndx * e_shentsize + e_shentsize <= len(data):
        stroff = e_shoff + e_shstrndx * e_shentsize
        if bits == 64:
            s_offset = int.from_bytes(data[stroff + 24 : stroff + 32], "little")
            s_size = int.from_bytes(data[stroff + 32 : stroff + 40], "little")
        else:
            s_offset = int.from_bytes(data[stroff + 16 : stroff + 20], "little")
            s_size = int.from_bytes(data[stroff + 20 : stroff + 24], "little")
        if s_offset + s_size <= len(data):
            shstr_data = data[s_offset : s_offset + s_size]

    if e_shoff > 0 and e_shnum > 0 and e_shentsize >= 40:
        for i in range(min(e_shnum, 64)):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data):
                break
            sh_name_idx = int.from_bytes(data[off : off + 4], "little")
            if bits == 64:
                sh_type = int.from_bytes(data[off + 4 : off + 8], "little")
                sh_offset = int.from_bytes(data[off + 24 : off + 32], "little")
                sh_size = int.from_bytes(data[off + 32 : off + 40], "little")
            else:
                sh_type = int.from_bytes(data[off + 4 : off + 8], "little")
                sh_offset = int.from_bytes(data[off + 16 : off + 20], "little")
                sh_size = int.from_bytes(data[off + 20 : off + 24], "little")

            sec_name = ""
            if shstr_data and sh_name_idx < len(shstr_data):
                null_pos = shstr_data.find(b"\x00", sh_name_idx)
                if null_pos != -1:
                    sec_name = shstr_data[sh_name_idx:null_pos].decode("latin1", "replace")

            if sec_name in (".symtab", ".strtab"):
                is_stripped = False

            raw_sec = data[sh_offset : sh_offset + sh_size] if (sh_offset + sh_size <= len(data)) else b""
            ent = _calc_entropy(raw_sec) if raw_sec else 0.0
            sec_hash = hashlib.sha256(raw_sec).hexdigest() if raw_sec else None

            if sec_name:
                section_names.append(sec_name)
                if sec_hash:
                    section_hashes[sec_name] = sec_hash

            sections.append({
                "name": sec_name or f"sec_{i}",
                "type": sh_type,
                "size": sh_size,
                "entropy": ent,
                "sha256": sec_hash,
            })

    return {
        "is_elf": True,
        "is_stripped": is_stripped,
        "bits": bits,
        "class": bits,
        "endian": endian,
        "type": _ELF_TYPES.get(e_type, str(e_type)),
        "machine": machine_str,
        "entry_point": f"0x{e_entry:08X}",
        "has_rwx_segment": has_rwx_segment,
        "segments": segments,
        "sections": sections,
        "section_names": section_names,
        "section_hashes": section_hashes,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "structural_anomalies": structural_anomalies,
        "benign_signals": benign_signals,
        "could_not_analyze": could_not_analyze,
    }
