"""Deep ELF (Executable and Linkable Format) static structure analyzer via pyelftools.

Analyzes Linux/Unix ELF binaries with pyelftools:
1. Architecture, endianness, ELF class (32/64-bit), OS/ABI, and binary type (EXEC/DYN/REL).
2. Program header analysis and RWX memory segments (PT_LOAD with PF_W | PF_X).
3. Section table parsing, per-section entropy, and section SHA-256 hashing.
4. Stripped vs unstripped status detection (.symtab analysis).
5. Dynamic tags (DT_NEEDED shared libraries, DT_RPATH, DT_RUNPATH for library hijacking).
6. Dynamic symbol table (.dynsym) imported APIs extraction for authoritative capability detection.
"""

import hashlib
import io
import math
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

from ..provenance import create_finding, create_provenance

_ELF_MACHINES = {
    "EM_386": "x86",
    "EM_X86_64": "x86-64",
    "EM_ARM": "ARM",
    "EM_AARCH64": "AArch64",
    "EM_MIPS": "MIPS",
    "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64",
    "EM_RISCV": "RISC-V",
}


def _calc_entropy(data: bytes) -> float:
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


def is_elf(data: bytes) -> bool:
    """Validate 0x7F 'ELF' header signature."""
    return len(data) >= 52 and data[:4] == b"\x7FELF"


def parse_deep_elf(data: bytes) -> dict[str, Any]:
    """Parse ELF binary using pyelftools with defensive exception isolation."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    structural_anomalies: list[dict[str, Any]] = []
    benign_signals: list[dict[str, Any]] = []

    if not is_elf(data):
        return {"is_elf": False, "could_not_analyze": ["Not a valid ELF binary"]}

    try:
        elf = ELFFile(io.BytesIO(data))
    except ELFError as exc:
        return {
            "is_elf": True,
            "could_not_analyze": [f"pyelftools: ELFError: {exc}"],
            "findings": findings,
            "indicators": indicators,
            "capabilities": capabilities,
            "structural_anomalies": structural_anomalies,
            "benign_signals": benign_signals,
        }
    except Exception as exc:
        return {
            "is_elf": True,
            "could_not_analyze": [f"pyelftools: {type(exc).__name__}: {exc}"],
            "findings": findings,
            "indicators": indicators,
            "capabilities": capabilities,
            "structural_anomalies": structural_anomalies,
            "benign_signals": benign_signals,
        }

    # 1. Header & Architecture Identification
    bits = elf.elfclass
    class_val = elf.elfclass
    endian = "little" if elf.little_endian else "big"

    # Type normalization (e.g. 'ET_DYN' -> 'DYN')
    raw_type = elf["e_type"]
    type_str = raw_type[3:] if isinstance(raw_type, str) and raw_type.startswith("ET_") else str(raw_type)

    # Machine normalization (e.g. 'EM_X86_64' -> 'x86-64')
    raw_machine = elf["e_machine"]
    machine_str = _ELF_MACHINES.get(raw_machine, raw_machine[3:].lower() if isinstance(raw_machine, str) and raw_machine.startswith("EM_") else str(raw_machine))

    entry_val = elf["e_entry"]
    entry_point = f"0x{entry_val:08X}"

    # 2. Program Headers & RWX Segment Detection
    segments: list[dict[str, Any]] = []
    has_rwx_segment = False

    for i, seg in enumerate(elf.iter_segments()):
        p_type = seg["p_type"]
        p_flags = seg["p_flags"]
        is_x = bool(p_flags & 1)
        is_w = bool(p_flags & 2)
        is_r = bool(p_flags & 4)

        # PT_LOAD segment with both write and execute permissions
        if (p_type == "PT_LOAD" or p_type == 1) and is_w and is_x:
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
            "filesz": seg["p_filesz"],
            "memsz": seg["p_memsz"],
        })

    # 3. Section Table Parsing & Stripped Status
    sections: list[dict[str, Any]] = []
    section_names: list[str] = []
    section_hashes: dict[str, str] = {}
    is_stripped = True

    dynamic_libraries: list[str] = []
    rpath: list[str] = []
    runpath: list[str] = []

    for sec in elf.iter_sections():
        name = sec.name
        section_names.append(name)
        if name in (".symtab", ".strtab"):
            is_stripped = False

        try:
            sec_data = sec.data()
        except Exception:
            sec_data = b""

        ent = _calc_entropy(sec_data)
        sec_hash = hashlib.sha256(sec_data).hexdigest() if sec_data else None

        if name:
            if sec_hash:
                section_hashes[name] = sec_hash

        sections.append({
            "name": name or "unnamed",
            "type": sec["sh_type"],
            "size": sec["sh_size"],
            "entropy": ent,
            "sha256": sec_hash,
        })

        # Dynamic Section tags: DT_NEEDED, DT_RPATH, DT_RUNPATH
        if isinstance(sec, DynamicSection):
            try:
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        dynamic_libraries.append(tag.needed)
                    elif tag.entry.d_tag == "DT_RPATH":
                        rpath.append(tag.rpath)
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        runpath.append(tag.runpath)
            except Exception:
                pass

    # Anomaly: Insecure RPATH or RUNPATH (e.g. /tmp, relative path, or $ORIGIN)
    for p in rpath + runpath:
        if any(bad in p for bad in ("/tmp", "/var/tmp", "..", "./")):
            prov = create_provenance("parser_field", "ELF Dynamic Section (DT_RPATH/DT_RUNPATH)", "parsed", "confirmed")
            findings.append(create_finding(
                "elf-insecure-rpath",
                "anomaly",
                "Insecure RPATH/RUNPATH Library Search Path",
                f"Binary contains writable or relative library search path: {p}",
                prov,
                ["T1574.002"],
            ))
            structural_anomalies.append({
                "title": f"Insecure dynamic linker search path ({p})",
                "weight": 20,
                "reliability": "parsed",
                "evidence": p,
            })

    # 4. Dynamic Symbol Table (.dynsym) Resolution
    imported_symbols: list[str] = []
    try:
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                if sym.name:
                    imported_symbols.append(sym.name)
    except Exception:
        pass

    # 5. Packer / Compression Detection (UPX or high-entropy packing)
    packer_identified = None
    upx_offset = None
    if b"UPX!" in data:
        packer_identified = "UPX Packer"
        upx_offset = data.find(b"UPX!")
    elif _calc_entropy(data) > 7.2 and len(sections) <= 6 and len(imported_symbols) == 0:
        packer_identified = "Compressed/Packed Executable"

    if packer_identified:
        ent = _calc_entropy(data)
        if upx_offset is not None:
            evidence_str = f"UPX! magic at offset 0x{upx_offset:X}, {len(sections)} section headers, file entropy {ent:.2f}"
        else:
            evidence_str = f"{len(sections)} sections, 0 dynamic imports, file entropy {ent:.2f}"

        factor_title = "UPX-packed" if "UPX" in packer_identified else f"{packer_identified}"

        prov = create_provenance("parser_field", "ELF Header / Compression Heuristics", "parsed", "confirmed")
        findings.append(create_finding(
            "elf-packed-binary",
            "structure",
            f"Packed or Compressed Executable ({factor_title})",
            f"Binary structure exhibits packing signatures or high-entropy compression ({factor_title}).",
            prov,
            ["T1027.002"],
        ))
        structural_anomalies.append({
            "title": factor_title,
            "weight": 25,
            "reliability": "parsed",
            "evidence": evidence_str,
        })
        could_not_analyze.append("packed_executable_code")
        could_not_analyze.append("obfuscated_imports")

    return {
        "is_elf": True,
        "is_stripped": is_stripped,
        "bits": bits,
        "class": class_val,
        "endian": endian,
        "type": type_str,
        "machine": machine_str,
        "entry_point": entry_point,
        "has_rwx_segment": has_rwx_segment,
        "packer": packer_identified,
        "is_packed": bool(packer_identified),
        "segments": segments,
        "sections": sections,
        "section_names": section_names,
        "section_hashes": section_hashes,
        "dynamic_libraries": dynamic_libraries,
        "rpath": rpath,
        "runpath": runpath,
        "imported_symbols": imported_symbols,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "structural_anomalies": structural_anomalies,
        "benign_signals": benign_signals,
        "could_not_analyze": could_not_analyze,
    }
