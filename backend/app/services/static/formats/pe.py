"""Deep PE (Portable Executable) static structure analyzer via pefile.

Analyzes Windows binaries with pefile:
1. Architecture, subsystem, image base, and COFF TimeDateStamp plausibility.
2. Per-section virtual/raw sizes, characteristics, RWX permissions, entropy, and SHA-256.
3. Appended overlay detection past the last mapped section.
4. Authenticode digital signature detection (IMAGE_DIRECTORY_ENTRY_SECURITY).
5. TLS Callbacks table (IMAGE_DIRECTORY_ENTRY_TLS) for pre-entrypoint execution.
6. Authoritative Import Table parsing & Canonical Imphash computation.
7. Export Table symbol resolution.
8. Packer identification (UPX, Aspack, Themida, VMProtect, MPRESS, PECompact, and structural heuristics).
"""

import datetime
import hashlib
import math
from typing import Any

import pefile

from ..provenance import create_finding, create_provenance

_PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

_KNOWN_PACKER_SECTIONS = {
    "UPX0": "UPX Packer",
    "UPX1": "UPX Packer",
    ".aspack": "Aspack",
    "MPRESS1": "MPRESS",
    ".themida": "Themida / Oreans",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    "pec1": "PECompact",
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


def is_pe(data: bytes) -> bool:
    """Validate PE MZ and PE\\0\\0 signature headers."""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    pe_off = int.from_bytes(data[60:64], "little")
    return pe_off + 4 <= len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00"


def _resolve_coff_section_name(name_raw: str, data: bytes, pe: pefile.PE) -> str:
    """Resolve COFF long section names (e.g. '/4') via the COFF string table."""
    if name_raw.startswith("/"):
        try:
            str_off_rel = int(name_raw[1:])
            sym_tab_off = pe.FILE_HEADER.PointerToSymbolTable
            num_syms = pe.FILE_HEADER.NumberOfSymbols
            if sym_tab_off > 0:
                str_tab_base = sym_tab_off + num_syms * 18
                target_offset = str_tab_base + str_off_rel
                if target_offset < len(data):
                    null_pos = data.find(b"\x00", target_offset)
                    if null_pos != -1:
                        resolved = data[target_offset:null_pos].decode("latin1", errors="replace")
                        if resolved:
                            return resolved
        except Exception:
            pass
    return name_raw


def parse_deep_pe(data: bytes) -> dict[str, Any]:
    """Parse PE binary using pefile with defensive exception isolation."""
    findings: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    capabilities: list[dict[str, Any]] = []
    could_not_analyze: list[str] = []
    benign_signals: list[dict[str, Any]] = []
    structural_anomalies: list[dict[str, Any]] = []

    if not is_pe(data):
        return {"is_pe": False, "could_not_analyze": ["Not a valid PE binary"]}

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        return {
            "is_pe": True,
            "could_not_analyze": [f"pefile: PEFormatError: {exc}"],
            "findings": findings,
            "indicators": indicators,
            "capabilities": capabilities,
            "structural_anomalies": structural_anomalies,
            "benign_signals": benign_signals,
        }
    except Exception as exc:
        return {
            "is_pe": True,
            "could_not_analyze": [f"pefile: {type(exc).__name__}: {exc}"],
            "findings": findings,
            "indicators": indicators,
            "capabilities": capabilities,
            "structural_anomalies": structural_anomalies,
            "benign_signals": benign_signals,
        }

    # 1. COFF File Header & Architecture
    machine_raw = pe.FILE_HEADER.Machine
    machine_str = _PE_MACHINES.get(machine_raw, f"0x{machine_raw:04X}")

    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    # Bits & Optional Header
    bits = None
    entry_rva = 0
    subsystem = 0
    image_base = 0

    if hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER is not None:
        magic = getattr(pe.OPTIONAL_HEADER, "Magic", 0)
        bits = 64 if magic == 0x020B else (32 if magic == 0x010B else None)
        entry_rva = getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)
        subsystem = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        image_base = getattr(pe.OPTIONAL_HEADER, "ImageBase", 0)

    # Check if .NET assembly (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR present)
    is_dotnet = False
    try:
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            com_desc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
            if com_desc.VirtualAddress > 0 and com_desc.Size > 0:
                is_dotnet = True
                could_not_analyze.append("managed assembly; native analysis limited")
    except Exception:
        pass

    # Timestamp Plausibility (Timestomping detection)
    # Note: .NET assemblies compiled deterministically (/deterministic) use TimeDateStamp
    # for reproducible build hashes, not calendar timestamps.
    timestamp_raw = pe.FILE_HEADER.TimeDateStamp
    try:
        compile_time = datetime.datetime.fromtimestamp(timestamp_raw, tz=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        is_future = compile_time.year > now.year + 1
        is_ancient = compile_time.year < 1995 or timestamp_raw == 0

        compile_time_str = compile_time.isoformat()
        if (is_future or is_ancient) and not is_dotnet:
            prov = create_provenance("parser_field", "COFF Header TimeDateStamp", "parsed", "confirmed")
            findings.append(create_finding(
                "pe-anomalous-compile-timestamp",
                "anomaly",
                "Anomalous / Timestomped COFF Header Timestamp",
                f"Binary header contains implausible timestamp: {compile_time_str} (timestamp_raw={timestamp_raw}).",
                prov,
                ["T1070.006"],
            ))
            structural_anomalies.append({
                "title": f"Implausible compilation timestamp ({compile_time.year})",
                "weight": 15,
                "reliability": "parsed",
                "evidence": f"TimeDateStamp={timestamp_raw} ({compile_time_str})",
            })
    except Exception:
        compile_time_str = "Invalid timestamp"

    # 2. Sections Parsing & RWX Detection
    sections: list[dict[str, Any]] = []
    section_hashes: dict[str, str] = {}

    for sec in pe.sections:
        raw_name = sec.Name.decode("latin1", errors="replace").rstrip("\x00").strip()
        name = _resolve_coff_section_name(raw_name, data, pe)
        virtual_size = sec.Misc_VirtualSize
        virtual_address = sec.VirtualAddress
        raw_size = sec.SizeOfRawData
        raw_ptr = sec.PointerToRawData
        chars = sec.Characteristics

        raw_data = sec.get_data() if hasattr(sec, "get_data") else b""
        sec_entropy = _calc_entropy(raw_data)
        sec_sha256 = hashlib.sha256(raw_data).hexdigest() if raw_data else None

        if name and sec_sha256:
            section_hashes[name] = sec_sha256

        is_exec = bool(chars & 0x20000000)
        is_write = bool(chars & 0x80000000)
        is_read = bool(chars & 0x40000000)
        is_rwx = is_exec and is_write

        sec_info = {
            "name": name,
            "raw_name": raw_name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
            "entropy": sec_entropy,
            "is_rwx": is_rwx,
            "permissions": ("R" if is_read else "-") + ("W" if is_write else "-") + ("X" if is_exec else "-"),
            "sha256": sec_sha256,
        }
        sections.append(sec_info)

        # Anomaly: RWX section
        if is_rwx and name not in ("", ".rsrc"):
            prov = create_provenance("parser_field", f"Section Table ({name})", "parsed", "confirmed")
            findings.append(create_finding(
                f"pe-rwx-section-{name}",
                "anomaly",
                f"Writable and Executable (RWX) Section: {name}",
                f"Section {name} has both MEM_EXECUTE and MEM_WRITE characteristics enabled.",
                prov,
                ["T1055"],
            ))
            structural_anomalies.append({
                "title": f"RWX memory permissions on section {name}",
                "weight": 25,
                "reliability": "parsed",
                "evidence": f"Characteristics=0x{chars:08X}",
            })

    # 3. Authenticode Signature (Data Directory 4: IMAGE_DIRECTORY_ENTRY_SECURITY)
    signature_info = {"is_signed": False}
    try:
        sec_dir_idx = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY")
        if (
            hasattr(pe, "OPTIONAL_HEADER")
            and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY")
            and sec_dir_idx is not None
            and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx
        ):
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            if sec_dir.VirtualAddress > 0 and sec_dir.Size > 8:
                file_off = sec_dir.VirtualAddress
                cert_len = sec_dir.Size
                if file_off + cert_len <= len(data):
                    sig_bytes = data[file_off : file_off + cert_len]
                    sig_blob_sha1 = hashlib.sha1(sig_bytes).hexdigest()
                    signature_info = {
                        "is_signed": True,
                        "cert_length": cert_len,
                        "file_offset": file_off,
                        "signature_blob_sha1": sig_blob_sha1,
                        "status": "signature present (unverified)",
                        "note": "Signature validity is not verified offline (requires external trust store and CRL/OCSP validation).",
                    }
    except Exception:
        pass

    # 4. Appended Overlay Detection
    overlay_offset = None
    overlay_size = 0
    overlay_entropy = 0.0
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_data = pe.get_overlay()
        if overlay_data:
            overlay_size = len(overlay_data)
            overlay_entropy = _calc_entropy(overlay_data)
    except Exception:
        overlay_size = 0

    # If the overlay strictly accounts for the Authenticode certificate table or
    # COFF symbol and string tables (e.g. MinGW debug symbols), it is not an unreferenced payload.
    is_cert_table_overlay = False
    if signature_info.get("is_signed"):
        cert_off = signature_info.get("file_offset", 0)
        cert_sz = signature_info.get("cert_length", 0)
        if overlay_offset is not None and abs(overlay_offset - cert_off) <= 16 and overlay_size <= cert_sz + 16:
            is_cert_table_overlay = True

    is_coff_symtab_overlay = False
    try:
        sym_ptr = getattr(pe.FILE_HEADER, "PointerToSymbolTable", 0)
        num_syms = getattr(pe.FILE_HEADER, "NumberOfSymbols", 0)
        if num_syms > 0 and overlay_offset is not None and overlay_size > 0:
            sym_size = num_syms * 18
            matches_direct_ptr = (sym_ptr > 0 and abs(overlay_offset - sym_ptr) <= 16)
            matches_trailing_format = False
            if overlay_size >= sym_size + 4:
                str_tab_size = int.from_bytes(data[overlay_offset + sym_size : overlay_offset + sym_size + 4], "little")
                if abs(overlay_size - (sym_size + str_tab_size)) <= 16:
                    matches_trailing_format = True
            if matches_direct_ptr or matches_trailing_format:
                is_coff_symtab_overlay = True
    except Exception:
        pass

    has_overlay = overlay_size > 512 and not is_cert_table_overlay and not is_coff_symtab_overlay
    if is_coff_symtab_overlay:
        prov = create_provenance("parser_field", f"COFF Symbol Table at 0x{(overlay_offset or 0):08X}", "parsed", "confirmed")
        findings.append(create_finding(
            "pe-coff-debug-symbols",
            "metadata",
            f"COFF debug symbols ({overlay_size} bytes)",
            f"Binary contains COFF symbol and string tables after last section ({num_syms} symbols).",
            prov,
            [],
        ))
    elif has_overlay:
        # Check for standard installer and self-extractor stubs
        installer_type = None
        overlay_head = overlay_data[:1024] if overlay_data else b""
        data_head = data[:0x10000]
        if overlay_head.startswith(b"7z\xbc\xaf\x27\x1c") or b"7-Zip" in data_head or b"7z.sfx" in data_head:
            installer_type = "7-Zip SFX"
        elif b"NullsoftInst" in overlay_head or b"NullsoftInst" in data_head or b"Nullsoft.NSIS" in data_head:
            installer_type = "NSIS Installer"
        elif b"Inno Setup" in overlay_head or b"Inno Setup" in data_head:
            installer_type = "Inno Setup Installer"
        elif overlay_head.startswith(b"MSCF") or b"IExpress" in data_head:
            installer_type = "Cabinet / IExpress SFX"
        elif overlay_head.startswith(b"PK\x03\x04"):
            installer_type = "ZIP SFX"
        elif overlay_head.startswith(b"Rar!\x1a\x07"):
            installer_type = "RAR SFX"

        could_not_analyze.append("compressed overlay payload not inspected")
        prov = create_provenance("parser_field", f"PE Overlay at 0x{(overlay_offset or 0):08X}", "parsed", "confirmed")

        if installer_type:
            title = f"installer/self-extractor; payload not analyzed ({installer_type})"
            evidence = f"{installer_type} format with {overlay_size:,} bytes compressed overlay at 0x{(overlay_offset or 0):08X} (entropy {overlay_entropy:.2f})"
            findings.append(create_finding(
                "pe-installer-sfx-detected",
                "metadata",
                title,
                f"Standard {installer_type} installer stub with appended compressed payload.",
                prov,
                [],
            ))
            structural_anomalies.append({
                "title": title,
                "weight": 0,
                "reliability": "parsed",
                "evidence": evidence,
                "is_informational": True,
            })
        else:
            # Merged single factor for high-entropy / large unparsed overlay
            title = f"High-entropy appended overlay data ({overlay_size} bytes)"
            evidence = f"PE Overlay at 0x{(overlay_offset or 0):08X} (entropy {overlay_entropy:.2f}); typical of installers, self-extractors, and droppers"
            findings.append(create_finding(
                "pe-appended-overlay-data",
                "structure",
                title,
                f"Binary contains {overlay_size:,} bytes appended past the last section (entropy {overlay_entropy:.2f}).",
                prov,
                ["T1027"],
            ))
            structural_anomalies.append({
                "title": title,
                "weight": 15 if overlay_entropy > 7.2 else 5,
                "reliability": "parsed",
                "evidence": evidence,
            })

    # 5. TLS Callbacks (Data Directory 9: IMAGE_DIRECTORY_ENTRY_TLS)
    has_tls_callbacks = False
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None:
            cb_addr = getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", 0)
            if cb_addr > 0:
                has_tls_callbacks = True
                prov = create_provenance("parser_field", "TLS Directory", "parsed", "confirmed")
                findings.append(create_finding(
                    "pe-tls-callbacks-present",
                    "capability",
                    "TLS Callbacks Present (Pre-EntryPoint Execution)",
                    "Binary defines TLS callbacks that execute before the main program entrypoint.",
                    prov,
                    ["T1055", "T1564"],
                ))
                capabilities.append({
                    "category": "Defense Evasion & Anti-Debug",
                    "matched": ["TLS Callbacks"],
                    "confidence": "high",
                    "provenance": prov,
                })
    except Exception:
        pass

    # 6. Imports & Canonical Imphash
    imported_dlls: list[str] = []
    imported_symbols: list[str] = []
    imported_function_names: list[str] = []

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("latin1", errors="replace") if entry.dll else ""
                if dll_name:
                    imported_dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        fn_name = imp.name.decode("latin1", errors="replace")
                        imported_function_names.append(fn_name)
                        imported_symbols.append(f"{dll_name}!{fn_name}")
                    elif imp.ordinal is not None:
                        imported_symbols.append(f"{dll_name}!ord{imp.ordinal}")
    except Exception:
        pass

    # Compute canonical imphash via pefile's standard get_imphash()
    imphash_canonical = None
    try:
        imphash_val = pe.get_imphash()
        if imphash_val:
            imphash_canonical = imphash_val
    except Exception:
        pass

    # Combined imports list containing DLL names, symbols (DLL!Function), and function names
    combined_imports = list(imported_dlls)
    for sym in imported_symbols:
        if sym not in combined_imports:
            combined_imports.append(sym)
    for fn in imported_function_names:
        if fn not in combined_imports:
            combined_imports.append(fn)

    _INJECTION_APIS = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
    }
    for fn in imported_function_names:
        if fn in _INJECTION_APIS:
            prov = create_provenance(0, 0, "parsed", "pe_import_table")
            capabilities.append({
                "category": "Process Injection",
                "name": fn,
                "matched": [fn],
                "confidence": "high",
                "source": "import_table",
                "provenance": prov,
            })

    # 7. Exports
    exports_list: list[str] = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT is not None:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports_list.append(exp.name.decode("latin1", errors="replace"))
    except Exception:
        pass

    # 8. Packer Detection
    packer_identified = None
    for sec in sections:
        if sec["name"] in _KNOWN_PACKER_SECTIONS:
            packer_identified = _KNOWN_PACKER_SECTIONS[sec["name"]]
            break

    # Structural packing heuristics
    if not packer_identified:
        has_tiny_imports = (len(imported_dlls) > 0 and len(imported_dlls) <= 2)
        has_packed_sections = any(s["entropy"] > 7.3 for s in sections)
        if has_tiny_imports and has_packed_sections:
            packer_identified = "Heuristic High-Entropy Stub Packer"

    if packer_identified:
        # Deduplicate packer RWX sections: RWX permissions on packer stubs (UPX0, UPX1)
        # are intrinsic to the stub, not separate threat factors.
        packer_sec_names = {s["name"] for s in sections if s["name"] in _KNOWN_PACKER_SECTIONS}
        if packer_sec_names:
            structural_anomalies = [
                a for a in structural_anomalies
                if not any(f"section {sname}" in a.get("title", "") for sname in packer_sec_names)
            ]
            findings = [
                f for f in findings
                if not any(f"Section: {sname}" in f.get("title", "") for sname in packer_sec_names)
            ]

        evidence_parts = []
        if b"UPX!" in data:
            upx_off = data.find(b"UPX!")
            evidence_parts.append(f"UPX! magic at offset 0x{upx_off:X}")
        if packer_sec_names:
            perm_str = ", ".join(f"{s['name']} ({s['permissions']})" for s in sections if s["name"] in packer_sec_names)
            evidence_parts.append(f"sections: {perm_str}")
        max_ent = max((s["entropy"] for s in sections), default=0.0)
        if max_ent > 0:
            evidence_parts.append(f"max section entropy {max_ent:.2f}")

        evidence_str = "; ".join(evidence_parts) if evidence_parts else packer_identified
        factor_title = "UPX-packed" if "UPX" in packer_identified else f"{packer_identified}-packed"

        prov = create_provenance("parser_field", "PE Section Table / Import Count", "parsed", "confirmed")
        structural_anomalies.append({
            "title": factor_title,
            "weight": 25,
            "reliability": "parsed",
            "evidence": evidence_str,
        })
        capabilities.append({
            "category": "Defense Evasion & Anti-Debug",
            "matched": [packer_identified],
            "confidence": "high",
            "provenance": prov,
        })
        could_not_analyze.append("packed_executable_code")
        could_not_analyze.append("obfuscated_imports")

    return {
        "is_pe": True,
        "machine": machine_str,
        "bits": bits,
        "is_dll": is_dll,
        "entry_point_rva": entry_rva,
        "subsystem": subsystem,
        "image_base": image_base,
        "compilation_timestamp": compile_time_str,
        "sections": sections,
        "section_hashes": section_hashes,
        "overlay": {
            "has_overlay": has_overlay,
            "size": overlay_size,
            "entropy": overlay_entropy,
        },
        "has_tls_callbacks": has_tls_callbacks,
        "signature": signature_info,
        "imports": combined_imports,
        "imported_dlls": imported_dlls,
        "imported_symbols": imported_symbols,
        "imported_functions": imported_function_names,
        "exports": exports_list,
        "imphash_canonical": imphash_canonical,
        "packer": packer_identified,
        "findings": findings,
        "indicators": indicators,
        "capabilities": capabilities,
        "structural_anomalies": structural_anomalies,
        "benign_signals": benign_signals,
        "could_not_analyze": could_not_analyze,
    }
