"""Unit and integration test suite for Stage 1 Static Analysis:
Core Hashes (MD5, SHA-1, SHA-256), TLSH fuzzy hash, Shannon Entropy,
PE parser (pefile), ELF parser (pyelftools), single-engine error policy, and EICAR.
"""

import hashlib
import os

import pytest

from app.services.static.formats.elf import is_elf, parse_deep_elf
from app.services.static.formats.pe import is_pe, parse_deep_pe
from app.services.static.pipeline import (
    calculate_entropy,
    calculate_entropy_histogram,
    compute_tlsh,
    run_complete_static_pipeline,
)
from app.services.static_analysis import compare_fuzzy_hashes


def test_core_hashes_and_shannon_entropy():
    """Verify that MD5, SHA-1, SHA-256, and Shannon entropy are calculated accurately."""
    sample = b"OutPost Static Analysis Suite - Core Hash and Shannon Entropy Verification Payload 2026!"
    result = run_complete_static_pipeline(sample)

    assert result["md5"] == hashlib.md5(sample).hexdigest()
    assert result["sha1"] == hashlib.sha1(sample).hexdigest()
    assert result["sha256"] == hashlib.sha256(sample).hexdigest()

    expected_entropy = calculate_entropy(sample)
    assert result["entropy"] == expected_entropy
    assert 0.0 <= result["entropy"] <= 8.0

    # Test empty payload entropy is 0.0
    assert calculate_entropy(b"") == 0.0

    # Test uniform random payload entropy approaches 8.0
    random_bytes = os.urandom(65536)
    assert calculate_entropy(random_bytes) > 7.9

    # Verify entropy histogram structure
    hist = result["entropy_histogram"]
    assert len(hist) == 32
    assert all("offset" in h and "entropy" in h and "bin" in h for h in hist)


def test_tlsh_fuzzy_hash():
    """Verify TLSH fuzzy hash generation, edge cases, and distance comparisons."""
    # 1. Short sample (< 50 bytes)
    short_data = b"Too short for TLSH"
    res_short = compute_tlsh(short_data)
    assert res_short == "TNULL (insufficient length < 50 bytes)"

    # 2. Zero-variance sample (> 50 bytes of uniform zeros)
    zeros_data = b"\x00" * 200
    res_zeros = compute_tlsh(zeros_data)
    assert res_zeros == "TNULL (insufficient variance/entropy)"

    # 3. Sufficient data with varied byte distribution
    sample1 = (b"OutPost static analysis test byte stream with sufficient entropy and variation. " * 10)
    tlsh1 = compute_tlsh(sample1)
    assert tlsh1.startswith("T1")
    assert len(tlsh1) == 72

    # 4. Similar sample (small mutation)
    sample2 = sample1[:len(sample1) - 5] + b"12345"
    tlsh2 = compute_tlsh(sample2)
    assert tlsh2.startswith("T1")

    # Identical samples must have 100% similarity score
    score_identical = compare_fuzzy_hashes(tlsh1, tlsh1)
    assert score_identical == 100

    # Mutated samples should have high/moderate similarity score
    score_mutated = compare_fuzzy_hashes(tlsh1, tlsh2)
    assert score_mutated > 0


def test_pe_parser_notepad_benign():
    """Verify deep PE parsing via pefile on stock benign notepad.exe."""
    notepad_path = "/usr/lib/wine/x86_64-windows/notepad.exe"
    if not os.path.exists(notepad_path):
        pytest.skip("wine notepad.exe not present on this host")

    with open(notepad_path, "rb") as f:
        data = f.read()

    assert is_pe(data) is True
    pe_info = parse_deep_pe(data)

    assert pe_info["is_pe"] is True
    assert pe_info["machine"] == "x86-64"
    assert pe_info["bits"] == 64
    assert pe_info["is_dll"] is False
    assert pe_info["entry_point_rva"] == 0x6D60
    assert pe_info["subsystem"] == 2  # Windows GUI
    assert pe_info["image_base"] == 0x140000000
    assert pe_info["imphash_canonical"] == "a468b0eeb8eb790b0f8c81d7d59bd2d2"

    # Verify sections
    section_names = [s["name"] for s in pe_info["sections"]]
    assert ".text" in section_names
    assert ".data" in section_names
    assert ".rdata" in section_names
    assert ".gnu_debuglink" in section_names
    assert len(pe_info["sections"]) == 11

    # Verify imports
    dlls = pe_info["imported_dlls"]
    assert "kernel32.dll" in dlls
    assert "user32.dll" in dlls
    assert "gdi32.dll" in dlls

    # Verify full pipeline execution yields non-malicious verdict
    res = run_complete_static_pipeline(data, file_path=notepad_path)
    assert res["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")
    assert res["verdict"] != "malicious"


def test_elf_parser_bin_ls():
    """Verify deep ELF parsing via pyelftools on stock benign /bin/ls."""
    ls_path = "/bin/ls"
    if not os.path.exists(ls_path):
        pytest.skip("/bin/ls not present on this host")

    with open(ls_path, "rb") as f:
        data = f.read()

    assert is_elf(data) is True
    elf_info = parse_deep_elf(data)

    assert elf_info["is_elf"] is True
    assert elf_info["machine"] == "x86-64"
    assert elf_info["bits"] == 64
    assert elf_info["class"] == 64
    assert elf_info["endian"] == "little"
    assert elf_info["type"] == "DYN"
    assert elf_info["entry_point"] == "0x00005620"
    assert elf_info["is_stripped"] is True
    assert elf_info["has_rwx_segment"] is False

    # Verify dynamic libraries
    dyn_libs = elf_info["dynamic_libraries"]
    assert "libc.so.6" in dyn_libs
    assert "libcap.so.2" in dyn_libs

    # Verify sections
    sec_names = elf_info["section_names"]
    assert ".text" in sec_names
    assert ".rodata" in sec_names
    assert ".dynamic" in sec_names
    assert len(elf_info["sections"]) == 29

    # Verify full pipeline execution yields non-malicious verdict
    res = run_complete_static_pipeline(data, file_path=ls_path)
    assert res["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")
    assert res["verdict"] != "malicious"


def test_elf_parser_probe_elf():
    """Verify deep ELF parsing on local probe_elf executable."""
    probe_path = "tests/probes/c_probe/probe_elf"
    if not os.path.exists(probe_path):
        pytest.skip("tests/probes/c_probe/probe_elf not compiled")

    with open(probe_path, "rb") as f:
        data = f.read()

    assert is_elf(data) is True
    elf_info = parse_deep_elf(data)

    assert elf_info["is_elf"] is True
    assert elf_info["machine"] == "x86-64"
    # probe_elf was built with gcc without -s, retaining .symtab
    assert elf_info["is_stripped"] is False
    assert "libc.so.6" in elf_info["dynamic_libraries"]

    # Verify pipeline execution on ground-truth probe yields non-malicious, zero-score verdict
    res = run_complete_static_pipeline(data, file_path=probe_path)
    assert res["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")
    assert res["static_risk_score"] == 0


def test_pe_malformed_truncated_error_handling():
    """Verify single-engine error policy on corrupted PE binary."""
    # Corrupted PE: valid MZ header and PE signature offset, but truncated NT headers
    corrupted_pe = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00\x01\x02"
    assert is_pe(corrupted_pe) is True

    result = run_complete_static_pipeline(corrupted_pe)
    assert result["format"] == "pe"
    # Must capture the exact library exception category in could_not_analyze
    cna = result.get("could_not_analyze", [])
    assert any("pefile: PEFormatError" in err for err in cna)
    # Generic analysis layer must remain fully functional
    assert len(result["sha256"]) == 64
    assert len(result["md5"]) == 32
    assert "tlsh" in result
    assert result["verdict"] != "malicious"


def test_elf_malformed_truncated_error_handling():
    """Verify single-engine error policy on corrupted ELF binary."""
    # Corrupted ELF: valid 0x7F 'ELF' header (>= 52 bytes), but truncated before valid 64-bit header
    corrupted_elf = b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00" + b"\x00" * 36
    assert is_elf(corrupted_elf) is True

    result = run_complete_static_pipeline(corrupted_elf)
    assert result["format"] == "elf"
    # Must capture the exact library exception category in could_not_analyze
    cna = result.get("could_not_analyze", [])
    assert any("pyelftools: ELFError" in err for err in cna)
    # Generic analysis layer must remain fully functional
    assert len(result["sha256"]) == 64
    assert len(result["md5"]) == 32
    assert "tlsh" in result
    assert result["verdict"] != "malicious"


def test_eicar_test_string_static_pipeline():
    """Verify standard EICAR anti-malware test string handling."""
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    result = run_complete_static_pipeline(eicar)

    # Core hashes computed properly on EICAR
    assert result["md5"] == "44d88612fea8a8f36de82e1278abb02f"
    assert result["sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert result["sha1"] == "3395856ce81f2b7382dee72602f798b642f14140"
    # Strings and preview generated cleanly
    assert any("EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in s for s in result["strings"])


def test_synthetic_injection_capability_corroboration():
    """Verify context-sensitive capability scoring:
    (a) Injection APIs + RWX section produces a corroborated suspicious verdict.
    (b) Injection APIs without RWX section remains informational with score 0.
    """
    try:
        from tests.fixtures.synthetic_pe import make_injection_pe
    except ImportError:
        import sys
        sys.path.insert(0, "/tmp")
        from gen_synthetic_pe import make_injection_pe

    # Case A: Injection APIs + RWX section (.evil)
    pe_rwx = make_injection_pe(is_rwx=True)
    res_rwx = run_complete_static_pipeline(pe_rwx)

    assert res_rwx["verdict"] == "suspicious"
    assert res_rwx["static_risk_score"] >= 25
    factors_rwx = [f["factor"] for f in res_rwx["assessment_factors"]]
    assert any("RWX memory permissions" in f for f in factors_rwx)
    assert any("Process Injection" in f for f in factors_rwx)

    # Case B: Injection APIs without RWX section (.text RX)
    pe_norwx = make_injection_pe(is_rwx=False)
    res_norwx = run_complete_static_pipeline(pe_norwx)

    assert res_norwx["verdict"] == "no_indicators_found_limited"
    assert res_norwx["static_risk_score"] == 0
    assert len(res_norwx["assessment_factors"]) == 0
    # Capability is present in capabilities list as informational
    assert any(c["category"] == "Process Injection" for c in res_norwx["capabilities"])


def test_managed_dotnet_assembly_inconclusive_verdict():
    """Verify that managed .NET assemblies are flagged as inconclusive with limited native analysis."""
    # Build minimal PE with COM descriptor directory set (PE32)
    opt = bytearray(224)
    opt[0:2] = (0x010B).to_bytes(2, "little")  # Magic PE32
    opt[16:20] = (0x1000).to_bytes(4, "little")  # Entrypoint
    opt[28:32] = (0x400000).to_bytes(4, "little")  # ImageBase
    opt[32:36] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    opt[36:40] = (0x200).to_bytes(4, "little")  # FileAlignment
    opt[56:60] = (0x3000).to_bytes(4, "little")  # SizeOfImage
    opt[60:64] = (0x400).to_bytes(4, "little")  # SizeOfHeaders
    opt[68:70] = (3).to_bytes(2, "little")  # Subsystem
    opt[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes
    # Entry 14 is COM Descriptor: 96 + 14 * 8 = 208
    opt[208:212] = (0x2000).to_bytes(4, "little")  # VirtualAddress
    opt[212:216] = (72).to_bytes(4, "little")  # Size

    pe = bytearray(b"MZ" + b"\x00" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * 64)
    pe.extend(b"PE\x00\x00")
    # COFF: x86, 1 section, timestamp 0x67100000
    pe.extend(b"\x4c\x01\x01\x00\x00\x00\x10\x67\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x02\x01")
    pe.extend(opt)
    # Section header
    sec = b".text\x00\x00\x00" + (0x1000).to_bytes(4, "little") + (0x1000).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + b"\x00" * 12 + (0x60000020).to_bytes(4, "little")
    pe.extend(sec)
    pe.extend(b"\x00" * (0x200 - len(pe)))
    pe.extend(b"\xc3" + b"\x00" * 511)

    res = run_complete_static_pipeline(bytes(pe))
    assert "managed assembly; native analysis limited" in res.get("could_not_analyze", [])
    assert res["verdict"] == "insufficient_evidence"
    assert res["static_risk_score"] == 0


def test_upx_elf_and_pe_specific_evidence():
    """Verify specific UPX packer evidence strings for ELF and PE formats."""
    # 1. UPX ELF fixture: header with b"UPX!" at offset 0xEC
    elf = bytearray(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    elf.extend(b"\x00" * (0xEC - len(elf)))
    elf.extend(b"UPX!\x0d\x24\x08\x08")
    elf.extend(b"\x00" * (512 - len(elf)))

    res_elf = run_complete_static_pipeline(bytes(elf))
    assert res_elf["verdict"] == "insufficient_evidence"
    assert res_elf["static_risk_score"] == 25
    factors_elf = res_elf.get("assessment_factors", [])
    assert len(factors_elf) == 1
    assert factors_elf[0]["factor"] == "UPX-packed"
    assert "UPX! magic at offset 0xEC" in factors_elf[0]["evidence"]

    # 2. UPX PE fixture: sections UPX0 and UPX1
    import struct
    mz = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x67100000, 0, 0, 240, 0x0022)
    std = struct.pack("<HBBIIIII", 0x020B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000)
    win = struct.pack("<QIIHHHHHHIIIIHHQQQQII",
        0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
        0x3000, 0x400, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
    )
    dirs = bytearray(128)
    sec1 = struct.pack("<8sIIIIIIHHI", b"UPX0\x00\x00\x00\x00", 0x1000, 0x1000, 0, 0x200, 0, 0, 0, 0, 0xE0000080)
    sec2 = struct.pack("<8sIIIIIIHHI", b"UPX1\x00\x00\x00\x00", 0x1000, 0x2000, 0x200, 0x200, 0, 0, 0, 0, 0xE0000040)
    hdrs = bytearray(mz + pe_sig + coff + std + win + dirs + sec1 + sec2)
    hdrs.extend(b"\x00" * (0x200 - len(hdrs)))
    # Add UPX! magic in code section at offset 0x205 (relative to file start)
    sec_data = bytearray(b"\x00" * 5 + b"UPX!\x00" + b"\x00" * 503)
    full_pe = bytes(hdrs + sec_data)

    res_pe = run_complete_static_pipeline(full_pe)
    assert res_pe["verdict"] == "insufficient_evidence"
    assert res_pe["static_risk_score"] == 25
    factors_pe = res_pe.get("assessment_factors", [])
    assert len(factors_pe) == 1
    assert factors_pe[0]["factor"] == "UPX-packed"
    assert "UPX! magic at offset 0x205" in factors_pe[0]["evidence"]
    assert "UPX0 (RWX)" in factors_pe[0]["evidence"]


def test_coff_debug_symbols_not_counted_as_overlay():
    """Verify that COFF symbol and string tables after the last section are recognized as debug data, not an overlay."""
    import struct
    mz = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64)
    pe_sig = b"PE\x00\x00"
    # PointerToSymbolTable=0x400 (1024), NumberOfSymbols=2 (36 bytes)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x67100000, 0x400, 2, 240, 0x0022)
    std = struct.pack("<HBBIIIII", 0x020B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    win = struct.pack("<QIIHHHHHHIIIIHHQQQQII",
        0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
        0x2000, 0x200, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
    )
    dirs = bytearray(128)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdrs = bytearray(mz + pe_sig + coff + std + win + dirs + sec1)
    hdrs.extend(b"\x00" * (0x200 - len(hdrs)))
    sec_data = bytearray(b"\xc3" + b"\x00" * 511)  # offset 0x200 to 0x400

    # At 0x400: COFF symbol table (2 symbols * 18 bytes = 36 bytes)
    coff_syms = bytearray(36)
    # COFF string table: 4-byte size followed by null-terminated strings
    str_table = struct.pack("<I", 16) + b"debug_sym\x00\x00\x00"
    full_data = bytes(hdrs + sec_data + coff_syms + str_table)

    res = run_complete_static_pipeline(full_data)
    assert res["verdict"] == "no_indicators_found_limited"
    assert res["static_risk_score"] == 0
    # No overlay finding or anomaly created
    assert not any("overlay" in f["factor"].lower() for f in res.get("assessment_factors", []))
    pe_details = res.get("pe", {})
    assert pe_details.get("overlay", {}).get("has_overlay") is False


def test_unverified_signature_info_not_risk_reducing():
    """Verify that an unverified Authenticode signature is reported in signature_info without reducing risk."""
    import struct
    mz = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x67100000, 0, 0, 240, 0x0022)
    std = struct.pack("<HBBIIIII", 0x020B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    win = struct.pack("<QIIHHHHHHIIIIHHQQQQII",
        0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
        0x2000, 0x200, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
    )
    dirs = bytearray(128)
    # Entry 4 is IMAGE_DIRECTORY_ENTRY_SECURITY at offset 0x400, size 32
    struct.pack_into("<II", dirs, 4 * 8, 0x400, 32)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdrs = bytearray(mz + pe_sig + coff + std + win + dirs + sec1)
    hdrs.extend(b"\x00" * (0x200 - len(hdrs)))
    sec_data = bytearray(b"\xc3" + b"\x00" * 511)  # offset 0x200 to 0x400
    cert_blob = bytearray(b"MIIFAKE_CERT_BLOB_FOR_TESTING\x00\x00\x00")  # 32 bytes at offset 0x400

    full_signed_pe = bytes(hdrs + sec_data + cert_blob)
    res = run_complete_static_pipeline(full_signed_pe)

    # Signature must be reported in signature_info
    sig_info = res.get("signature_info", {})
    assert sig_info.get("is_signed") is True
    assert sig_info.get("status") == "signature present (unverified)"
    assert "not verified offline" in sig_info.get("note", "")

    # Must NOT appear under benign_factors with negative risk reduction weight
    assert len(res.get("benign_factors", [])) == 0


def test_installer_sfx_overlay_insufficient_evidence():
    """Verify that a standard installer / self-extracting archive overlay returns insufficient_evidence, not suspicious."""
    import struct
    mz = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x67100000, 0, 0, 240, 0x0022)
    std = struct.pack("<HBBIIIII", 0x020B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000)
    win = struct.pack("<QIIHHHHHHIIIIHHQQQQII",
        0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
        0x2000, 0x200, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16
    )
    dirs = bytearray(128)
    sec1 = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    hdrs = bytearray(mz + pe_sig + coff + std + win + dirs + sec1)
    hdrs.extend(b"\x00" * (0x200 - len(hdrs)))
    sec_data = bytearray(b"\xc3" + b"\x00" * 511)
    # High-entropy 7-Zip SFX overlay payload
    sfx_overlay = bytearray(b"7z\xbc\xaf\x27\x1c" + os.urandom(4096))

    installer_pe = bytes(hdrs + sec_data + sfx_overlay)
    res = run_complete_static_pipeline(installer_pe)

    # Must be insufficient_evidence with score 0 (not suspicious)
    assert res["verdict"] == "insufficient_evidence"
    assert res["static_risk_score"] == 0
    assert "compressed overlay payload not inspected" in res.get("could_not_analyze", [])
    factors = res.get("assessment_factors", [])
    assert len(factors) == 1
    assert "installer/self-extractor" in factors[0]["factor"]


def test_pe_injection_imports_appear_in_imports_and_capabilities_list():
    """Verify that PE injection imports are populated in pe['imports'], pe['imported_symbols'],

    and tagged with MITRE capability details in pe['capabilities'].
    """
    try:
        from tests.fixtures.synthetic_pe import make_injection_pe
    except ImportError:
        import sys
        sys.path.insert(0, "/tmp")
        from gen_synthetic_pe import make_injection_pe

    pe_bytes = make_injection_pe(is_rwx=False)
    parsed = parse_deep_pe(pe_bytes)

    # 1. Imported function names must be present in imports
    assert "VirtualAllocEx" in parsed["imports"]
    assert "WriteProcessMemory" in parsed["imports"]
    assert "CreateRemoteThread" in parsed["imports"]

    # 2. DLL!Symbol format for UI library breakdown
    assert "KERNEL32.dll!VirtualAllocEx" in parsed["imported_symbols"]
    assert "KERNEL32.dll!WriteProcessMemory" in parsed["imported_symbols"]
    assert "KERNEL32.dll!CreateRemoteThread" in parsed["imported_symbols"]

    # 3. Tagged as security capabilities
    cap_names = [c["name"] for c in parsed["capabilities"]]
    assert "VirtualAllocEx" in cap_names
    assert "WriteProcessMemory" in cap_names
    assert "CreateRemoteThread" in cap_names

    # Check capability category
    for c in parsed["capabilities"]:
        if c["name"] in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
            assert c["category"] == "Process Injection"
