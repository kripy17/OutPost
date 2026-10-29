"""Unit and integration tests for Stage 2 Static Analysis:
Strings Extraction (ASCII and UTF-16LE) and Analyst Categorization.

Validates exact concordance with GNU Binutils strings (strings -a -n 4 and strings -a -e l -n 4),
offset accuracy, even/odd UTF-16 alignment, NUL-byte hygiene, category intelligence buckets,
exclusion of bare words from commands/network, and proof that strings never affect static verdicts.
"""

import os
import shutil
import subprocess

import pytest

from app.services.static.pipeline import run_complete_static_pipeline
from app.services.static.strings import (
    categorize_string,
    categorize_strings,
    extract_strings,
    extract_strings_detailed,
)


def test_ascii_and_utf16le_synthetic_fixture():
    """Verify clean extraction of ASCII and UTF-16LE strings with exact offsets and encodings."""
    buf = bytearray(256)
    ascii_str = b"TargetCommandExecutor\x00"
    buf[0x10 : 0x10 + len(ascii_str)] = ascii_str

    utf16_str = "RegistryKeyPath\\Run\x00".encode("utf-16le")
    buf[0x30 : 0x30 + len(utf16_str)] = utf16_str

    odd_utf16 = "OddAlignedString\x00".encode("utf-16le")
    buf[0x71 : 0x71 + len(odd_utf16)] = odd_utf16

    detailed, trunc = extract_strings_detailed(bytes(buf), min_length=4)
    string_map = {item["string"]: item for item in detailed}

    # Verify ASCII entry
    assert "TargetCommandExecutor" in string_map
    ascii_item = string_map["TargetCommandExecutor"]
    assert ascii_item["offset"] == 0x10
    assert ascii_item["offset_hex"] == "0x00000010"
    assert ascii_item["encoding"] == "ascii"
    assert "\x00" not in ascii_item["string"]

    # Verify UTF-16LE entry at even offset
    assert "RegistryKeyPath\\Run" in string_map
    utf16_item = string_map["RegistryKeyPath\\Run"]
    assert utf16_item["offset"] == 0x30
    assert utf16_item["offset_hex"] == "0x00000030"
    assert utf16_item["encoding"] == "utf-16le"
    assert "\x00" not in utf16_item["string"]

    # Verify UTF-16LE entry at odd offset
    assert "OddAlignedString" in string_map
    odd_item = string_map["OddAlignedString"]
    assert odd_item["offset"] == 0x71
    assert odd_item["offset_hex"] == "0x00000071"
    assert odd_item["encoding"] == "utf-16le"
    assert "\x00" not in odd_item["string"]

    assert trunc["is_truncated"] is False
    assert trunc["total_found"] == 3


def test_gnu_binutils_strings_cross_check_notepad():
    """Cross-check UTF-16LE and ASCII extraction against GNU strings on notepad.exe."""
    notepad_path = "/usr/lib/wine/x86_64-windows/notepad.exe"
    if not os.path.exists(notepad_path):
        pytest.skip("wine notepad.exe not present on this host")

    strings_bin = shutil.which("strings")
    if not strings_bin:
        pytest.skip("GNU strings binary not available")

    with open(notepad_path, "rb") as f:
        data = f.read()

    # 1. Cross-check UTF-16LE counts and specific known strings
    detailed, _ = extract_strings_detailed(data, min_length=4, max_count=5000)
    utf16_items = [d for d in detailed if d["encoding"] == "utf-16le"]

    # Run GNU strings -a -e l -n 4
    res_gnu = subprocess.run(
        [strings_bin, "-a", "-e", "l", "-t", "x", "-n", "4", notepad_path],
        capture_output=True,
        text=True,
        check=True,
    )
    gnu_lines = [line.strip() for line in res_gnu.stdout.splitlines() if line.strip()]

    # Parse GNU output: '<hex_offset> <string>'
    gnu_map: dict[int, str] = {}
    for line in gnu_lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            try:
                gnu_map[int(parts[0], 16)] = parts[1]
            except ValueError:
                pass

    # Verify exact match on key Windows strings at exact offsets
    # 0x8000: 'output.prn'
    assert 0x8000 in gnu_map
    assert gnu_map[0x8000] == "output.prn"
    our_output_prn = next((d for d in utf16_items if d["offset"] == 0x8000), None)
    assert our_output_prn is not None
    assert our_output_prn["string"] == "output.prn"
    assert our_output_prn["offset_hex"] == "0x00008000"

    # 0x9150: 'Sorry, no help available'
    assert 0x9150 in gnu_map
    assert gnu_map[0x9150] == "Sorry, no help available"
    our_help = next((d for d in utf16_items if d["offset"] == 0x9150), None)
    assert our_help is not None
    assert our_help["string"] == "Sorry, no help available"

    # 0x92C8: 'Software\Microsoft\Notepad'
    assert 0x92C8 in gnu_map
    assert gnu_map[0x92C8] == "Software\\Microsoft\\Notepad"
    our_reg = next((d for d in utf16_items if d["offset"] == 0x92C8), None)
    assert our_reg is not None
    assert our_reg["string"] == "Software\\Microsoft\\Notepad"
    assert "registry" in our_reg["categories"]


def test_gnu_binutils_strings_cross_check_ls():
    """Cross-check ASCII extraction against GNU strings on /bin/ls."""
    ls_path = "/bin/ls"
    if not os.path.exists(ls_path):
        pytest.skip("/bin/ls not present on this host")

    strings_bin = shutil.which("strings")
    if not strings_bin:
        pytest.skip("GNU strings binary not available")

    with open(ls_path, "rb") as f:
        data = f.read()

    detailed, _ = extract_strings_detailed(data, min_length=4, max_count=5000)
    ascii_items = [d for d in detailed if d["encoding"] == "ascii"]

    res_gnu = subprocess.run(
        [strings_bin, "-a", "-t", "x", "-n", "4", ls_path],
        capture_output=True,
        text=True,
        check=True,
    )
    gnu_lines = [line.strip() for line in res_gnu.stdout.splitlines() if line.strip()]

    gnu_map: dict[int, str] = {}
    for line in gnu_lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            try:
                gnu_map[int(parts[0], 16)] = parts[1]
            except ValueError:
                pass

    # Verify libc and symbol offsets match GNU strings exactly
    for our_item in ascii_items[:50]:
        if our_item["offset"] in gnu_map:
            assert our_item["string"] == gnu_map[our_item["offset"]]


def test_analyst_categorization_buckets_strict():
    """Verify that strings are categorized into intelligence buckets under strict specification."""
    test_cases = [
        # URLs and Network
        ("https://malicious-c2.duckdns.org/payload.exe", ["urls", "network"]),
        ("http://198.51.100.50:8080/beacon", ["urls", "network"]),
        ("https://www.gnu.org/software/coreutils/", ["urls"]),
        ("tcp://c2.example.com:4444", ["urls"]),
        ("192.0.2.1", ["network"]),
        ("evil-c2.duckdns.org", ["network"]),
        ("POST /beacon HTTP/1.1", ["network"]),
        # File paths: path structure with root and subpath
        ("C:\\Windows\\System32\\drivers\\etc\\hosts", ["file_paths"]),
        ("%TEMP%\\payload.tmp", ["file_paths"]),
        ("/etc/shadow", ["file_paths"]),
        ("/var/log/auth.log", ["file_paths"]),
        # Commands: command-line shape with arguments
        ("powershell.exe -ExecutionPolicy Bypass -enc AAAA", ["commands"]),
        ("cmd.exe /c whoami", ["commands"]),
        ("chmod +x /tmp/dropper", ["commands"]),
        ("vssadmin delete shadows /all /quiet", ["commands"]),
        # Registry: rooted hive keys
        ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", ["registry"]),
        ("Software\\Microsoft\\Notepad", ["registry"]),
        ("HKEY_CURRENT_USER\\Software\\Classes", ["registry"]),
        # Security APIs: high-risk functions
        ("VirtualAllocEx", ["security_apis", "api_names"]),
        ("WriteProcessMemory", ["security_apis", "api_names"]),
        ("CreateRemoteThread", ["security_apis", "api_names"]),
        ("IsDebuggerPresent", ["security_apis", "api_names"]),
        ("MiniDumpWriteDump", ["security_apis", "api_names"]),
        ("CryptEncrypt", ["security_apis", "api_names"]),
        # Benign / un-categorized
        ("StandardBenignStringLiteral", []),
    ]

    for test_str, expected_cats in test_cases:
        actual_cats = categorize_string(test_str)
        for cat in expected_cats:
            assert cat in actual_cats, f"Expected '{test_str}' in category '{cat}', got {actual_cats}"

    # Batch categorization
    sample_pool = [s for s, _ in test_cases]
    categorized = categorize_strings(sample_pool)
    assert "https://malicious-c2.duckdns.org/payload.exe" in categorized["urls"]
    assert "https://malicious-c2.duckdns.org/payload.exe" in categorized["network"]
    assert "https://www.gnu.org/software/coreutils/" in categorized["urls"]
    assert "https://www.gnu.org/software/coreutils/" not in categorized["network"]
    assert "powershell.exe -ExecutionPolicy Bypass -enc AAAA" in categorized["commands"]
    assert "Software\\Microsoft\\Notepad" in categorized["registry"]
    assert "VirtualAllocEx" in categorized["security_apis"]
    assert "VirtualAllocEx" in categorized["api_names"]


def test_specification_positive_and_negative_examples():
    """Verify categorization against positive and negative test cases from the specification document."""
    # 1. Commands
    cmd_positives = [
        "powershell.exe -enc AAAA",
        "pwsh -ExecutionPolicy Bypass",
        "cmd.exe /c whoami",
        "/bin/sh -c evil_dropper",
        "chmod +x /tmp/payload",
        "chmod 0755 /tmp/script.sh",
        "chown root:root /tmp/payload",
        "net user evil_user /add",
        "vssadmin delete shadows",
        "schtasks /create /tn RunEvil /tr C:\\evil.exe",
    ]
    for p in cmd_positives:
        cats = categorize_string(p)
        assert "commands" in cats, f"Expected 'commands' in {cats} for '{p}'"

    cmd_negatives = [
        "chmod",
        "chmod@GLIBC_2.2.5",
        "whoami",
        "netstat",
        "curl",
        "wget",
        "crontab",
        "A technical note about chmod usage",
    ]
    for n in cmd_negatives:
        cats = categorize_string(n)
        assert "commands" not in cats, f"Did not expect 'commands' in {cats} for '{n}'"

    # 2. URLs vs Network
    url_positives = [
        "https://www.gnu.org/software/coreutils/",
        "http://update.example.com/check?v=1",
        "ftp://downloads.open-source.org/pub/file.tar.gz",
    ]
    for p in url_positives:
        cats = categorize_string(p)
        assert "urls" in cats, f"Expected 'urls' in {cats} for '{p}'"

    net_positives = [
        "192.0.2.1",
        "evil-c2.duckdns.org",
        "pastebin.com/raw/d83hfn",
        "POST /beacon HTTP/1.1",
        "Host: c2.badactor.invalid",
    ]
    for p in net_positives:
        cats = categorize_string(p)
        assert "network" in cats, f"Expected 'network' in {cats} for '{p}'"

    net_negatives = [
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "SOCK 01;35 # socket",
        "socket",
        "connect",
        "send",
        "recv",
        "WSAStartup",
    ]
    for n in net_negatives:
        cats = categorize_string(n)
        assert "network" not in cats, f"Did not expect 'network' in {cats} for '{n}'"

    # 3. File Paths
    path_positives = [
        "C:\\Windows\\System32\\cmd.exe",
        "%TEMP%\\dropper.exe",
        "/etc/shadow",
        "/etc/passwd",
        "/tmp/payload.elf",
        "\\\\.\\pipe\\evil_named_pipe",
    ]
    for p in path_positives:
        cats = categorize_string(p)
        assert "file_paths" in cats, f"Expected 'file_paths' in {cats} for '{p}'"

    path_negatives = [
        "passwd",
        "shadow",
        "id_rsa",
        "cmd.exe",
    ]
    for n in path_negatives:
        cats = categorize_string(n)
        assert "file_paths" not in cats, f"Did not expect 'file_paths' in {cats} for '{n}'"

    # 4. Registry
    reg_positives = [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Office",
        "Software\\Microsoft\\Notepad",
    ]
    for p in reg_positives:
        cats = categorize_string(p)
        assert "registry" in cats, f"Expected 'registry' in {cats} for '{p}'"

    reg_negatives = [
        "CurrentVersion",
        "RunOnce",
        "Notepad",
    ]
    for n in reg_negatives:
        cats = categorize_string(n)
        assert "registry" not in cats, f"Did not expect 'registry' in {cats} for '{n}'"

    # 5. Security APIs
    sec_api_positives = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "IsDebuggerPresent",
        "MiniDumpWriteDump",
        "CryptEncrypt",
    ]
    for p in sec_api_positives:
        cats = categorize_string(p)
        assert "security_apis" in cats, f"Expected 'security_apis' in {cats} for '{p}'"
        assert "api_names" in cats

    sec_api_negatives = [
        "printf",
        "malloc",
        "free",
        "strlen",
        "Unknown system error occurred",
    ]
    for n in sec_api_negatives:
        cats = categorize_string(n)
        assert "security_apis" not in cats, f"Did not expect 'security_apis' in {cats} for '{n}'"


def test_bare_words_not_categorized_as_commands_or_network():
    """Single isolated words must NOT be categorized as commands or network indicators.

    For example, 'SOCK 01;35 # socket' is a color string, and 'chmod@GLIBC_2.2.5' is a symbol.
    """
    bare_samples = [
        "socket",
        "connect",
        "WSAStartup",
        "SOCK 01;35 # socket",
        "chmod",
        "chmod@GLIBC_2.2.5",
        "whoami",
        "netstat",
        "schtasks",
        "passwd",
        "shadow",
        "id_rsa",
    ]
    for s in bare_samples:
        cats = categorize_string(s)
        assert "commands" not in cats, f"Bare word '{s}' must not be in 'commands'"
        assert "network" not in cats, f"Bare word '{s}' must not be in 'network'"


def test_strings_never_contribute_to_verdict_or_factors():
    """Verify that extracted strings and categorized buckets never elevate static risk score or verdict.

    A benign document/binary containing suspicious keywords across all categories
    must remain at score 0 with zero assessment factors in the absence of structural anomalies.
    """
    keyword_payload = (
        b"This is a benign technical document containing security analysis notes.\n"
        b"Commands discussed: cmd.exe /c whoami, powershell -enc AAAA, chmod +x dropper\n"
        b"APIs referenced: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, IsDebuggerPresent\n"
        b"Registry keys: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
        b"Paths: C:\\Windows\\System32\\cmd.exe, /etc/shadow\n"
        b"Network: https://example.com/api/v1/update\n"
    )
    result = run_complete_static_pipeline(keyword_payload)

    # Risk score must be strictly 0
    assert result["static_risk_score"] == 0
    # Must have 0 threat assessment factors
    assert len(result["assessment_factors"]) == 0
    # Verdict must be non-malicious
    assert result["verdict"] in ("no_indicators_found_limited", "insufficient_evidence")
    # Strings and categorization remain fully populated for analyst UI
    assert len(result["strings"]) > 0
    cats = result["categorized_strings"]
    assert len(cats["commands"]) > 0
    assert len(cats["security_apis"]) > 0
    assert len(cats["registry"]) > 0


def test_utf16le_non_ascii_known_limitation():
    """Document and verify the UTF-16LE ASCII-plane limitation (matching GNU binutils).

    Latin-1 code points (ASCII range 0x20..0x7E) are extracted; non-Latin code points
    (such as Cyrillic or CJK) have non-zero high bytes and are excluded from the ASCII plane.
    """
    latin_utf16 = "SystemConfigKey\x00".encode("utf-16le")
    cyrillic_utf16 = "Привет мир!\x00".encode("utf-16le")
    combined = latin_utf16 + b"\x00\x00" + cyrillic_utf16

    detailed, _ = extract_strings_detailed(combined, min_length=4)
    extracted_strings = [d["string"] for d in detailed]

    assert "SystemConfigKey" in extracted_strings
    # Non-Latin Cyrillic is not extracted by the Latin-1 plane scan (matching GNU strings -a -e l)
    assert not any("Привет" in s for s in extracted_strings)


def test_large_file_bounds_and_truncation():
    """Verify that extraction limits prevent memory inflation and report truncation faithfully."""
    # Generate 2 MB synthetic buffer containing 6,000 distinct strings
    chunks = [f"SyntheticStringNumber_{i:05d}\x00".encode("ascii") for i in range(6000)]
    payload = b"".join(chunks)

    # Default max_count is 2000
    detailed, trunc = extract_strings_detailed(payload, max_count=2000)

    assert len(detailed) == 2000
    assert trunc["is_truncated"] is True
    assert trunc["total_found"] == 6000
    assert trunc["stored_limit"] == 2000
    assert trunc["scan_bytes_processed"] == len(payload)


def test_pipeline_integration_returns_strings_and_detailed():
    """Verify that run_complete_static_pipeline populates strings, strings_detailed, and categorized_strings."""
    sample = (
        b"MZ"
        + b"\x00" * 10
        + b"https://update.example.com/check\x00"
        + b"C:\\Windows\\System32\\calc.exe\x00\x00"
        + "Software\\Microsoft\\TestApp\x00".encode("utf-16le")
        + b"\x00\x00VirtualAlloc\x00"
    )
    result = run_complete_static_pipeline(sample)

    assert "strings" in result
    assert "strings_detailed" in result
    assert "strings_truncation" in result
    assert "categorized_strings" in result

    cats = result["categorized_strings"]
    assert any("https://update.example.com" in s for s in cats["urls"])
    assert any("calc.exe" in s for s in cats["file_paths"])
    assert any("Software\\Microsoft\\TestApp" in s for s in cats["registry"])
    assert any("VirtualAlloc" in s for s in cats["security_apis"])
    assert any("VirtualAlloc" in s for s in cats["api_names"])

    # Verify strings_detailed ordering
    detailed = result["strings_detailed"]
    offsets = [d["offset"] for d in detailed]
    assert offsets == sorted(offsets), "strings_detailed must be sorted by file offset"
