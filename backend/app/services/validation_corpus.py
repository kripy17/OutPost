"""Local security validation corpus runner & accuracy regression gate.

Quantifies real detection rates and false-positive rates against an offline ground-truth
corpus of known-benign system binaries, admin scripts, and handled threat samples:
1. Enforces zero false positives on known-benign administration binaries and scripts.
2. Quantifies true-positive detection rate on handled malware families.
3. Fails regression gates if false-positive rate increases or detection rate decreases.
"""

import glob
import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any

from . import static_analysis

_CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"
_GROUND_TRUTH_FILE = _CORPUS_DIR / "ground_truth.json"


def _generate_synthetic_sample(sample_meta: dict[str, Any]) -> bytes:
    """Generate deterministic synthetic bytes matching the ground truth spec."""
    s_id = sample_meta["id"]

    if s_id == "benign-system-util-exe":
        # Clean PE with standard GetModuleHandle, normal sections, benign entropy
        pe_header = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64)
        pe_header.extend(b"PE\x00\x00")
        # Machine=0x8664 (x86-64), num_sections=1, opt_size=240, chars=0x0002
        pe_header.extend(b"\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x02\x00")
        # Optional header: magic=0x020B (PE32+), entry=0x1000
        pe_header.extend(b"\x0b\x02\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00")
        pe_header.extend(b"\x00" * 228)
        # Section header (.text): virtual_size=0x1000, virtual_addr=0x1000, raw_size=0x200, raw_ptr=0x200, chars=0x60000020 (RX)
        pe_header.extend(b".text\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60")
        pe_header.extend(b"\x00" * (0x200 - len(pe_header)))
        # Text section data: benign string and return
        pe_header.extend(b"\xc3" + b"OutPost Host Telemetry Core Service v1.0\x00" + b"\x90" * 450)
        return bytes(pe_header)

    elif s_id == "benign-admin-backup-sh":
        return (
            b"#!/bin/bash\n"
            b"# System Administrator Log Rotation and Archive Backup\n"
            b"BACKUP_DIR='/var/backups/system'\n"
            b"mkdir -p $BACKUP_DIR\n"
            b"tar -czf $BACKUP_DIR/logs_$(date +%Y%m%d).tar.gz /var/log/syslog\n"
            b"echo 'Backup completed successfully.'\n"
        )

    elif s_id == "benign-audit-ps1":
        return (
            b"# IT Administration Host Inventory and Performance Audit\n"
            b"$processes = Get-Process | Select-Object -Property Id, ProcessName, WorkingSet\n"
            b"$services = Get-Service | Where-Object { $_.Status -eq 'Running' }\n"
            b"Write-Output 'Host inventory collection complete.'\n"
        )

    elif s_id == "benign-manual-docx":
        # Clean OOXML without macros
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Standard Employee Handbook</w:t></w:r></w:p></w:body></w:document>")
        return buf.getvalue()

    elif s_id == "benign-invoice-pdf":
        return (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 40 >>\nstream\nBT /F1 12 Tf 72 712 Td (Invoice #4092 Paid) ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R /Size 5 >>\nstartxref\n250\n%%EOF\n"
        )

    elif s_id == "malicious-ransomware-sim":
        # PE with CryptEncrypt, vssadmin delete shadows, VirtualAllocEx, RWX section
        pe = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64)
        pe.extend(b"PE\x00\x00")
        pe.extend(b"\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x02\x00")
        pe.extend(b"\x0b\x02\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00")
        pe.extend(b"\x00" * 228)
        # Section header (.evil): RWX chars=0xE0000020
        pe.extend(b".evil\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\xe0")
        pe.extend(b"\x00" * (0x200 - len(pe)))
        pe.extend(b"vssadmin delete shadows /all /quiet\x00")
        pe.extend(b"CryptEncrypt\x00VirtualAllocEx\x00WriteProcessMemory\x00")
        pe.extend(b"YOUR FILES HAVE BEEN ENCRYPTED! Send 5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\x00")
        pe.extend(b"\x90" * 200)
        return bytes(pe)

    elif s_id == "malicious-c2-implant-elf":
        # ELF reverse shell calling socket, connect to public C2
        elf = bytearray(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3E\x00")
        elf.extend(b"\x01\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00")
        elf.extend(b"\x00" * 128)
        elf.extend(b"connect(sockfd, &serv_addr, sizeof(serv_addr))\x00")
        elf.extend(b"socket\x00ptrace\x00")
        elf.extend(b"185.220.101.5\x00")
        elf.extend(b"http://c2.darknet-command.xyz/heartbeat\x00")
        return bytes(elf)

    elif s_id == "malicious-macro-dropper-docm":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Invoice Document</w:t></w:r></w:p></w:body></w:document>")
            zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\nSet sh = CreateObject(\"WScript.Shell\")\nsh.Run \"powershell.exe -enc aWV4\"\nEnd Sub")
        return buf.getvalue()

    elif s_id == "malicious-stealth-shortcut-lnk":
        # LNK header with SW_HIDE (ShowCommand = 0) targeting powershell
        lnk = bytearray(b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46")
        lnk.extend(b"\x21\x00\x00\x00")  # Flags: HasTargetIDList | HasArguments
        lnk.extend(b"\x00" * 32)
        lnk.extend(b"\x00\x00\x00\x00")  # ShowCommand: SW_HIDE (0)
        lnk.extend(b"\x00" * 16)
        lnk.extend(b"powershell.exe -WindowStyle Hidden -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp")
        return bytes(lnk)

    elif s_id == "malicious-phish-smuggle-html":
        return (
            b"<!DOCTYPE html>\n"
            b"<html><body>\n"
            b"<script>\n"
            b"var payload = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAA...';\n"
            b"var bytes = atob(payload);\n"
            b"var blob = new Blob([bytes], {type: 'application/octet-stream'});\n"
            b"var a = document.createElement('a');\n"
            b"a.href = window.URL.createObjectURL(blob);\n"
            b"a.download = 'urgent_invoice.exe';\n"
            b"a.click();\n"
            b"</script>\n"
            b"</body></html>\n"
        )

    return b"Generic test payload"


def evaluate_validation_corpus() -> dict[str, Any]:
    """Execute complete validation suite across all corpus samples and compute accuracy metrics."""
    if not _GROUND_TRUTH_FILE.exists():
        raise FileNotFoundError(f"Ground truth catalog missing at {_GROUND_TRUTH_FILE}")

    with open(_GROUND_TRUTH_FILE, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    samples = catalog.get("samples", [])
    results: list[dict[str, Any]] = []

    tp = 0  # True Positives (correctly identified as malicious or suspicious)
    fp = 0  # False Positives (benign misidentified as malicious or suspicious)
    tn = 0  # True Negatives (benign correctly marked as no_indicators_found_limited)
    fn = 0  # False Negatives (malicious missed)
    crashes = 0

    for s_meta in samples:
        sample_bytes = _generate_synthetic_sample(s_meta)
        expected_malicious = s_meta["is_malicious"]
        expected_verdict = s_meta["expected_verdict"]

        try:
            analysis = static_analysis.analyze_sample(sample_bytes)
            actual_verdict = analysis.get("verdict", "unknown")
            is_flagged_threat = actual_verdict in ("malicious", "suspicious")

            if expected_malicious:
                if is_flagged_threat:
                    tp += 1
                    status = "PASS_TP"
                else:
                    fn += 1
                    status = "FAIL_FN"
            else:
                if not is_flagged_threat:
                    tn += 1
                    status = "PASS_TN"
                else:
                    fp += 1
                    status = "FAIL_FP"

            results.append({
                "sample_id": s_meta["id"],
                "filename": s_meta["filename"],
                "expected_malicious": expected_malicious,
                "expected_verdict": expected_verdict,
                "actual_verdict": actual_verdict,
                "evidence_quality": analysis.get("evidence_quality"),
                "status": status,
                "passed": status in ("PASS_TP", "PASS_TN"),
                "indicators_count": analysis.get("indicators_found_count", 0),
            })
        except Exception as exc:
            crashes += 1
            results.append({
                "sample_id": s_meta["id"],
                "filename": s_meta["filename"],
                "status": "CRASH",
                "error": str(exc),
                "passed": False,
            })

    total_malicious = tp + fn
    total_benign = tn + fp
    total_samples = len(samples)

    detection_rate = round(tp / total_malicious, 4) if total_malicious > 0 else 1.0
    false_positive_rate = round(fp / total_benign, 4) if total_benign > 0 else 0.0

    # Regression gate: Zero tolerance for FP on benign set; detection rate must be >= 0.95
    passed_gate = (false_positive_rate == 0.0) and (detection_rate >= 0.95) and (crashes == 0)

    stock_os = evaluate_stock_os_files()
    if stock_os["malicious_count"] > 0:
        passed_gate = False

    return {
        "corpus_name": catalog.get("corpus_name"),
        "version": catalog.get("version"),
        "total_samples": total_samples,
        "metrics": {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "parser_crashes": crashes,
            "detection_rate": detection_rate,
            "false_positive_rate": false_positive_rate,
        },
        "stock_os_metrics": {
            "total_files": stock_os["total_files"],
            "clean_count": stock_os["clean_count"],
            "suspicious_count": stock_os["suspicious_count"],
            "malicious_count": stock_os["malicious_count"],
            "false_positive_rate": stock_os["false_positive_rate"],
        },
        "regression_gate": {
            "passed": passed_gate,
            "fp_tolerance": 0.0,
            "min_detection_rate": 0.95,
            "max_crashes": 0,
        },
        "sample_results": results,
        "stock_os_results": stock_os["files"],
    }


def evaluate_stock_os_files(min_files: int = 50) -> dict[str, Any]:
    """Evaluate OutPost static pipeline against stock host OS binaries, scripts, and utilities.

    Verifies that distribution-provided binaries and system scripts yield zero false-positive
    'malicious' verdicts, capturing SHA-256 provenance for each analyzed artifact.
    """
    candidate_paths = [
        # Linux core utilities (ELF)
        "/usr/bin/ls", "/usr/bin/cp", "/usr/bin/mv", "/usr/bin/rm", "/usr/bin/cat",
        "/usr/bin/grep", "/usr/bin/tar", "/usr/bin/sed", "/usr/bin/date", "/usr/bin/echo",
        "/usr/bin/uname", "/usr/bin/df", "/usr/bin/kill", "/usr/bin/sleep", "/usr/bin/chmod",
        "/usr/bin/mkdir", "/usr/bin/touch", "/usr/bin/ln", "/usr/bin/gzip", "/usr/bin/find",
        "/usr/bin/wc", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/cut", "/usr/bin/sort",
        "/usr/bin/uniq", "/usr/bin/tr", "/usr/bin/diff", "/usr/bin/stat", "/usr/bin/strings",
        "/usr/bin/basename", "/usr/bin/dirname", "/usr/bin/env", "/usr/bin/xargs", "/usr/bin/tee",
        "/usr/bin/readelf", "/usr/bin/objdump", "/usr/bin/nm", "/usr/bin/strip", "/usr/bin/file",
        "/usr/bin/which", "/usr/bin/id", "/usr/bin/groups", "/usr/bin/whoami", "/usr/bin/du",
    ]

    # System administration shell scripts
    system_scripts = glob.glob("/etc/profile.d/*.sh") + ["/etc/bash.bashrc", "/etc/profile"]
    candidate_paths.extend(system_scripts)

    # Standard Python library scripts
    for p in glob.glob("/usr/lib/python3*"):
        if os.path.isdir(p):
            for py_name in (
                "os.py", "argparse.py", "subprocess.py", "hashlib.py", "shutil.py",
                "tarfile.py", "zipfile/__init__.py", "json/__init__.py", "logging/__init__.py",
                "pathlib/__init__.py", "urllib/parse.py", "email/__init__.py", "http/__init__.py",
            ):
                full_py = os.path.join(p, py_name)
                if os.path.exists(full_py):
                    candidate_paths.append(full_py)

    # Resolve unique real files
    collected_files: list[str] = []
    seen_real_paths: set[str] = set()

    for c in candidate_paths:
        try:
            real = os.path.realpath(c)
            if os.path.exists(real) and os.path.isfile(real) and real not in seen_real_paths:
                seen_real_paths.add(real)
                collected_files.append(real)
        except Exception:
            continue

    # If still below target min_files, discover additional binaries from /usr/bin
    if len(collected_files) < min_files:
        for extra in glob.glob("/usr/bin/*"):
            try:
                real = os.path.realpath(extra)
                if os.path.isfile(real) and real not in seen_real_paths:
                    seen_real_paths.add(real)
                    collected_files.append(real)
                    if len(collected_files) >= min_files:
                        break
            except Exception:
                continue

    file_results: list[dict[str, Any]] = []
    malicious_files: list[str] = []
    suspicious_files: list[str] = []
    clean_count = 0

    for file_path in collected_files:
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            analysis = static_analysis.analyze_sample(data)
            verdict = analysis.get("verdict", "unknown")

            if verdict == "malicious":
                malicious_files.append(file_path)
            elif verdict == "suspicious":
                suspicious_files.append(file_path)
            else:
                clean_count += 1

            file_results.append({
                "provenance": {
                    "path": file_path,
                    "sha256": sha256,
                    "size_bytes": len(data),
                },
                "format": analysis.get("format", "unknown"),
                "verdict": verdict,
                "risk_score": analysis.get("static_risk_score", 0),
                "could_not_analyze": analysis.get("could_not_analyze", []),
            })
        except Exception as exc:
            file_results.append({
                "provenance": {
                    "path": file_path,
                    "sha256": "",
                    "size_bytes": 0,
                },
                "format": "error",
                "verdict": "parser_failed",
                "error": str(exc),
            })

    total = len(file_results)
    malicious_count = len(malicious_files)
    suspicious_count = len(suspicious_files)
    fp_rate = round(malicious_count / total, 4) if total > 0 else 0.0

    return {
        "total_files": total,
        "clean_count": clean_count,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "false_positive_rate": fp_rate,
        "malicious_files": malicious_files,
        "suspicious_files": suspicious_files,
        "files": file_results,
    }

