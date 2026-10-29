"""Test suite and regression gate for the local security validation corpus."""

from app.services import validation_corpus


def test_validation_corpus_regression_gate():
    """Verify that OutPost achieves 0% false positives on benign samples and >= 95% detection rate."""
    report = validation_corpus.evaluate_validation_corpus()

    assert report["total_samples"] >= 10
    metrics = report["metrics"]

    # Gate 1: Zero False Positives on legitimate administration tools and clean documents
    assert metrics["false_positives"] == 0, f"False positive regression: {metrics['false_positives']} benign files misidentified"
    assert metrics["false_positive_rate"] == 0.0

    # Gate 2: True positive detection rate must meet or exceed 95%
    assert metrics["detection_rate"] >= 0.95, f"Detection rate regression: {metrics['detection_rate']} < 0.95"

    # Gate 3: Zero parser crashes
    assert metrics["parser_crashes"] == 0, f"Parser crashed on {metrics['parser_crashes']} samples"

    # Gate 4: Master regression gate passes
    assert report["regression_gate"]["passed"] is True


def test_corpus_api_report_endpoint(client):
    """Verify the /corpus/report API endpoint returns valid metrics."""
    resp = client.get("/corpus/report")
    assert resp.status_code == 200
    data = resp.json()

    assert "metrics" in data
    assert data["metrics"]["false_positive_rate"] == 0.0
    assert data["metrics"]["detection_rate"] >= 0.95
    assert len(data["sample_results"]) >= 10


def test_stock_os_files_validation_gate():
    """Verify that OutPost evaluates at least 50 real OS system files with zero malicious false positives."""
    res = validation_corpus.evaluate_stock_os_files()
    assert res["total_files"] >= 50
    assert res["malicious_count"] == 0, f"Stock OS files flagged as malicious: {res['malicious_files']}"
    assert res["false_positive_rate"] == 0.0
    for file_res in res["files"]:
        assert "provenance" in file_res
        assert "sha256" in file_res["provenance"]
        assert "path" in file_res["provenance"]
        assert "format" in file_res
        assert file_res["verdict"] != "malicious"


def test_held_out_multi_format_clean_corpus():
    """Verify that OutPost evaluates a held-out set of multi-format benign files (PE, PDF, Office, Scripts, LNK, Archives)
    with zero malicious false positives and bounded medium/low confidence."""
    import io
    import tarfile
    import zipfile

    from app.services import static_analysis

    held_out_samples = {}

    # 1. Benign Windows PE32+ (x64) binary
    pe = bytearray(b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64)
    pe.extend(b"PE\x00\x00")
    pe.extend(b"\x64\x86\x01\x00\x00\x00\x10\x67\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x02\x00")
    opt = bytearray(b"\x0b\x02" + b"\x00" * 14 + (0x1000).to_bytes(4, "little") + b"\x00" * (108 - 20))
    opt.extend((16).to_bytes(4, "little") + b"\x00" * (240 - 112))
    pe.extend(opt)
    sec = (
        b".text\x00\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x10\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00\x02\x00\x00" +
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
        b"\x20\x00\x00\x60"
    )
    pe.extend(sec)
    pe.extend(b"\x00" * (0x200 - len(pe)))
    pe.extend(b"\x31\xc0\xc3" + b"Held-out clean utility\x00")
    pe.extend(b"\x00" * (0x400 - len(pe)))
    held_out_samples["clean_heldout_x64.exe"] = bytes(pe)

    # 2. Benign PDF 1.7 document
    held_out_samples["security_report_q3.pdf"] = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 55 >>\nstream\nBT /F1 12 Tf 72 700 Td (Quarterly Security Infrastructure Audit) ET\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R /Size 5 >>\nstartxref\n290\n%%EOF\n"
    )

    # 3. Benign Office DOCX (no macros)
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Standard Operating Procedure Document</w:t></w:r></w:p></w:body></w:document>")
    held_out_samples["incident_response_sop.docx"] = docx_buf.getvalue()

    # 4. Benign Office XLSX (no macros)
    xlsx_buf = io.BytesIO()
    with zipfile.ZipFile(xlsx_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>')
    held_out_samples["asset_inventory.xlsx"] = xlsx_buf.getvalue()

    # 5. Benign Windows Shell Link (LNK) - standard SW_SHOWNORMAL (1) at offset 0x3C
    lnk_data = bytearray(b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46")
    lnk_data.extend(b"\x00" * (76 - len(lnk_data)))
    lnk_data[60] = 1  # SW_SHOWNORMAL (normal window launch, not SW_HIDE)
    held_out_samples["calculator_shortcut.lnk"] = bytes(lnk_data)

    # 6. Benign PowerShell administration script
    held_out_samples["audit_inventory.ps1"] = (
        b"# Infrastructure Health Inventory\n"
        b"$info = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property Caption, Version, LastBootUpTime\n"
        b"Write-Host 'OS Inventory gathered:' $info.Caption\n"
    )

    # 7. Benign Bash maintenance script
    held_out_samples["rotate_logs.sh"] = (
        b"#!/usr/bin/env bash\n"
        b"set -euo pipefail\n"
        b"LOG_DIR='/var/log/audit'\n"
        b"if [ -d \"$LOG_DIR\" ]; then\n"
        b"    find \"$LOG_DIR\" -name '*.log.*' -mtime +14 -delete\n"
        b"fi\n"
    )

    # 8. Benign Python administrative script
    held_out_samples["check_metrics.py"] = (
        b"import sys, os, logging\n"
        b"logging.basicConfig(level=logging.INFO)\n"
        b"def main():\n"
        b"    load1, load5, load15 = os.getloadavg()\n"
        b"    logging.info('System load averages: 1m=%s 5m=%s 15m=%s', load1, load5, load15)\n"
        b"if __name__ == '__main__':\n"
        b"    main()\n"
    )

    # 9. Benign tar.gz archive
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        data_bytes = b"Config parameter = true\n"
        ti = tarfile.TarInfo(name="config.conf")
        ti.size = len(data_bytes)
        tf.addfile(ti, io.BytesIO(data_bytes))
    held_out_samples["bundle_config.tar.gz"] = tar_buf.getvalue()

    # 10. Benign ZIP archive
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "Held-out benign documentation archive\n")
    held_out_samples["notes_archive.zip"] = zip_buf.getvalue()

    for filename, raw_data in held_out_samples.items():
        res = static_analysis.analyze_sample(raw_data)
        verdict = res.get("verdict")
        confidence = res.get("confidence")

        # Must never be flagged malicious
        assert verdict != "malicious", f"False positive on held-out benign file {filename}: {res}"
        assert verdict in ("no_indicators_found_limited", "insufficient_evidence"), f"Unexpected verdict {verdict} for {filename}"
        # Negative static verdict confidence must be bounded to medium or low (never high)
        assert confidence in ("medium", "low"), f"Contradictory confidence '{confidence}' for {verdict} on {filename}"

