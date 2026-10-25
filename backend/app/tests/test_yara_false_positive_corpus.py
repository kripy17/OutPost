"""Negative test corpus: ensure documentation, source code, and benign files do not false-positive.

Step 1 Review Requirement 9:
Broaden the YARA false-positive corpus (system files, docs, source packages, JS, PDFs).
"""

from pathlib import Path

from ..services import static_analysis, yara


def test_readme_clean_scan():
    readme_path = Path(__file__).resolve().parent.parent.parent.parent / "README.md"
    assert readme_path.exists(), "README.md must exist at repo root"
    data = readme_path.read_bytes()

    # Bundled YARA signature check
    yara_hits = yara.scan_sample(data)
    assert yara_hits == [], f"Expected 0 YARA hits on README.md, got {yara_hits}"

    # Static analysis pipeline check
    res = static_analysis.analyze_sample(data)
    assert res.get("static_severity") not in ("malicious", "suspicious")
    assert res.get("verdict") != "malicious"


def test_system_files_clean_scan():
    """System files (/etc/hosts, /etc/os-release, etc.) must not trigger YARA rules."""
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
                    if count >= 15:  # Sample up to 15 doc files for fast execution
                        break
                except (PermissionError, OSError):
                    continue


def test_source_packages_clean_scan():
    """Application source code across backend and CLI packages must not false positive."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    check_files = [
        repo_root / "backend" / "app" / "main.py",
        repo_root / "backend" / "app" / "core" / "db.py",
        repo_root / "backend" / "app" / "models" / "run.py",
        repo_root / "backend" / "app" / "services" / "dynamic_sandbox.py",
        repo_root / "cli" / "outpost" / "main.py",
        repo_root / "cli" / "outpost" / "commands" / "yara.py",
        repo_root / "cli" / "outpost" / "commands" / "samples.py",
    ]
    for src_file in check_files:
        assert src_file.exists(), f"Source file {src_file} must exist"
        data = src_file.read_bytes()
        hits = yara.scan_sample(data)
        assert hits == [], f"Expected 0 YARA hits on {src_file.name}, got {hits}"


def test_frontend_chunks_and_sources_clean():
    """Frontend JavaScript / TypeScript source chunks must not match malware rules."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    frontend_files = [
        repo_root / "frontend" / "src" / "main.tsx",
        repo_root / "frontend" / "src" / "App.tsx",
        repo_root / "frontend" / "src" / "routes" / "sampleDetail.tsx",
        repo_root / "frontend" / "package.json",
    ]
    for f in frontend_files:
        if f.exists():
            data = f.read_bytes()
            hits = yara.scan_sample(data)
            assert hits == [], f"Expected 0 YARA hits on frontend file {f.name}, got {hits}"


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
