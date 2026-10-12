import tempfile
from pathlib import Path
from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_decode_b64_utf8():
    result = runner.invoke(app, ["decode", "d2hvYW1pIC9hbGw="])
    assert result.exit_code == 0
    assert "whoami /all" in result.stdout
    assert "Base64" in result.stdout


def test_decode_b64_powershell_utf16le():
    # "whoami /all" in UTF-16LE Base64
    result = runner.invoke(app, ["decode", "dwBoAG8AYQBtAGkAIAAvAGEAbABsAA=="])
    assert result.exit_code == 0
    assert "whoami /all" in result.stdout
    assert "PowerShell" in result.stdout


def test_decode_defanged_url_and_ioc_extraction():
    result = runner.invoke(app, ["decode", "hxxps://185[.]220[.]101[.]34/malware[.]exe"])
    assert result.exit_code == 0
    assert "185.220.101.34" in result.stdout
    assert "https://185.220.101.34/malware.exe" in result.stdout
    assert "Refanged IOCs" in result.stdout


def test_decode_hex():
    result = runner.invoke(app, ["decode", "\\x43\\x6d\\x64\\x2e\\x65\\x78\\x65"])
    assert result.exit_code == 0
    assert "Cmd.exe" in result.stdout


def test_decode_url_percent_encoding():
    result = runner.invoke(app, ["decode", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"])
    assert result.exit_code == 0
    assert "../../etc/passwd" in result.stdout


def test_hash_text():
    result = runner.invoke(app, ["hash", "test-payload"])
    assert result.exit_code == 0
    assert "MD5" in result.stdout
    assert "SHA-256" in result.stdout


def test_hash_file():
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("malicious payload contents")
        f_path = f.name

    try:
        result = runner.invoke(app, ["hash", f_path])
        assert result.exit_code == 0
        assert "SHA-256" in result.stdout
        assert "File:" in result.stdout
    finally:
        Path(f_path).unlink(missing_ok=True)


def test_decode_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTczMDAwMDAwMH0.dummy_sig"
    result = runner.invoke(app, ["decode", jwt])
    assert result.exit_code == 0
    assert "JWT Header" in result.stdout
    assert "JWT Payload" in result.stdout
    assert "admin" in result.stdout


def test_decode_rot13():
    rot = "cbjrefuryy -rap"
    result = runner.invoke(app, ["decode", rot])
    assert result.exit_code == 0
    assert "ROT13" in result.stdout
    assert "powershell -enc" in result.stdout


def test_decode_single_byte_xor():
    xor_hex = "322e2e2a6075753f2c333674393537"
    result = runner.invoke(app, ["decode", xor_hex])
    assert result.exit_code == 0
    assert "XOR Decrypted" in result.stdout
    assert "http://evil.com" in result.stdout


def test_decode_unix_timestamp():
    ts = "1730000000"
    result = runner.invoke(app, ["decode", ts])
    assert result.exit_code == 0
    assert "Unix Epoch Timestamp" in result.stdout
    assert "2024-10-27" in result.stdout

