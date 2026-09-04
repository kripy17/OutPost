"""Tests for advanced sandbox forensics: in-memory carving and malware config extractor."""

from app.services.sandbox_forensics import calculate_entropy, extract_malware_config


def test_entropy_calculation():
    # Zero / empty
    assert calculate_entropy(b"") == 0.0
    # Single repeating byte (low entropy)
    assert calculate_entropy(b"A" * 1000) == 0.0
    # Random bytes (high entropy)
    high_ent_bytes = bytes([i % 256 for i in range(1024)])
    assert calculate_entropy(high_ent_bytes) > 7.5


def test_extract_malware_config():
    # Synthetic malware string containing C2, BTC wallet, and ransom note
    mock_payload = (
        b"Welcome to LockBit 3.0 Ransomware!\n"
        b"Your files have been encrypted with AES-256.\n"
        b"Send 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        b"Contact C2 server at http://198.51.100.45:8080/beacon\n"
        b"Do not reboot or shadows delete will execute.\n"
    )
    conf = extract_malware_config(mock_payload)
    assert conf["threat_score"] >= 60
    assert conf["verdict"] == "MALICIOUS"
    assert "198.51.100.45" in conf["c2_ips"]
    assert any("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in w for w in conf["crypto_wallets"])
    assert any("ransom" in r.lower() or "encrypt" in r.lower() for r in conf["ransom_indicators"])
    assert len(conf["behavioral_indicators"]) >= 3
