"""Unit and integration tests for Stage 2 Item 4 Static Analysis:
Malware Family Configuration Decoders Expansion (AgentTesla, Cobalt Strike, Remcos, AsyncRAT, RedLine).

Validates:
- Precise family structural fingerprint verification (can_decode)
- Exact parameter extraction (C2 endpoints, ports, encryption keys, mutexes, campaigns)
- In-memory RC4 and XOR configuration decryption
- Static pipeline integration: decoded C2 endpoints feed into embedded indicators and elevate verdict to 'malicious'
- Zero false positives on benign system binaries and vendor DLLs
"""

import os
import struct
import pytest

from app.services.static.decoders.agent_tesla import AgentTeslaDecoder
from app.services.static.decoders.asyncrat import AsyncRATDecoder
from app.services.static.decoders.cobalt_strike import CobaltStrikeDecoder
from app.services.static.decoders.manager import run_family_decoders
from app.services.static.decoders.redline import RedLineDecoder
from app.services.static.decoders.remcos import RemcosDecoder, rc4_decrypt
from app.services.static.pipeline import run_complete_static_pipeline


def test_agent_tesla_telegram_decoder():
    """Verify AgentTesla Telegram API exfiltration channel extraction."""
    payload = (
        b"MZ" + b"\x00" * 100 +
        b"AgentTesla webpanel smtpserver telegrambot "
        b"https://api.telegram.org/bot123456789:ABCDEF1234567890abcdef1234567890abc/sendmessage\x00"
    )
    dec = AgentTeslaDecoder()
    assert dec.can_decode(payload, {}) is True
    cfg = dec.decode(payload, {})
    assert cfg is not None
    assert cfg["family"] == "AgentTesla"
    assert cfg["exfiltration_protocol"] == "telegram"
    assert "123456789:ABCDEF" in cfg["c2_endpoint"]


def test_agent_tesla_smtp_decoder():
    """Verify AgentTesla SMTP exfiltration channel extraction."""
    payload = (
        b"MZ" + b"\x00" * 100 +
        b"AgentTesla smtpserver exfiltration "
        b"smtp.evil-mailserver.com victim@malware-c2.net"
    )
    dec = AgentTeslaDecoder()
    assert dec.can_decode(payload, {}) is True
    cfg = dec.decode(payload, {})
    assert cfg is not None
    assert cfg["family"] == "AgentTesla"
    assert cfg["exfiltration_protocol"] == "smtp"
    assert cfg["c2_endpoint"] == "smtp.evil-mailserver.com"
    assert cfg["port"] == 587


def test_cobalt_strike_beacon_xor2e_decoder():
    """Verify Cobalt Strike Beacon configuration decoding with XOR 0x2E key."""
    dec = CobaltStrikeDecoder()
    xor_key = 0x2E

    # Construct minimal raw TLV block
    # Entry 1: beacon_type (short=8: HTTPS), Entry 2: port (short=443), Entry 8: c2_server (string)
    raw_block = bytearray()
    raw_block.extend(struct.pack(">HHH", 1, 1, 2))  # setting 1, kind short (1), len 2
    raw_block.extend(struct.pack(">H", 8))
    raw_block.extend(struct.pack(">HHH", 2, 1, 2))  # setting 2, kind short (1), len 2
    raw_block.extend(struct.pack(">H", 443))
    c2_bytes = b"c2.cobaltstrike-demo.com\x00"
    raw_block.extend(struct.pack(">HHH", 8, 3, len(c2_bytes)))  # setting 8, kind string (3)
    raw_block.extend(c2_bytes)
    raw_block.extend(b"\x00" * (4096 - len(raw_block)))

    # XOR encode with 0x2E
    encoded_block = bytes([b ^ xor_key for b in raw_block])
    sample = b"PE\x00\x00" + b"\x00" * 200 + encoded_block

    assert dec.can_decode(sample, {}) is True
    cfg = dec.decode(sample, {})
    assert cfg is not None
    assert cfg["family"] == "CobaltStrike"
    assert cfg["xor_key"] == "0x2E"
    assert cfg["c2_server"] == "c2.cobaltstrike-demo.com"
    assert cfg["port"] == 443


def test_remcos_rat_rc4_encrypted_decoder():
    """Verify Remcos RAT configuration decryption from RC4-encrypted SETTINGS block."""
    dec = RemcosDecoder()
    rc4_key = b"MySecretRemcosEncryptionKey12345"  # 32 bytes
    key_len = len(rc4_key)

    plaintext_cfg = b"198.51.100.25:2404:password|RMC-TESTBOT99|Remcos v3.8.4 Pro|install.exe"
    ciphertext = rc4_decrypt(rc4_key, plaintext_cfg)

    # Format: SETTINGS marker followed by 1-byte key_len, key, and ciphertext
    settings_block = bytearray(b"SETTINGS\x00\x00\x00")
    settings_block.append(key_len)
    settings_block.extend(rc4_key)
    settings_block.extend(ciphertext)
    settings_block.extend(b"\x00" * 512)

    sample = b"MZ" + b"\x00" * 500 + bytes(settings_block)

    assert dec.can_decode(sample, {}) is True
    cfg = dec.decode(sample, {})
    assert cfg is not None
    assert cfg["family"] == "Remcos"
    assert cfg["c2_endpoint"] == "198.51.100.25:2404"
    assert cfg["port"] == 2404
    assert cfg["mutex"] == "RMC-TESTBOT99"
    assert "3.8.4" in cfg["version"]


def test_remcos_rat_unpacked_stream_decoder():
    """Verify Remcos RAT decoding on unpacked memory dumps."""
    sample = (
        b"MZ" + b"\x00" * 200 +
        b"Remcos breaking-security geoplugin.net cmd.exe /k "
        b"c2.remcos-sample.org:443:Pass123|RMC-CAMPAIGN1|"
    )
    dec = RemcosDecoder()
    assert dec.can_decode(sample, {}) is True
    cfg = dec.decode(sample, {})
    assert cfg is not None
    assert cfg["family"] == "Remcos"
    assert cfg["c2_endpoint"] == "c2.remcos-sample.org:443"
    assert cfg["port"] == 443
    assert cfg["mutex"] == "RMC-CAMPAIGN1"


def test_asyncrat_decoder():
    """Verify AsyncRAT configuration extraction from .NET configuration tokens."""
    sample = (
        b"MZ" + b"\x00" * 200 +
        b"AsyncClient AsyncRAT Server.exe "
        b"Ports: 6606,7707 "
        b"Hosts: c2.asyncrat-hunter.net,198.51.100.40 "
        b"Pastebin: https://pastebin.com/raw/TestFeed123 "
        b"Version: 0.5.7B "
        b"Mutex: AsyncRAT-AlphaMutex"
    )
    dec = AsyncRATDecoder()
    assert dec.can_decode(sample, {}) is True
    cfg = dec.decode(sample, {})
    assert cfg is not None
    assert cfg["family"] == "AsyncRAT"
    assert "c2.asyncrat-hunter.net" in cfg["c2_endpoint"]
    assert cfg["port"] == 6606
    assert cfg["pastebin_fallback"] == "https://pastebin.com/raw/TestFeed123"
    assert cfg["mutex"] == "AsyncRAT-AlphaMutex"
    assert cfg["version"] == "0.5.7B"


def test_redline_stealer_net_tcp_decoder():
    """Verify RedLine Stealer Net.Tcp C2 endpoint and campaign extraction."""
    sample = (
        b"MZ" + b"\x00" * 200 +
        b"RedLine IRemoteEndpoint DownloadAndExecute "
        b"net.tcp://198.51.100.77:4125/service "
        b"Build: Campaign_RED_2026 "
        b"Key: RedLineXorSecretToken123"
    )
    dec = RedLineDecoder()
    assert dec.can_decode(sample, {}) is True
    cfg = dec.decode(sample, {})
    assert cfg is not None
    assert cfg["family"] == "RedLine"
    assert cfg["c2_endpoint"] == "net.tcp://198.51.100.77:4125/service"
    assert cfg["campaign_id"] == "Campaign_RED_2026"
    assert cfg["encryption_key"] == "RedLineXorSecretToken123"


def test_pipeline_integration_decoders_produce_malicious_verdict():
    """Verify decoded malware configurations propagate to static pipeline and elevate verdict to malicious."""
    # Synthetic Remcos sample
    remcos_payload = (
        b"MZ" + b"\x00" * 200 +
        b"Remcos breaking-security geoplugin.net cmd.exe /k "
        b"c2.remcos-threat.org:8080:Pass123|RMC-CAMPAIGN1|"
    )
    pipe_res = run_complete_static_pipeline(remcos_payload)
    assert len(pipe_res["decoded_configs"]) >= 1
    assert pipe_res["verdict"] == "malicious"
    assert pipe_res["static_risk_score"] >= 60
    assert any("Remcos" in f["factor"] for f in pipe_res["assessment_factors"])
    assert any(i["type"] == "c2_endpoint" and "c2.remcos-threat.org:8080" in i["value"] for i in pipe_res["embedded_indicators"])


def test_benign_binaries_zero_decoder_false_positives():
    """Verify benign host and vendor binaries yield 0 decoded configurations."""
    benign_paths = [
        "/bin/ls",
        "/tmp/heldout_eval/notepad.exe",
        "/tmp/throwaway_eval/sigcheck64.exe",
        "/tmp/throwaway_eval/7z.dll",
        "/tmp/throwaway_eval/nano_ubuntu_jammy",
    ]
    for bp in benign_paths:
        if not os.path.exists(bp):
            continue
        with open(bp, "rb") as f:
            data = f.read()
        res = run_family_decoders(data)
        assert len(res) == 0, f"Expected 0 decoded configs for {bp}, got {[c['family'] for c in res]}"
