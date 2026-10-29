"""Remcos RAT configuration decoder.

Targets Remcos RAT payloads (v2.x - v4.x).
Extracts C2 servers, connection ports, encryption passwords, mutex names,
and bot installation settings from RC4-encrypted SETTINGS resource blocks
or unpacked memory streams.
"""

import re
from typing import Any

from .base import FamilyConfigDecoder

_REMCOS_SIGNATURES = [
    b"remcos",
    b"breaking-security",
    b"settings",
    b"geoplugin.net",
    b"cmd.exe /k ",
]


def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    """Standard RC4 stream cipher decryption."""
    if not key or not data:
        return b""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    res = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        res.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(res)


class RemcosDecoder(FamilyConfigDecoder):
    """Decoder targeting Remcos RAT configurations."""

    family_name = "Remcos"
    target_version = "v2.x - v4.x"
    description = "Decodes RC4-encrypted Remcos RAT configuration blocks"

    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        lower_data = data.lower()
        if b"remcos" in lower_data or b"breaking-security" in lower_data:
            return True
        # Check for explicit SETTINGS resource marker paired with Remcos indicators
        if b"SETTINGS" in data and (b"RMC-" in data or b"Remcos" in data):
            return True
        return False

    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        # 1. Attempt RC4 decryption of candidate SETTINGS block
        decrypted_text = None
        settings_idx = data.find(b"SETTINGS")
        if settings_idx != -1:
            candidate_region = data[settings_idx : settings_idx + 8192]
            decrypted_text = self._try_rc4_extract(candidate_region)

        # Fallback scan across file for key-length prefixed RC4 payload
        if not decrypted_text:
            decrypted_text = self._try_rc4_extract(data)

        # Fallback to plain text scan if sample is an unpacked dump
        if not decrypted_text:
            decrypted_text = data.decode("latin1", errors="replace")

        # 2. Extract Remcos fields: C2 endpoints, ports, mutex
        return self._parse_config_fields(decrypted_text)

    def _try_rc4_extract(self, block: bytes) -> str | None:
        """Scan candidate blocks with key length byte (16-128 bytes) followed by ciphertext."""
        for offset in range(0, min(len(block) - 64, 4096)):
            key_len = block[offset]
            if 16 <= key_len <= 128 and offset + 1 + key_len + 32 <= len(block):
                key = block[offset + 1 : offset + 1 + key_len]
                ciphertext = block[offset + 1 + key_len : offset + 1 + key_len + 2048]
                plain = rc4_decrypt(key, ciphertext)
                # Remcos configuration strings typically contain '|' or '\x1e' and host:port
                if (b":" in plain or b"|" in plain) and (b"RMC" in plain or re.search(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}\b", plain)):
                    return plain.decode("latin1", errors="replace")
        return None

    def _parse_config_fields(self, text: str) -> dict[str, Any] | None:
        """Parse C2 host, port, mutex, and version from decrypted text."""
        # Check for host:port pattern
        c2_match = re.search(r"((?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})):(\d{2,5})", text)
        if not c2_match:
            return None

        c2_host = c2_match.group(1)
        port = int(c2_match.group(2))
        c2_endpoint = f"{c2_host}:{port}"

        # Extract mutex if present (e.g. RMC-XXXX or Remcos-XXXX)
        mutex_match = re.search(r"(RMC-[a-zA-Z0-9_-]{4,20}|Remcos-[a-zA-Z0-9_-]{4,20})", text)
        mutex = mutex_match.group(1) if mutex_match else None

        # Extract version
        ver_match = re.search(r"Remcos (?:v|version )?([0-9.]+ ?(?:Pro|Free|Community)?)", text, re.IGNORECASE)
        version = ver_match.group(1) if ver_match else self.target_version

        return {
            "family": self.family_name,
            "version": version,
            "c2_endpoint": c2_endpoint,
            "c2_servers": [c2_endpoint],
            "port": port,
            "mutex": mutex,
            "encryption": "RC4",
            "confidence": "high",
        }
