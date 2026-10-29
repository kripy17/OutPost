"""Cobalt Strike Beacon configuration block decoder.

Targets Cobalt Strike Beacon payloads (v3/v4).
Extracts C2 servers, port, sleep time, jitter, user-agent, pipe names,
and watermark from XOR 0x2E or 0x69 encoded config blocks.
"""

import struct
from typing import Any

from .base import FamilyConfigDecoder

_BEACON_SETTINGS = {
    1: ("beacon_type", "short"),
    2: ("port", "short"),
    3: ("sleep_time_ms", "int"),
    4: ("max_get_size", "int"),
    5: ("jitter_percent", "short"),
    6: ("max_dns_size", "short"),
    7: ("public_key", "bytes"),
    8: ("c2_server", "string"),
    9: ("user_agent", "string"),
    10: ("http_post_uri", "string"),
    11: ("http_get_uri", "string"),
    14: ("spawn_to_x86", "string"),
    29: ("spawn_to_x64", "string"),
    37: ("watermark", "int"),
}


class CobaltStrikeDecoder(FamilyConfigDecoder):
    """Decoder targeting Cobalt Strike Beacon configurations."""

    family_name = "CobaltStrike"
    target_version = "v3/v4"
    description = "Decodes XOR 0x2E and 0x69 encoded Cobalt Strike Beacon configurations"

    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        # Fast scan for XOR-encoded beacon block signature (0x2E or 0x69)
        # Type 1 (beacon_type) XORed with 0x2E is 0x2F; XORed with 0x69 is 0x68
        return len(data) >= 1024 and (self._find_config_block(data, 0x2E) is not None or self._find_config_block(data, 0x69) is not None)

    def _find_config_block(self, data: bytes, xor_key: int) -> int | None:
        """Scan for beacon setting index 1 (beacon_type) and index 2 (port) sequence."""
        target_seq1 = bytes([0 ^ xor_key, 1 ^ xor_key, 0 ^ xor_key, 1 ^ xor_key])
        target_seq2 = bytes([0 ^ xor_key, 1 ^ xor_key, 0 ^ xor_key, 2 ^ xor_key])
        pos = data.find(target_seq1)
        if pos != -1:
            return pos
        pos = data.find(target_seq2)
        if pos != -1:
            return pos
        return None

    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        for xor_key in (0x2E, 0x69):
            pos = self._find_config_block(data, xor_key)
            if pos is not None:
                # Decode 4096-byte config block
                block = bytes([b ^ xor_key for b in data[pos : pos + 4096]])
                config = self._parse_block(block)
                if config and "c2_server" in config:
                    c2_host = config.get("c2_server")
                    port = config.get("port")
                    c2_endpoint = f"{c2_host}:{port}" if c2_host and port else c2_host
                    return {
                        "family": self.family_name,
                        "version": self.target_version,
                        "xor_key": f"0x{xor_key:02X}",
                        "c2_endpoint": c2_endpoint,
                        **config,
                        "confidence": "high",
                    }
        return None

    def _parse_block(self, block: bytes) -> dict[str, Any]:
        """Parse decrypted TLV settings."""
        result: dict[str, Any] = {}
        offset = 0
        while offset + 6 <= len(block):
            setting_type, val_type, val_len = struct.unpack_from(">HHH", block, offset)
            offset += 6
            if setting_type == 0 or offset + val_len > len(block):
                break

            val_bytes = block[offset : offset + val_len]
            offset += val_len

            if setting_type in _BEACON_SETTINGS:
                name, kind = _BEACON_SETTINGS[setting_type]
                if kind == "string":
                    result[name] = val_bytes.split(b"\x00", 1)[0].decode("latin1", "ignore").strip()
                elif kind == "short" and len(val_bytes) >= 2:
                    result[name] = struct.unpack(">H", val_bytes[:2])[0]
                elif kind == "int" and len(val_bytes) >= 4:
                    result[name] = struct.unpack(">I", val_bytes[:4])[0]

        return result
